/*
 * PDS Reliability-CC APIs
 */

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>

#include <sys/poll.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/if_packet.h>

#include <ofi_list.h>

#include <uet_addr.h>
#include <uet_pkt_hdr.h>
#include <uet_nic.h>
#include <uet_api.h>
#include <uet_pds.h>
#include <uet_api_private.h>
#include <uet_util.h>
#include "uet_cc_st.h"

#define UET_CC_MAX_SACK_MTUS 16

struct uet_cc_ctx;

enum uet_cc_path_update {
	UET_CC_PATH_ACK,
	UET_CC_PATH_ECN,
	UET_CC_PATH_NACK,
	UET_CC_PATH_RTO
};

enum uet_cc_path_state {
	UET_CC_PATH_GOOD,
	UET_CC_PATH_BAD,
	UET_CC_PATH_SKIP
};

enum uet_ccc_state {
	UET_CCC_STATE_IDLE,     /* nothing to send, idle */
	UET_CCC_STATE_PENDING,  /* nothing to send, awaiting acks */
	UET_CCC_STATE_ACTIVE,   /* data to send, cwnd too low */
	UET_CCC_STATE_READY     /* data to send, ready */
};

/* SmaRTTrack Sender API */

struct uet_cc_ctx {
	struct {
		uint32_t bdp_bytes;
		uint32_t cwnd_max;
		uint32_t base_rtt_usec;
		uint32_t target_qdelay_usec;
		uint32_t qa_scale;
		uint32_t qa_thresh;
		uint32_t adj_bytes_thresh;
		uint32_t adj_usec_thresh;
		uint32_t fi_scale;
		uint32_t pi;
		float scaling_c;
		float alpha;
		float fd;
		float fi;
		float gamma;
		float scaling_factor_a;
		float eta;
		float ecn_alpha;
		float ecn_thresh;
		float max_md_factor;
		float delay_ewma_factor;
		uint16_t max_paths;
		uint16_t mtu;
		enum uet_cc_spraying_type spraying_type;
	}
	params;

	void *handle;

	uint32_t cwnd;
	uint32_t backlog;
	uint32_t in_flight;
	uint32_t recv_bytes;
	uint32_t achieved_bytes;
	uint32_t fi_cnt;
	uint32_t qa_ign_bytes;
	uint32_t inc_bytes;
	uint32_t dec_bytes;
	uint32_t rtx_cnt;
	uint32_t avg_delay_usec;
	uint32_t next_ev;
	enum uet_ccc_state state;
	struct timespec qa_end;
	struct timespec last_cwnd_adj;
	struct timespec last_dec;
	uint8_t *ev_state;
	uint16_t num_paths;
	uint16_t bad_paths;
	uint16_t skip_paths;
	bool qa_trigger;
	bool fi_active;
	float ecn_exp_table[UET_CC_MAX_SACK_MTUS];
	float avg_ecn_rate;
};

static inline uint8_t get_ev_state(struct uet_cc_ctx *ccc, uint16_t ev)
{
	uint16_t idx = ev >> 2;
	uint8_t shift = 2 * (ev & 3);
	uint8_t mask = 3 << shift;

	return (ccc->ev_state[idx] & mask) >> shift;
}

static inline void set_ev_state(struct uet_cc_ctx *ccc, uint16_t ev, enum uet_cc_path_state state)
{
	uint16_t idx = ev >> 2;
	uint8_t shift = 2 * (ev & 3);
	uint8_t mask = ~(3 << shift);

	ccc->ev_state[idx] &= mask; /* clear existing state bits */
	mask = state << shift;
	ccc->ev_state[idx] |= mask;
}

struct uet_cc_ctx *uet_cc_alloc_ctx(enum uet_cc_spraying_type spraying_type, bool trim_supp,
	uint16_t mtu, uint32_t bw_mbps, uint32_t base_rtt_usec, uint16_t max_paths, void *handle)
{
	struct uet_cc_ctx *ccc = calloc(1, sizeof(*ccc));

	if (!ccc) {
		UET_API_PRINT_ERRNO("calloc");
		return NULL;
	}
	ccc->params.base_rtt_usec = base_rtt_usec;
	ccc->params.bdp_bytes = bw_mbps * base_rtt_usec / 8;
	ccc->params.cwnd_max = 1.25 * ccc->params.bdp_bytes;
	ccc->params.target_qdelay_usec = trim_supp ? base_rtt_usec / 2 : base_rtt_usec;
	ccc->params.mtu = mtu;
	ccc->params.pi = 5 * mtu;
	ccc->params.scaling_c = mtu / (ccc->params.target_qdelay_usec * ccc->params.pi);
	ccc->params.alpha = ccc->params.pi * mtu * ccc->params.scaling_c;
	ccc->params.fd = 0.8;
	ccc->params.fi = 1;
	ccc->params.fi_scale = 1;
	ccc->params.scaling_factor_a = (float) ccc->params.bdp_bytes / 150000; /* 100Gbps * 12us */
	ccc->params.eta = 0.15 * mtu * ccc->params.scaling_factor_a;
	ccc->params.qa_thresh = (trim_supp ? 4 : 2) * ccc->params.target_qdelay_usec;
	ccc->params.ecn_alpha = 0.125;
	ccc->params.ecn_thresh = 0.2;
	ccc->params.max_md_factor = 0.5;
	ccc->params.adj_bytes_thresh = 8 * mtu;
	ccc->params.adj_usec_thresh = base_rtt_usec;
	ccc->params.max_paths = max_paths;
	ccc->params.spraying_type = spraying_type;
	ccc->params.qa_scale = 1;
	ccc->params.delay_ewma_factor = 0.9;

	ccc->state = UET_CCC_STATE_IDLE;
	ccc->cwnd = ccc->params.cwnd_max;
	ccc->num_paths = max_paths;
	ccc->handle = handle;
	clock_gettime(CLOCK_MONOTONIC, &ccc->last_cwnd_adj);
	ccc->last_dec = ccc->last_cwnd_adj;

	float exp_decay = 1.0 - ccc->params.ecn_alpha;

	for (int i = 0; i < UET_CC_MAX_SACK_MTUS; i++) {
		ccc->ecn_exp_table[i] = exp_decay;
		exp_decay *= (1.0 - ccc->params.ecn_alpha);
	}

	ccc->ev_state = calloc(ccc->params.max_paths / 4, sizeof(uint8_t)); /* (2 bits / path) */
	if (!ccc->ev_state) {
		UET_API_PRINT_ERRNO("malloc");
		return NULL;
	}
	return ccc;
}

void uet_cc_free_ctx(struct uet_cc_ctx *ccc)
{
	free(ccc->ev_state);
	free(ccc);
}

static void update_ccc_state(struct uet_cc_ctx *ccc)
{
	if (!ccc->backlog && !ccc->rtx_cnt)
		ccc->state = ccc->in_flight ? UET_CCC_STATE_PENDING : UET_CCC_STATE_IDLE;
	else if (ccc->state == UET_CCC_STATE_IDLE || ccc->state == UET_CCC_STATE_PENDING)
		ccc->state = UET_CCC_STATE_ACTIVE;

	if (ccc->state == UET_CCC_STATE_ACTIVE && ccc->in_flight < ccc->cwnd)
		ccc->state = UET_CCC_STATE_READY;
	else if (ccc->state == UET_CCC_STATE_READY && ccc->in_flight >= ccc->cwnd)
		ccc->state = UET_CCC_STATE_ACTIVE;

	uet_cc_state_update(ccc->handle, ccc->state == UET_CCC_STATE_READY);
}

static void update_path(struct uet_cc_ctx *ccc, uint32_t ev, enum uet_cc_path_update update)
{
	if (update == UET_CC_PATH_RTO) {
		if (get_ev_state(ccc, ev) == UET_CC_PATH_SKIP)
			ccc->skip_paths--;
		ccc->bad_paths++;
		set_ev_state(ccc, ev, UET_CC_PATH_BAD);
	} else if (update == UET_CC_PATH_ECN || update == UET_CC_PATH_NACK) {
		if (get_ev_state(ccc, ev) == UET_CC_PATH_BAD)
			ccc->bad_paths--;
		ccc->skip_paths++;
		set_ev_state(ccc, ev, UET_CC_PATH_SKIP);
	} else if (update == UET_CC_PATH_ACK) {
		if (get_ev_state(ccc, ev) == UET_CC_PATH_SKIP)
			ccc->skip_paths--;
		else if (get_ev_state(ccc, ev) == UET_CC_PATH_BAD)
			ccc->bad_paths--;
		set_ev_state(ccc, ev, UET_CC_PATH_GOOD);
	}

	/* Too many paths skipped, likely incast. */
	if (ccc->skip_paths > ccc->cwnd / (2 * ccc->params.mtu)) {
		/* TODO Re-enable 2 paths. */
		/* ccc->skip_paths -= 2 */;
	}

	/* Too many paths disabled, likely incast, not a failed link. */
	if (ccc->bad_paths > ccc->cwnd / (2 * ccc->params.mtu)) {
		/* TODO Re-enable 2 paths. */
		/* TODO send probes on re-enabled paths. */
		/* ccc->bad_paths -= 2 */;
	}
}

static uint32_t select_entropy(struct uet_cc_ctx *ccc)
{
	if (ccc->params.spraying_type == UET_CC_NO_SPRAY) {
		/* TODO (single-path) change path if congestion experienced and idle */
		return ccc->next_ev;
	}

	uint32_t ev;

	while (true) {
		ev = ccc->next_ev;
		/* TODO random shuffle */
		ccc->next_ev++;
		if (ccc->next_ev == ccc->num_paths)
			ccc->next_ev = 0;

		if (ccc->params.spraying_type == UET_CC_OBLIVIOUS_SPRAY)
			break;

		enum uet_cc_path_state ev_state = get_ev_state(ccc, ev);

		if (ev_state == UET_CC_PATH_GOOD)
			break;
		if (ev_state == UET_CC_PATH_SKIP)
			set_ev_state(ccc, ev, UET_CC_PATH_GOOD);
	}

	return ev;
}

static void adjust_cwnd(struct uet_cc_ctx *ccc)
{
	ccc->cwnd += (ccc->inc_bytes + ccc->params.eta) / ccc->cwnd
				- (ccc->dec_bytes * ccc->cwnd / ccc->params.bdp_bytes);
	if (ccc->cwnd < ccc->params.mtu)
		ccc->cwnd = ccc->params.mtu;
	ccc->inc_bytes = 0;
	ccc->dec_bytes = 0;
	ccc->recv_bytes = 0;
	clock_gettime(CLOCK_MONOTONIC, &ccc->last_cwnd_adj);
}

static void fair_increase(struct uet_cc_ctx *ccc, uint32_t newly_acked_bytes)
{
	ccc->inc_bytes += ccc->params.fi * ccc->params.mtu * newly_acked_bytes;
}

static void fast_increase(struct uet_cc_ctx *ccc, uint32_t newly_acked_bytes, uint32_t delay_usec)
{
	if (!delay_usec) {
		ccc->fi_cnt += newly_acked_bytes;
		if (ccc->fi_cnt > ccc->cwnd || ccc->fi_active) {
			ccc->cwnd += newly_acked_bytes * ccc->params.fi_scale;
			ccc->fi_active = true;
			return;
		}
	} else {
		ccc->fi_cnt = 0;
	}
	ccc->fi_active = false;
}

static void proportional_increase(struct uet_cc_ctx *ccc, uint32_t newly_acked_bytes,
	uint32_t delay_usec)
{
	fast_increase(ccc, newly_acked_bytes, delay_usec);
	if (ccc->fi_active)
		return;
	ccc->inc_bytes += uet_min(newly_acked_bytes * ccc->params.pi,
				ccc->params.alpha * (ccc->params.target_qdelay_usec - delay_usec));
	fair_increase(ccc, newly_acked_bytes);
}

static void fair_decrease(struct uet_cc_ctx *ccc, bool can_decrease, uint32_t newly_acked_bytes)
{
	ccc->fi_active = false;
	ccc->fi_cnt = 0;
	if (can_decrease)
		ccc->dec_bytes += ccc->params.fd * newly_acked_bytes;
}

static inline uint32_t delta_usec(struct timespec start, struct timespec end)
{
	uint64_t delta_nsec = end.tv_nsec - start.tv_nsec
				+ (end.tv_sec - start.tv_sec) * 1000000000;

	return delta_nsec / 1000;
}

static inline struct timespec add_usec(struct timespec start, uint32_t delta_usec)
{
	uint64_t delta_nsec = delta_usec * 1000;

	start.tv_nsec += delta_nsec;
	if (start.tv_nsec > 1000000000) {
		start.tv_sec++;
		start.tv_nsec -= 1000000000;
	}
	return start;
}

static void aggressive_decrease(struct uet_cc_ctx *ccc, bool can_decrease,
	uint32_t newly_acked_bytes)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ccc->fi_active = false;
	ccc->fi_cnt = 0;
	if (can_decrease && ccc->avg_delay_usec > ccc->params.target_qdelay_usec) {
		if (delta_usec(ccc->last_dec, now) > ccc->params.base_rtt_usec) {
			ccc->cwnd *= uet_max(1 - ccc->params.gamma *
				(1 - (float) ccc->params.target_qdelay_usec / ccc->avg_delay_usec),
				ccc->params.max_md_factor);
			ccc->last_dec = now;
		}
		fair_decrease(ccc, can_decrease, newly_acked_bytes);
	}
}

static bool quick_adapt(struct uet_cc_ctx *ccc, bool loss)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec > ccc->qa_end.tv_sec || (now.tv_sec == ccc->qa_end.tv_sec
		&& now.tv_nsec > ccc->qa_end.tv_nsec)) {
		if ((ccc->qa_end.tv_sec || ccc->qa_end.tv_nsec) && (ccc->qa_trigger || loss
			|| ccc->avg_delay_usec > ccc->params.qa_thresh)) {
			ccc->cwnd = uet_max(uet_min(ccc->cwnd, ccc->achieved_bytes),
				ccc->params.mtu);
			ccc->qa_ign_bytes = ccc->in_flight;
			ccc->qa_trigger = false;
			return true;
		}
		ccc->qa_end = add_usec(now, ccc->params.base_rtt_usec);
		ccc->achieved_bytes = 0;
	}
	return false;
}

static void retx(struct uet_cc_ctx *ccc, uint32_t pktsize)
{
	ccc->in_flight -= pktsize;
	ccc->rtx_cnt++;
	update_ccc_state(ccc);
}

static inline void update_avg_delay(struct uet_cc_ctx *ccc, uint32_t delay_usec)
{
	ccc->avg_delay_usec = ccc->params.delay_ewma_factor * ccc->avg_delay_usec
						+ (1 - ccc->params.delay_ewma_factor) * delay_usec;
}

static inline void update_avg_ecn_rate(struct uet_cc_ctx *ccc, uint32_t newly_acked_bytes,
	bool skip)
{
	uint16_t num_mtus_acked = uet_min(UET_CC_MAX_SACK_MTUS,
		newly_acked_bytes / ccc->params.mtu);
	float exp_decay = ccc->ecn_exp_table[num_mtus_acked];

	ccc->avg_ecn_rate = ccc->params.ecn_alpha * skip + exp_decay * ccc->avg_ecn_rate;
}

void uet_cc_req_to_send(struct uet_cc_ctx *ccc, uint32_t delta_backlog)
{
	ccc->backlog += delta_backlog;
	update_ccc_state(ccc);
}

uint32_t uet_cc_send_complete(struct uet_cc_ctx *ccc, uint32_t pktsize, bool retx)
{
	uint32_t ev = select_entropy(ccc);

	if (retx)
		ccc->rtx_cnt--;
	else
		ccc->backlog -= pktsize;
	ccc->in_flight += pktsize;
	update_ccc_state(ccc);
	return ev;
}

void uet_cc_process_ack(struct uet_cc_ctx *ccc, uint16_t *ev, bool skip, uint32_t rtt_usec,
	int32_t delta_inflight)
{
	uint32_t newly_acked_bytes = -delta_inflight;

	ccc->in_flight += delta_inflight;
	ccc->qa_ign_bytes -= uet_min(newly_acked_bytes, ccc->qa_ign_bytes);
	ccc->recv_bytes += newly_acked_bytes;
	ccc->achieved_bytes += newly_acked_bytes;

	uint32_t delay_usec = uet_max(0, (int64_t) rtt_usec - ccc->params.base_rtt_usec);

	update_avg_delay(ccc, delay_usec);

	if (ev != NULL)
		update_path(ccc, *ev, skip ? UET_CC_PATH_ECN : UET_CC_PATH_ACK);
	update_avg_ecn_rate(ccc, newly_acked_bytes, skip);
	bool can_decrease = ccc->avg_ecn_rate > ccc->params.ecn_thresh;

	if (ccc->qa_ign_bytes && skip)
		return;

	if (quick_adapt(ccc, false)) {
		update_ccc_state(ccc);
		return;
	}

	if (!skip && delay_usec >= ccc->params.target_qdelay_usec)
		fair_increase(ccc, newly_acked_bytes);
	else if (!skip && delay_usec < ccc->params.target_qdelay_usec)
		proportional_increase(ccc, newly_acked_bytes, delay_usec);
	else if (skip && delay_usec >= ccc->params.target_qdelay_usec)
		aggressive_decrease(ccc, can_decrease, newly_acked_bytes);

	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (delta_usec(ccc->last_cwnd_adj, now) >= ccc->params.adj_usec_thresh
			|| ccc->recv_bytes > ccc->params.adj_bytes_thresh)
		adjust_cwnd(ccc);
	update_ccc_state(ccc);
}

void uet_cc_process_loss(struct uet_cc_ctx *ccc, uint32_t lost_bytes, uint16_t *ev,
						enum uet_cc_loss_type type, bool skip)
{
	retx(ccc, lost_bytes);
	if (type == UET_CC_LOSS_TYPE_TIMEOUT) {
		ccc->qa_trigger = true;
		if (!ccc->qa_ign_bytes)
			quick_adapt(ccc, true);
	} else if (type == UET_CC_LOSS_TYPE_NACK) {
		ccc->qa_trigger = true;
		if (!ccc->qa_ign_bytes)
			quick_adapt(ccc, true);
		if (ev)
			update_path(ccc, *ev, UET_CC_PATH_NACK);
	}
	ccc->qa_ign_bytes -= uet_min(lost_bytes, ccc->qa_ign_bytes);
}
