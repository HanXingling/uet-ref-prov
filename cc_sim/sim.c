/*
 * Basic incast simulator for UET CC.
 *
 * The purpose of this program is to test the UET CC API.
 * It simulates 1 or more source(s) sending packets to 1 destination.
 * The simulation is real-time, in order to verify the time-based code in
 * the CC implementation.
 * Virtual packets are inserted into a single queue and ECN marked, trimmed
 * and/or dropped according to the parameters set in this file.
 * The receiver queues an ACK/NACK for each packet into a per-sender queue.
 * Congestion on the return path is not simulated.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <signal.h>
#include <unistd.h>

#include <time.h>
#include <stdbool.h>

#include <cc/uet_cc_st.h>

#include "sim_util.h"

static bool running = 1;

void sigint_handler(int)
{
	__atomic_store_n(&running, 0, __ATOMIC_RELEASE);
}

/* Configurable simulation parameters */
struct config_params {
	uint32_t qsize;					/* simulated switch queue size */
	uint16_t pkt_size;				/* size of sent data pkts */
	uint16_t trim_pkt_size;			/* size of trimmed data pkts */
	uint16_t mtu;
	uint32_t bw_gbps;				/* receiver link speed */
	uint32_t rtt_nsec;				/* unloaded network RTT */
	uint32_t rto_nsec;
	uint32_t num_senders;			/* number of senders */
	struct red_cfg drop_params;		/* RED config for dropping pkts */
	struct red_cfg trim_params;		/* RED config for trimming pkts */
	struct red_cfg ecn_params;		/* RED config for ECN marking pkts */
};

enum pkt_flags {
	FLAG_TRIM = 1 << 0,
	FLAG_ECN_CE = 1 << 1,
	FLAG_ACK = 1 << 2,
	FLAG_NACK = 1 << 3,
};

struct data_pkt {
	uint32_t sender_id;
	uint16_t size;
	enum pkt_flags flags;
	struct timespec send_time;
};

struct ctrl_pkt {
	enum pkt_flags flags;
	struct timespec mirrored_send_time;
	struct timespec dequeue_time;
};

struct sender_ctx {
	struct {
		uint32_t ecns;
		uint32_t trims;
		uint32_t drops;
		uint32_t sent;
	}
	stats;
	struct {
		struct timespec can_send;
		struct timespec can_recv;
		struct timespec next_timeout;
		struct timespec can_print;
	}
	timestamps;
	struct spsc_ring ctrl_queue;
	struct spsc_ring loss_queue;
	struct uet_cc_ctx *ccc;
	struct config_params *params;
	uint32_t id;
	uint32_t in_flight;
	bool send_requested;
	bool ready;
};

/* Called by the CC implementation to signal when a CCC is ready/not ready to send. */
void uet_cc_state_update(void *handle, bool ready)
{
	struct sender_ctx *send_ctx = handle;

	send_ctx->ready = ready;
}

/* Iteration of the sender simulation. */
void send_iter(struct config_params *params, struct sender_ctx *sender,
			struct spsc_ring *data_queue, struct spsc_ring *trim_queue)
{
	struct data_pkt pkt = {.size = params->pkt_size, .sender_id = sender->id, .flags = 0};
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Request to send a packet if the flight limit isn't reached. */
	if (!sender->send_requested && sender->in_flight < 2 * params->qsize) {
		uet_cc_req_to_send(sender->ccc, pkt.size);
		sender->send_requested = true;
	}

	/* Once the CCC is ready, send the packet. */
	if (sender->send_requested && sender->ready
			&& later_than(now, sender->timestamps.can_send)) {
		uint32_t serialize_nsec = pkt.size * 8 / params->bw_gbps;

		pkt.send_time = now;
		/* Wait until packet is serialized before sending another. */
		sender->timestamps.can_send = add_time(now, serialize_nsec);

		uet_cc_send_complete(sender->ccc, pkt.size, false);
		sender->send_requested = false;
		sender->in_flight++;

		uint32_t data_queue_pop = ring_count(data_queue);

		/* Check if packet should be dropped. */
		if (red_mark(data_queue_pop, &params->drop_params)
			    || data_queue_pop == params->qsize) {
			struct timespec timeout = add_time(now, params->rto_nsec);

			/* Queue a timestamp indicating when the sender knows packet was lost. */
			ring_enq_tail(&sender->loss_queue, &timeout, sizeof(timeout));
			sender->stats.drops++;
			return;
		}

		/* Check if packet should be trimmed. */
		if (red_mark(data_queue_pop, &params->trim_params)) {
			uint32_t trim_queue_pop = ring_count(trim_queue);

			/* If the trim queue is full, drop the packet. */
			if (trim_queue_pop == params->qsize) {
				struct timespec timeout = add_time(now, params->rto_nsec);

				ring_enq_tail(&sender->loss_queue, &timeout, sizeof(timeout));
				sender->stats.drops++;
				return;
			}
			sender->stats.trims++;
			pkt.flags |= FLAG_TRIM;
			ring_enq_tail(trim_queue, &pkt, sizeof(pkt));
		} else {
			sender->stats.sent++;
			ring_enq_tail(data_queue, &pkt, sizeof(pkt));
		}
	}

	/* Check if there are queued control packets and when the first one can be processed. */
	if (!sender->timestamps.can_recv.tv_sec
			&& !sender->timestamps.can_recv.tv_nsec) {
		struct ctrl_pkt queued_pkt;

		if (ring_peek_head(&sender->ctrl_queue, &queued_pkt, sizeof(queued_pkt)))
			sender->timestamps.can_recv = queued_pkt.dequeue_time;

	/* Process the control packet once the time has passed. */
	} else if (later_than(now, sender->timestamps.can_recv)) {
		struct ctrl_pkt recv_pkt;

		ring_deq_head(&sender->ctrl_queue, &recv_pkt, sizeof(recv_pkt));

		if (recv_pkt.flags & FLAG_ACK) {
			uet_cc_process_ack(sender->ccc, NULL, recv_pkt.flags & FLAG_ECN_CE,
				elapsed_usec(recv_pkt.mirrored_send_time, now), -params->pkt_size);
			sender->in_flight--;
		} else if (recv_pkt.flags & FLAG_NACK) {
			uet_cc_process_loss(sender->ccc, params->pkt_size, NULL,
				UET_CC_LOSS_TYPE_NACK, false);
			sender->in_flight--;
		}

		sender->timestamps.can_recv.tv_sec = 0;
		sender->timestamps.can_recv.tv_nsec = 0;
	}

	/* Check if there are queued timeouts and when the first one can be processed. */
	if (!sender->timestamps.next_timeout.tv_sec && !sender->timestamps.next_timeout.tv_nsec) {
		ring_peek_head(&sender->loss_queue, &sender->timestamps.next_timeout,
			sizeof(struct timespec));

	/* Process the timeout once the time has passed. */
	} else if (later_than(now, sender->timestamps.next_timeout)) {
		struct timespec timeout;

		ring_deq_head(&sender->loss_queue, &timeout, sizeof(timeout));

		uet_cc_process_loss(sender->ccc, params->pkt_size, NULL,
			UET_CC_LOSS_TYPE_TIMEOUT, false);

		sender->in_flight--;

		sender->timestamps.next_timeout.tv_sec = 0;
		sender->timestamps.next_timeout.tv_nsec = 0;
	}

	if (later_than(now, sender->timestamps.can_print)) {
		char bw[32];
		float bps = (float) sender->stats.sent * params->pkt_size * 8;

		if (bps >= 1000000000)
			snprintf(bw, sizeof(bw) - 1, "%.2f Gbps", bps / 1000000000);
		else if (bps >= 1000000)
			snprintf(bw, sizeof(bw) - 1, "%.2f Mbps", bps / 1000000);
		else if (bps >= 1000)
			snprintf(bw, sizeof(bw) - 1, "%.2f Kbps", bps / 1000);
		else
			snprintf(bw, sizeof(bw) - 1, "%.2f bps", bps);

		printf("[%d]: Throughput: %s, trims: %u, ECN marked: %u, drops: %u\n", sender->id,
			bw, sender->stats.trims, sender->stats.ecns, sender->stats.drops);
		memset(&sender->stats, 0, sizeof(sender->stats));

		sender->timestamps.can_print.tv_sec++;
	}
}

/* Iteration of the receiver simulation. */
void recv_iter(struct config_params *params, struct sender_ctx *senders,
	struct spsc_ring *data_queue, struct spsc_ring *trim_queue, struct timespec *can_recv)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* Process queued data/trimmed packets. */
	if (later_than(now, *can_recv)) {
		struct data_pkt recv_pkt;
		struct sender_ctx *src;
		uint32_t serialize_nsec;
		bool pkt_recvd = false;

		/* Check trim (high priority) queue first. */
		if (ring_count(trim_queue)) {
			ring_peek_head(trim_queue, &recv_pkt, sizeof(recv_pkt));
			struct timespec earliest_recv = add_time(recv_pkt.send_time,
								params->rtt_nsec / 2);

			if (!later_than(now, earliest_recv)) {
				*can_recv = earliest_recv;
			} else {
				ring_deq_head(trim_queue, &recv_pkt, sizeof(recv_pkt));
				serialize_nsec = params->trim_pkt_size * 8 / params->bw_gbps;
				pkt_recvd = true;
			}
		}
		if (!pkt_recvd && ring_count(data_queue)) {
			ring_peek_head(data_queue, &recv_pkt, sizeof(recv_pkt));
			struct timespec earliest_recv = add_time(recv_pkt.send_time,
								params->rtt_nsec / 2);

			if (!later_than(now, earliest_recv)) {
				if (later_than(*can_recv, earliest_recv))
					*can_recv = earliest_recv;
			} else {
				ring_deq_head(data_queue, &recv_pkt, sizeof(recv_pkt));
				serialize_nsec = params->pkt_size * 8 / params->bw_gbps;
				pkt_recvd = true;
			}
		}
		if (!pkt_recvd)
			return;
		/* Wait until the serialization time elapses before dequeuing another packet. */
		*can_recv = add_time(now, serialize_nsec);
		src = &senders[recv_pkt.sender_id];

		struct ctrl_pkt reply = {
			.flags = 0,
			.mirrored_send_time = recv_pkt.send_time,
			.dequeue_time = add_time(now, params->rtt_nsec / 2)
		};
		if (recv_pkt.flags & FLAG_TRIM)
			reply.flags |= FLAG_NACK;
		else
			reply.flags |= FLAG_ACK;

		/* ECN mark at dequeue time. */
		if (red_mark(ring_count(data_queue), &params->ecn_params)) {
			reply.flags |= FLAG_ECN_CE;
			src->stats.ecns++;
		}

		ring_enq_tail(&src->ctrl_queue, &reply, sizeof(reply));
	}
}


int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s num_senders\n", argv[0]);
		return -1;
	}
	int num_senders = atoi(argv[1]);

	if (num_senders <= 0) {
		fprintf(stderr, "Usage: %s num_senders\n", argv[0]);
		return -1;
	}

	struct config_params params = {
		.qsize = 256,
		.pkt_size = 4096,
		.trim_pkt_size = 128,
		.mtu = 4096,
		.bw_gbps = 10,
		.rtt_nsec = 400000, /* Must be <= 2 * qsize * pktsize / bw */
		.rto_nsec = 1000000,
		.num_senders = num_senders,
		.drop_params = {
			.high_thresh = 256,
			.low_thresh = 240,
			.ewm = 0.1,
			.pmax = 1,
			.avg_len = 0
		},
		.trim_params = {
			.high_thresh = 240,
			.low_thresh = 200,
			.ewm = 0.1,
			.pmax = 1,
			.avg_len = 0
		},
		.ecn_params = {
			.high_thresh = 200,
			.low_thresh = 128,
			.ewm = 0.1,
			.pmax = 1,
			.avg_len = 0
		}
	};

	srand(time(NULL));

	struct timespec now, sink_can_recv = {0, 0};

	clock_gettime(CLOCK_MONOTONIC, &now);

	struct sender_ctx *senders = calloc(num_senders, sizeof(struct sender_ctx));

	for (uint32_t i = 0; i < num_senders; i++) {
		struct sender_ctx send_ctx = {
			.stats = {
				.ecns = 0,
				.trims = 0,
				.drops = 0,
				.sent = 0
			},
			.timestamps = {
				.can_send = now,
				.can_recv = {0, 0},
				.next_timeout = {0, 0},
				.can_print = now
			},
			.ctrl_queue = {
				.cap = 2 * params.qsize,
				.head = 0,
				.tail = 0,
				.buf = calloc(2 * params.qsize + 1, sizeof(struct ctrl_pkt))
			},
			.loss_queue = {
				.cap = 2 * params.qsize,
				.head = 0,
				.tail = 0,
				.buf = calloc(2 * params.qsize + 1, sizeof(struct timespec))
			},
			.ccc = uet_cc_alloc_ctx(UET_CC_NO_SPRAY, true, params.mtu,
				params.bw_gbps * 1000, params.rtt_nsec / 1000, 1, &senders[i]),
			.params = &params,
			.id = i,
			.in_flight = 0,
			.send_requested = false,
			.ready = false
		};
		send_ctx.timestamps.can_print.tv_sec++;
		senders[i] = send_ctx;
	}
	struct spsc_ring data_queue, trim_queue;

	data_queue.cap = params.qsize;
	data_queue.head = 0;
	data_queue.tail = 0;
	data_queue.buf = calloc(params.qsize + 1, sizeof(struct data_pkt));
	trim_queue.cap = num_senders * params.qsize;
	trim_queue.head = 0;
	trim_queue.tail = 0;
	trim_queue.buf = calloc(num_senders * params.qsize + 1, sizeof(struct data_pkt));

	signal(SIGINT, sigint_handler);

	while (__atomic_load_n(&running, __ATOMIC_ACQUIRE)) {
		for (uint32_t i = 0; i < num_senders; i++)
			send_iter(&params, &senders[i], &data_queue, &trim_queue);
		recv_iter(&params, senders, &data_queue, &trim_queue, &sink_can_recv);
	}

	for (uint32_t i = 0; i < num_senders; i++) {
		free(senders[i].ctrl_queue.buf);
		free(senders[i].loss_queue.buf);
		uet_cc_free_ctx(senders[i].ccc);
	}

	free(senders);
	free(data_queue.buf);
	free(trim_queue.buf);
	return 0;
}
