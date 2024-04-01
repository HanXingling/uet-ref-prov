/*
 * Definitions for PDS Reliability-CC APIs
 */
#ifndef _UET_CC_ST_H_
#define _UET_CC_ST_H_

#include <stdint.h>
#include <stdbool.h>

struct uet_cc_ctx;

enum uet_cc_loss_type {
	UET_CC_LOSS_TYPE_NACK,
	UET_CC_LOSS_TYPE_SACK,
	UET_CC_LOSS_TYPE_TIMEOUT,
	UET_CC_LOSS_TYPE_PROBE
};

enum uet_cc_spraying_type {
	UET_CC_NO_SPRAY,
	UET_CC_OBLIVIOUS_SPRAY,
	UET_CC_SELECTIVE_SPRAY
};

/* Reliability -> CC API */

struct uet_cc_ctx *uet_cc_alloc_ctx(enum uet_cc_spraying_type spraying_type, bool trim_supp,
	uint16_t mtu, uint32_t bw_mbps, uint32_t base_rtt_usec, uint16_t max_paths, void *handle);

void uet_cc_free_ctx(struct uet_cc_ctx *ccc);

void uet_cc_req_to_send(struct uet_cc_ctx *ccc, uint32_t delta_backlog);

uint32_t uet_cc_send_complete(struct uet_cc_ctx *ccc, uint32_t pktsize, bool retx);

void uet_cc_process_ack(struct uet_cc_ctx *ccc, uint16_t *ev, bool skip, uint32_t rtt_usec,
	int32_t delta_inflight);

void uet_cc_process_loss(struct uet_cc_ctx *ccc, uint32_t lost_bytes, uint16_t *ev,
	enum uet_cc_loss_type type, bool skip);

/* CC -> Reliability API */

void uet_cc_state_update(void *handle, bool can_send);

#endif /* _UET_CC_ST_H_ */
