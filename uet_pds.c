/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ofi_list.h>
#include <uthash.h>

#include "uet_api.h"
#include "uet_pds.h"
#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_util.h"
#include "uet_log.h"
#include "uet_pkt_chk.h"
#include "bitmap.h"

#define UET_DEFAULT_TC  0
#define UET_DEFAULT_MPR 128
#define UET_DEFAULT_START_PSN 13

#define UET_PDC_MAX 64

typedef enum {
	PDC_STATE_UNALLOC,
	PDC_STATE_SYN,
	PDC_STATE_ESTABLISHED,
	PDC_STATE_CLOSING,
	PDC_STATE_ERROR,
} pdc_state_t;

typedef enum {
	PDC_TYPE_NONE,
	PDC_TYPE_RUD,
	PDC_TYPE_ROD,
} pdc_type_t;

struct uet_pdc_pkt {
	struct dlist_entry    node;
	int                   psn;
	uint16_t              msg_id;

	union uet_pkt        *pkt;
	int		      pkt_len;
	time_t                tx_time; /* tx time for detecting timeout */
	int                   tx_retry_cnt;  /* number of retransmissions */
	uet_pkt_handle_t      tx_pkt_handle;
	bool                  tx_pkt_acked; /* this packet has been acked */
	uet_pds_tx_flags_t    flags;

	bool                  needs_clear;
	bool                  reordered; /* rx_req() upcall called for ROD */

	union uet_pkt        *ack;
	int		      ack_len;

	struct uet_parsed_pkt pkt_pp;
	bool                  pkt_parsed;
	struct uet_parsed_pkt ack_pp;
	bool                  ack_parsed;
};

/*
 * The PDC key used for hash table lookups. Note that this implementation
 * of the PDS only supports one PDC (per these key fields) between two FEPs.
 * This implies there is NOT a mapping of msg_id to PDC being maintained.
 */
struct uet_pdc_key {
	pdc_type_t    type;
	uint32_t      job_id;
	struct uet_fa src_ip;
	struct uet_fa dst_ip;
	uint8_t       tc;
	uint16_t      spdcid; /* only used for receive side lookups */
};

struct uet_pdc {
	struct dlist_entry  node;

	pdc_state_t         state;
	bool                is_initiator;

	uint16_t            pdc_id; /* local PDC identifier */
	uint16_t            dpdcid; /* peer PDC identifier */
	uint32_t            open_msg_cnt; /* can only free the PDC if zero */

	struct uet_pdc_key  hkey;
	UT_hash_handle      pdc_hh; /* hash handle for the PDC */

	struct dlist_entry  tx_pkt_list_head; /* 'tx_time' order (for rtx) */

	/* initiator side fields (and target side reverse direction) */
	uint16_t            syn_offset; /* initiator SYN offset until ACK */
	uint32_t            next_psn; /* next Tx pkt seq number */
	struct bitmap      *tx_bm;
	struct bitmap      *ack_bm;
	uint32_t            tx_bm_base_psn; /* start PSN for initiator MPR */

	/* target side fields */
	struct bitmap      *rx_bm;
	uint32_t            rx_bm_base_psn; /* start PSN for target MPR */
};

struct uet_msgid_map {
	uint16_t        msg_id;
	UT_hash_handle  msgid_hh; /* hash handle for the PDC */
	struct uet_pdc *pdc;
};

struct uet_pds_state {
	bool                  ready;
	struct uet_pdc        pdc[UET_PDC_MAX];
	struct dlist_entry    pdc_alloc_head;
	struct dlist_entry    pdc_free_head;
	struct uet_pdc       *pdc_ht; /* key = "type|job_id|dst_ip|tc" */
	struct uet_msgid_map *pdc_msgid_ht; /* key = "msg_id" */
	struct dlist_entry    pending_pkts_head; /* TODO: not implemented yet */
};

static struct uet_pds_state pds_state;

#define PDS_GO()                                          \
	do {                                              \
		if (pds_state.ready != true) {            \
			UET_PDS_ERR("PDS is not ready!"); \
			exit(1);                          \
		}                                         \
	} while (0)

#define PSN_IN_MPR(psn, base_psn)                            \
	(((uint32_t)((psn) - (base_psn)) >= 0) &&            \
	 ((uint32_t)((psn) - (base_psn)) < UET_DEFAULT_MPR))

#define PSN_IN_PRIOR_MPR(psn, base_psn)                             \
	PSN_IN_MPR((psn), (uint32_t)((base_psn) - UET_DEFAULT_MPR))

#define PDS_TYPE_TO_STR(t)                              \
	(((t) == UET_PDS_TYPE_RUD_REQ)   ? "RUD_REQ" :  \
	 ((t) == UET_PDS_TYPE_ROD_REQ)   ? "ROD_REQ" :  \
	 ((t) == UET_PDS_TYPE_RUDI_REQ)  ? "RUDI_REQ" : \
	 ((t) == UET_PDS_TYPE_UUD_REQ)   ? "UUD_REQ" :  \
	 ((t) == UET_PDS_TYPE_RUDI_RESP) ? "RUDI_RSP" : \
	 ((t) == UET_PDS_TYPE_ACK)       ? "ACK" :      \
	 ((t) == UET_PDS_TYPE_NACK)      ? "NACK" :     \
	 ((t) == UET_PDS_TYPE_CTRL)      ? "CTRL" :     \
					   "UNKNOWN")
#define NEXT_HDR_TO_STR(n)                                    \
	(((n) == UET_HDR_REQ_SMALL)      ? "REQ_SMALL" :      \
	 ((n) == UET_HDR_REQ_MEDIUM)     ? "REQ_MEDIUM" :     \
	 ((n) == UET_HDR_REQ_STD)        ? "REQ_STD" :        \
	 ((n) == UET_HDR_RSP)            ? "RSP" :            \
	 ((n) == UET_HDR_RSP_DATA)       ? "RSP_DATA" :       \
	 ((n) == UET_HDR_RSP_DATA_SMALL) ? "RSP_DATA_SMALL" : \
					   "UNKNOWN")

#define PDS_DBG_TX(pp, msg)                                 \
	UET_PDS_DBG("PDC %u [Tx %u] [PSN %u] [%s/%s] - %s", \
		    (pp)->pds_spdcid, (pp)->pds_dpdcid,     \
		    (pp)->pds_psn,                          \
		    PDS_TYPE_TO_STR((pp)->pds_type),        \
		    NEXT_HDR_TO_STR((pp)->next_hdr),        \
		    (msg))

#define PDS_DBG_RX(pp, msg)                                 \
	UET_PDS_DBG("PDC %u [Rx %u] [PSN %u] [%s/%s] - %s", \
		    (pp)->pds_dpdcid, (pp)->pds_spdcid,     \
		    (pp)->pds_psn,                          \
		    PDS_TYPE_TO_STR((pp)->pds_type),        \
		    NEXT_HDR_TO_STR((pp)->next_hdr),        \
		    (msg))

static void uet_pds_pkt_dbg(struct uet_instance *uet,
			    struct uet_parsed_pkt *pp,
			    bool is_tx,
			    const char *msg)
{
#if defined(UET_LOG_PDS) && (UET_LOG_LVL >= UET_LOG_DBG)
	if (is_tx)
		PDS_DBG_TX(pp, msg);
	else
		PDS_DBG_RX(pp, msg);
#endif

	UET_PDS_PKT_HDR_TRACE(uet, pp, NULL, 0, msg);
}

/****************************************************************************/
/*                       Security and NIC Shim APIs                         */
/****************************************************************************/

static int uet_pds_nic_tx_pkt(struct uet_instance *uet,
			      union uet_pkt *pkt,
			      int pkt_len)
{
	/* TODO: IPv6 support */
	return uet_nic_tx_pkt(UET_NIC(uet),
			      pkt,
			      &pkt->common.ipv4,
			      pkt_len);
}

/*
 * Returns:
 *   0, no valid packet available
 *   1, read a packet
 *   negative value corresponding to fabric errno, err reading packet
 */
static int uet_pds_nic_rx_pkt(struct uet_instance *uet,
			      union uet_pkt **pkt,
			      int *pkt_len)
{
	int rc;

	*pkt = NULL;
	*pkt_len = 0;

	/* check if packet is available */
	rc = uet_nic_rx_poll(UET_NIC(uet));
	if (rc != 1)
		return rc;

	/* TODO: Remove this malloc... */
	/* allocate a receive packet buffer */
	*pkt = calloc(1, uet->nic.max_pkt_size);
	if (*pkt == NULL) {
		UET_PDS_ERR("failed to alloc Rx packet buffer");
		return -FI_ENOMEM;
	}

	/* receive the packet */
	rc = uet_nic_rx_pkt(UET_NIC(uet),
			    *pkt,
			    uet->nic.max_pkt_size,
			    (size_t *)pkt_len);
	if (rc != 1) {
		free(*pkt);
		*pkt = NULL;
		*pkt_len = 0;
		return rc;
	}

	return 1;
}

/****************************************************************************/
/*                            PDS Manager APIs                              */
/****************************************************************************/

static void uet_init_pdc(struct uet_pdc *pdc,
			 pdc_state_t state,
			 bool is_initiator)
{
	/* initialze this PDC and stick it in the hashtable */
	pdc->state = state;
	pdc->is_initiator = is_initiator;

	pdc->dpdcid = 0;
	pdc->open_msg_cnt = 0;

	dlist_init(&pdc->tx_pkt_list_head);

	pdc->syn_offset = 0;
	pdc->next_psn = 0;
	bm_clear(pdc->tx_bm);
	bm_clear(pdc->ack_bm);
	pdc->tx_bm_base_psn = 0;

	bm_clear(pdc->rx_bm);
	pdc->rx_bm_base_psn = 0;
}

static struct uet_pdc *uet_pdsm_alloc_pdc(void)
{
	struct uet_pdc *pdc;

	PDS_GO();

	/* allocate a new PDC from the head of the free list */
	pdc = dlist_first_entry_or_null(&pds_state.pdc_free_head,
					struct uet_pdc, node);
	if (pdc == NULL)
		return NULL;

	dlist_remove(&pdc->node);

	dlist_insert_tail(&pdc->node, &pds_state.pdc_alloc_head);

	return pdc;
}

static void uet_pdsm_free_pdc(struct uet_pdc *pdc)
{
	PDS_GO();

	pdc->state = PDC_STATE_UNALLOC;

	/* free a PDC by inserting to the tail of the free list */
	dlist_remove(&pdc->node);
	dlist_insert_tail(&pdc->node, &pds_state.pdc_free_head);
}

static struct uet_pdc *uet_pdsm_assign_ini_pdc(struct uet_ep *uet_ep,
					       struct uet_addr *dst_addr,
					       uet_pds_mode_t mode)
{
	struct uet_pdc_key pdc_key;
	struct uet_pdc *pdc;

	PDS_GO();

	/* get the PDC if it already exists */
	memset(&pdc_key, 0, sizeof(pdc_key));
	pdc_key.type = ((mode == UET_PDS_MODE_ROD) ? PDC_TYPE_ROD :
			(mode == UET_PDS_MODE_RUD) ? PDC_TYPE_RUD :
						     PDC_TYPE_NONE);
	pdc_key.job_id = uet_ep->job_id;
	pdc_key.tc = UET_DEFAULT_TC;
	pdc_key.src_ip.v4 = uet_ep->ipv4_addr; /* TODO: IPv6 support */
	memcpy(&pdc_key.dst_ip, &dst_addr->fa, sizeof(struct uet_fa));

	HASH_FIND(pdc_hh, pds_state.pdc_ht, &pdc_key,
		  sizeof(struct uet_pdc_key), pdc);
	if (pdc) {
		UET_PDS_DBG("lookup found initiator PDC %u", pdc->pdc_id);
		return pdc;
	}

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for initiator");
		return NULL;
	}

	/* initialze this initiator PDC and stick it in the hashtable */
	uet_init_pdc(pdc, PDC_STATE_SYN, true);
	pdc->next_psn       = UET_DEFAULT_START_PSN;
	pdc->tx_bm_base_psn = UET_DEFAULT_START_PSN;
	pdc->rx_bm_base_psn = UET_DEFAULT_START_PSN;
	memcpy(&pdc->hkey, &pdc_key, sizeof(struct uet_pdc_key));
	HASH_ADD(pdc_hh, pds_state.pdc_ht, hkey,
		 sizeof(struct uet_pdc_key), pdc);

	UET_PDS_DBG("allocated initiator PDC %u", pdc->pdc_id);

	return pdc;
}

static struct uet_pdc *uet_pdsm_assign_tgt_pdc(struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_cmn *ses_cmn = (struct uet_ses_req_cmn *)pp->ses;
	struct iphdr *ipv4 = (struct iphdr *)pp->ip; /* TODO: IPv6 support */
	struct uet_pdc_key pdc_key;
	struct uet_pdc *pdc;

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ))
		return NULL;

	if ((pp->next_hdr != UET_HDR_REQ_SMALL) &&
	    (pp->next_hdr != UET_HDR_REQ_MEDIUM) &&
	    (pp->next_hdr != UET_HDR_REQ_STD))
		return NULL;

	if (!(pp->pds_flags & UET_PDS_REQ_FLAGS_SYN))
		return NULL;

	memset(&pdc_key, 0, sizeof(pdc_key));

	pdc_key.type =
		((pp->pds_type == UET_PDS_TYPE_RUD_REQ) ? PDC_TYPE_RUD :
		 (pp->pds_type == UET_PDS_TYPE_ROD_REQ) ? PDC_TYPE_ROD :
							  PDC_TYPE_NONE);
	pdc_key.job_id = uet_get_std_req_job_id(
		(struct uet_ses_req_std *)ses_cmn);

	pdc_key.tc = UET_DEFAULT_TC;

	/* TODO: IPv6 support */
	pdc_key.src_ip.v4 = ntohl(ipv4->saddr);
	pdc_key.dst_ip.v4 = ntohl(ipv4->daddr);

	pdc_key.spdcid = pp->pds_spdcid; /* target side needs spdcid */

	HASH_FIND(pdc_hh, pds_state.pdc_ht, &pdc_key,
		  sizeof(struct uet_pdc_key), pdc);
	if (pdc) {
		UET_PDS_DBG("lookup found target PDC %u", pdc->pdc_id);

		/* can't receive a SYN on an initiator PDC */
		if (pdc->is_initiator) {
			UET_PDS_ERR("PDC %u is initiator and received SYN",
				     pdc->pdc_id);
			return NULL;
		}

		UET_PDS_DBG("SYN request for PDC %u (PSN %u offset %u)",
			    pdc->pdc_id, pp->pds_psn, pp->pds_syn_off);

		return pdc;
	}

	UET_PDS_DBG("First SYN request from PDC %u (PSN %u offset %u)",
		    pp->pds_spdcid, pp->pds_psn, pp->pds_syn_off);

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for target");
		return -FI_ENODEV;
	}

	/* initialze this target PDC and stick it in the hashtable */
	uet_init_pdc(pdc, PDC_STATE_ESTABLISHED, false);
	pdc->dpdcid         = pp->pds_spdcid;
	pdc->rx_bm_base_psn = (pp->pds_psn - pp->pds_syn_off);
	pdc->tx_bm_base_psn = pdc->rx_bm_base_psn;
	pdc->next_psn       = pdc->tx_bm_base_psn;
	memcpy(&pdc->hkey, &pdc_key, sizeof(struct uet_pdc_key));
	HASH_ADD(pdc_hh, pds_state.pdc_ht, hkey,
		 sizeof(struct uet_pdc_key), pdc);

	UET_PDS_DBG("allocated target PDC %u (established with PDC %u)",
		    pdc->pdc_id, pdc->dpdcid);

	return pdc;
}

static struct uet_pdc *uet_pdsm_get_pdc(uint16_t pdc_id,
					bool for_fwd)
{
	struct uet_pdc *pdc;

	if (pdc_id >= UET_PDC_MAX) {
		UET_PDS_ERR("invalid PDC %u (range)", pdc_id);
		return NULL;
	}

	pdc = &pds_state.pdc[pdc_id];

	if (pdc->state == PDC_STATE_UNALLOC) {
		UET_PDS_ERR("invalid PDC %u (unalloc)", pdc_id);
		return NULL;
	}

	if (for_fwd && pdc->is_initiator) {
		UET_PDS_ERR("invalid forward PDC %u (initiator)", pdc_id);
		return NULL;
	}

	return pdc;
}

static int uet_pdsm_map_msgid_pdc(uint16_t msg_id,
				  struct uet_pdc *pdc)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	/* TODO: pull msgid_map descriptor from a pool (not malloc) */
	msgid_map = calloc(1, sizeof(*msgid_map));
	if (msgid_map == NULL)
		return -FI_ENOMEM;

	msgid_map->msg_id = msg_id;
	msgid_map->pdc    = pdc;

	HASH_ADD(msgid_hh, pds_state.pdc_msgid_ht, msg_id,
		 sizeof(uint16_t), msgid_map);

	return FI_SUCCESS;
}

static int uet_pdsm_unmap_msgid_pdc(uint16_t msg_id)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	HASH_FIND(msgid_hh, pds_state.pdc_msgid_ht, &msg_id,
		  sizeof(uint16_t), msgid_map);
	if (msgid_map == NULL) {
		UET_PDS_ERR("msg_id %u not found", msg_id);
		return -FI_ENOKEY;
	}

	HASH_DELETE(msgid_hh, pds_state.pdc_msgid_ht, msgid_map);
	free(msgid_map);

	return FI_SUCCESS;
}

static struct uet_pdc *uet_pdsm_get_msgid_pdc(uint16_t msg_id)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	HASH_FIND(msgid_hh, pds_state.pdc_msgid_ht, &msg_id,
		  sizeof(uint16_t), msgid_map);
	if (msgid_map == NULL) {
		UET_PDS_ERR("msg_id %u not found", msg_id);
		return NULL;
	}

	return msgid_map->pdc;
}

#if 0
static int uet_pdsm_insert_pend_pkt(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -FI_ENOSYS;
}

static struct uet_pdc_pkt *uet_pdsm_remove_pend_pkt(void)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return NULL;
}

static struct uet_pdc *uet_pdsm_select_pdc_to_close(void)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return NULL;
}

static int uet_pdsm_check_pkt(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -FI_ENOSYS;
}

static struct uet_pdc *uet_pdsm_check_pdc(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO:
	 * - get PDC (from tpdcid)
	 * - verify valid event
	 */

	return NULL;
}

static int uet_pdsm_check_nack_code(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -FI_ENOSYS;
}
#endif

/****************************************************************************/
/*                            PDC Initiator APIs                            */
/****************************************************************************/

/****************************************************************************/
/*                             PDC Target APIs                              */
/****************************************************************************/

/****************************************************************************/
/*                             SES->PDS APIs                                */
/****************************************************************************/

int uet_pds_initialize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	int i;

	uet->pds.tx_timeout     = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl            = UET_DEFAULT_MSL;
	uet->pds.ack_ip_tos     = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);

	memset(&pds_state, 0, sizeof(struct uet_pds_state));

	/* initialize the PDCs */

	dlist_init(&pds_state.pdc_alloc_head);
	dlist_init(&pds_state.pdc_free_head);
	pds_state.pdc_ht = NULL;
	pds_state.pdc_msgid_ht = NULL;

	for (i = 0; i < UET_PDC_MAX; i++) {
		pdc = &pds_state.pdc[i];
		pdc->state = PDC_STATE_UNALLOC;
		pdc->pdc_id = i;

		pdc->tx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->tx_bm) {
			UET_PDS_ERR("failed to create Tx bitmap");
			uet_pdsm_free_pdc(pdc);
			return -FI_ENOMEM; /* TODO: unwind and free PDCs */
		}

		pdc->ack_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->ack_bm) {
			UET_PDS_ERR("failed to create ACK bitmap");
			bm_destroy(pdc->tx_bm);
			return -FI_ENOMEM; /* TODO: unwind and free PDCs */
		}

		pdc->rx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->rx_bm) {
			UET_PDS_ERR("failed to create Rx bitmap");
			bm_destroy(pdc->tx_bm);
			bm_destroy(pdc->ack_bm);
			return -FI_ENOMEM; /* TODO: unwind and free PDCs */
		}

		dlist_insert_tail(&pdc->node, &pds_state.pdc_free_head);
	}

	/* initialize the pending packets list */

	dlist_init(&pds_state.pending_pkts_head);

	/* good to go... */
	pds_state.ready = true;

	return FI_SUCCESS;
}

void uet_pds_finalize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;

	PDS_GO();

	/* TODO: reclaim/free all packets stored in the bitmaps... */

	/* destory all allocated PDCs */
	while (!dlist_empty(&pds_state.pdc_alloc_head)) {
		dlist_pop_front(&pds_state.pdc_alloc_head,
				struct uet_pdc, pdc, node);
		HASH_DELETE(pdc_hh, pds_state.pdc_ht, pdc);
		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);
		if (pdc->ack_bm)
			bm_destroy(pdc->ack_bm);
		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* destroy all free PDCs */
	while (!dlist_empty(&pds_state.pdc_free_head)) {
		dlist_pop_front(&pds_state.pdc_free_head,
				struct uet_pdc, pdc, node);
		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);
		if (pdc->ack_bm)
			bm_destroy(pdc->ack_bm);
		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* free all the packets in the pending list */
	while (!dlist_empty(&pds_state.pending_pkts_head)) {
		dlist_pop_front(&pds_state.pending_pkts_head,
				struct uet_pdc_pkt, pdc_pkt, node);
		free(pdc_pkt->pkt);
		free(pdc_pkt);
	}

	/* wipe out all existing state */
	memset(&pds_state, 0, sizeof(struct uet_pds_state));
	pds_state.ready = false;
}

int uet_pds_ep_initialize(struct uet_ep *uet_ep)
{
	PDS_GO();

	/* TODO: Anything needed here? */
	uet_ep->pds = &pds_state;

	return FI_SUCCESS;
}

void uet_pds_ep_finalize(struct uet_ep *uet_ep)
{
	PDS_GO();

	/* TODO: Anything needed here? */
	uet_ep->pds = NULL;
}

int uet_pds_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
		   struct uet_ep *uet_ep,
		   uet_addr_handle_t dst_addr_handle,
		   uet_pds_mode_t mode,
		   uet_pds_tx_flags_t flags,
		   struct uet_pds_info *pds_info,
		   uint16_t msg_id,
		   uet_next_hdr_t next_hdr,
		   void *ses,
		   size_t ses_len,
		   void *pkt,
		   size_t pkt_len,
		   bool dma_rdy)
{
	struct uet_instance *uet;
	struct uet_av_entry *av_entry;
	struct uet_addr *dst_addr;
	struct uet_pdc_pkt *pdc_pkt;
	uet_pds_pkt_type_t pds_pkt_type;
	struct uet_pdc *pdc;
	struct uet_pds_req *pds_hdr;
	void *ses_hdr, *payload;
	uint16_t pds_flags;
	int rc, hdr_len;

	PDS_GO();

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *)dst_addr_handle;
	dst_addr = av_entry->addr;

	if ((mode == UET_PDS_MODE_RUD) ||
	    (mode == UET_PDS_MODE_UUD) ||
	    (mode == UET_PDS_MODE_RUDI)) {
		return -FI_EINVAL; /* not supported yet */
	}

	/* if pds_info is specified, take the PDC from its pdcid */
	if (pds_info) {
		UET_PDS_DBG("SES Tx %p (pds_info pdcid %u psn %u)",
			    tx_pkt_handle, pds_info->pdcid, pds_info->opsn);
		pdc = uet_pdsm_get_pdc(pds_info->pdcid, true);
		if (pdc == NULL)
			return -FI_ENODEV;
	} else if (flags & UET_PDS_FLAG_SOM) {
		UET_PDS_DBG("SES Tx %p SOM", tx_pkt_handle);
		pdc = uet_pdsm_assign_ini_pdc(uet_ep, dst_addr, mode);
		if (pdc) {
			rc = uet_pdsm_map_msgid_pdc(msg_id, pdc);
			if (rc != FI_SUCCESS)
				return rc;
			pdc->open_msg_cnt++;
		}
	} else {
		UET_PDS_DBG("SES Tx %p", tx_pkt_handle);
		pdc = uet_pdsm_get_msgid_pdc(msg_id);
	}

	if (!pdc) {
		UET_PDS_ERR("failed to get PDC, put on pending list %p",
			    tx_pkt_handle);
		/* TODO: put this packet on the PDS pending pkt list */
		return -FI_ENODEV;
	}

	if (!pds_info && (flags & UET_PDS_FLAG_EOM)) {
		UET_PDS_DBG("SES Tx %p EOM%s", tx_pkt_handle,
			    (flags & UET_PDS_FLAG_MAINTAIN_PDC)
				? " (maintain PDC)" : "");
		if (!(flags & UET_PDS_FLAG_MAINTAIN_PDC)) {
			rc = uet_pdsm_unmap_msgid_pdc(msg_id);
			if (rc != FI_SUCCESS)
				return rc;
			pdc->open_msg_cnt--;
		}
	}

	/* allocate descriptor and buffer to build packet */

	/* TODO:
	 * - pull packet descriptor and buffer from a pool (not malloc)
	 * - add support for gather iov send
	 */

	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		return -FI_ENOMEM;
	}

	pdc_pkt->pkt = calloc(1, uet->nic.max_pkt_size);
	if (pdc_pkt->pkt == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer");
		free(pdc_pkt);
		return -FI_ENOMEM;
	}

	uet_build_eth_hdr(&pdc_pkt->pkt->common.eth,
			  av_entry->nh_mac_addr,
			  uet->nic.mac_addr);

	switch (next_hdr) {
	case UET_HDR_REQ_STD:
	case UET_HDR_RSP_DATA:

		switch (mode) {
		case UET_PDS_MODE_RUD:
			pds_pkt_type = UET_PDS_TYPE_RUD_REQ;
			break;
		case UET_PDS_MODE_ROD:
			pds_pkt_type = UET_PDS_TYPE_ROD_REQ;
			break;
		default:
			UET_PDS_ERR("unsupported pkt delivery mode %d", mode);
			free(pdc_pkt->pkt);
			free(pdc_pkt);
			return -FI_EINVAL;
		}

		/* TODO: IPv6 support */
		hdr_len = (sizeof(struct ethhdr) +
			   sizeof(struct iphdr) +
			   sizeof(struct uet_pds_req) +
			   ses_len);

		if (next_hdr == UET_HDR_REQ_STD) {
			pds_hdr = &pdc_pkt->pkt->std_req.pds;
			ses_hdr = &pdc_pkt->pkt->std_req.ses;
			payload = pdc_pkt->pkt->std_req.payload;
		} else { /* UET_HDR_RSP_DATA */
			pds_hdr = &pdc_pkt->pkt->std_rsp_d.pds;
			ses_hdr = &pdc_pkt->pkt->std_rsp_d.ses;
			payload = pdc_pkt->pkt->std_rsp_d.payload;
		}

		pdc_pkt->pkt_len = (pkt_len + hdr_len);

		/* fill in PDS header (i.e. pdcid, flag, etc) */

		pds_hdr->prlg.entropy = 0;

		pds_flags = ((pds_pkt_type << UET_PDS_TYPE_SHIFT)          |
			     (UET_PDS_REQ_FLAGS_AR << UET_PDS_FLAGS_SHIFT) |
			     (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
		if (pdc->state == PDC_STATE_SYN) {
			pds_flags |= (UET_PDS_REQ_FLAGS_SYN <<
				      UET_PDS_FLAGS_SHIFT);
		}

		pds_hdr->prlg.type_next_flags = htons(pds_flags);

		pdc_pkt->psn = pdc->next_psn++;

		pds_hdr->psn = htonl(pdc_pkt->psn);
		pds_hdr->spdcid = htons(pdc->pdc_id);

		if (pdc->state == PDC_STATE_SYN) {
			pds_hdr->mode_psn_off =
				htons((pdc->syn_offset &
				       UET_PDS_REQ_PSN_OFF_MASK) <<
				      UET_PDS_REQ_PSN_OFF_SHIFT);
			pdc->syn_offset++;
		} else {
			pds_hdr->dpdcid = htons(pdc->dpdcid);
		}

		if (pds_info) {
			pds_hdr->fwd_psn = htonl(pds_info->opsn);
		} else {
			/*
			 * Set the clear_psn to the left edge of the tx_bm
			 * which moves forward as ACKs are received. Note that
			 * this is considered a cumulative clear value.
			 */
			pds_hdr->clear_psn = htonl(pdc->tx_bm_base_psn);
		}

		break;

	default:

		UET_PDS_ERR("Unsupported next header type %d", next_hdr);
		free(pdc_pkt);
		return -FI_EINVAL;
	}

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr(uet,
			   &pdc_pkt->pkt->common.ipv4,
			   htonl(dst_addr->fa.v4),
			   htonl(uet_ep->ipv4_addr),
			   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
			   uet_ep->msg_ip_tos);

	memcpy(ses_hdr, ses, ses_len);
	memcpy(payload, pkt, pkt_len);

	/* save some params specific for this packet */
	pdc_pkt->msg_id        = msg_id;
	pdc_pkt->tx_retry_cnt  = 0;
	pdc_pkt->tx_pkt_handle = tx_pkt_handle;
	pdc_pkt->tx_pkt_acked  = false;
	pdc_pkt->flags         = flags;

	/* set this packet in the tx_bm */
	UET_PDS_DBG("PDC %u tx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->tx_bm_base_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	bm_set(pdc->tx_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn), pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %u tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %u ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->ack_bm);
	}

	/* insert the packet to the end of the timeout queue */
	uet_gettime(&pdc_pkt->tx_time);
	dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);

	rc = uet_parse_pkt(uet, pdc_pkt->pkt, pdc_pkt->pkt_len,
			   &pdc_pkt->pkt_pp);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("malformed Tx packet");
		free(pdc_pkt->pkt);
		free(pdc_pkt);
		return rc;
	}

	pdc_pkt->pkt_parsed = true;

	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX PACKET");

	rc = uet_pds_nic_tx_pkt(uet, pdc_pkt->pkt, pdc_pkt->pkt_len);
	if (rc != FI_SUCCESS) {
		bm_unset(pdc->tx_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn));
		free(pdc_pkt->pkt);
		free(pdc_pkt);
	}

	return rc;
}

static int uet_pds_rtx_pkt(struct uet_instance *uet,
			   struct uet_pdc *pdc,
			   struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_pds_req *pds_hdr;
	int rc;

	if (!pdc_pkt->pkt_parsed) {
		rc = uet_parse_pkt(uet, pdc_pkt->pkt, pdc_pkt->pkt_len,
				   &pdc_pkt->pkt_pp);
		if (rc != FI_SUCCESS) {
			UET_PDS_ERR("malformed Tx packet to retransmit");
			return rc;
		}

		pdc_pkt->pkt_parsed = true;
	}

	/* set the retransmit flag in the PDS header */
	pds_hdr = (struct uet_pds_req *)pdc_pkt->pkt_pp.pds;
	pds_hdr->prlg.type_next_flags |=
		 htons(UET_PDS_REQ_FLAGS_RETX << UET_PDS_FLAGS_SHIFT);

	pdc_pkt->tx_retry_cnt++;
	uet_gettime(&pdc_pkt->tx_time);

	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX PACKET (retransmit)");

	return uet_pds_nic_tx_pkt(uet, pdc_pkt->pkt, pdc_pkt->pkt_len);
}

static int uet_pds_check_rtx_pkt(struct uet_instance *uet,
				 struct uet_pdc *pdc,
				 struct uet_pdc_pkt *pdc_pkt)
{
	time_t now, delta;
	int rc;

	uet_gettime(&now);
	delta = (now - pdc_pkt->tx_time);
	if (delta < uet->pds.tx_timeout)
		return FI_SUCCESS; /* no retransmit */

	if (pdc_pkt->tx_retry_cnt >= uet->pds.max_tx_retries) {
		UET_PDS_ERR("PDC %u PSN %u retry exceeded",
			    pdc->pdc_id, pdc_pkt->psn);
		return -FI_EIO; /* assume this PDC is dead */
	}

	UET_PDS_WARN("PDC %u PSN %u retransmit", pdc->pdc_id, pdc_pkt->psn);

	rc = uet_pds_rtx_pkt(uet, pdc, pdc_pkt);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("PDC %u PSN %u retransmit failed",
			    pdc->pdc_id, pdc_pkt->psn);
		return -FI_EIO; /* assume this PDC is dead */
	}

	return -FI_EAGAIN; /* pkt retransmitted, could be more */
}

int uet_pds_progress_tx(struct uet_ep *uet_ep,
			uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet;
	struct uet_pdc *pdc;
	struct dlist_entry *tmp1, *tmp2;
	struct uet_pdc_pkt *pdc_pkt;
	time_t now, delta;
	int rc;

	uet = uet_ep->uet_domain->uet;

	/* TODO:
	 * [x] walk the allocated PDC list
	 *     [x] walk the tx_pkt_list (sorted in tx time order, oldest first)
	 *         [x] if the packet has not timed out
	 *             [x] done with this PDC, continue
	 *         [x] increment the retry count
	 *         [x] if the retry count has exceeeded the max
	 *             [x] set the error handle to the tx_handle
	 *             [ ] change PDC state(?)
	 *         [x] update the tx time
	 *         [x] move the packet to the end of the tx_pkt_list
	 *         [x] retransmit the pkt
	 */

	dlist_foreach_container_safe(&pds_state.pdc_alloc_head,
				     struct uet_pdc, pdc, node, tmp1) {
		dlist_foreach_container_safe(&pdc->tx_pkt_list_head,
					     struct uet_pdc_pkt, pdc_pkt,
					     node, tmp2) {
			rc = uet_pds_check_rtx_pkt(uet, pdc, pdc_pkt);
			if (rc == FI_SUCCESS) {
				break; /* no retransmit, done with this PDC */
			} else if (rc == -FI_EIO) {
				/* TODO: Need to destroy this PDC... */
				dlist_remove(&pdc_pkt->node);
				break; /* done with this PDC */
			} else if (rc == -FI_EAGAIN) {
				/*
				 * This packet was retransmitted, move this
				 * packet to the end of the list and continue.
				 */
				dlist_remove(&pdc_pkt->node);
				dlist_insert_tail(&pdc_pkt->node,
						  &pdc->tx_pkt_list_head);
			}
		}
	}

	return FI_SUCCESS;
}

int uet_pds_msg_cmpl_ind(struct uet_ep *uet_ep,
			 uet_addr_handle_t dst_addr_handle,
			 uet_pds_mode_t mode,
			 uint16_t msg_id)
{
	struct uet_pdc *pdc;
	int rc;

	pdc = uet_pdsm_get_msgid_pdc(msg_id);
	if (pdc == NULL)
		return -FI_EINVAL;

	rc = uet_pdsm_unmap_msgid_pdc(msg_id);
	if (rc != FI_SUCCESS)
		return rc;

	UET_PDS_DBG("PDC %d complete indication for msg_id %u",
		    pdc->pdc_id, msg_id);
	pdc->open_msg_cnt--;

	return FI_SUCCESS;
}

static void uet_pds_build_ack_pkt(struct uet_instance *uet,
				  struct uet_pdc *pdc,
				  struct uet_pdc_pkt *pdc_pkt,
				  uet_next_hdr_t next_hdr,
				  size_t ses_hdr_len,
				  void *ses_hdr)
{
	uint8_t flags;
	void *ack_ses;

	if (next_hdr == UET_HDR_RSP)
		ack_ses = &pdc_pkt->ack->std_rsp.ses;
	else /* response w/ data */
		ack_ses = &pdc_pkt->ack->std_rsp_d_ack.ses;

	uet_build_eth_hdr(&pdc_pkt->ack->common.eth,
			  pdc_pkt->pkt->common.eth.h_source,
			  pdc_pkt->pkt->common.eth.h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr(uet,
			   &pdc_pkt->ack->common.ipv4,
			   pdc_pkt->pkt->common.ipv4.saddr,
			   pdc_pkt->pkt->common.ipv4.daddr,
			   (pdc_pkt->ack_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos);

	pdc_pkt->ack->common.pds.prlg.entropy =
		pdc_pkt->pkt->common.pds.prlg.entropy;

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	flags = (pdc_pkt->needs_clear) ? UET_PDS_ACK_FLAGS_REQ_TGT_CLR
				       : UET_PDS_ACK_FLAGS_NONE;
	pdc_pkt->ack->common.pds.prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (next_hdr << UET_PDS_NEXT_HDR_SHIFT) |
		      (flags << UET_PDS_FLAGS_SHIFT));

	pdc_pkt->ack->common.pds.psn    = pdc_pkt->pkt->common.pds.psn;
	pdc_pkt->ack->common.pds.spdcid = htons(pdc->pdc_id);
	pdc_pkt->ack->common.pds.dpdcid = htons(pdc->dpdcid);

	memcpy(ack_ses, ses_hdr, ses_hdr_len);
}

static int uet_pds_tx_ack_pkt(struct uet_instance *uet,
			      struct uet_pdc *pdc,
			      struct uet_pdc_pkt *pdc_pkt,
			      uet_next_hdr_t next_hdr,
			      size_t ses_hdr_len,
			      void *ses_hdr,
			      bool gtd_del)
{
	uint16_t ack_pkt_len;
	uint16_t ack_data_len;
	int rc;

	if (next_hdr == UET_HDR_RSP)
		pdc_pkt->ack_len = sizeof(struct uet_std_rsp_pkt);
	else { /* response w/ data */
		ack_data_len = (ses_hdr_len - sizeof(struct uet_ses_rsp_d));
		pdc_pkt->ack_len = (sizeof(struct uet_std_rsp_d_ack_pkt) +
				    ack_data_len);
	}

	/* allocate buffer for ack packet */
	pdc_pkt->ack = calloc(1, pdc_pkt->ack_len);
	if (pdc_pkt->ack == NULL) {
		UET_PDS_ERR("failed to alloc ACK packet buffer");
		return -FI_ENOMEM;
	}

	pdc_pkt->needs_clear = gtd_del;

	/* build the ACK packet */
	uet_pds_build_ack_pkt(uet, pdc, pdc_pkt, next_hdr,
			      ses_hdr_len, ses_hdr);

	rc = uet_parse_pkt(uet, pdc_pkt->ack, pdc_pkt->ack_len,
			   &pdc_pkt->ack_pp);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("malformed ACK packet");
		pdc_pkt->needs_clear = false;
		pdc_pkt->ack_len = 0;
		free(pdc_pkt->ack);
		return rc;
	}

	pdc_pkt->ack_parsed = true;

	uet_pds_pkt_dbg(uet, &pdc_pkt->ack_pp, true, "TX ACK PACKET");

	/* send the ACK packet */
	rc = uet_pds_nic_tx_pkt(uet, pdc_pkt->ack, pdc_pkt->ack_len);
	if (rc != FI_SUCCESS) {
		pdc_pkt->needs_clear = false;
		pdc_pkt->ack_len = 0;
		free(pdc_pkt->ack);
	}

	return rc;
}

static int uet_pds_tx_def_rsp_ack_pkt(struct uet_instance *uet,
				      struct uet_pdc *pdc,
				      struct uet_pdc_pkt *pdc_pkt)
{
	union uet_pkt def_rsp;
	int def_rsp_len = sizeof(struct uet_def_rsp_pkt);
	struct uet_parsed_pkt pp;
	int rc;

	memset(&def_rsp, 0, sizeof(def_rsp));

	uet_build_eth_hdr(&def_rsp.common.eth,
			  pdc_pkt->pkt->common.eth.h_source,
			  pdc_pkt->pkt->common.eth.h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr(uet,
			   &def_rsp.common.ipv4,
			   pdc_pkt->pkt->common.ipv4.saddr,
			   pdc_pkt->pkt->common.ipv4.daddr,
			   (def_rsp_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos);

	def_rsp.common.pds.prlg.entropy =
		pdc_pkt->pkt->common.pds.prlg.entropy;

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	def_rsp.common.pds.prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_RSP << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_NONE << UET_PDS_FLAGS_SHIFT));

	def_rsp.common.pds.psn    = pdc_pkt->pkt->common.pds.psn;
	def_rsp.common.pds.spdcid = htons(pdc->pdc_id);
	def_rsp.common.pds.dpdcid = htons(pdc->dpdcid);

	def_rsp.def_rsp.ses.list_opcode =
		(UET_DEFAULT_RESPONSE << UET_PDS_SES_DEF_RSP_OPCODE_SHIFT);
	def_rsp.def_rsp.ses.ver_return_code =
		(UET_RC_NULL << UET_PDS_SES_DEF_RSP_RETCODE_SHIFT);
	def_rsp.def_rsp.ses.msg_id =
		((struct uet_ses_rsp_cmn *)pdc_pkt->pkt_pp.ses)->msg_id;

	rc = uet_parse_pkt(uet, &def_rsp, def_rsp_len, &pp);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("malformed DEF_RSP ACK packet");
		return rc;
	}

	uet_pds_pkt_dbg(uet, &pp, true, "TX DEF_RSP ACK PACKET (duplicate)");

	/* send the ACK packet */
	return uet_pds_nic_tx_pkt(uet, &def_rsp, def_rsp_len);
}

static int uet_pds_check_duplicate_and_rtx(struct uet_instance *uet,
					   struct uet_pdc *pdc,
					   struct uet_pdc_pkt *pdc_pkt,
					   bool *rtx)
{
	struct uet_pdc_pkt *orig_pkt = NULL;
	int rc;

	*rtx = false;

	/* if the PSN is outside the current +/- MPR then drop it */

	if (PSN_IN_PRIOR_MPR(pdc_pkt->pkt_pp.pds_psn,
			     pdc->rx_bm_base_psn)) {
		orig_pkt = NULL; /* indicate a default response */
	} else if (PSN_IN_MPR(pdc_pkt->pkt_pp.pds_psn,
			      pdc->rx_bm_base_psn)) {
		/* check if this packet is a duplicate */
		if (!bm_get(pdc->rx_bm,
			    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn),
			    (void **)&orig_pkt)) {
			return FI_SUCCESS; /* new PSN */
		}
	} else {
		UET_PDS_WARN("invalid PSN %u on PDC %u (outside MPR %u[+/-%u])",
			     pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id,
			     pdc->rx_bm_base_psn, UET_DEFAULT_MPR);
		return -FI_EINVAL;
	}

	UET_PDS_WARN("duplicate %sPSN %u on PDC %u (ACK retransmit)",
		     (pdc_pkt->pkt_pp.pds_flags &
		      UET_PDS_REQ_FLAGS_SYN) ? "SYN " : "",
		     pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id);

	if (orig_pkt == NULL) {
		/* send a default response */
		rc = uet_pds_tx_def_rsp_ack_pkt(uet, pdc, pdc_pkt);
		if (rc != FI_SUCCESS)
			return rc;

		*rtx = true;
	} else if (orig_pkt->ack) {
		uet_pds_pkt_dbg(uet, &orig_pkt->ack_pp, true,
				"TX ACK PACKET (duplicate)");

		/* resend previous ACK/response */
		rc = uet_pds_nic_tx_pkt(uet, orig_pkt->ack, orig_pkt->ack_len);
		if (rc != FI_SUCCESS)
			return rc;

		*rtx = true;
	} else {
		UET_PDS_ERR("no ACK to retransmit PSN %u on PDC %u",
			    pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id);
		return -FI_EINVAL;
	}

	return FI_SUCCESS;
}

static int uet_pds_upcall_ses_rx_req(struct uet_instance *uet,
				     struct uet_pdc *pdc,
				     struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_pds_info pds_info;
	uet_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del;
	int rc;

	/* upcall for ses processing */
	memset(&pds_info, 0, sizeof(struct uet_pds_info));
	pds_info.opsn  = pdc_pkt->pkt_pp.pds_psn;
	pds_info.pdcid = pdc->pdc_id;

	/* allocate a buffer for the SES reponse data */
	rsp_ses_hdr = calloc(1, (sizeof(struct uet_ses_rsp_d) +
				 uet->pds.max_ack_data));
	if (rsp_ses_hdr == NULL) {
		UET_PDS_ERR("failed to alloc SES response buffer");
		return -FI_ENOMEM;
	}

	rc = uet->pds.upcall.rx_req((uet_pkt_handle_t)pdc_pkt, uet,
				    &pdc_pkt->pkt_pp, &pds_info,
				    &rsp_next_hdr, rsp_ses_hdr,
				    &rsp_ses_hdr_len, &ses_nack,
				    &gtd_del);
	if (rc == FI_SUCCESS) {
		/* TODO: add support for sending a PDS NACK
		 * For now, if this is a bad request, not sending a
		 * NACK will cause a retransmit of the request packet
		 * by the initiator.
		 */
		if (ses_nack) {
			UET_PDS_ERR("PDC %u PSN %u SES NACK",
				    pdc->pdc_id, pdc_pkt->pkt_pp.pds_psn);
			rc = -FI_EINVAL;
		} else {
			/* transmit ACK */
			rc = uet_pds_tx_ack_pkt(uet, pdc, pdc_pkt,
						rsp_next_hdr, rsp_ses_hdr_len,
						rsp_ses_hdr, gtd_del);
		}
	} else {
		UET_PDS_ERR("PDC %u PSN %u SES upcall failed (rx_req=%d)",
			    pdc_pkt->pkt_pp.pds_dpdcid,
			    pdc_pkt->pkt_pp.pds_psn, rc);
	}

	free(rsp_ses_hdr);
	return rc;
}

static int uet_pds_shift_rx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc,
				   bool is_rod)
{
	struct uet_pdc_pkt *pdc_pkt;
	bool shifted = false;
	int rc;

	while (true) {
		if (!bm_get(pdc->rx_bm, 0, (void **)&pdc_pkt))
			break;

		if (is_rod && !pdc_pkt->reordered) { /* reorder using rx_bm */
			rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
			if (rc != FI_SUCCESS)
				return rc;

			pdc_pkt->reordered = true;
		}

		/* packet requires a clear that hasn't been received yet */
		if (pdc_pkt->needs_clear)
			break;

		shifted = true;
		bm_shift_right(pdc->rx_bm, 1);
		pdc->rx_bm_base_psn++;

		if (pdc_pkt->ack)
			free(pdc_pkt->ack);
		if (pdc_pkt->pkt)
			free(pdc_pkt->pkt);
		free(pdc_pkt);
	}

#if 0
	if (shifted && (UET_LOG_LVL >= UET_LOG_DBG)) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm);
	}
#endif
	(void)shifted;

	return FI_SUCCESS;
}

static int uet_pds_shift_tx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc)
{
	struct uet_pdc_pkt *pdc_pkt;
	bool shifted = false;
	int rc;

	while (true) {
		if (!bm_get(pdc->tx_bm, 0, (void **)&pdc_pkt))
			break;

		if (!bm_get(pdc->ack_bm, 0, NULL))
			break;

		 /*
		  * This transmitted packet has been ACK'ed. Note that when
		  * the ACK was processed, the packet was removed from the
		  * PDC's tx list that is managed for retransmissions.
		  */

		shifted = true;
		bm_shift_right(pdc->tx_bm, 1);
		bm_shift_right(pdc->ack_bm, 1);
		pdc->tx_bm_base_psn++;

		if (pdc_pkt->ack)
			free(pdc_pkt->ack);
		if (pdc_pkt->pkt)
			free(pdc_pkt->pkt);
		free(pdc_pkt);
	}

#if 0
	if (shifted && (UET_LOG_LVL >= UET_LOG_DBG)) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %d ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->ack_bm);
	}
#endif
	(void)shifted;

	return FI_SUCCESS;
}

static int uet_pds_process_ack(struct uet_instance *uet,
			       struct uet_parsed_pkt *pp)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;
	int rc;

	/* TODO:
	 * [x] fetch the PDC (from dpdcid)
	 * [x] verify PDC is in an active state (not UNALLOC)
	 *     [x] if not then drop the ACK
	 * [x] verify the spdcid PDC is the correct peer
	 *     [x] if not then drop the Request
	 * [x] verify the PSN is within the MPR
	 *     [x] if not then drop the ACK
	 * [x] fetch the PSN/packet from the tx_bm
	 *     [x] if not found/set then drop the ACK
	 * [x] verify the PSN/packet has not been ACK'ed
	 *     [x] if already ACK'ed then drop the ACK
	 * [x] mark the PSN/packet as ACK'ed
	 * [x] call SES upcall/rx_rsp
	 * [x] if in the SYN state then move to establed (save spdcid)
	 * [x] move the tx_bm PSN window for all contiguous ACK'ed PSN
	 */

	pdc = uet_pdsm_get_pdc(pp->pds_dpdcid, false);
	if (pdc == NULL)
		return -FI_ENODEV;

	if ((pdc->state != PDC_STATE_SYN) &&
	    (pdc->dpdcid != pp->pds_spdcid)) {
		UET_PDS_WARN("invalid PDC %u (dpdcid %u != spdcid %u)",
			     pdc->pdc_id, pdc->dpdcid, pp->pds_spdcid);
		return -FI_EINVAL;
	}

	if (!PSN_IN_MPR(pp->pds_psn, pdc->tx_bm_base_psn)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u "
			     "(outside MPR %u[+%u])",
			     pp->pds_psn, pp->pds_dpdcid,
			     pdc->tx_bm_base_psn, UET_DEFAULT_MPR);
		return -FI_EINVAL;
	}

	if (!bm_get(pdc->tx_bm, (pp->pds_psn - pdc->tx_bm_base_psn),
		    (void **)&pdc_pkt)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u (packet not found)",
			     pp->pds_psn, pp->pds_dpdcid);
		return -FI_EINVAL;
	}

	if (pdc_pkt->tx_pkt_acked) {
		UET_PDS_WARN("duplicate ACK PSN %u on PDC %u",
			     pp->pds_psn, pp->pds_dpdcid);
		return -FI_EINVAL;
	}

	UET_PDS_DBG("PDC %u tx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->tx_bm_base_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	bm_set(pdc->ack_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn), NULL);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %d ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->ack_bm);
	}

	pdc_pkt->tx_pkt_acked = true;
	dlist_remove(&pdc_pkt->node); /* remove from Tx list */

	/* upcall for SES processing */
	rc = uet->pds.upcall.rx_rsp(pdc_pkt->tx_pkt_handle, pp);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("PDC %u ACK PSN %u SES upcall failed (rx_rsp=%d)",
			    pp->pds_dpdcid, pp->pds_psn, rc);
		return rc;
	}

	if (pdc->state == PDC_STATE_SYN) {
		pdc->state  = PDC_STATE_ESTABLISHED;
		pdc->dpdcid = pp->pds_spdcid;
	}

	/* shift the tx_bm window for all left edge ACK'ed PSNs */
	rc = uet_pds_shift_tx_window(uet, pdc);
	if (rc != FI_SUCCESS)
		return rc;

	/* TODO:
	 * If the UET_PDS_ACK_FLAGS_REQ_TGT_CLR flag was set on the ACK,
	 * immediately send a PDS CLEAR control packet now. This allows the
	 * CLEAR to be acknowledged right away instead of waiting for the
	 * next request to be sent that would contain a cumulative clear PSN.
	 */

	return FI_SUCCESS;
}

static int uet_pds_process_syn_pkt(struct uet_instance *uet,
				   struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_parsed_pkt *pp = &pdc_pkt->pkt_pp;
	struct uet_pdc *pdc;
	bool rtx;
	int rc;

	/* TODO:
	 * [x] find PDC (possibly created from previous SYN)
	 * [x] if not found
	 *     [x] create and init PDC
	 * [x] if duplicate
	 *     [x] send previous response / or default response
	 *     [x] done
	 * [x] place packet with SYN offset
	 * [x] process packet with SES (rx_req)
	 * [x] send ACK
	 *     [ ] or NACK
	 * [x] save response packet and mark if non-default
	 */

	pdc = uet_pdsm_assign_tgt_pdc(pp);
	if (pdc == NULL)
		return -FI_ENODEV;

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	/* TODO: if error, free PDC if allocated with this SYN */
	if (rc != FI_SUCCESS)
		return rc;
	else if (rtx)
		return FI_SUCCESS;

	UET_PDS_DBG("PDC %u rx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn, pp->pds_psn,
		    (pp->pds_psn - pdc->rx_bm_base_psn));

	bm_set(pdc->rx_bm, (pp->pds_psn - pdc->rx_bm_base_psn), pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm);
	}

	if (pp->pds_type == UET_PDS_TYPE_RUD_REQ) {
		/* for RUD, call into SES immediately ignoring order */
		rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
		if (rc != FI_SUCCESS)
			return rc;

		rc = uet_pds_shift_rx_window(uet, pdc, false);
		if (rc != FI_SUCCESS)
			return rc;
	} else if (pp->pds_type == UET_PDS_TYPE_ROD_REQ) {
		/* for ROD, reorder before calling into SES */
		rc = uet_pds_shift_rx_window(uet, pdc, true);
		if (rc != FI_SUCCESS)
			return rc;
	}

	return FI_SUCCESS;
}

static int uet_pds_process_request(struct uet_instance *uet,
				   struct uet_parsed_pkt *pp,
				   union uet_pkt *pkt,
				   int pkt_len)
{
	struct uet_pdc_pkt *pdc_pkt;
	struct uet_pdc *pdc;
	bool rtx;
	int rc;

	/* TODO:
	 * [ ] if RUDI/UUD...
	 *     [ ] process request
	 *     [ ] send ACK (or NACK)
	 *     [ ] done
	 */

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ)) {
		UET_PDS_WARN("Rx packet type not supported %d",
			     pp->pds_type);
		return -FI_EINVAL;
	}

	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		return -FI_ENOMEM;
	}

	pdc_pkt->psn = pp->pds_psn;
	pdc_pkt->msg_id = pp->ses_msg_id;
	pdc_pkt->pkt = pkt;
	pdc_pkt->pkt_len = pkt_len;
	memcpy(&pdc_pkt->pkt_pp, pp, sizeof(*pp));
	pdc_pkt->pkt_parsed = true;

	/* if this is a SYN packet then a new PDC might be needed */
	if (pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_SYN) {
		rc = uet_pds_process_syn_pkt(uet, pdc_pkt);
		if (rc != FI_SUCCESS)
			goto exit_err;
		return FI_SUCCESS;
	}

	/* TODO:
	 * [x] fetch the PDC (from dpdcid)
	 * [x] verify PDC is in an active state (not UNALLOC)
	 *     [x] if not then drop the Request
	 * [x] verify the spdcid PDC is the correct peer
	 *     [x] if not then drop the Request
	 * [x] verify the PSN is within the +/- MPR
	 *     [x] if not then drop the Request
	 * [x] if duplicate
	 *     [x] send previous response / or default response
	 *     [x] done
	 * [x] place packet in the Rx bitmap
	 * [x] process packet with SES (rx_req)
	 * [x] send ACK (or NACK)
	 * [x] save response packet and mark if non-default
	 * [x] move the rx_bm PSN window for all contiguous PSNs
	 */

	pdc = uet_pdsm_get_pdc(pdc_pkt->pkt_pp.pds_dpdcid, false);
	if (pdc == NULL) {
		rc = -FI_ENODEV;
		goto exit_err;
	}

	if (pdc_pkt->pkt_pp.pds_spdcid != pdc->dpdcid) {
		UET_PDS_WARN("invalid PDC %u (spdcid %u != dpdcid %u)",
			     pdc->pdc_id, pdc_pkt->pkt_pp.pds_spdcid,
			     pdc->dpdcid);
		rc = -FI_EINVAL;
		goto exit_err;
	}

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	if (rc != FI_SUCCESS)
		goto exit_err;
	else if (rtx)
		return FI_SUCCESS;

	UET_PDS_DBG("PDC %u rx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn, pdc_pkt->pkt_pp.pds_psn,
		    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn));

	bm_set(pdc->rx_bm, (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn),
	       pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm);
	}

	if (pp->pds_type == UET_PDS_TYPE_RUD_REQ) {
		/* for RUD, call into SES immediately ignoring order */
		rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
		if (rc != FI_SUCCESS)
			return rc;

		rc = uet_pds_shift_rx_window(uet, pdc, false);
		if (rc != FI_SUCCESS)
			return rc;
	} else if (pp->pds_type == UET_PDS_TYPE_ROD_REQ) {
		/* for ROD, reorder before calling into SES */
		rc = uet_pds_shift_rx_window(uet, pdc, true);
		if (rc != FI_SUCCESS)
			return rc;
	}

	return FI_SUCCESS;

exit_err:
	free(pdc_pkt);
	return rc;
}

int uet_pds_progress_rx(struct uet_instance *uet)
{
	union uet_pkt *pkt;
	int pkt_len;
	struct uet_parsed_pkt pp;
	bool pkt_is_ack, pkt_is_rd_rsp;
	struct uet_pdc_pkt *pdc_pkt = NULL;
	struct uet_pdc *pdc;
	struct uet_pds_info pds_info;
	uet_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr = NULL;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del, rtx;
	int rc = FI_SUCCESS;

	rc = uet_pds_nic_rx_pkt(uet, &pkt, &pkt_len);
	if (rc != 1)
		return rc;

	/* validate the packet */
	if (!uet_pds_rx_pkt_chk(uet, pkt, pkt_len,
				&pkt_is_ack,
				&pkt_is_rd_rsp)) {
		UET_PDS_WARN("invalid Rx packet");
		rc = -FI_EINVAL;
		goto exit_err;
	}

	/* parse the packet */
	rc = uet_parse_pkt(uet, pkt, pkt_len, &pp);
	if (rc != FI_SUCCESS) {
		UET_PDS_ERR("malformed Rx packet");
		goto exit_err;
	}

	uet_pds_pkt_dbg(uet, &pp, false, "RX PACKET");

	if (pkt_is_ack) {

		rc = uet_pds_process_ack(uet, &pp);
		if (rc != FI_SUCCESS)
			goto exit_err;

	} else { /* request packet */

		rc = uet_pds_process_request(uet, &pp, pkt, pkt_len);
		if (rc != FI_SUCCESS)
			goto exit_err;

	}

	return FI_SUCCESS;

exit_err:
	free(pkt);
	return rc;
}

void uet_pds_ep_close_wait(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;
	time_t start_time, now;

	uet_ep->ep_state = UET_EP_CLOSE_WAIT;

	uet = uet_ep->uet_domain->uet;

	/*
	 * Continue receiving packets for max segment lifetime after the
	 * EP is closed. This gives time to retransmit any lost ACKs but
	 * no other packet Rx processing is performed.
	 */

	if (uet_gettime(&start_time)) {
		UET_PDS_ERR("Aborting endpoint close wait state");
		return;
	}

	while (1) {
		if (uet_gettime(&now)) {
			UET_PDS_ERR("Aborting endpoint close wait state");
			break;
		}

		if ((now - start_time) > uet->pds.msl)
			break;

		uet->pds.downcall.progress_rx(uet);
	}
}

