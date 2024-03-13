/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* SES-PDS APIs */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_pds.h"
#include "uet_api_private.h"
#include "uet_nic.h"

/* determine if tx is active for an endpoint */
static bool uet_pds_ep_tx_active(struct uet_ep *uet_ep)
{
	return uet_ep->pds.tx.tx_active;
}

/* determine if uet packet type is valid */
static bool uet_pds_pkt_type_valid(union uet_pkt *pkt, bool *pkt_is_ack)
{
	uint16_t pds_type, next_hdr;
	bool pds_req;

	*pkt_is_ack = false;

	pds_type = (ntohs(pkt->common.pds.prolog.type_flags_next) &
		    UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT;
	next_hdr = (ntohs(pkt->common.pds.prolog.type_flags_next) &
		    UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT;

	switch (pds_type) {
	case UET_PDS_ROD_REQ:
		pds_req = true;
		break;
	case UET_PDS_ACK:
		pds_req = false;
		next_hdr = UET_HDR_RSP;
		break;
	default:
		return false;
	}

	switch (next_hdr) {
	case UET_HDR_REQ_STD:
		if (pds_req)
			return true;
		break;
	case UET_HDR_RSP:
		if (pds_req == false) {
			*pkt_is_ack = true;
			return true;
		}
		break;
	default:
		break;
	}

	return false;
}

/*
 * parse and validate received packet as follows:
 *   - validate dest mac address
 *   - validate ethertype
 *   - validate ip header version
 *   - validate ip header len
 *   - validate ip header total length
 *   - validate ip header checksum
 *   - validate ip protocol
 *   - validate uet packet type
 *
 * parms:
 *      uet        - ptr to uet instance struct
 *      pkt        - ptr to received packet
 *      pkt_size   - size of received packet in bytes
 *      pkt_is_ack - ptr to location where indication of packet type
 *                   is returned, true => packet is an ack packet,
 *                   only valid when function returns true
 *
 * returns:
 *      true  => packet passed validation checks
 *      false => packet did not pass validation checks
 */
static bool uet_pds_rx_pkt_valid(struct uet_instance *uet,
				 union uet_pkt *pkt, size_t pkt_size,
				 bool *pkt_is_ack)
{
	if (!memcmp(pkt->common.eth.h_dest, uet->nic.mac_addr, ETH_ALEN) &&
	    (pkt->common.eth.h_proto == htons(ETH_P_IP)) &&
	    (pkt->common.ipv4.version == IPVERSION) &&
	    (pkt->common.ipv4.ihl == UET_IPV4_IHL_NO_OPTIONS) &&
	    (pkt->common.ipv4.protocol == UET_IPPROTO) &&
	    (pkt->common.ipv4.tot_len >= htons(uet->nic.min_ip_pkt_size)) &&
	    (pkt->common.ipv4.tot_len <=
	     htons((pkt_size - uet->nic.l2_hdr_size))) &&
	    (uet_ipv4_csum(&pkt->common.ipv4) == 0) &&
	    (uet_pds_pkt_type_valid(pkt, pkt_is_ack)))
		return true;

	return false;
}

/* determine if pkt is destined for endpoint */
static bool uet_pds_ep_addr_match(
	struct uet_ep *uet_ep, union uet_pkt *pkt, bool pkt_is_ack,
	struct uet_msg_match_info *match_info)
{
	uint16_t msg_id, pid_on_fep, index;
	uint32_t job_id;

	if (ntohl(pkt->common.ipv4.daddr) != uet_ep->ipv4_addr)
		return false;
	match_info->ip_addr_match = true;

	if (pkt_is_ack) {
		if (!uet_ep->pds.tx.tx_active)
			return false;

		job_id = (ntohl(pkt->std_rsp.ses.gen_jobid) &
			  UET_SES_JOB_ID_MASK) >> UET_SES_JOB_ID_SHIFT;
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		msg_id = ntohs(pkt->std_rsp.ses.msg_id);
		if (msg_id != uet_ep->pds.tx.pkt_parms.msg_id)
			return false;
		match_info->msg_id_match = true;
	} else {
		job_id = (ntohl(pkt->std_req.ses.gen_jobid) &
			  UET_SES_JOB_ID_MASK) >> UET_SES_JOB_ID_SHIFT;
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		pid_on_fep = (ntohs(pkt->std_req.ses.resv_pid_on_fep) &
			      UET_SES_STD_REQ_PID_ON_FEP_MASK) >>
			     UET_SES_STD_REQ_PID_ON_FEP_SHIFT;
		if (pid_on_fep != uet_ep->uet_addr.pid_on_fep)
			return false;
		match_info->pid_on_fep_match = true;

		index = (ntohs(pkt->std_req.ses.resv_index) &
			      UET_SES_STD_REQ_INDEX_MASK) >>
			     UET_SES_STD_REQ_INDEX_SHIFT;
		if (index != uet_ep->uet_addr.start_index)
			return false;
		match_info->index_match = true;
	}

	return true;
}

/* find endpoint that packet is destined for */
static struct uet_ep *uet_pds_find_dst_ep(
	struct uet_instance *uet, union uet_pkt *pkt, bool pkt_is_ack,
	struct uet_msg_match_info *match_info)
{
	struct dlist_entry *dom_head, *dom_item, *ep_head, *ep_item;
	struct uet_domain *uet_dom;
	struct uet_ep *uet_ep;

	dom_head = &uet->domain_list_head;
	dlist_foreach(dom_head, dom_item) {
		uet_dom = container_of(dom_item, struct uet_domain,
				       domain_list_entry);
		ep_head = &uet_dom->ep_list_head;
		dlist_foreach(ep_head, ep_item) {
			uet_ep = container_of(ep_item, struct uet_ep,
					      ep_list_entry);
			if (uet_pds_ep_addr_match(uet_ep, pkt, pkt_is_ack,
						  match_info))
				return uet_ep;
		}
	}

	return NULL;
}

/* determine if pds request is a duplicate that has already been received */
static bool uet_pds_is_dup_req(struct uet_ep *uet_ep, union uet_pkt *pkt,
			       struct uet_pds_ack_state **dup_ack_state)
{
	struct dlist_entry *head, *item, *prev_item;
	struct uet_pds_ack_state *ack_state;
	struct uet_pds_hdr_overlay *ack_overlay, *pkt_overlay;
	time_t now;

	*dup_ack_state = NULL;
	uet_gettime(&now);

	head = &uet_ep->pds.ack_state_list_head;
	dlist_foreach(head, item) {
		ack_state = container_of(item, struct uet_pds_ack_state,
					 list_entry);
		ack_overlay = (struct uet_pds_hdr_overlay *)
					&ack_state->ack.pds.spdcid;
		pkt_overlay = (struct uet_pds_hdr_overlay *)
					&pkt->common.pds.spdcid;
		if ((ack_state->ack.ipv4.daddr == pkt->common.ipv4.saddr) &&
		    (ack_overlay->pid_on_fep == pkt_overlay->pid_on_fep)  &&
		    (ack_overlay->index == pkt_overlay->index)) {
			if (ack_state->ack.pds.psn == pkt->common.pds.psn) {
				*dup_ack_state = ack_state;
				return true;
			}
			/* free saved ack, sender has received it and */
			/* moved on to a new psn                      */
			dlist_remove(item);
			free(ack_state);
			return false;
		}
		/* check if ack should be aged out */
		if ((now - ack_state->ack_time) >
		    uet_ep->uet_domain->uet->pds.msl) {
			dlist_remove(item);
			free(ack_state);
			item = prev_item;
		}
		prev_item = item;
	}

	return false;
}

/*
 * build a uet ack packet
 *
 * parms:
 *      uet         - ptr to uet instance struct
 *      pkt         - ptr to packet that is being acknowledged
 *      ack         - ptr to buffer where ack packet is to be built
 *      ack_pkt_len - size of ack packet in bytes
 *      next_hdr    - ses header format identifier
 *      ses_hdr_len - length of ses header in bytes
 *      ses_hdr     - ptr to ses header
 */
static void uet_pds_build_ack_pkt(struct uet_instance *uet, union uet_pkt *pkt,
				  struct uet_std_rsp_pkt *ack,
				  uint16_t ack_pkt_len, uet_next_hdr_t next_hdr,
				  size_t ses_hdr_len, void *ses_hdr)
{
	struct uet_pds_hdr_overlay *pkt_overlay, *ack_overlay;
	uint16_t tot_len;

	uet_build_eth_hdr(&ack->eth, pkt->common.eth.h_source,
			  pkt->common.eth.h_dest);

	tot_len = ack_pkt_len - ((uint16_t) uet->nic.l2_hdr_size);
	uet_build_ipv4_hdr(&ack->ipv4, pkt->common.ipv4.saddr,
			   pkt->common.ipv4.daddr, tot_len,
			   uet->pds.ack_ip_tos);

	ack->pds.prolog.type_flags_code = htons(
			(UET_PDS_ACK << UET_PDS_TYPE_SHIFT)                   |
			(UET_PDS_RSP_FLAGS_NONE << UET_PDS_FLAGS_SHIFT)       |
			(UET_PDS_CODE_ACK << UET_PDS_CODE_SHIFT));
	ack->pds.psn = pkt->common.pds.psn;
	pkt_overlay = (struct uet_pds_hdr_overlay *) &pkt->common.pds.spdcid;
	ack_overlay = (struct uet_pds_hdr_overlay *) &ack->pds.spdcid;
	ack_overlay->pid_on_fep = pkt_overlay->pid_on_fep;
	ack_overlay->index = pkt_overlay->index;

	memcpy(&ack->ses, ses_hdr, ses_hdr_len);
}

/*
 * build and transmit a uet ack packet
 *
 * parms:
 *      uet_ep      - ptr to uet endpoint struct
 *      pkt         - ptr to packet that is being acknowledged
 *      next_hdr    - ses header format identifier
 *      ses_hdr_len - length of ses header in bytes
 *      ses_hdr     - ptr to ses header
 *
 * returns:
 *      FI_SUCCESS on success,
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_tx_ack_pkt(struct uet_ep *uet_ep, union uet_pkt *pkt,
			      uet_next_hdr_t next_hdr, size_t ses_hdr_len,
			      void *ses_hdr)
{
	int rc;
	uint16_t ack_pkt_len;
	time_t now;
	struct uet_instance *uet;
	struct uet_pds_ack_state *ack_state;
	struct uet_std_rsp_pkt *ack;

	uet = uet_ep->uet_domain->uet;
	ack_pkt_len = sizeof(struct uet_std_rsp_pkt);

	/* allocate buffer for ack packet */
	ack_state = calloc(1, sizeof(struct uet_pds_ack_state));
	if (ack_state == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -FI_ENOMEM;
	}
	ack = &ack_state->ack;

	/* build ack packet */
	uet_pds_build_ack_pkt(uet, pkt, ack, ack_pkt_len, next_hdr,
			      ses_hdr_len, ses_hdr);

	/* send ack packet */
	rc = uet_nic_tx_pkt(UET_NIC(uet), (union uet_pkt *) ack, (size_t) ack_pkt_len);
	if (rc == FI_SUCCESS) {
		uet_gettime(&now);
		ack_state->ack_time = now;
		dlist_insert_head(&ack_state->list_entry,
				  &uet_ep->pds.ack_state_list_head);
	} else
		free(ack_state);
	return rc;
}

/*
 * build and transmit a uet ack packet with ses error code,
 * specifically for case where the packet is not deliverable because
 * there is no libfabric endpoint with the uet address in the request
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      pkt    - ptr to packet that is being acknowledged with ses err
 *      ses_rc - ses return code
 *
 * returns:
 *      FI_SUCCESS on success,
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_tx_err_ack_pkt(struct uet_instance *uet,
				  union uet_pkt *pkt, uet_ses_rc_t ses_rc)
{
	int rc;
	uint16_t ack_pkt_len;
	struct uet_std_rsp_pkt *ack;
	struct uet_ses_std_rsp ses;

	ack_pkt_len = sizeof(struct uet_std_rsp_pkt);

	/* allocate buffer for ack packet */
	ack = calloc(1, sizeof(struct uet_std_rsp_pkt));
	if (ack == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -FI_ENOMEM;
	}

	/* build ses header */
	ses.w0 = htonl((UET_RESPONSE << UET_SES_STD_RSP_OPCODE_SHIFT) |
		       (UET_SES_VER << UET_SES_STD_RSP_VER_SHIFT)     |
		       (UET_EXPECTED << UET_SES_STD_RSP_LIST_SHIFT)   |
		       (ses_rc << UET_SES_STD_RSP_RC_SHIFT));
	ses.msg_id = pkt->std_req.ses.msg_id;
	ses.mod_len = 0;
	ses.resv = 0;
	ses.gen_jobid = pkt->std_req.ses.gen_jobid;

	/* build ack packet */
	uet_pds_build_ack_pkt(uet, pkt, ack, ack_pkt_len, UET_HDR_RSP,
			      sizeof(struct uet_ses_std_rsp), &ses);

	/* send ack packet */
	rc = uet_nic_tx_pkt(UET_NIC(uet), (union uet_pkt *) ack, (size_t) ack_pkt_len);
	free(ack);
	return rc;
}

/*********************************************************************
 * Below functions implement SES-PDS APIs
 *********************************************************************/

/* init pds resources for uet instance */
int uet_pds_initialize(struct uet_instance *uet)
{
	uet->pds.tx_timeout = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl = UET_DEFAULT_MSL;
	uet->pds.ack_ip_tos = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);
	return FI_SUCCESS;
}

/* free pds resources for uet instance */
void uet_pds_finalize(struct uet_instance *uet)
{
}

/* init pds resources for endpoint */
int uet_pds_ep_initialize(struct uet_ep *uet_ep)
{
	dlist_init(&uet_ep->pds.ack_state_list_head);
	return FI_SUCCESS;
}

/* free pds resources for endpoint */
void uet_pds_ep_finalize(struct uet_ep *uet_ep)
{
	struct dlist_entry *head, *item;
	struct uet_pds_ack_state *pds_rx;

	head = &uet_ep->pds.ack_state_list_head;
	dlist_foreach(head, item) {
		pds_rx = container_of(item, struct uet_pds_ack_state,
				      list_entry);
		dlist_remove(item);
		item = head;
		free(pds_rx);
	}
}

/* pds packet transmission */
int uet_pds_tx_pkt(uet_pkt_handle_t tx_pkt_handle, struct uet_ep *uet_ep,
		   uet_addr_handle_t dst_addr_handle, uet_pds_mode_t mode,
		   uet_pds_tx_flags_t flags, bool pds_info_valid,
		   struct uet_pds_info pds_info, uint16_t msg_id,
		   uet_next_hdr_t next_hdr, void *pkt, size_t pkt_len,
		   bool dma_rdy)
{
	int rc;
	uint8_t tos;
	uint16_t tot_len;
	size_t uet_pkt_len;
	void *ses_hdr, *payload;
	uet_pds_pkt_type_t pds_pkt_type;
	struct uet_instance *uet;
	union uet_pkt *uet_pkt;
	struct uet_av_entry *av_entry;
	struct uet_addr *dst_addr;
	struct uet_pds_req *pds;
	struct uet_pds_to_ses_funcs *ses_upcall;
	struct uet_pds_tx_state *state;
	struct uet_pds_hdr_overlay *pds_overlay;

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *) dst_addr_handle;
	dst_addr = av_entry->addr;

	/* done for now if transmit in progress and not retry */
	if (uet_pds_ep_tx_active(uet_ep) &&
	    !(flags & UET_PDS_FLAG_RETRANSMIT))
		return -FI_EAGAIN;

	/* allocate buffer to build packet   */
	/* TODO: add support for gather send */
	uet_pkt = calloc(1, uet->nic.max_pkt_size);
	if (uet_pkt == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -FI_ENOMEM;
	}

	uet_build_eth_hdr(&uet_pkt->common.eth, av_entry->nh_mac_addr,
			  uet->nic.mac_addr);

	switch (next_hdr) {
	case UET_HDR_REQ_STD:
		switch (mode) {
		case UET_PDS_MODE_ROD:
			pds_pkt_type = UET_PDS_ROD_REQ;
			break;
		default:
			UET_API_ERR("Unsupported packet delivery mode = %d",
				    mode);
			return -FI_EINVAL;
		}

		pds = &uet_pkt->std_req.pds;
		pds->prolog.type_flags_next = htons(
			(pds_pkt_type << UET_PDS_TYPE_SHIFT)                  |
			((UET_PDS_REQ_FLAGS_NO_CLR | UET_PDS_REQ_FLAGS_AR) <<
			 UET_PDS_FLAGS_SHIFT)                                 |
			(next_hdr << UET_PDS_NEXT_HDR_SHIFT));
		if (flags & UET_PDS_FLAG_RETRANSMIT)
			pds->prolog.type_flags_next |= htons(
				(UET_PDS_REQ_FLAGS_RETX <<
				 UET_PDS_FLAGS_SHIFT));
		pds->psn = htonl(uet_ep->pds.tx.psn);
		pds_overlay = (struct uet_pds_hdr_overlay *) &pds->spdcid;
		pds_overlay->pid_on_fep = htons(uet_ep->uet_addr.pid_on_fep);
		pds_overlay->index = htons(uet_ep->uet_addr.start_index);

		tot_len = (uint16_t)(pkt_len +
				     (sizeof(struct uet_std_req_pkt) -
				      uet->nic.l2_hdr_size));
		tos = uet_ep->msg_ip_tos;

		ses_hdr = &uet_pkt->std_req.ses;

		uet_pkt_len = pkt_len + sizeof(struct uet_std_req_pkt);

		payload = uet_pkt->std_req.payload;
		break;
	default:
		UET_API_ERR("Unsupported next header type  = %d", next_hdr);
		return -FI_EINVAL;
	};

	uet_build_ipv4_hdr(&uet_pkt->common.ipv4, htonl(dst_addr->fa.v4),
			   htonl(uet_ep->ipv4_addr), tot_len, tos);

	ses_upcall = &uet->pds.upcall;
	ses_upcall->build_ses_hdr(tx_pkt_handle, pkt_len, ses_hdr, 0);

	memcpy(payload, pkt, pkt_len);

	if (!(flags & UET_PDS_FLAG_RETRANSMIT))
		uet_ep->pds.tx.retry_cnt = 0;

	uet_gettime(&uet_ep->pds.tx.start_time);

	/* save parms needed for pkt retransmission */
	state = &uet_ep->pds.tx;
	state->pkt_parms.tx_pkt_handle = tx_pkt_handle;
	state->pkt_parms.dst_addr_handle = dst_addr_handle;
	state->pkt_parms.mode = mode;
	state->pkt_parms.flags = flags;
	state->pkt_parms.pds_info_valid = pds_info_valid;
	state->pkt_parms.pds_info = pds_info;
	state->pkt_parms.msg_id = msg_id;
	state->pkt_parms.next_hdr = next_hdr;
	state->pkt_parms.pkt = pkt;
	state->pkt_parms.pkt_len = pkt_len;
	state->pkt_parms.dma_rdy = dma_rdy;

	rc = uet_nic_tx_pkt(UET_NIC(uet), uet_pkt, uet_pkt_len);
	if (rc == FI_SUCCESS)
		uet_ep->pds.tx.tx_active = true;
	free(uet_pkt);
	return rc;
}

/* progress tx operations for endpoint */
int uet_pds_progress_tx(struct uet_ep *uet_ep,
			uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet;
	struct uet_pds_tx_state *pds_tx;
	time_t now, delta;

	uet = uet_ep->uet_domain->uet;

	/* check if tx is active on endpoint */
	if (!uet_pds_ep_tx_active(uet_ep))
		return -FI_ENODATA;

	pds_tx = &uet_ep->pds.tx;
	*err_pkt_handle = pds_tx->pkt_parms.tx_pkt_handle;

	/* check if packet retransmission is needed */
	uet_gettime(&now);
	delta = now - pds_tx->start_time;
	if (delta < uet->pds.tx_timeout)
		return FI_SUCCESS;

	if (pds_tx->retry_cnt >= uet->pds.max_tx_retries) {
		/* retries exhausted */
		uet_ep->pds.tx.tx_active = false;
		return -FI_EIO;
	}

	/* retransmit the packet */
	pds_tx->retry_cnt++;
	uet_gettime(&pds_tx->start_time);
	return (uet_pds_tx_pkt(pds_tx->pkt_parms.tx_pkt_handle,
			       uet_ep,
			       pds_tx->pkt_parms.dst_addr_handle,
			       pds_tx->pkt_parms.mode,
			       pds_tx->pkt_parms.flags |
			       UET_PDS_FLAG_RETRANSMIT,
			       pds_tx->pkt_parms.pds_info_valid,
			       pds_tx->pkt_parms.pds_info,
			       pds_tx->pkt_parms.msg_id,
			       pds_tx->pkt_parms.next_hdr,
			       pds_tx->pkt_parms.pkt,
			       pds_tx->pkt_parms.pkt_len,
			       pds_tx->pkt_parms.dma_rdy));
}

/* progress rx operations */
int uet_pds_progress_rx(struct uet_instance *uet)
{
	int rc;
	uet_ses_rc_t ses_rc;
	size_t rx_pkt_size;
	bool pkt_is_ack, gtd_del;
	union uet_pkt *pkt;
	struct uet_ep *dst_uet_ep;
	struct uet_msg_match_info match_info;
	struct uet_pds_to_ses_funcs *ses_upcall;
	struct uet_pds_tx_state *pds_tx;
	struct uet_pds_ack_state *ack_state;
	struct uet_ses_std_rsp rsp_ses_hdr;
	struct uet_pds_info pds_info;
	size_t rsp_ses_hdr_len;
	uet_next_hdr_t rsp_next_hdr;

	/* check if packet is available */
	rc = uet_nic_rx_poll(UET_NIC(uet));
	if (rc != 1)
		return rc;

	/* allocate temporary packet buffer                                */
	/*  - need temp buffer to parse packet and determine what endpoint */
	/*    the packet is destined for                                   */
	pkt = (union uet_pkt *)malloc(uet->nic.max_pkt_size);
	if (pkt == NULL) {
		UET_API_PRINT_ERRNO("malloc");
		return -FI_ENOMEM;
	}

	/* receive the packet */
	rc = uet_nic_rx_pkt(UET_NIC(uet), pkt, uet->nic.max_pkt_size, &rx_pkt_size);
	if (rc != 1)
		goto exit;

	/* validate the packet */
	rc = FI_SUCCESS;
	if (!uet_pds_rx_pkt_valid(uet, pkt, rx_pkt_size, &pkt_is_ack))
		goto exit;

	/* find the endpoint the packet is for */
	memset(&match_info, 0, sizeof(struct uet_msg_match_info));
	dst_uet_ep = uet_pds_find_dst_ep(uet, pkt, pkt_is_ack,
					 &match_info);
	if (dst_uet_ep == NULL) {
		if (pkt_is_ack)
			goto exit;
		if (!match_info.ip_addr_match)
			ses_rc = UET_RC_UNDELIVERABLE;
		else if (!match_info.job_id_match)
			ses_rc = UET_RC_BAD_JOB_ID;
		else if (!match_info.pid_on_fep_match)
			ses_rc = UET_RC_BAD_PID;
		else if (!match_info.index_match)
			ses_rc = UET_RC_BAD_INDEX;
		else
			ses_rc = UET_RC_UNDELIVERABLE;
		rc = uet_pds_tx_err_ack_pkt(uet, pkt, ses_rc);
		goto exit;
	}

	pds_tx = &dst_uet_ep->pds.tx;
	ses_upcall = &uet->pds.upcall;

	/* process the packet */
	if (pkt_is_ack) {

		/* packet is ack => process ack */
		if (dst_uet_ep->ep_state == UET_EP_CLOSE_WAIT)
			goto exit;

		if (!uet_pds_ep_tx_active(dst_uet_ep))
			goto exit;

		if (pkt->common.pds.psn != htonl(pds_tx->psn))
			goto exit;

		/* upcall for ses processing */
		rc = ses_upcall->rx_rsp(pds_tx->pkt_parms.tx_pkt_handle,
					pkt, rx_pkt_size);
		if (rc == FI_SUCCESS) {
			/* update seq num for transmission of next packet */
			pds_tx->psn++;
			pds_tx->tx_active = false;
		}
	} else {  /* process message packet */

		/* check if we have received this message pkt before */
		/* (i.e., if ack was dropped)                        */
		if (uet_pds_is_dup_req(dst_uet_ep, pkt, &ack_state)) {
			/* retransmit ack */
			rc = uet_nic_tx_pkt(UET_NIC(uet),
					    (union uet_pkt *) &ack_state->ack,
					    sizeof(struct uet_std_rsp_pkt));
			goto exit;
		}

		/* done if endpoint close wait state */
		if (dst_uet_ep->ep_state == UET_EP_CLOSE_WAIT)
			goto exit;

		/* upcall for ses processing */
		memset(&pds_info, 0, sizeof(struct uet_pds_info));
		pds_info.opsn = pkt->common.pds.psn;
		rc = ses_upcall->rx_req((uet_pkt_handle_t) pkt,
					dst_uet_ep, pkt, rx_pkt_size,
					pds_info, UET_HDR_REQ_STD,
					&rsp_ses_hdr_len, &rsp_next_hdr,
					&rsp_ses_hdr, &gtd_del);
		if (rc == FI_SUCCESS)
			/* transmit ack */
			rc = uet_pds_tx_ack_pkt(dst_uet_ep, pkt, rsp_next_hdr,
						rsp_ses_hdr_len, &rsp_ses_hdr);
	}

exit:
	/* free temp packet buffer and return */
	free(pkt);
	return rc;
}

/* implement endpoint close wait state */
void uet_pds_ep_close_wait(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;
	time_t start_time, now;

	uet_ep->ep_state = UET_EP_CLOSE_WAIT;

	uet = uet_ep->uet_domain->uet;

	/* continue receiving packets for max segment lifetime after */
	/* ep close                                                  */
	/*   - this gives time to retransmit any lost acks,          */
	/*     no other packet rx processing is performed            */
	if (uet_gettime(&start_time)) {
		UET_API_ERR("Aborting endpoint close wait state");
		return;
	}

	while (1) {
		if (uet_gettime(&now)) {
			UET_API_ERR("Aborting endpoint close wait state");
			break;
		}
		if ((now - start_time) > uet->pds.msl)
			break;
		uet_pds_progress_rx(uet);
	}
}

