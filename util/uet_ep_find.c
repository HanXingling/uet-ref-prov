/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include "uet_ep_find.h"

/* determine if pkt is destined for endpoint */
static bool uet_pds_ep_addr_match(struct uet_ep *uet_ep,
				  union uet_pkt *pkt,
				  bool pkt_is_ack,
				  bool pkt_is_rd_rsp,
				  struct uet_msg_match_info *match_info)
{
	uint16_t msg_id, pid_on_fep, index;
	uint32_t job_id;
#if 0
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;
#endif
	struct uet_rx_desc *rx_desc;

	if (ntohl(pkt->common.ipv4.daddr) != uet_ep->ipv4_addr)
		return false;
	match_info->ip_addr_match = true;

	if (pkt_is_ack) {
#if 0
		if (!pds_state->tx.tx_active)
			return false;
#endif

		job_id = ((ntohl(pkt->std_rsp.ses.cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

#if 0
		msg_id = ntohs(pkt->std_rsp.ses.cmn.msg_id);
		if (msg_id != pds_state->tx.pkt_parms.msg_id)
			return false;
		match_info->msg_id_match = true;
#endif
	} else if (pkt_is_rd_rsp) {
		job_id = ((ntohl(pkt->std_rsp_d.ses.cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		match_info->pid_on_fep_match = true;
		match_info->index_match = true;

#if 0
		msg_id = ntohs(pkt->std_rsp_d.ses.cmn.msg_id);
		rx_desc = uet_ep->uet_domain->msg_id_cb.rx_desc[msg_id];
		if (rx_desc == NULL)
			return false;
		if (rx_desc->uet_ep != uet_ep)
			return false;
		match_info->msg_id_match = true;
#endif
	} else {
		job_id = ((ntohl(pkt->std_req.ses.cmn.index_gen_job_id) &
			   UET_SES_REQ_JOB_ID_MASK) >>
			  UET_SES_REQ_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		pid_on_fep = ((ntohs(pkt->std_req.ses.cmn.rsvd_pid_on_fep) &
			       UET_SES_REQ_PID_ON_FEP_MASK) >>
			      UET_SES_REQ_PID_ON_FEP_SHIFT);
		if (pid_on_fep != uet_ep->uet_addr.pid_on_fep)
			return false;
		match_info->pid_on_fep_match = true;

		index = ((ntohs(pkt->std_req.ses.cmn.rsvd_res_index) &
			  UET_SES_REQ_RES_INDEX_MASK) >>
			 UET_SES_REQ_RES_INDEX_SHIFT);
		if (index != uet_ep->uet_addr.start_index)
			return false;
		match_info->index_match = true;
	}

	return true;
}

/* find endpoint that packet is destined for */
struct uet_ep *uet_pds_find_dst_ep(struct uet_instance *uet,
				   union uet_pkt *pkt,
				   bool pkt_is_ack,
				   bool pkt_is_rd_rsp,
				   struct uet_msg_match_info *match_info)
{
	struct dlist_entry *dom_head, *dom_item, *ep_head, *ep_item;
	struct uet_domain *uet_dom;
	struct uet_ep *uet_ep;

	dom_head = &uet->domain_list_head;
	dlist_foreach(dom_head, dom_item) {
		uet_dom = container_of(dom_item, struct uet_domain,
				       domain_list_entry);
		uet_rw_lock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);
		ep_head = &uet_dom->ep_list_head;
		dlist_foreach(ep_head, ep_item) {
			uet_ep = container_of(ep_item, struct uet_ep,
					      ep_list_entry);
			if (uet_pds_ep_addr_match(uet_ep, pkt, pkt_is_ack,
						  pkt_is_rd_rsp, match_info)) {
				uet_rw_unlock(&uet_dom->ep_lock,
					      UET_RW_LOCK_RD_ACCESS);
				return uet_ep;
			}
		}
		uet_rw_unlock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);
	}

	return NULL;
}

