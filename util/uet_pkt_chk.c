/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include "uet_pkt_chk.h"

/* determine if uet packet type is valid */
static bool uet_pds_pkt_type_valid(union uet_pkt *pkt,
				   bool *pkt_is_ack,
				   bool *pkt_is_rd_rsp)
{
	uint16_t pds_type, next_hdr;
	bool pds_req;

	*pkt_is_ack = false;
	*pkt_is_rd_rsp = false;

	pds_type = (ntohs(pkt->common.pds.prlg.type_next_flags) &
		    UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT;
	next_hdr = (ntohs(pkt->common.pds.prlg.type_next_flags) &
		    UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT;

	switch (pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		pds_req = true;
		break;
	case UET_PDS_TYPE_ACK:
		pds_req = false;
		next_hdr = UET_HDR_RSP;
		break;
	default:
		return false;
	}

	switch (next_hdr) {
	case UET_HDR_REQ_SMALL:
	case UET_HDR_REQ_MEDIUM:
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
	case UET_HDR_RSP_DATA:
	case UET_HDR_RSP_DATA_SMALL:
		if (pds_req == false) {
			*pkt_is_ack = true;
			return true;
		}
		*pkt_is_rd_rsp = true;
		return true;
	default:
		break;
	}

	return false;
}

bool uet_pds_rx_pkt_chk(struct uet_instance *uet,
			union uet_pkt *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp)
{
	if (!memcmp(pkt->common.eth.h_dest, uet->nic.mac_addr, ETH_ALEN) &&
	    (pkt->common.eth.h_proto == htons(ETH_P_IP)) &&
	    (pkt->common.ipv4.version == IPVERSION) &&
	    (pkt->common.ipv4.ihl == UET_IPV4_IHL_NO_OPTIONS) &&
	    (pkt->common.ipv4.protocol == uet->uet_ipproto) &&
	    (pkt->common.ipv4.tot_len >= htons(uet->nic.min_ip_pkt_size)) &&
	    (pkt->common.ipv4.tot_len <=
	     htons((pkt_size - uet->nic.l2_hdr_size))) &&
	    (uet_ipv4_csum(&pkt->common.ipv4) == 0) &&
	    (uet_pds_pkt_type_valid(pkt, pkt_is_ack, pkt_is_rd_rsp)))
		return true;

	return false;
}

