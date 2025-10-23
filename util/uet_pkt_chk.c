/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <arpa/inet.h>
#include <linux/ip.h>

#include "uet_pkt_chk.h"
#include "uet_log.h"

/* determine if uet packet type is valid */
static bool uet_pds_pkt_type_valid(uint8_t *pkt,
				   size_t pkt_size,
				   bool *pkt_is_ack,
				   bool *pkt_is_rd_rsp,
				   bool *pkt_is_ctrl)
{
	struct uet_sec *sec_hdr;
	struct uet_pds_req *pds_hdr;
	uint16_t pds_type, next_hdr;
	bool pds_req;

	*pkt_is_ack = false;
	*pkt_is_rd_rsp = false;
	*pkt_is_ctrl = false;

	/* TODO: IPv6 support and UDP support */
	pds_hdr = (struct uet_pds_req *)(pkt +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr) +
					 sizeof(struct uet_entropy));

	pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);

	if (pds_type == UET_PDS_TYPE_SECURITY) {
		/* TODO: IPv6 support */
		sec_hdr = (struct uet_sec *)pds_hdr;
		if (ntohl(sec_hdr->type_flags_sdi) & UET_SEC_SP_MASK) {
			pds_hdr = (struct uet_pds_req *)
				      ((uint8_t *)sec_hdr +
				       sizeof(struct uet_sec_ssi));
		} else {
			pds_hdr = (struct uet_pds_req *)
				      ((uint8_t *)sec_hdr +
				       sizeof(struct uet_sec));
		}

		pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
			     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);
	}

	next_hdr = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT);

	switch (pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		pds_req = true;
		break;
	case UET_PDS_TYPE_UUD_REQ:
		/* TODO: unsupported */
		UET_PDS_WARN("UUD_REQ packets not supported");
		return false;
	case UET_PDS_TYPE_ACK:
		pds_req = false;
		next_hdr = UET_HDR_RSP;
		break;
	case UET_PDS_TYPE_ACK_CC:
	case UET_PDS_TYPE_ACK_CCX:
		/* TODO: unsupported */
		UET_PDS_WARN("ACK_CC packets not supported");
		return false;
	case UET_PDS_TYPE_NACK:
		/* TODO: unsupported */
		UET_PDS_WARN("NACK packets not supported");
		return false;
	case UET_PDS_TYPE_CTRL:
		*pkt_is_ctrl = true;
		return true;
	case UET_PDS_TYPE_RUDI_REQ:
	case UET_PDS_TYPE_RUDI_RESP:
		/* TODO: unsupported */
		UET_PDS_WARN("RUDI packets not supported");
		return false;
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
			uint8_t *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp,
			bool *pkt_is_ctrl)
{
	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct iphdr *ipv4 = (struct iphdr *)(eth + 1);

	/* TODO: IPv6 support */

	if (memcmp(eth->h_dest, uet->nic.mac_addr, ETH_ALEN) != 0) {
		UET_PDS_WARN("dest MAC mismatch");
		return false;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		UET_PDS_WARN("not an IPv4 packet");
		return false;
	}

	if (ipv4->version != IPVERSION) {
		UET_PDS_WARN("invalid IPv4 header version");
		return false;
	}

	if (ipv4->ihl != UET_IPV4_IHL_NO_OPTIONS) {
		UET_PDS_WARN("IPv4 header options not supported");
		return false;
	}

	if (ipv4->protocol != uet->uet_ipproto) {
		UET_PDS_WARN("unsupported IP protocol");
		return false;
	}

	if (ipv4->tot_len < htons(uet->nic.min_ip_pkt_size)) {
		UET_PDS_WARN("IPv4 total length too small");
		return false;
	}

	if (ipv4->tot_len > htons((pkt_size - uet->nic.l2_hdr_size))) {
		UET_PDS_WARN("IPv4 total length too large");
		return false;
	}

	if (uet_ipv4_csum(ipv4) != 0) {
		UET_PDS_WARN("IPv4 header checksum invalid");
		return false;
	}

	if (!uet_pds_pkt_type_valid(pkt, pkt_size, pkt_is_ack,
				    pkt_is_rd_rsp, pkt_is_ctrl)) {
		UET_PDS_WARN("invalid UET PDS packet type");
		return false;
	}

	return true;
}

