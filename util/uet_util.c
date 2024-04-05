/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* UET Utilities */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>

#include "uet_addr.h"
#include "uet_pkt_hdr.h"
#include "uet_util.h"

/* get current time in milliseconds */
int uet_gettime(time_t *time_ms)
{
	struct timespec s;

	if (clock_gettime(CLOCK_REALTIME, &s)) {
		*time_ms = 0;
		return -1;
	}

	*time_ms = ((time_t) (s.tv_sec  * UET_MSEC_PER_SEC)) +
		   ((time_t) (s.tv_nsec / UET_NSEC_PER_MSEC));
	return 0;
}

/* convert mac address to string */
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr)
{
	sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		mac_addr[4], mac_addr[5]);
}

/* convert ipv4 address to string */
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str)
{
	uint32_t net_order;

	net_order = htonl(ipv4_addr);
	inet_ntop(AF_INET, (char *) &net_order, ipv4_addr_str, INET_ADDRSTRLEN);
}

/* print mac address */
void uet_print_mac_addr(uint8_t *mac)
{
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* print ipv4 address */
void uet_print_ipv4_addr(uint32_t ipv4_addr)
{
	printf("%d.%d.%d.%d\n",
	       (ipv4_addr >> 24) & 0xff, (ipv4_addr >> 16) & 0xff,
	       (ipv4_addr >> 8)  & 0xff, ipv4_addr & 0xff);
}

/* print uet address */
void uet_print_uet_addr(struct uet_addr *uet_addr)
{
	char ip_addr_str[INET_ADDRSTRLEN];

	uet_ipv4_addr_to_str(uet_addr->fa.v4, ip_addr_str);

	printf("UET Address\n");
	printf("  IP Address:      %s\n", ip_addr_str);
	printf("  PIDonFEP:        %u\n", uet_addr->pid_on_fep);
	printf("  Index:           %u\n", uet_addr->start_index);
	printf("  Initiator ID:    %u\n", uet_addr->initiator_id);
	printf("  Profiles:      ");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_MIN)
		printf("  AI Min");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_FULL)
		printf("  AI Full");
	if (uet_addr->fep_cap & UET_FEP_CAP_HPC)
		printf("  HPC");
	printf("\n");
}

/* print mac header */
void uet_print_mac_hdr(struct ethhdr *eth)
{
	printf("  MAC Header\n");
	printf("    Destination MAC Addr: ");
	uet_print_mac_addr(eth->h_dest);
	printf("    Source MAC Addr:      ");
	uet_print_mac_addr(eth->h_source);
	printf("    Ethertype:            0x%.4x\n", ntohs(eth->h_proto));
}

/* print ipv4 header */
void uet_print_ipv4_hdr(struct iphdr *ipv4)
{
	printf("  IPv4 Header\n");
	printf("    IP Version:           %u\n", ipv4->version);
	printf("    IHL:                  %u\n", ipv4->ihl);
	printf("    TOS:                  0x%x\n", ipv4->tos);
	printf("    Tot Len:              %u\n", ntohs(ipv4->tot_len));
	printf("    ID:                   %u\n", ntohs(ipv4->id));
	printf("    Frag Offset:          0x%x\n", ntohs(ipv4->frag_off));
	printf("    TTL:                  %u\n", ipv4->ttl);
	printf("    Protocol:             0x%x\n", ipv4->protocol);
	printf("    Checksum:             0x%x\n", ntohs(ipv4->check));
	printf("    Destination Addr:     ");
	uet_print_ipv4_addr(ntohl(ipv4->daddr));
	printf("    Source Addr:          ");
	uet_print_ipv4_addr(ntohl(ipv4->saddr));
}

/* print uet header */
void uet_print_uet_hdr(union uet_pkt *pkt)
{
	uint8_t opcode, gen, rc;
	uint16_t pds_type, next_hdr, index, pid_on_fep;
	uint32_t job_id;
	uint64_t msg_off, payload_len;
	bool eom, som, hd;

	printf("  PDS Header\n");
	pds_type = (ntohs(pkt->common.pds.prlg.type_next_flags) &
		    UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT;
	printf("    PDS Packet Type:      ");
	switch (pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
		printf("ROD Request\n");
		break;
	case UET_PDS_TYPE_ACK:
		printf("ACK\n");
		break;
	default:
		printf("Unknown (0x%x)\n", pds_type);
		return;
	}

	next_hdr = (ntohs(pkt->common.pds.prlg.type_next_flags) &
		    UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT;
	printf("    PDS Next Header:      ");
	switch (next_hdr) {
	case UET_HDR_REQ_STD:
		printf("SES Standard Request\n");
		break;
	case UET_HDR_RSP:
		printf("SES Response\n");
		break;
	case UET_HDR_RSP_DATA:
		printf("SES Response with Data\n");
		break;
	default:
		if (pds_type == UET_PDS_TYPE_ACK) {
			printf("SES Response\n");
			printf("    PDS Code:             %u\n", next_hdr);
			next_hdr = UET_HDR_RSP;
			break;
		}
		printf("Unknown (0x%x)\n", next_hdr);
		return;
	}

	printf("    PDS PSN:              %u\n", ntohl(pkt->common.pds.psn));

	printf("  SES Header\n");
	switch (next_hdr) {
	case UET_HDR_REQ_STD:
		printf("    SES Opcode:           ");
		opcode = ((pkt->std_req.ses.cmn.eom_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		if (pkt->std_req.ses.cmn.eom_opcode & UET_SES_EOM_MASK)
			eom = true;
		else
			eom = false;
		if (pkt->std_req.ses.cmn.ver_flags & UET_SES_REQ_FLAG_SOM)
			som = true;
		else
			som = false;
		if (pkt->std_req.ses.cmn.ver_flags & UET_SES_REQ_FLAG_HD)
			hd = true;
		else
			hd = false;

		switch (opcode) {
		case UET_SEND:
			printf("SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_WRITE:
			printf("WRITE, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_READ:
			printf("READ, SOM = %d, EOM = %d\n", som, eom);
			break;
		default:
			printf("Unknown (0x%x), SOM = %d, EOM = %d\n",
			       opcode, som, eom);
			return;
		}
		printf("    SES Flags:            0x%x\n",
		       pkt->std_req.ses.cmn.ver_flags);
		index = ((ntohs(pkt->std_req.ses.cmn.rsvd_res_index) &
			  UET_SES_REQ_RES_INDEX_MASK) >>
			 UET_SES_REQ_RES_INDEX_SHIFT);
		printf("    SES Index:            %u\n", index);
		job_id = ((ntohl(pkt->std_req.ses.cmn.index_gen_job_id) &
			   UET_SES_REQ_JOB_ID_MASK) >>
			  UET_SES_REQ_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		gen = (uint8_t)((ntohl(pkt->std_req.ses.cmn.index_gen_job_id) &
				 UET_SES_REQ_INDEX_GEN_MASK) >>
				UET_SES_REQ_INDEX_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		pid_on_fep = ((ntohl(pkt->std_req.ses.cmn.rsvd_pid_on_fep) &
			       UET_SES_REQ_PID_ON_FEP_MASK) >>
			      UET_SES_REQ_PID_ON_FEP_SHIFT);
		printf("    SES PIDonFEP:         %u\n", pid_on_fep);
		printf("    SES Message ID:       %u\n",
		       ntohs(pkt->std_req.ses.cmn.msg_id));
		printf("    SES Initiator ID:     %u\n",
		       ntohl(pkt->std_req.ses.initiator));
		printf("    SES Request Length:   %u\n",
		       ntohl(pkt->std_req.ses.req_len));
		printf("    SES Buffer Offset:    %lu\n",
		       ntohll(pkt->std_req.ses.buf_off));
		if (som && hd)
			printf("    SES Header Data:      %lu\n",
			       ntohll(pkt->std_req.ses.cmpl_data));
		else if (!som) {
			msg_off = (ntohll(pkt->std_req.ses.msg_off_payload_len)
				   & UET_SES_REQ_STD_MSG_OFF_MASK) >>
				  UET_SES_REQ_STD_MSG_OFF_SHIFT;
			payload_len =
				(ntohll(pkt->std_req.ses.msg_off_payload_len) &
				 UET_SES_REQ_STD_PAYLOAD_LEN_MASK) >>
				UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT;
			printf("    SES Message Offset:   %lu\n", msg_off);
			printf("    SES Payload Length:   %lu\n", payload_len);
		}
		printf("    SES Match Bits:       0x%lx\n",
		       ntohll(pkt->std_req.ses.match_bits));
		break;
	case UET_HDR_RSP:
		printf("    SES Opcode:           ");
		opcode = ((pkt->std_rsp.ses.cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_RESPONSE:
			printf("RESPONSE\n");
			break;
		default:
			printf("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((pkt->std_rsp.ses.cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printf("    SES Return Code:      %u\n", rc);
		gen = (uint8_t)((ntohl(pkt->std_rsp.ses.cmn.index_gen_job_id) &
				 UET_SES_RSP_INDEX_GEN_MASK) >>
				UET_SES_RSP_INDEX_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(pkt->std_rsp.ses.cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		printf("    SES Message ID:       %u\n",
		       ntohs(pkt->std_rsp.ses.cmn.msg_id));
		printf("    SES Modified Length:  %u\n",
		       ntohl(pkt->std_rsp.ses.mod_len));
		break;
	case UET_HDR_RSP_DATA:
		printf("    SES Opcode:           ");
		opcode = ((pkt->std_rsp_d.ses.cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_RESPONSE_W_DATA:
			printf("RESPONSE WITH DATA\n");
			break;
		default:
			printf("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((pkt->std_rsp_d.ses.cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printf("    SES Return Code:      %u\n", rc);
		gen = (uint8_t)
			((ntohl(pkt->std_rsp_d.ses.cmn.index_gen_job_id) &
			  UET_SES_RSP_INDEX_GEN_MASK) >>
			 UET_SES_RSP_INDEX_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(pkt->std_rsp_d.ses.cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		printf("    SES Message ID:       %u\n",
		       ntohs(pkt->std_rsp_d.ses.cmn.msg_id));
		printf("    SES Modified Length:  %u\n",
		       ntohl(pkt->std_rsp_d.ses.mod_len));
		printf("    SES Message Offset:   %u\n",
		       ntohl(pkt->std_rsp_d.ses.msg_off));
		printf("    SES Payload Length:   %u\n",
		       (ntohl(pkt->std_rsp_d.ses.rsvd_payload_len) &
			UET_SES_RSP_D_PAYLOAD_LEN_MASK) >>
		       UET_SES_RSP_D_PAYLOAD_LEN_SHIFT);
		break;
	default:
		break;
	}
}

/* print packet headers */
void uet_print_pkt_hdrs(union uet_pkt *pkt)

{
	printf("UET Packet Headers\n");
	uet_print_mac_hdr(&pkt->common.eth);
	uet_print_ipv4_hdr(&pkt->common.ipv4);
	uet_print_uet_hdr(pkt);
}

/* round up to next multiple of 8 */
size_t uet_roundup_8(size_t val)
{
	return (((val + 7) >> 3) << 3);
}

/* convert dscp value to ip tos value */
uint8_t uet_dscp_to_tos(uint8_t dscp)
{
	return (dscp << 2);
}

/*
 * compute internet checksum
 *
 * parms:
 *      buf - ptr to buffer that checksum is to be computed over
 *      cnt - number of 16b words in buf
 *
 * returns:
 *      computed checksum
 */
uint16_t uet_csum(uint16_t *buf, int cnt)
{
	unsigned long sum;

	for (sum = 0; cnt > 0; cnt--)
		sum += htons(*(buf)++);
	do {
		sum = ((sum >> 16) + (sum & 0xFFFF));
	} while (sum & 0xFFFF0000);

	return (~sum);
}

/*
 * compute ipv4 header checksum
 *
 * parms:
 *      ipv4 - ptr to ipv4 header for which checksum is to be computed
 *
 * returns:
 *      computed checksum
 */
uint16_t uet_ipv4_csum(struct iphdr *ipv4)
{
	return htons(uet_csum((uint16_t *)ipv4, ipv4->ihl * 2));
}

/*
 * build ipv4 header
 *
 * parms:
 *      ipv4    - ptr to location where ipv4 header is to be built
 *      dip     - destination ipv4 address
 *      sip     - source ipv4 address
 *      tot_len - value for total length field of ipv4 header
 *      tos     - value for tos field of ipv4 header
 */
void uet_build_ipv4_hdr(struct iphdr *ipv4, uint32_t dip, uint32_t sip,
			uint16_t tot_len, uint8_t tos)
{
	ipv4->version = IPVERSION;
	ipv4->ihl = UET_IPV4_IHL_NO_OPTIONS;
	ipv4->tos = tos;
	ipv4->tot_len = htons(tot_len);
	ipv4->id = 0;
	ipv4->frag_off = htons(UET_IPV4_FRAG_OFF_DF);
	ipv4->ttl = IPDEFTTL;
	ipv4->protocol = UET_IPPROTO;
	ipv4->saddr = sip;
	ipv4->daddr = dip;
	ipv4->check = 0;
	ipv4->check = uet_ipv4_csum(ipv4);
}

/*
 * build ethernet header
 *
 * parms:
 *      eth  - ptr to location where ethernet header is to be built
 *      dmac - ptr to destination mac address
 *      smac - ptr to source mac address
 */
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac)
{
	eth->h_proto = htons(ETH_P_IP);
	memcpy(eth->h_dest, dmac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
}

void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr, bool is_tx)
{
	const uint8_t *address = (uint8_t *)pkt;
	const uint8_t *line = address;
	size_t line_size = 16;
	uint64_t offset = 0;
	uint8_t c;
	int i = 0;

	printf("%s addr = 0x%lx / length = %u\n",
	       (is_tx ? "TX -->" : "RX <--"), addr, length);

	printf("%08lu: ", offset);

	while (length-- > 0) {
		printf("%02X ", *address++);

		if (!(++i % line_size) ||
		    ((length == 0) && (i % line_size))) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}

			printf(" | ");	/* right close */

			while (line < address) {
				c = *line++;
				printf("%c", ((c < 33) ||
					      (c > 127) ||
					      (c == 255)) ? 0x2E : c);
			}

			printf("\n");

			if (length > 0) {
				offset += line_size;
				printf("%08lu: ", offset);
			}
		}
	}

	printf("\n");
}
