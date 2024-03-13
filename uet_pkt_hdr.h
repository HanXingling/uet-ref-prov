/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Packet Headers */

#ifndef _UET_PKT_HDR_H_
#define _UET_PKT_HDR_H_

#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define UET_IPV4_IHL_NO_OPTIONS	5
#define UET_IPV4_FRAG_OFF_DF	0x4000 /* don't fragment */
#define UET_DSCP_CS0		0
#define UET_DSCP_EF		46
#define UET_IP_DEFAULT_MSG_DSCP UET_DSCP_CS0
#define UET_IP_DEFAULT_ACK_DSCP UET_DSCP_EF
#define UET_IPPROTO		253

#define UET_PACKED __attribute__((__packed__))

/* uet pds packet types */
typedef enum {
	UET_PDS_ROD_REQ = 0x03,
	UET_PDS_ACK     = 0x07,
} uet_pds_pkt_type_t;

/* uet pds ack/nack codes */
typedef enum {
	UET_PDS_CODE_ACK = 0x00,
} uet_pds_code_t;

/* uet next hdr enumeration */
typedef enum {
	UET_HDR_REQ_STD = 0x02, /* standard ses req hdr */
	UET_HDR_RSP     = 0x03, /* ses response */
} uet_next_hdr_t;

/* uet ses request opcodes */
typedef enum {
	UET_WRITE       = 0x01,
	UET_READ        = 0x02,
	UET_SEND        = 0x05,
	UET_TAGGED_SEND = 0x09,
	UET_MSG_ERR     = 0x0f,
} uet_ses_req_opcode_t;

/* uet ses response opcodes */
typedef enum {
	UET_DEFAULT_RESPONSE = 0x00,
	UET_RESPONSE         = 0x01,
	UET_RESPONSE_W_DATA  = 0x02,
} uet_ses_rsp_opcode_t;

/* uet ses response list */
typedef enum {
	UET_EXPECTED = 0x00,
	UET_OVERFLOW = 0x01,
} uet_ses_list_t;

/* uet ses return codes */
typedef enum {
	UET_RC_OK               = 0x00,
	UET_RC_BAD_GENERATION   = 0x01,
	UET_RC_DISABLED         = 0x02,
	UET_RC_DISABLED_GEN     = 0x03,
	UET_RC_NO_MATCH         = 0x05,
	UET_RC_UNSUPPORTED_OP   = 0x06,
	UET_RC_UNSUPPORTED_SIZE = 0x07,
	UET_RC_PERM_VIOLATION   = 0x17,
	UET_RC_OP_VIOLATION     = 0x18,
	UET_RC_BAD_INDEX        = 0x19,
	UET_RC_BAD_PID          = 0x1A,
	UET_RC_BAD_JOB_ID       = 0x1B,
	UET_RC_BAD_ADDR         = 0x1C,
	UET_RC_CANCELLED        = 0x1D,
	UET_RC_UNDELIVERABLE    = 0x1E,
	UET_RC_DROPPED          = 0x1F,
	UET_RC_UNCOR_TRNSNT     = 0x21,
} uet_ses_rc_t;

/* uet pds prologue header */
struct UET_PACKED uet_pds_prolog {
	uint16_t entropy;
#define UET_PDS_TYPE_MASK      0xf000
#define UET_PDS_TYPE_SHIFT     12
#define UET_PDS_FLAGS_MASK     0x0fe0
#define UET_PDS_FLAGS_SHIFT    5
#define UET_PDS_NEXT_HDR_MASK  0x001f
#define UET_PDS_NEXT_HDR_SHIFT 0
#define UET_PDS_CODE_MASK      UET_PDS_NEXT_HDR_MASK
#define UET_PDS_CODE_SHIFT     UET_PDS_NEXT_HDR_SHIFT
	union {
		uint16_t type_flags_next; /* for requests */
		uint16_t type_flags_code; /* for acks */
	};
};

/* uet pds rod/rud request header */
struct UET_PACKED uet_pds_req {
	/* uet pds request flags in prolog */
#define UET_PDS_REQ_FLAGS_NONE		0x00  /* no flags */
#define UET_PDS_REQ_FLAGS_SYN		0x80  /* connection setup request */
#define UET_PDS_REQ_FLAGS_NO_CLR	0x00  /* no clear */
#define UET_PDS_REQ_FLAGS_ORIG_CLR	0x40  /* clear original psn from req */
#define UET_PDS_REQ_FLAGS_CUM_CLR	0x20  /* cumulative clear */
#define UET_PDS_REQ_FLAGS_CC		0x10  /* cc state field present */
#define UET_PDS_REQ_FLAGS_AR		0x08  /* ack requested */
#define UET_PDS_REQ_FLAGS_RETX		0x04  /* this is retransmit */
#define UET_PDS_REQ_FLAGS_RESV		0x02  /* reserved */
	struct uet_pds_prolog prolog;
	uint32_t psn;
	uint16_t spdcid;
	union {
		uint16_t dpdcid;
#define UET_PDS_PDC_MODE_MASK      0xf000
#define UET_PDS_PDC_MODE_SHIFT     12
#define UET_PDS_PSN_OFFSET_MASK    0x0fdd
#define UET_PDS_PSN_OFFSET_SHIFT   0
		uint16_t mode_offset;
	};
};

/* uet pds rod/rud ack header */
struct UET_PACKED uet_pds_ack {
	/* uet pds ack flags in prolog */
#define UET_PDS_RSP_FLAGS_NONE	0x00
	struct uet_pds_prolog prolog;
	uint32_t psn;
	uint16_t spdcid;
	uint16_t dpdcid;
};

/* uet ses standard request header */
struct UET_PACKED uet_ses_std_req {
#define UET_SES_STD_REQ_OPCODE_MASK	0x3f
#define UET_SES_STD_REQ_OPCODE_SHIFT	0
	uint8_t resv_opcode;
#define UET_SES_VER			0
#define UET_SES_STD_REQ_VER_MASK	0xc0
#define UET_SES_STD_REQ_VER_SHIFT	6
#define UET_SES_STD_REQ_DC		0x20
#define UET_SES_STD_REQ_IE		0x10
#define UET_SES_STD_REQ_REL		0x08
#define UET_SES_STD_REQ_RSP		0x04
#define UET_SES_STD_REQ_HD		0x02
#define UET_SES_STD_REQ_SOM		0x01
	uint8_t flags;
#define UET_SES_STD_REQ_INDEX_MASK	0x0fff
#define UET_SES_STD_REQ_INDEX_SHIFT	0
	uint16_t resv_index;
#define UET_SES_GEN_MASK		0xff000000
#define UET_SES_GEN_SHIFT		24
#define UET_SES_JOB_ID_MASK		0x00ffffff
#define UET_SES_JOB_ID_SHIFT		0
	uint32_t gen_jobid;
#define UET_SES_STD_REQ_PID_ON_FEP_MASK		0x00fff
#define UET_SES_STD_REQ_PID_ON_FEP_SHIFT	0
	uint16_t resv_pid_on_fep;
	uint16_t msg_id;
#define UET_SES_STD_REQ_BUF_OFF_MASK		0x01ffffffffffffULL
#define UET_SES_STD_REQ_BUF_OFF_SHIFT		0
	uint64_t resv_buf_off;
	uint32_t initiator;
	uint64_t match;
	/* below defines for hd field are for SOM=0                      */
	/* TODO: exact format of hd for SOM=0 is not defined in SES spec */
#define UET_SES_STD_REQ_HD_MSG_OFF_MASK		0xffffffff00000000ULL
#define UET_SES_STD_REQ_HD_MSG_OFF_SHIFT	32
#define UET_SES_STD_REQ_HD_PAY_LEN_MASK		0x0000000000003fffULL
#define UET_SES_STD_REQ_HD_PAY_LEN_SHIFT	0
	uint64_t hd;
	uint32_t req_len;
};

/* uet ses standard response header */
struct UET_PACKED uet_ses_std_rsp {
#define UET_SES_STD_RSP_OPCODE_MASK	0x3f000000
#define UET_SES_STD_RSP_OPCODE_SHIFT	24
#define UET_SES_STD_RSP_VER_MASK	0x00c00000
#define UET_SES_STD_RSP_VER_SHIFT	22
#define UET_SES_STD_RSP_LIST_MASK	0x00300000
#define UET_SES_STD_RSP_LIST_SHIFT	20
#define UET_SES_STD_RSP_RC_MASK		0x000fc000
#define UET_SES_STD_RSP_RC_SHIFT	14
	uint32_t w0;
	uint32_t gen_jobid;
	uint32_t mod_len;
	uint16_t msg_id;
	uint16_t resv;
};

/* uet standard request packet format */
struct UET_PACKED uet_std_req_pkt {
	struct ethhdr eth;
	struct iphdr ipv4;
	struct uet_pds_req pds;
	struct uet_ses_std_req ses;
	uint8_t payload[];
};

/* uet standard response packet format */
struct UET_PACKED uet_std_rsp_pkt {
	struct ethhdr eth;
	struct iphdr ipv4;
	struct uet_pds_ack pds;
	struct uet_ses_std_rsp ses;
	uint8_t payload[];
};

#define UET_MIN_PKT_SIZE sizeof(struct uet_std_rsp_pkt)

/* uet packet */
union UET_PACKED uet_pkt {
	struct UET_PACKED {
		struct ethhdr eth;
		struct iphdr ipv4;
		struct UET_PACKED {
			struct uet_pds_prolog prolog;
			uint32_t psn;
			uint16_t spdcid;
			uint16_t dpdcid;
		} pds;
	} common;
	struct uet_std_req_pkt std_req;
	struct uet_std_rsp_pkt std_rsp;
};

#endif /* _UET_PKT_HDR_H_ */
