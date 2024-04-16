/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Utilities */

#ifndef _UET_UTIL_H_
#define _UET_UTIL_H_

#include <stdint.h>
#include <stdbool.h>
#include <rdma/fi_errno.h>

#include "uet_pkt_hdr.h"

#define UET_MSEC_PER_SEC  1000
#define UET_NSEC_PER_MSEC 1000000

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | \
		    htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | \
		    ntohl((x) >> 32))
#endif

#define uet_max(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a > _b ? _a : _b;      \
})

#define uet_min(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a < _b ? _a : _b;      \
})

/* read-write lock data structs */
typedef enum {
	UET_RW_LOCK_RD_ACCESS,
	UET_RW_LOCK_WR_ACCESS
} uet_rw_lock_access_t;

typedef enum {
	UET_RW_LOCK_WR_ACQUIRED_VAL = -1,
	UET_RW_LOCK_IDLE_VAL = 0,
	UET_RW_LOCK_RD_ACQUIRED_VAL = 1,
} uet_rw_lock_val_t;

struct uet_rw_lock {
	uet_rw_lock_val_t val;
};

/* parsed uet packet                                         */
/*   - ptr's to headers can be NULL if header is not present */
struct uet_parsed_pkt {
	uint16_t pkt_len;                  /* total length of received packet */
	void *eth;
	uint16_t eth_len;
	uint16_t ethertype;
	void *ip;                         /* can point to ipv4 or ipv6 header */
	uint16_t ip_len;
	uint8_t ip_protocol;                        /* next protocol after ip */
	void *udp;
	uint16_t udp_len;
	void *sec;                                     /* uet security header */
	uint16_t sec_len;
	void *pds;
	uint16_t pds_len;
	uint16_t entropy;             /* from udp source port or pds_prologue */
	uint8_t pds_type;
	uint8_t next_hdr;        /* identifies format of header following pds */
	void *ses;
	uint16_t ses_len;
	uint8_t ses_opcode;
	uint16_t hdr_len;                              /* total header length */
	void *payload;                                         /* ses payload */
	uint16_t payload_len;
	void *ses_crc;
};

struct uet_instance; /* forward reference */

int uet_gettime(time_t *time_ms);
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr);
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str);
void uet_print_mac_addr(uint8_t *mac);
void uet_print_ipv4_addr(uint32_t ipv4_addr);
void uet_print_uet_addr(struct uet_addr *uet_addr);
void uet_print_mac_hdr(struct ethhdr *eth);
void uet_print_ipv4_hdr(struct iphdr *ipv4);
void uet_print_uet_hdr(struct uet_parsed_pkt *pp);
void uet_print_pkt_hdrs(struct uet_parsed_pkt *pp);
size_t uet_roundup_8(size_t val);
uint8_t uet_dscp_to_tos(uint8_t dscp);
uint16_t uet_csum(uint16_t *buf, int cnt);
uint16_t uet_ipv4_csum(struct iphdr *ipv4);
void uet_build_ipv4_hdr(struct uet_instance *uet, struct iphdr *ipv4,
			uint32_t dip, uint32_t sip, uint16_t tot_len,
			uint8_t tos);
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac);
void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr, bool is_tx);
void uet_rw_lock_wr(struct uet_rw_lock *lock);
void uet_rw_lock(struct uet_rw_lock *lock, uet_rw_lock_access_t access);
void uet_rw_unlock(struct uet_rw_lock *lock, uet_rw_lock_access_t access);
uint16_t uet_get_ses_req_payload_len(struct uet_parsed_pkt *pp,
				     uint16_t max_payload_len);
int uet_parse_pkt(struct uet_instance *uet, void *pkt, size_t pkt_len,
		  struct uet_parsed_pkt *pp);

#endif /* _UET_UTIL_H_ */
