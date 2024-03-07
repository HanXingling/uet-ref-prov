/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Utilities */

#ifndef _UET_UTIL_H_
#define _UET_UTIL_H_

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

int uet_gettime(time_t *time_ms);
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr);
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str);
void uet_print_mac_addr(uint8_t *mac);
void uet_print_ipv4_addr(uint32_t ipv4_addr);
void uet_print_uet_addr(struct uet_addr *uet_addr);
void uet_print_mac_hdr(struct ethhdr *eth);
void uet_print_ipv4_hdr(struct iphdr *ipv4);
void uet_print_uet_hdr(union uet_pkt *pkt);
void uet_print_pkt_hdrs(union uet_pkt *pkt);
size_t uet_roundup_8(size_t val);
uint8_t uet_dscp_to_tos(uint8_t dscp);
uint16_t uet_csum(uint16_t *buf, int cnt);
uint16_t uet_ipv4_csum(struct iphdr *ipv4);
void uet_build_ipv4_hdr(struct iphdr *ipv4, uint32_t dip, uint32_t sip,
			uint16_t tot_len, uint8_t tos);
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac);
void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr);

#endif /* _UET_UTIL_H_ */
