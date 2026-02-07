/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define IP_PROTO_UET 253 /* Defined in "uet_pkt_hdr.h"! */

#define ETH_PROTO_IPV4 0x0800
#define ETH_PROTO_IPV6 0x86DD

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1); /* resized from userspace before attach */
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

int parse_pkt_is_UET(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return -1;

	if (eth_type == bpf_htons(ETH_PROTO_IPV4)) {
		struct iphdr *iph;
		int ip_type = parse_iphdr(&nh, data_end, &iph);

		if (ip_type < 0)
			return -1;

		if (ip_type == IP_PROTO_UET)
			return 1;

	} else if (eth_type == bpf_htons(ETH_PROTO_IPV6)) {
		struct ipv6hdr *ip6h;
		int ip_type = parse_ip6hdr(&nh, data_end, &ip6h);

		if (ip_type < 0)
			return -1;

		if (ip_type == IP_PROTO_UET)
			return 1;
	}

	return 0;
}


SEC("uet_nic_xdp_sock") int uet_nic_xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	int rc;

	/*
	 * We only want to pick out UET packets. Everything else goes
	 * through the kernel stack.
	 */
	rc = parse_pkt_is_UET(ctx);
	if (rc <= 0)
		return XDP_PASS; /* to kernel stack */

	//bpf_printk("UET pkt");

	/*
	 * A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);

	return XDP_PASS; /* to kernel stack */
}

char LICENSE[] SEC("license") = "GPL v2";

