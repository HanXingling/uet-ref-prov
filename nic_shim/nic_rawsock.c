/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* NIC Interface using Raw Sockets */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_nic.h"
#include "uet_api_private.h"

#define UET_NETWORK_TYPE_RAWSOCK "Ethernet(rawsock)"

struct rawsock_data {
	struct pollfd sock_fd;             /* socket file descriptor */
	struct ifreq ifr;	  /* socket interface request struct */
	struct sockaddr_ll sadr;           /* link-level socket addr */
};

/* get nic info for libfabric fid_nic struct */
int nic_rawsock_getinfo(struct uet_nic *nic,
			struct fid_nic *fnic)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;

	int rc;

	/* allocate memory for nic structs */
	fnic->device_attr = calloc(1, sizeof(struct fi_device_attr));
	if (fnic->device_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	fnic->link_attr = calloc(1, sizeof(struct fi_link_attr));
	if (fnic->link_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	/* get interface flags */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFFLAGS, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting interface flags");
		goto err_return;
	}

	/* init nic info */
	fnic->device_attr->name = nic->ifname;
	fnic->link_attr->mtu = nic->mtu;
	fnic->link_attr->network_type = nic->network_type;
	fnic->link_attr->address = nic->mac_addr_str;
	if (rdata->ifr.ifr_flags & IFF_UP)
		fnic->link_attr->state = FI_LINK_UP;
	else
		fnic->link_attr->state = FI_LINK_DOWN;

	return FI_SUCCESS;

err_return:
	if (fnic->device_attr != NULL) {
		free(fnic->device_attr);
		fnic->device_attr = NULL;
	}
	if (fnic->link_attr != NULL) {
		free(fnic->link_attr);
		fnic->link_attr = NULL;
	}
	return rc;
}

/* get next-hop info for ipv4 destination address */
int nic_rawsock_get_ipv4_nh(struct uet_nic *nic,
			    uint32_t dst_ip,
			    uint8_t *mac)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];
	int i, rc;
	uint32_t net_order;
	FILE *cmd_stream;
	struct in_addr nh_ipv4;
	struct arpreq areq;
	struct sockaddr_in *sin;
	uint8_t invalid_mac[ETH_ALEN];

	/* convert ipv4 addr to string */
	net_order = htonl(dst_ip);
	inet_ntop(AF_INET, (char *) &net_order, nic->dst_ip_addr_str,
		  INET_ADDRSTRLEN);

	/* find next-hop ipv4 address */
	strcpy(sys_cmd, "ip route get to ");
	strcat(sys_cmd, nic->dst_ip_addr_str);
	strcat(sys_cmd, " oif ");
	strcat(sys_cmd, nic->ifname);
	cmd_stream = popen(sys_cmd, "r");
	if (cmd_stream == NULL) {
		UET_API_PRINT_ERRNO("popen");
		UET_API_ERR("Error getting next-hop IP address");
		pclose(cmd_stream);
		return -FI_EIO;
	}
	for (i = 0; i < INET_ADDRSTRLEN; i++) {
		nic->nh_ip_addr_str[i] = getc(cmd_stream);
		if (isspace((int) nic->nh_ip_addr_str[i])) {
			nic->nh_ip_addr_str[i] = '\0';
			break;
		}
	}
	if (i == INET_ADDRSTRLEN) {
		UET_API_ERR("Error parsing next-hop IP address");
		pclose(cmd_stream);
		return -FI_EIO;
	}
	inet_pton(AF_INET, nic->nh_ip_addr_str, &nh_ipv4);
	pclose(cmd_stream);

	/* delete any entry for next-hop already in arp cache */
	/*  - to handle case where the entry is associated    */
	/*    with a different interface                      */
	strcpy(sys_cmd, "arp -d ");
	strcat(sys_cmd, nic->nh_ip_addr_str);
	strcat(sys_cmd, " 2> /dev/null 1> /dev/null");
	system(sys_cmd);

	/* ping next hop to load arp cache using our interface */
	strcpy(sys_cmd, "ping -c 1 -I ");
	strcat(sys_cmd, nic->ifname);
	strcat(sys_cmd, " ");
	strcat(sys_cmd, nic->nh_ip_addr_str);
	strcat(sys_cmd, " 2> /dev/null 1> /dev/null");
	system(sys_cmd);

	/* read next-hop mac address from arp cache */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_port = UET_IPPROTO;
	sin->sin_addr = nh_ipv4;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;
	strcpy(areq.arp_dev, nic->ifname);
	if (ioctl(rdata->sock_fd.fd, SIOCGARP, (caddr_t) &areq) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting ARP entry");
		return -FI_EIO;
	}
	memcpy(mac, areq.arp_ha.sa_data, ETH_ALEN);

	rc = FI_SUCCESS;
	memset(invalid_mac, 0, ETH_ALEN);
	if (memcmp(mac, invalid_mac, ETH_ALEN) == 0) {
		UET_API_ERR("Unable to resolve next-hop MAC addr");
		rc = -FI_ENETUNREACH;
	}

	printf("Next-Hop Address Resolution\n");
	printf("  Destination IPv4 Addr: %s\n", nic->dst_ip_addr_str);
	printf("  Next-Hop IPv4 Addr:    %s\n", nic->nh_ip_addr_str);
	printf("  Next-Hop MAC Addr:     ");
	uet_print_mac_addr(mac);

	return rc;
}

/* transmit a packet */
int nic_rawsock_tx_pkt(struct uet_nic *nic,
		       union uet_pkt *pkt,
		       size_t pkt_size)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	size_t len;

	memcpy(rdata->sadr.sll_addr, pkt->common.eth.h_dest, ETH_ALEN);

	pkt->common.ipv4.check = 0;
	pkt->common.ipv4.check = uet_ipv4_csum(&pkt->common.ipv4);

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump((void *)pkt, pkt_size, 0, true);
#endif

	len = sendto(rdata->sock_fd.fd, pkt, pkt_size, 0,
		     (const struct sockaddr *)&rdata->sadr,
		     sizeof(struct sockaddr_ll));
	if (len != pkt_size) {
		if (len == -1)
			UET_API_PRINT_ERRNO("sendto");
		else
			UET_API_ERR("Error transmitting packet, "
				    "sent %ld of %ld bytes",
				    len, pkt_size);
		return -FI_EIO;
	}

	return FI_SUCCESS;
}

/* receive a packet */
int nic_rawsock_rx_pkt(struct uet_nic *nic,
		       union uet_pkt *pkt,
		       size_t pkt_buf_size,
		       size_t *rx_pkt_size)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	size_t len;

	len = recvfrom(rdata->sock_fd.fd, pkt, pkt_buf_size, 0, NULL, NULL);
	if (len == -1) {
		UET_API_PRINT_ERRNO("recvfrom");
		return -FI_EIO;
	} else if (len > pkt_buf_size) {
		UET_API_DEBUG("Error receiving packet: too big: "
			      "%ld bytes", len);
		return 0;
	} else if (len < nic->min_pkt_size) {
		UET_API_DEBUG("Error receiving packet: too small: "
			      "%ld bytes", len);
		return 0;
	}

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump((void *)pkt, len, 0, false);
#endif

	*rx_pkt_size = len;
	return 1;
}

/* poll to determine if rx packet is available */
int nic_rawsock_rx_poll(struct uet_nic *nic)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	int ret;

	/* check if packet is available */
	ret = poll(&rdata->sock_fd, 1, 0);
	switch (ret) {
	case 0:
		return 0;
	case 1:
		if (rdata->sock_fd.revents & POLLIN)
			return 1;
		return 0;
	case -1:
		UET_API_PRINT_ERRNO("poll");
		return -FI_EIO;
	default:
		break;
	}

	UET_API_ERR("unexpected val from poll: %d", ret);
	return -FI_EIO;
}

/* register memory region with nic */
int nic_rawsock_mr_reg(struct uet_nic *nic,
		       struct uet_mr_buf_desc *desc,
		       uet_nic_mr_handle_t *handle)
{
	if (desc->type != UET_MR_BUF_TYPE_CONTIG) {
		UET_API_ERR("MR reg only supported for contiguous buf type");
		return -FI_EINVAL;
	}

	desc->contig.dma_addr = desc->contig.buf;
	return FI_SUCCESS;
}

/* deregister memory region that was registered with nic */
int nic_rawsock_mr_dereg(struct uet_nic *nic,
			 uet_nic_mr_handle_t handle)
{
	return FI_SUCCESS;
}

/* free nic resources */
void nic_rawsock_finalize(struct uet_nic *nic)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;

	if (!rdata)
		return;

	if (rdata->sock_fd.fd != -1) {
		close(rdata->sock_fd.fd);
		rdata->sock_fd.fd = -1;
	}

	free(rdata);
	nic->nic_priv_data = NULL;
}

/* init nic resources */
int nic_rawsock_initialize(struct uet_nic *nic)
{
	struct rawsock_data *rdata = NULL;
	int rc;
	char *ifname, *ip;

	nic->min_pkt_size = UET_MIN_PKT_SIZE;
	nic->l2_hdr_size = sizeof(struct ethhdr);
	nic->min_ip_pkt_size = (nic->min_pkt_size - nic->l2_hdr_size);

	rdata = calloc(1, sizeof(struct rawsock_data));
	if (rdata == NULL) {
		UET_API_ERR("ERROR: Failed to alloc RAWSOCK priv data");
		return -FI_ENOMEM;
	}

	nic->nic_priv_data = (void *)rdata;
	rdata->sock_fd.fd = -1;

	strncpy(nic->network_type, UET_NETWORK_TYPE_RAWSOCK,
		UET_NET_TYPE_SIZE);

	/* get interface name from environment variable */
	ifname = getenv(UET_IFNAME);
	if (ifname == NULL) {
		UET_API_ERR("err reading UET_IFNAME environment variable");
		rc = -FI_ENODEV;
		goto err_return;
	}

	strncpy(nic->ifname, ifname, IFNAMSIZ);

	/* open transport raw socket */
	rdata->sock_fd.fd = socket(AF_PACKET, SOCK_RAW, ETH_P_IP);
	if (rdata->sock_fd.fd == -1) {
		UET_API_PRINT_ERRNO("socket");
		rc = -FI_EIO;
		goto err_return;
	}
	rdata->sock_fd.events = POLLIN;

	/* get index of interface */
	strcpy(rdata->ifr.ifr_name, nic->ifname);
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFINDEX, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("bad interface device name");
		rc = -FI_ENODEV;
		goto err_return;
	}

	/* init link-level socket addr struct and bind to socket */
	rdata->sadr.sll_family   = AF_PACKET;
	rdata->sadr.sll_ifindex  = rdata->ifr.ifr_ifindex;
	rdata->sadr.sll_halen    = ETH_ALEN;
	rdata->sadr.sll_protocol = htons(ETH_P_IP);

	if (bind(rdata->sock_fd.fd, (struct sockaddr *) &rdata->sadr,
		 sizeof(struct sockaddr_ll)) < 0) {
		UET_API_PRINT_ERRNO("socket bind");
		rc = -FI_EIO;
		goto err_return;
	}

	/* get ipv4 address of interface */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFADDR, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting IP address of local device");
		rc = -FI_EIO;
		goto err_return;
	}
	ip = &rdata->ifr.ifr_hwaddr.sa_data[2];
	nic->ipv4_addr = ntohl(*((uint32_t *) ip));
	inet_ntop(AF_INET, ip, nic->ip_addr_str, INET_ADDRSTRLEN);

	/* get mac address of interface */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFHWADDR, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting MAC addr of local device");
		rc = -FI_EIO;
		goto err_return;
	}
	memcpy(nic->mac_addr, rdata->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	uet_mac_addr_to_str(nic->mac_addr_str, nic->mac_addr);

	/* get MTU of interface */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFMTU, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting MTU of local device");
		goto err_return;
	}
	nic->mtu = (size_t)rdata->ifr.ifr_mtu;
	nic->max_pkt_size = (nic->mtu + nic->l2_hdr_size);

	return FI_SUCCESS;

err_return:
	nic_rawsock_finalize(nic);
	return rc;
}

