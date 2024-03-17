/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* AF_XDP NIC Interface for UET API's */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <sys/resource.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_nic.h"
#include "uet_api_private.h"

#define STRINGIZEIT(x) STRINGIZE(x)
#define STRINGIZE(x) #x

#define UET_NETWORK_TYPE_XDP "Ethernet(xdp)"

#ifndef XDP_PKT_CONTD /* should be in "linux/if_xdp.h" */
#define XDP_PKT_CONTD (1 << 0)
#endif

/*
 * NUM_FAMES >= (MAX_FILL_SIZE + MAX_TX_SIZE)
 * RX_SIZE   >= (MAX_FILL_SIZE)
 * COMP_SIZE >= (MAX_TX_SIZE)
 *
 * BATCH_SIZE <= MAX_FILL_SIZE
 * BATCH_SIZE <= MAX_TX_SIZE
 */

#define MAX_FILL_SIZE XSK_RING_PROD__DEFAULT_NUM_DESCS /* default=2048 */
#define MAX_TX_SIZE   XSK_RING_PROD__DEFAULT_NUM_DESCS
#define MAX_RX_SIZE   MAX_FILL_SIZE
#define MAX_COMP_SIZE MAX_TX_SIZE

#define NUM_FRAMES (MAX_FILL_SIZE + MAX_TX_SIZE)

#define BATCH_SIZE 64
#if (BATCH_SIZE > MAX_FILL_SIZE) || (BATCH_SIZE > MAX_TX_SIZE)
#error "Invalid BATCH_SIZE!"
#endif

#define MIN_PKT_SIZE UET_MIN_PKT_SIZE
#define MAX_PKT_SIZE 9728 /* Max frame size supported by many NICs */

//#define TX_PKT_SIZE MIN_PKT_SIZE

#define XSK_FRAME_SIZE 2048 // XSK_UMEM__DEFAULT_FRAME_SIZE
#define FRAMES_PER_PKT 1 // (((TX_PKT_SIZE - 1) / XSK_FRAME_SIZE) + 1)

struct xsk_umem_info {
	struct xsk_ring_prod fq; /* Rx Fill producer ring */
	struct xsk_ring_cons cq; /* Tx Completion consumer ring */
	struct xsk_umem *umem;
	void *buffer;
	uint32_t buffer_size;
};

struct xsk_socket_info {
	bool created;
	struct xsk_ring_cons rx; /* Rx consumer ring */
	struct xsk_ring_prod tx; /* Tx producer ring */
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	//struct xsk_ring_stats ring_stats;
	//struct xsk_app_stats app_stats;
	//struct xsk_driver_stats drv_stats;
	uint32_t outstanding_tx;
};

struct xdp_data {
#define MAX_SOCKS 4
	struct xsk_socket_info *xsks[MAX_SOCKS];
	uint32_t next_frame[MAX_SOCKS]; /* for Tx */
	int num_socks; /* or MAX_SOCKS */

	struct xdp_program *xdp_prog;
	int xdp_ifindex;

	int xdp_rx_queue;

	void *mem;
	int mem_size;
	struct xsk_umem_info *umem;

	int sock_fd;
};

/* get nic info for libfabric fid_nic struct */
int nic_xdp_getinfo(struct uet_nic *nic,
		    struct fid_nic *fnic)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	struct ifreq ifr;	  /* socket interface request struct */
	int rc;

	/* allocate memory for nic structs */
	fnic->device_attr = calloc(1, sizeof(struct fi_device_attr));
	if (fnic->device_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto exit_err;
	}

	fnic->link_attr = calloc(1, sizeof(struct fi_link_attr));
	if (fnic->link_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto exit_err;
	}

	/* get the interface flags */
	strcpy(ifr.ifr_name, nic->ifname);
	if ((ioctl(xdata->sock_fd, SIOCGIFFLAGS, &ifr)) < 0) {
		UET_API_ERR("ERROR: Failed to get interface flags");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* init from the NIC info */
	fnic->device_attr->name       = nic->ifname;
	fnic->link_attr->mtu          = nic->mtu;
	fnic->link_attr->network_type = nic->network_type;
	fnic->link_attr->address      = nic->mac_addr_str;

	if (ifr.ifr_flags & IFF_UP)
		fnic->link_attr->state = FI_LINK_UP;
	else
		fnic->link_attr->state = FI_LINK_DOWN;

	return FI_SUCCESS;

exit_err:

	if (fnic->device_attr) {
		free(fnic->device_attr);
		fnic->device_attr = NULL;
	}

	if (fnic->link_attr) {
		free(fnic->link_attr);
		fnic->link_attr = NULL;
	}

	return rc;
}

/* get next-hop info for ipv4 destination address */
int nic_xdp_get_ipv4_nh(struct uet_nic *nic,
			uint32_t dst_ip,
			uint8_t *mac)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];
	int i, rc;
	uint32_t net_order;
	FILE *cmd_stream;
	struct in_addr nh_ipv4;
	struct arpreq areq;
	struct sockaddr_in *sin;
	uint8_t invalid_mac[ETH_ALEN];

	/* convert IP addr to a string */
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
		UET_API_ERR("ERROR: Failed to get next-hop IP address");
		pclose(cmd_stream);
		return -FI_EIO;
	}

	for (i = 0; i < INET_ADDRSTRLEN; i++) {
		nic->nh_ip_addr_str[i] = getc(cmd_stream);
		if (isspace((int)nic->nh_ip_addr_str[i])) {
			nic->nh_ip_addr_str[i] = '\0';
			break;
		}
	}

	if (i == INET_ADDRSTRLEN) {
		UET_API_ERR("ERROR: Failed to parse next-hop IP address");
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
	sin = (struct sockaddr_in *)&areq.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_port = UET_IPPROTO;
	sin->sin_addr = nh_ipv4;
	sin = (struct sockaddr_in *)&areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;
	strcpy(areq.arp_dev, nic->ifname);
	if (ioctl(xdata->sock_fd, SIOCGARP, (caddr_t)&areq) < 0) {
		UET_API_ERR("ERROR: Failed getting ARP entry");
		return -FI_EIO;
	}
	memcpy(mac, areq.arp_ha.sa_data, ETH_ALEN);

	rc = FI_SUCCESS;
	memset(invalid_mac, 0, ETH_ALEN);
	if (memcmp(mac, invalid_mac, ETH_ALEN) == 0) {
		UET_API_ERR("ERROR: Failed to resolve next-hop MAC addr");
		rc = -FI_ENETUNREACH;
	}

	printf("Next-Hop Address Resolution\n");
	printf("  Destination IPv4 Addr: %s\n", nic->dst_ip_addr_str);
	printf("  Next-Hop IPv4 Addr:    %s\n", nic->nh_ip_addr_str);
	printf("  Next-Hop MAC Addr:     ");
	uet_print_mac_addr(mac);

	return rc;
}

static inline void nic_xdp_tx_complete(struct xsk_socket_info *xsk,
				       int batch_size)
{
	uint32_t rcvd, idx;
	int ret;

	if (!xsk->outstanding_tx) /* nothing to complete */
		return;

	/* Complete as many as available, up to the batch_size. */
	batch_size = xsk_cons_nb_avail(&xsk->umem->cq, batch_size);

	/* Kick the Tx ring. */
	if (xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0,
			     MSG_DONTWAIT, NULL, 0);
		if ((ret < 0) &&
		    (errno != ENOBUFS) &&
		    (errno != EAGAIN) &&
		    (errno != EBUSY) &&
		    (errno != ENETDOWN)) {
			assert(0); /* wtf, this is bad */
		}
	}

	/* Get the number of available completions, up to the batch_size. */
	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		/* Update the consumer of the completion ring. */
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);

		/* Decrement the number of un-completed Tx entries. */
		xsk->outstanding_tx -= rcvd;
	}
}

/* transmit a packet */
int nic_xdp_tx_pkt(struct uet_nic *nic,
		   union uet_pkt *pkt,
		   size_t pkt_size)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	struct xsk_socket_info *xsk;
	struct xdp_desc *tx_desc;
	uint8_t *xdp_pkt_data;
	uint32_t idx;
	size_t len;

	/* XXX only one XSK socket for now... */
	xsk = xdata->xsks[0];

	/* Reserve an entry on the Tx ring. */
	while (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) < 1) {
		/* Not enough slots available, process pending completions. */
		nic_xdp_tx_complete(xsk, BATCH_SIZE);
	}

	if (pkt_size > XSK_FRAME_SIZE)
		return -FI_EIO;

	/* Get the desc at the next Tx ring producer index. */
	tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);

	/* Set the frame addr in the descriptor. */
	tx_desc->addr    = (xdata->next_frame[0] * XSK_FRAME_SIZE);
	tx_desc->len     = pkt_size;
	tx_desc->options = 0;

	xdp_pkt_data = xsk_umem__get_data(xsk->umem->buffer, tx_desc->addr);
	memcpy(xdp_pkt_data, pkt, pkt_size);

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump(xdp_pkt_data, tx_desc->len, tx_desc->addr, true);
#endif

	xdata->next_frame[0] = ((xdata->next_frame[0] + 1) % NUM_FRAMES);

	/* Submit the newly added packet into the Tx ring. */
	xsk_ring_prod__submit(&xsk->tx, 1);

	/* Increment the number of un-completed Tx entries. */
	xsk->outstanding_tx += 1;

	/* Process any outstanding completions... */
	nic_xdp_tx_complete(xsk, BATCH_SIZE);

	return FI_SUCCESS;
}

/* receive a packet */
int nic_xdp_rx_pkt(struct uet_nic *nic,
		   union uet_pkt *pkt,
		   size_t pkt_buf_size,
		   size_t *rx_pkt_size)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	struct xsk_socket_info *xsk;
	const struct xdp_desc *desc;
	uint32_t rx_cnt, idx_rx, idx_fq;
	uint64_t orig_addr;
	uint8_t *xdp_pkt_data;
	int i, ret;

	size_t len;

	for (i = 0; i < xdata->num_socks; i++) {
		xsk = xdata->xsks[i];

		/* Get the first available Rx packet. */
		rx_cnt = xsk_ring_cons__peek(&xsk->rx, 1, &idx_rx);
		if (!rx_cnt)
			continue;

		/* Reserve one packet from the fill queue. */
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1, &idx_fq);
		while (ret != 1) {
			if (ret < 0)
				return 0; /* Something is very wrong... */

			/*
			 * If the required number of slots wasn't avaiable,
			 * kick the Fill ring and retry.
			 */
			if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0,
					 MSG_DONTWAIT, NULL, NULL);
			}

			/* Again, reserve the number of slots in the Fill ring. */
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, 1,
						     &idx_fq);
		}

		/*
		 * Process the packet...
		 * For now the packet data is copied out from the frame.
		 */

		desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx);

		/* Get the frame addr from the desc. */
		orig_addr = xsk_umem__extract_addr(desc->addr);

		assert(!(desc->options & XDP_PKT_CONTD)); /* not supported */

		xdp_pkt_data = xsk_umem__get_data(
			xsk->umem->buffer,
			xsk_umem__add_offset_to_addr(desc->addr));

		if (desc->len > pkt_buf_size) {
			UET_API_DEBUG("ERROR Rx: pkt too big: %u bytes",
				      desc->len);
			return 0;
		} else if (desc->len < nic->min_pkt_size) {
			UET_API_DEBUG("ERROR Rx: pkt too small: %u bytes",
				      desc->len);
			return 0;
		}

		*rx_pkt_size = desc->len;
		memcpy(pkt, xdp_pkt_data, desc->len);

#ifdef UET_NIC_DEBUG_HEXDUMP
		uet_pkt_hex_dump(pkt, desc->len, orig_addr, false);
#endif

		/* Push the addr back at the current Fill index. */
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig_addr;

		/* Submit the newly added frame into the Fill ring. */
		xsk_ring_prod__submit(&xsk->umem->fq, 1);

		/* Update the consumer of the Rx ring with 1 packet processed. */
		xsk_ring_cons__release(&xsk->rx, 1);

		return 1; /* done, a packet was processed */
	}

	return 0; /* No packets are available! */
}

/* poll to determine if rx packet is available */
int nic_xdp_rx_poll(struct uet_nic *nic)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	struct xsk_socket_info *xsk;
	uint32_t rx_cnt, idx_rx;
	int i;

	for (i = 0; i < xdata->num_socks; i++) {
		xsk = xdata->xsks[i];

		/* Get the count of available Rx pkts up to BATCH_SIZE. */
		rx_cnt = xsk_cons_nb_avail(&xsk->rx, BATCH_SIZE);
		if (rx_cnt)
			return 1; /* At least one packet waiting! */

		/* If nothing is available kick the Rx ring. */
		if (xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0,
				 MSG_DONTWAIT, NULL, NULL);
		}
	}

	return 0;
}

/* register memory region with nic */
int nic_xdp_mr_reg(struct uet_nic *nic,
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
int nic_xdp_mr_dereg(struct uet_nic *nic,
		     uet_nic_mr_handle_t handle)
{
	return FI_SUCCESS;
}

static struct xsk_umem_info *nic_xdp_xsk_configure_umem(void *mem,
							uint64_t mem_size)
{
	int ret;
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		.fill_size      = MAX_FILL_SIZE,
		.comp_size      = MAX_COMP_SIZE,
		.frame_size     = XSK_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags          = XSK_UMEM__DEFAULT_FLAGS,
	};

	umem = calloc(1, sizeof(*umem));
	if (umem == NULL)
		return NULL;

	/* Create the XSK umem. */
	ret = xsk_umem__create(&umem->umem, mem, mem_size,
			       &umem->fq, &umem->cq, &cfg);
	if (ret) {
		free(umem);
		return NULL;
	}

	umem->buffer      = mem;
	umem->buffer_size = mem_size;

	return umem;
}

static int nic_xdp_xsk_init_fill_ring(struct xsk_umem_info *umem)
{
	int rc, i;
	uint32_t idx;

	/* Reserve entries to fill the entire Fill ring. */
	rc = xsk_ring_prod__reserve(&umem->fq, MAX_FILL_SIZE, &idx);
	if (rc != MAX_FILL_SIZE)
		return -1;

	/* Set the frame address for each of the Fill ring entries. */
	for (i = 0; i < MAX_FILL_SIZE; i++) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			(i * XSK_FRAME_SIZE);
	}

	/* Submit the newly added number of frames into the Fill ring. */
	xsk_ring_prod__submit(&umem->fq, MAX_FILL_SIZE);

	return 0;
}

static struct xsk_socket_info *nic_xdp_xsk_create_socket(
	struct xsk_umem_info *umem,
	int xdp_rx_queue,
	char *ifname)
{
	struct xsk_socket_info *xsk;
	int rc;

	struct xsk_socket_config cfg = {
		.rx_size      = MAX_RX_SIZE,
		.tx_size      = MAX_TX_SIZE,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags    = XDP_FLAGS_DRV_MODE,
		.bind_flags   = XDP_USE_NEED_WAKEUP,
	};

	xsk = calloc(1, sizeof(*xsk));
	if (xsk == NULL)
		return NULL;

	xsk->umem = umem;

	/* Create the AF_XDP socket. */
	rc = xsk_socket__create(&xsk->xsk, ifname, xdp_rx_queue,
				umem->umem, &xsk->rx, &xsk->tx, &cfg);
	if (rc) {
		free(xsk);
		return NULL;
	}

	return xsk;
}

static int nic_xdp_get_xsks_map(int prog_fd)
{
	uint32_t i, *map_ids, num_maps;
	uint32_t prog_len = sizeof(struct bpf_prog_info);
	uint32_t map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	memset(&prog_info, 0, prog_len);

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (map_ids == NULL)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break; /* found it */
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}

static int nic_xdp_config_xsks_map(struct xdp_data *xdata)
{
	int i, fd, rc;
	int xsks_map;
	int key;

#if 0
	/* Set "num_socks" in the kernel program, dynamic update! */
	struct bpf_map *data_map;

	data_map = bpf_object__find_map_by_name(
		xdp_program__bpf_obj(xdata->xdp_prog), ".bss");
	if (!data_map || !bpf_map__is_internal(data_map)) {
		UET_API_ERR("ERROR: Failed to find bss map");
		return -1;
	}

	if (bpf_map_update_elem(bpf_map__fd(data_map), &key,
				&xdata->num_socks, BPF_ANY)) {
		UET_API_ERR("ERROR: Failed to update num_socks");
		return -1;
	}
#endif

	xsks_map = nic_xdp_get_xsks_map(xdp_program__fd(xdata->xdp_prog));
	if (xsks_map < 0)
		return -1;

	for (i = 0; i < xdata->num_socks; i++) {
		fd = xsk_socket__fd(xdata->xsks[i]->xsk);
		key = i;

		rc = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (rc)
			return -1;
	}

	return 0;
}

/* free nic resources */
void nic_xdp_finalize(struct uet_nic *nic)
{
	struct xdp_data *xdata = (struct xdp_data *)nic->nic_priv_data;
	int i;

	if (!xdata)
		return;

	if (xdata->sock_fd != -1)
		close(xdata->sock_fd);

	for (i = 0; i < xdata->num_socks; i++) {
		if (xdata->xsks[i]) {
			xsk_socket__delete(xdata->xsks[i]->xsk);
			free(xdata->xsks[i]);
		}
	}

	if (xdata->umem) {
		xsk_umem__delete(xdata->umem->umem);
		free(xdata->umem);
	}

	if (xdata->mem)
		munmap(xdata->mem, xdata->mem_size);

	xdp_program__detach(xdata->xdp_prog, xdata->xdp_ifindex,
			    XDP_MODE_NATIVE, 0);

	free(xdata);
	nic->nic_priv_data = NULL;
}

/* init nic resources */
int nic_xdp_initialize(struct uet_nic *nic)
{
	char err_msg[1024];
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	struct sched_param schparam;
	struct xdp_data *xdata = NULL;
	pthread_t p_rx_thr, p_tx_thr;
	struct ifreq ifr;	  /* socket interface request struct */
	int i, rc, mem_size;
	char *ifname;
	char *ip;

	/* Make sure we can abuse memory usage! */
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		UET_API_ERR("ERROR: setrlimit(RLIMIT_MEMLOCK)");
		return -FI_ENODEV;
	}

	/* Configure sched priority for better wake-up accuracy */
	memset(&schparam, 0, sizeof(schparam));
	schparam.sched_priority = 0; /* default SCHED_OTHER */
	rc = sched_setscheduler(0, SCHED_OTHER, &schparam);
	if (rc) {
		UET_API_ERR("ERROR: Failed to set scheduler priority");
		return -FI_ENODEV;
	}

	xdata = calloc(1, sizeof(struct xdp_data));
	if (xdata == NULL) {
		UET_API_ERR("ERROR: Failed to alloc XDP priv data");
		return -FI_ENODEV;
	}

	nic->nic_priv_data = (void *)xdata;
	xdata->num_socks    = 1;
	xdata->xdp_rx_queue = 0;
	xdata->xdp_prog     = NULL;
	xdata->xdp_ifindex  = -1;
	xdata->sock_fd      = -1;

	/* get interface name from environment variable */
	ifname = getenv(UET_IFNAME);
	if (ifname == NULL) {
		UET_API_ERR("ERROR: unknown UET_IFNAME environment variable");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	strncpy(nic->ifname, ifname, IFNAMSIZ);

	strncpy(nic->network_type, UET_NETWORK_TYPE_XDP, UET_NET_TYPE_SIZE);

	xdata->xdp_ifindex = if_nametoindex(nic->ifname);
	if (!xdata->xdp_ifindex) {
		UET_API_ERR("ERROR: Interface %s does not exist",
			    nic->ifname);
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* Load the XDP program from the object file. */
	xdata->xdp_prog = xdp_program__open_file(STRINGIZEIT(XDP_PROG), NULL, NULL);
	rc = libxdp_get_error(xdata->xdp_prog);
	if (rc) {
		libxdp_strerror(rc, err_msg, sizeof(err_msg));
		UET_API_ERR("ERROR: Failed to load XDP program: %s", err_msg);
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* Attach the XDP program to the interface (NATIVE only!). */
	rc = xdp_program__attach(xdata->xdp_prog, xdata->xdp_ifindex,
				 XDP_MODE_NATIVE, 0);
	if (rc) {
		libxdp_strerror(rc, err_msg, sizeof(err_msg));
		UET_API_ERR("ERROR: Failed to attach XDP program: %s", err_msg);
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* Reserve/allocate the memory for the umem. */
	xdata->mem_size = (NUM_FRAMES * XSK_FRAME_SIZE);

	xdata->mem = mmap(NULL, xdata->mem_size,
			  (PROT_READ | PROT_WRITE),
			  (MAP_PRIVATE | MAP_ANONYMOUS),
			  -1, 0);
	if (xdata->mem == MAP_FAILED) {
		xdata->mem = NULL;
		UET_API_ERR("ERROR: mmap failed");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* Allocate the XSK umem. */
	xdata->umem = nic_xdp_xsk_configure_umem(xdata->mem,
						 xdata->mem_size);
	if (xdata->umem == NULL) {
		UET_API_ERR("ERROR: Failed to configure XSK umem");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	/* Rx, fill up the fill ring by posting receive buffers. */
	rc = nic_xdp_xsk_init_fill_ring(xdata->umem);
	if (rc < 0) {
		UET_API_ERR("ERROR: Failed to fill the fill ring");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	for (i = 0; i < xdata->num_socks; i++) {
		xdata->xsks[i] =
			nic_xdp_xsk_create_socket(xdata->umem,
						  xdata->xdp_rx_queue,
						  nic->ifname);
		if (xdata->xsks[i] == NULL) {
			UET_API_ERR("ERROR: Failed to create XSK socket");
			rc = -FI_ENODEV;
			goto exit_err;
		}
	}

	/* Rx, set the socket fds in the XDP program xsks map. */
	rc = nic_xdp_config_xsks_map(xdata);
	if (rc < 0) {
		UET_API_ERR("ERROR: Failed to configure XSKs map");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	nic->min_pkt_size = UET_MIN_PKT_SIZE;
	nic->l2_hdr_size = sizeof(struct ethhdr);
	nic->min_ip_pkt_size = (nic->min_pkt_size - nic->l2_hdr_size);

	/* open control socket */
	xdata->sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (xdata->sock_fd == -1) {
		UET_API_ERR("ERROR: Failed to create control socket");
		rc = -FI_ENODEV;
		goto exit_err;
	}

	strcpy(ifr.ifr_name, nic->ifname);

	/* get the IPv4 address of the interface */
	ifr.ifr_addr.sa_family = AF_INET;
	if ((ioctl(xdata->sock_fd, SIOCGIFADDR, &ifr)) < 0) {
		UET_API_ERR("ERROR: Failed to get local IPv4 address");
		rc = -FI_ENODEV;
		goto exit_err;
	}
	ip = &ifr.ifr_addr.sa_data[2];
	nic->ipv4_addr = ntohl(*((uint32_t *)ip));
	inet_ntop(AF_INET, ip, nic->ip_addr_str, INET_ADDRSTRLEN);

	/* get the MAC address of the interface */
	if ((ioctl(xdata->sock_fd, SIOCGIFHWADDR, &ifr)) < 0) {
		UET_API_ERR("ERROR: Failed to get local MAC address");
		rc = -FI_ENODEV;
		goto exit_err;
	}
	memcpy(nic->mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	uet_mac_addr_to_str(nic->mac_addr_str, nic->mac_addr);

	/* get the MTU of the interface */
	if ((ioctl(xdata->sock_fd, SIOCGIFMTU, &ifr)) < 0) {
		UET_API_ERR("ERROR: Failed to get MTU");
		rc = -FI_ENODEV;
		goto exit_err;
	}
	nic->mtu = (size_t)ifr.ifr_mtu;
	nic->max_pkt_size = (nic->mtu + nic->l2_hdr_size);

	return FI_SUCCESS;

exit_err:

	nic_xdp_finalize(nic);
	return rc;
}

