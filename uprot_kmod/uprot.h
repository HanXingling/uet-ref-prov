/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

#ifndef UPROT_H
#define UPROT_H

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_vlan.h>
#include <rdma/ib_addr.h>

#include "uprot_pool.h"

/*
 * Version 1 and Version 2 are identical on 64 bit machines, but on 32 bit
 * machines Version 2 has a different struct layout.
 */
#define UPROT_UVERBS_ABI_VERSION		2

#define RDMA_DRIVER_UPROT ((enum rdma_driver_id)0x42)

#define DEFAULT_MAX_VALUE (1 << 20)

/* default/initial uprot device parameter settings */
enum uprot_device_param {
	UPROT_MAX_MR_SIZE			= -1ull,
	UPROT_PAGE_SIZE_CAP		= 0xfffff000,
	UPROT_MAX_QP_WR			= DEFAULT_MAX_VALUE,
	UPROT_DEVICE_CAP_FLAGS		= IB_DEVICE_BAD_PKEY_CNTR
					| IB_DEVICE_BAD_QKEY_CNTR
					| IB_DEVICE_AUTO_PATH_MIG
					| IB_DEVICE_CHANGE_PHY_PORT
					| IB_DEVICE_UD_AV_PORT_ENFORCE
					| IB_DEVICE_PORT_ACTIVE_EVENT
					| IB_DEVICE_SYS_IMAGE_GUID
					| IB_DEVICE_RC_RNR_NAK_GEN
					| IB_DEVICE_SRQ_RESIZE
					| IB_DEVICE_MEM_MGT_EXTENSIONS
					| IB_DEVICE_MEM_WINDOW
					| IB_DEVICE_FLUSH_GLOBAL
					| IB_DEVICE_FLUSH_PERSISTENT
#ifdef CONFIG_64BIT
					| IB_DEVICE_MEM_WINDOW_TYPE_2B
					| IB_DEVICE_ATOMIC_WRITE,
#else
					| IB_DEVICE_MEM_WINDOW_TYPE_2B,
#endif /* CONFIG_64BIT */
	UPROT_MAX_SGE			= 32,
	UPROT_MAX_WQE_SIZE		= 0,
	UPROT_MAX_INLINE_DATA		= 0, /* Set to PMTU? */
	UPROT_MAX_SGE_RD			= 32,
	UPROT_MAX_CQ			= DEFAULT_MAX_VALUE,
	UPROT_MAX_LOG_CQE			= 15,
	UPROT_MAX_PD			= DEFAULT_MAX_VALUE,
	UPROT_MAX_QP_RD_ATOM		= 128,
	UPROT_MAX_RES_RD_ATOM		= 0x3f000,
	UPROT_MAX_QP_INIT_RD_ATOM		= 128,
	UPROT_MAX_MCAST_GRP		= 8192,
	UPROT_MAX_MCAST_QP_ATTACH		= 56,
	UPROT_MAX_TOT_MCAST_QP_ATTACH	= 0x70000,
	UPROT_MAX_AH			= (1<<15) - 1,	/* 32Ki - 1 */
	UPROT_MIN_AH_INDEX		= 1,
	UPROT_MAX_AH_INDEX		= UPROT_MAX_AH,
	UPROT_MAX_SRQ_WR			= DEFAULT_MAX_VALUE,
	UPROT_MIN_SRQ_WR			= 1,
	UPROT_MAX_SRQ_SGE			= 27,
	UPROT_MIN_SRQ_SGE			= 1,
	UPROT_MAX_FMR_PAGE_LIST_LEN	= 512,
	UPROT_MAX_PKEYS			= 64,
	UPROT_LOCAL_CA_ACK_DELAY		= 15,

	UPROT_MAX_UCONTEXT		= DEFAULT_MAX_VALUE,

	UPROT_NUM_PORT			= 1,

	UPROT_MIN_QP_INDEX		= 16,
	UPROT_MAX_QP_INDEX		= DEFAULT_MAX_VALUE,
	UPROT_MAX_QP			= DEFAULT_MAX_VALUE - UPROT_MIN_QP_INDEX,

	UPROT_MIN_SRQ_INDEX		= 0x00020001,
	UPROT_MAX_SRQ_INDEX		= DEFAULT_MAX_VALUE,
	UPROT_MAX_SRQ			= DEFAULT_MAX_VALUE - UPROT_MIN_SRQ_INDEX,

	UPROT_MIN_MR_INDEX		= 0x00000001,
	UPROT_MAX_MR_INDEX		= DEFAULT_MAX_VALUE >> 1,
	UPROT_MAX_MR			= UPROT_MAX_MR_INDEX - UPROT_MIN_MR_INDEX,
	UPROT_MIN_MW_INDEX		= UPROT_MAX_MR_INDEX + 1,
	UPROT_MAX_MW_INDEX		= DEFAULT_MAX_VALUE,
	UPROT_MAX_MW			= UPROT_MAX_MW_INDEX - UPROT_MIN_MW_INDEX,

	UPROT_MAX_PKT_PER_ACK		= 64,

	UPROT_MAX_UNACKED_PSNS		= 128,

	/* Max inflight SKBs per queue pair */
	UPROT_INFLIGHT_SKBS_PER_QP_HIGH	= 64,
	UPROT_INFLIGHT_SKBS_PER_QP_LOW	= 16,

	/* Max number of interations of each work item
	 * before yielding the cpu to let other
	 * work make progress
	 */
	UPROT_MAX_ITERATIONS		= 1024,

	/* Delay before calling arbiter timer */
	UPROT_NSEC_ARB_TIMER_DELAY	= 200,

	/* IBTA v1.4 A3.3.1 VENDOR INFORMATION section */
	UPROT_VENDOR_ID			= 0XFFFFFF,
};

/* default/initial uprot port parameters */
enum uprot_port_param {
	UPROT_PORT_GID_TBL_LEN		= 1024,
	UPROT_PORT_PORT_CAP_FLAGS	= 0,
	UPROT_PORT_MAX_MSG_SZ		= 0x800000,
	UPROT_PORT_BAD_PKEY_CNTR	= 0,
	UPROT_PORT_QKEY_VIOL_CNTR	= 0,
	UPROT_PORT_LID			= 0,
	UPROT_PORT_SM_LID		= 0,
	UPROT_PORT_SM_SL		= 0,
	UPROT_PORT_LMC			= 0,
	UPROT_PORT_MAX_VL_NUM		= 1,
	UPROT_PORT_SUBNET_TIMEOUT	= 0,
	UPROT_PORT_INIT_TYPE_REPLY	= 0,
	UPROT_PORT_ACTIVE_WIDTH		= IB_WIDTH_1X,
	UPROT_PORT_ACTIVE_SPEED		= 1,
	UPROT_PORT_PKEY_TBL_LEN		= 1,
	UPROT_PORT_PHYS_STATE		= IB_PORT_PHYS_STATE_POLLING,
	UPROT_PORT_SUBNET_PREFIX	= 0xfe80000000000000ULL,
};

/* default/initial port info parameters */
enum uprot_port_info_param {
	UPROT_PORT_INFO_VL_CAP		= 4,	/* 1-8 */
	UPROT_PORT_INFO_MTU_CAP		= 5,	/* 4096 */
	UPROT_PORT_INFO_OPER_VL		= 1,	/* 1 */
};

struct uprot_ucontext {
	struct ib_ucontext ibuc;
	struct uprot_pool_elem elem;
};

struct uprot_pd {
	struct ib_pd ibpd;
	struct uprot_pool_elem elem;
};

enum {
	UPROT_ACCESS_REMOTE	= IB_ACCESS_REMOTE_READ
				| IB_ACCESS_REMOTE_WRITE
				| IB_ACCESS_REMOTE_ATOMIC,
	UPROT_ACCESS_SUPPORTED_MR	= UPROT_ACCESS_REMOTE
				| IB_ACCESS_LOCAL_WRITE
				| IB_ACCESS_MW_BIND
				| IB_ACCESS_ON_DEMAND
				| IB_ACCESS_FLUSH_GLOBAL
				| IB_ACCESS_FLUSH_PERSISTENT
				| IB_ACCESS_OPTIONAL,
	UPROT_ACCESS_SUPPORTED_QP	= UPROT_ACCESS_SUPPORTED_MR,
	UPROT_ACCESS_SUPPORTED_MW	= UPROT_ACCESS_SUPPORTED_MR
				| IB_ZERO_BASED,
};

struct uprot_port {
	struct ib_port_attr	attr;
	__be64			port_guid;
	__be64			subnet_prefix;
	unsigned int		mtu_cap;
};

struct uprot_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr	attr;
	int			max_ucontext;
	int			max_inline_data;
	struct mutex		usdev_lock;

	struct net_device	*ndev;

	struct uprot_pool	uc_pool;
	struct uprot_pool	pd_pool;

	struct uprot_port	port;
};

static inline struct uprot_dev *to_uprot_dev(struct ib_device *dev)
{
	return dev ? container_of(dev, struct uprot_dev, ib_dev) : NULL;
}

static inline struct uprot_ucontext *to_uprot_ucontext(struct ib_ucontext *uc)
{
	return uc ? container_of(uc, struct uprot_ucontext, ibuc) : NULL;
}

static inline struct uprot_pd *to_uprot_pd(struct ib_pd *pd)
{
	return pd ? container_of(pd, struct uprot_pd, ibpd) : NULL;
}

int uprot_register_device(struct uprot_dev *uprot,
			  const char *ibdev_name);

void uprot_set_port_state(struct uprot_dev *uprot);

void uprot_dealloc(struct ib_device *ib_dev);

#endif /* UPROT_H */
