/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

#include <net/addrconf.h>

#include "uprot.h"

MODULE_AUTHOR("Eric Davis");
MODULE_DESCRIPTION("Userspace Software RDMA transport");
MODULE_LICENSE("Dual BSD/GPL");

/* the caller must do a matching ib_device_put(&dev->ib_dev) */
static struct uprot_dev *uprot_get_dev_from_net(struct net_device *ndev)
{
	struct ib_device *ib_dev =
		ib_device_get_by_netdev(ndev, RDMA_DRIVER_UPROT);

	if (!ib_dev)
		return NULL;

	return to_uprot_dev(ib_dev);
}

/* Free resources for a uprot device, all objects created for this device
 * must have been destroyed.
 */
void uprot_dealloc(struct ib_device *ib_dev)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	uprot_pool_cleanup(&uprot->uc_pool);
	uprot_pool_cleanup(&uprot->pd_pool);
}

static void uprot_init_device_param(struct uprot_dev *uprot)
{
	uprot->max_inline_data			= UPROT_MAX_INLINE_DATA;

	uprot->attr.vendor_id			= UPROT_VENDOR_ID;
	uprot->attr.max_mr_size			= UPROT_MAX_MR_SIZE;
	uprot->attr.page_size_cap		= UPROT_PAGE_SIZE_CAP;
	uprot->attr.max_qp			= UPROT_MAX_QP;
	uprot->attr.max_qp_wr			= UPROT_MAX_QP_WR;
	uprot->attr.device_cap_flags		= UPROT_DEVICE_CAP_FLAGS;
	uprot->attr.kernel_cap_flags		= IBK_ALLOW_USER_UNREG;
	uprot->attr.max_send_sge		= UPROT_MAX_SGE;
	uprot->attr.max_recv_sge		= UPROT_MAX_SGE;
	uprot->attr.max_sge_rd			= UPROT_MAX_SGE_RD;
	uprot->attr.max_cq			= UPROT_MAX_CQ;
	uprot->attr.max_cqe			= (1 << UPROT_MAX_LOG_CQE) - 1;
	uprot->attr.max_mr			= UPROT_MAX_MR;
	uprot->attr.max_mw			= UPROT_MAX_MW;
	uprot->attr.max_pd			= UPROT_MAX_PD;
	uprot->attr.max_qp_rd_atom		= UPROT_MAX_QP_RD_ATOM;
	uprot->attr.max_res_rd_atom		= UPROT_MAX_RES_RD_ATOM;
	uprot->attr.max_qp_init_rd_atom		= UPROT_MAX_QP_INIT_RD_ATOM;
	uprot->attr.atomic_cap			= IB_ATOMIC_HCA;
	uprot->attr.max_mcast_grp		= UPROT_MAX_MCAST_GRP;
	uprot->attr.max_mcast_qp_attach		= UPROT_MAX_MCAST_QP_ATTACH;
	uprot->attr.max_total_mcast_qp_attach	= UPROT_MAX_TOT_MCAST_QP_ATTACH;
	uprot->attr.max_ah			= UPROT_MAX_AH;
	uprot->attr.max_srq			= UPROT_MAX_SRQ;
	uprot->attr.max_srq_wr			= UPROT_MAX_SRQ_WR;
	uprot->attr.max_srq_sge			= UPROT_MAX_SRQ_SGE;
	uprot->attr.max_fast_reg_page_list_len	= UPROT_MAX_FMR_PAGE_LIST_LEN;
	uprot->attr.max_pkeys			= UPROT_MAX_PKEYS;
	uprot->attr.local_ca_ack_delay		= UPROT_LOCAL_CA_ACK_DELAY;
	addrconf_addr_eui48((unsigned char *)&uprot->attr.sys_image_guid,
			    uprot->ndev->dev_addr);

	uprot->max_ucontext			= UPROT_MAX_UCONTEXT;
}

static void uprot_init_port_param(struct uprot_port *port)
{
	port->attr.state		= IB_PORT_DOWN;
	port->attr.max_mtu		= IB_MTU_4096;
	port->attr.active_mtu		= IB_MTU_256;
	port->attr.gid_tbl_len		= UPROT_PORT_GID_TBL_LEN;
	port->attr.port_cap_flags	= UPROT_PORT_PORT_CAP_FLAGS;
	port->attr.max_msg_sz		= UPROT_PORT_MAX_MSG_SZ;
	port->attr.bad_pkey_cntr	= UPROT_PORT_BAD_PKEY_CNTR;
	port->attr.qkey_viol_cntr	= UPROT_PORT_QKEY_VIOL_CNTR;
	port->attr.pkey_tbl_len		= UPROT_PORT_PKEY_TBL_LEN;
	port->attr.lid			= UPROT_PORT_LID;
	port->attr.sm_lid		= UPROT_PORT_SM_LID;
	port->attr.lmc			= UPROT_PORT_LMC;
	port->attr.max_vl_num		= UPROT_PORT_MAX_VL_NUM;
	port->attr.sm_sl		= UPROT_PORT_SM_SL;
	port->attr.subnet_timeout	= UPROT_PORT_SUBNET_TIMEOUT;
	port->attr.init_type_reply	= UPROT_PORT_INIT_TYPE_REPLY;
	port->attr.active_width		= UPROT_PORT_ACTIVE_WIDTH;
	port->attr.active_speed		= UPROT_PORT_ACTIVE_SPEED;
	port->attr.phys_state		= UPROT_PORT_PHYS_STATE;
	port->mtu_cap			= ib_mtu_enum_to_int(IB_MTU_256);
	port->subnet_prefix		= cpu_to_be64(UPROT_PORT_SUBNET_PREFIX);
}

/* Initialize the port state, note the IB convention that HCA ports are always
 * numbered from 1.
 */
static void uprot_init_ports(struct uprot_dev *uprot)
{
	struct uprot_port *port = &uprot->port;

	uprot_init_port_param(port);
	addrconf_addr_eui48((unsigned char *)&port->port_guid,
			    uprot->ndev->dev_addr);
}

static void uprot_init_pools(struct uprot_dev *uprot)
{
	uprot_pool_init(uprot, &uprot->uc_pool, UPROT_TYPE_UC);
	uprot_pool_init(uprot, &uprot->pd_pool, UPROT_TYPE_PD);
}

static void uprot_init(struct uprot_dev *uprot)
{
	/* init default device parameters */
	uprot_init_device_param(uprot);

	uprot_init_ports(uprot);
	uprot_init_pools(uprot);

	mutex_init(&uprot->usdev_lock);
}

static enum ib_mtu uprot_mtu_int_to_enum(int mtu)
{
	if (mtu < 256)       return 0;
	else if (mtu < 512)  return IB_MTU_256;
	else if (mtu < 1024) return IB_MTU_512;
	else if (mtu < 2048) return IB_MTU_1024;
	else if (mtu < 4096) return IB_MTU_2048;
	else                 return IB_MTU_4096;
}

static void uprot_set_mtu(struct uprot_dev *uprot,
			  unsigned int ndev_mtu)
{
	struct uprot_port *port = &uprot->port;
	enum ib_mtu mtu;

	mtu = uprot_mtu_int_to_enum(ndev_mtu);

	/* make sure the new MTU is in range */
	mtu = mtu ? min_t(enum ib_mtu, mtu, IB_MTU_4096) : IB_MTU_256;

	port->attr.active_mtu = mtu;
	port->mtu_cap = ib_mtu_enum_to_int(mtu);

	pr_info("mtu set to %d", port->mtu_cap);
}

static int uprot_net_add(const char *ibdev_name,
			 struct net_device *ndev)
{
	struct uprot_dev *uprot;
	int err;

	uprot = ib_alloc_device(uprot_dev, ib_dev);
	if (!uprot)
		return -ENOMEM;

	uprot->ndev = ndev;

	uprot_init(uprot);
	uprot_set_mtu(uprot, ndev->mtu);

	err = uprot_register_device(uprot, ibdev_name);
	if (err) {
		ib_dealloc_device(&uprot->ib_dev);
		return err;
	}

	return 0;
}

static int uprot_newlink(const char *ibdev_name,
			 struct net_device *ndev)
{
	struct uprot_dev *uprot;
	int err;

	if (is_vlan_dev(ndev)) {
		pr_err("uprot creation not allowed on vlan device");
		return -EPERM;
	}

	uprot = uprot_get_dev_from_net(ndev);
	if (uprot) {
		ib_device_put(&uprot->ib_dev);
		pr_err("already configured on %s", ndev->name);
		return -EEXIST;
	}

	err = uprot_net_add(ibdev_name, ndev);
	if (err) {
		pr_err("failed to add %s\n", ndev->name);
		return err;
	}

	return 0;
}

static struct rdma_link_ops uprot_link_ops = {
	.type = "uprot",
	.newlink = uprot_newlink,
};

static void uprot_port_event(struct uprot_dev *uprot,
			     enum ib_event_type event)
{
	struct ib_event ev;

	ev.device = &uprot->ib_dev;
	ev.element.port_num = 1;
	ev.event = event;

	ib_dispatch_event(&ev);
}

/* caller must hold net_info_lock */
static void uprot_port_up(struct uprot_dev *uprot)
{
	struct uprot_port *port;

	port = &uprot->port;
	port->attr.state = IB_PORT_ACTIVE;

	uprot_port_event(uprot, IB_EVENT_PORT_ACTIVE);
	dev_info(&uprot->ib_dev.dev, "port up\n");
}

/* caller must hold net_info_lock */
static void uprot_port_down(struct uprot_dev *uprot)
{
	struct uprot_port *port;

	port = &uprot->port;
	port->attr.state = IB_PORT_DOWN;

	uprot_port_event(uprot, IB_EVENT_PORT_ERR);
	dev_info(&uprot->ib_dev.dev, "port down\n");
}

void uprot_set_port_state(struct uprot_dev *uprot)
{
	if (netif_running(uprot->ndev) && netif_carrier_ok(uprot->ndev))
		uprot_port_up(uprot);
	else
		uprot_port_down(uprot);
}

static int uprot_notify(struct notifier_block *not_blk,
			unsigned long event,
			void *arg)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(arg);
	struct uprot_dev *uprot = uprot_get_dev_from_net(ndev);

	if (!uprot)
		return NOTIFY_OK;

	switch (event) {
	case NETDEV_UNREGISTER:
		ib_unregister_device_queued(&uprot->ib_dev);
		break;
	case NETDEV_UP:
		uprot_port_up(uprot);
		break;
	case NETDEV_DOWN:
		uprot_port_down(uprot);
		break;
	case NETDEV_CHANGEMTU:
		pr_debug("%s changed mtu to %d\n", ndev->name, ndev->mtu);
		uprot_set_mtu(uprot, ndev->mtu);
		break;
	case NETDEV_CHANGE:
		uprot_set_port_state(uprot);
		break;
	case NETDEV_REBOOT:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGENAME:
	case NETDEV_FEAT_CHANGE:
	default:
		pr_debug("ignoring netdev event = %ld for %s\n",
			 event, ndev->name);
		break;
	}

	ib_device_put(&uprot->ib_dev);
	return NOTIFY_OK;
}

static struct notifier_block uprot_net_notifier = {
	.notifier_call = uprot_notify,
};

static int uprot_net_init(void)
{
	int err;

	err = register_netdevice_notifier(&uprot_net_notifier);
	if (err) {
		pr_err("failed to register netdev notifier\n");
		unregister_netdevice_notifier(&uprot_net_notifier);
		return err;
	}

	return 0;
}

static void uprot_net_exit(void)
{
	unregister_netdevice_notifier(&uprot_net_notifier);
}

static int __init uprot_module_init(void)
{
	int err;

	err = uprot_net_init();
	if (err)
		return err;

	rdma_link_register(&uprot_link_ops);

	pr_info("loaded\n");
	return 0;
}

static void __exit uprot_module_exit(void)
{
	rdma_link_unregister(&uprot_link_ops);
	ib_unregister_driver(RDMA_DRIVER_UPROT);
	uprot_net_exit();

	pr_info("unloaded\n");
}

late_initcall(uprot_module_init);
module_exit(uprot_module_exit);

MODULE_ALIAS_RDMA_LINK("uprot");

