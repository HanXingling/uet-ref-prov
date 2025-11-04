/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

#include <net/addrconf.h>
#include <rdma/ib_mad.h>

#include "uprot.h"

static int uprot_query_device(struct ib_device *ib_dev,
			      struct ib_device_attr *attr,
			      struct ib_udata *udata)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	if (udata->inlen || udata->outlen) {
		pr_debug("query_device malformed udata");
		return -EINVAL;
	}

	memcpy(attr, &uprot->attr, sizeof(*attr));

	return 0;
}

static int uprot_query_port(struct ib_device *ib_dev,
			    u32 port_num,
			    struct ib_port_attr *attr)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);
	int ret;

	if (port_num != 1) {
		pr_debug("query_port invalid port_num = %d", port_num);
		return -EINVAL;
	}

	memcpy(attr, &uprot->port.attr, sizeof(*attr));

	mutex_lock(&uprot->usdev_lock);

	ret = ib_get_eth_speed(ib_dev, port_num, &attr->active_speed,
			       &attr->active_width);

	if (attr->state == IB_PORT_ACTIVE)
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	else if (dev_get_flags(uprot->ndev) & IFF_UP)
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	else
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;

	mutex_unlock(&uprot->usdev_lock);

	return ret;
}

static int uprot_query_pkey(struct ib_device *ib_dev,
			    u32 port_num,
			    u16 index,
			    u16 *pkey)
{
	//struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	if (index != 0) {
		pr_debug("query_pkey invalid index = %d", index);
		return -EINVAL;
	}

	*pkey = IB_DEFAULT_PKEY_FULL;

	return 0;
}

static int uprot_modify_device(struct ib_device *ib_dev,
			       int mask,
			       struct ib_device_modify *attr)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
		     IB_DEVICE_MODIFY_NODE_DESC)) {
		pr_debug("modify_device unsupported mask = 0x%x", mask);
		return -EOPNOTSUPP;
	}

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		uprot->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		memcpy(uprot->ib_dev.node_desc,
		       attr->node_desc, sizeof(uprot->ib_dev.node_desc));
	}

	return 0;
}

static int uprot_modify_port(struct ib_device *ib_dev,
			     u32 port_num,
			     int mask,
			     struct ib_port_modify *attr)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);
	struct uprot_port *port;

	if (port_num != 1) {
		pr_debug("modify_port invalid port_num = %d", port_num);
		return -EINVAL;
	}

	if (mask & ~(IB_PORT_RESET_QKEY_CNTR)) {
		pr_debug("modify_port unsupported mask = 0x%x", mask);
		return -EOPNOTSUPP;
	}

	port = &uprot->port;
	port->attr.port_cap_flags |= attr->set_port_cap_mask;
	port->attr.port_cap_flags &= ~attr->clr_port_cap_mask;

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		port->attr.qkey_viol_cntr = 0;

	return 0;
}

static enum rdma_link_layer uprot_get_link_layer(struct ib_device *ib_dev,
						 u32 port_num)
{
	//struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	if (port_num != 1) {
		pr_debug("get_link_layer invalid port_num = %d", port_num);
		return IB_LINK_LAYER_UNSPECIFIED;
	}

	return IB_LINK_LAYER_ETHERNET;
}

static int uprot_port_immutable(struct ib_device *ib_dev,
				u32 port_num,
				struct ib_port_immutable *immutable)
{
	//struct uprot_dev *uprot = to_uprot_dev(ib_dev);
	struct ib_port_attr attr = {};
	int err;

	if (port_num != 1) {
		pr_debug("port_immutable invalid port_num = %d", port_num);
		return -EINVAL;
	}

	err = ib_query_port(ib_dev, port_num, &attr);
	if (err) {
		pr_debug("port_immutable failed to query port");
		return err;
	}

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	immutable->pkey_tbl_len   = attr.pkey_tbl_len;
	immutable->gid_tbl_len    = attr.gid_tbl_len;
	immutable->max_mad_size   = 0;

	return 0;
}

static int uprot_alloc_ucontext(struct ib_ucontext *ibuc,
				struct ib_udata *udata)
{
	struct uprot_dev *uprot = to_uprot_dev(ibuc->device);
	struct uprot_ucontext *uc = to_uprot_ucontext(ibuc);
	int err;

	err = uprot_add_to_pool(&uprot->uc_pool, uc);
	if (err) {
		pr_err("alloc_ucontext failed");
		return err;
	}

	return 0;
}

static void uprot_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	struct uprot_ucontext *uc = to_uprot_ucontext(ibuc);
	int err;

	err = uprot_cleanup(uc);
	if (err)
		pr_err("dealloc_ucontext failed");
}

static int uprot_alloc_pd(struct ib_pd *ibpd,
			  struct ib_udata *udata)
{
	struct uprot_dev *uprot = to_uprot_dev(ibpd->device);
	struct uprot_pd *pd = to_uprot_pd(ibpd);
	int err;

	err = uprot_add_to_pool(&uprot->pd_pool, pd);
	if (err) {
		pr_debug("alloc_pd failed");
		return err;
	}

	return 0;
}

static int uprot_dealloc_pd(struct ib_pd *ibpd,
			    struct ib_udata *udata)
{
	struct uprot_pd *pd = to_uprot_pd(ibpd);
	int err;

	err = uprot_cleanup(pd);
	if (err) {
		pr_err("dealloc_pd failed");
		return err;
	}

	return 0;
}

static ssize_t parent_show(struct device *device,
			   struct device_attribute *attr,
			   char *buf)
{
	struct uprot_dev *uprot =
		rdma_device_to_drv_device(device, struct uprot_dev, ib_dev);

	return sysfs_emit(buf, "%s\n", uprot->ndev->name);
}

static DEVICE_ATTR_RO(parent);

static struct attribute *uprot_dev_attributes[] = {
	&dev_attr_parent.attr,
	NULL
};

static const struct attribute_group uprot_attr_group = {
	.attrs = uprot_dev_attributes,
};

static int uprot_enable_driver(struct ib_device *ib_dev)
{
	struct uprot_dev *uprot = to_uprot_dev(ib_dev);

	uprot_set_port_state(uprot);
	dev_info(&uprot->ib_dev.dev, "added %s\n", netdev_name(uprot->ndev));

	return 0;
}

static const struct ib_device_ops uprot_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_UPROT,
	.uverbs_abi_ver = UPROT_UVERBS_ABI_VERSION,

	// .alloc_hw_port_stats = uprot_ib_alloc_hw_port_stats,
	// .alloc_mr = uprot_alloc_mr,
	// .alloc_mw = uprot_alloc_mw,
	.alloc_pd = uprot_alloc_pd,
	.alloc_ucontext = uprot_alloc_ucontext,
	// .attach_mcast = uprot_attach_mcast,
	// .create_ah = uprot_create_ah,
	// .create_cq = uprot_create_cq,
	// .create_qp = uprot_create_qp,
	// .create_srq = uprot_create_srq,
	// .create_user_ah = uprot_create_ah,
	.dealloc_driver = uprot_dealloc,
	// .dealloc_mw = uprot_dealloc_mw,
	.dealloc_pd = uprot_dealloc_pd,
	.dealloc_ucontext = uprot_dealloc_ucontext,
	// .dereg_mr = uprot_dereg_mr,
	// .destroy_ah = uprot_destroy_ah,
	// .destroy_cq = uprot_destroy_cq,
	// .destroy_qp = uprot_destroy_qp,
	// .destroy_srq = uprot_destroy_srq,
	// .detach_mcast = uprot_detach_mcast,
	.device_group = &uprot_attr_group,
	.enable_driver = uprot_enable_driver,
	// .get_dma_mr = uprot_get_dma_mr,
	// .get_hw_stats = uprot_ib_get_hw_stats,
	.get_link_layer = uprot_get_link_layer,
	.get_port_immutable = uprot_port_immutable,
	// .map_mr_sg = uprot_map_mr_sg,
	// .mmap = uprot_mmap,
	// .modify_ah = uprot_modify_ah,
	.modify_device = uprot_modify_device,
	.modify_port = uprot_modify_port,
	// .modify_qp = uprot_modify_qp,
	// .modify_srq = uprot_modify_srq,
	// .peek_cq = uprot_peek_cq,
	// .poll_cq = uprot_poll_cq,
	// .post_recv = uprot_post_recv,
	// .post_send = uprot_post_send,
	// .post_srq_recv = uprot_post_srq_recv,
	// .query_ah = uprot_query_ah,
	.query_device = uprot_query_device,
	.query_pkey = uprot_query_pkey,
	.query_port = uprot_query_port,
	// .query_qp = uprot_query_qp,
	// .query_srq = uprot_query_srq,
	// .reg_user_mr = uprot_reg_user_mr,
	// .req_notify_cq = uprot_req_notify_cq,
	// .rereg_user_mr = uprot_rereg_user_mr,
	// .resize_cq = uprot_resize_cq,

	// INIT_RDMA_OBJ_SIZE(ib_ah, uprot_ah, ibah),
	// INIT_RDMA_OBJ_SIZE(ib_cq, uprot_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, uprot_pd, ibpd),
	// INIT_RDMA_OBJ_SIZE(ib_qp, uprot_qp, ibqp),
	// INIT_RDMA_OBJ_SIZE(ib_srq, uprot_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, uprot_ucontext, ibuc),
	// INIT_RDMA_OBJ_SIZE(ib_mw, uprot_mw, ibmw),
};

int uprot_register_device(struct uprot_dev *uprot, const char *ibdev_name)
{
	struct ib_device *dev = &uprot->ib_dev;
	int err;

	strscpy(dev->node_desc, "uprot", sizeof(dev->node_desc));

	dev->node_type        = RDMA_NODE_IB_CA;
	dev->phys_port_cnt    = 1;
	dev->num_comp_vectors = num_possible_cpus();
	dev->local_dma_lkey   = 0;

	addrconf_addr_eui48((unsigned char *)&dev->node_guid,
			    uprot->ndev->dev_addr);

#if 0
	dev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND) |
				BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ);
#endif

	ib_set_device_ops(dev, &uprot_dev_ops);
	err = ib_device_set_netdev(&uprot->ib_dev, uprot->ndev, 1);
	if (err)
		return err;

	err = ib_register_device(dev, ibdev_name, NULL);
	if (err) {
		pr_debug("failed with error %d\n", err);
		return err;
	}

	/* Note that uprot may be invalid at this point if another thread
	 * unregistered it.
	 */
	return 0;
}

