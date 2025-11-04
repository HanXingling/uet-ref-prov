/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

#include "uprot.h"
#include "uprot_pool.h"

#define UPROT_POOL_TIMEOUT	(200)
#define UPROT_POOL_ALIGN	(16)

static const struct uprot_type_info {
	const char *name;
	size_t size;
	size_t elem_offset;
	void (*cleanup)(struct uprot_pool_elem *elem);
	u32 min_index;
	u32 max_index;
	u32 max_elem;
} uprot_type_info[UPROT_NUM_TYPES] = {
	[UPROT_TYPE_UC] = {
		.name		= "uc",
		.size		= sizeof(struct uprot_ucontext),
		.elem_offset	= offsetof(struct uprot_ucontext, elem),
		.min_index	= 1,
		.max_index	= UPROT_MAX_UCONTEXT,
		.max_elem	= UPROT_MAX_UCONTEXT,
	},
	[UPROT_TYPE_PD] = {
		.name		= "pd",
		.size		= sizeof(struct uprot_pd),
		.elem_offset	= offsetof(struct uprot_pd, elem),
		.min_index	= 1,
		.max_index	= UPROT_MAX_PD,
		.max_elem	= UPROT_MAX_PD,
	},
};

void uprot_pool_init(struct uprot_dev *uprot,
		     struct uprot_pool *pool,
		     enum uprot_elem_type type)
{
	const struct uprot_type_info *info = &uprot_type_info[type];

	memset(pool, 0, sizeof(*pool));

	pool->uprot		= uprot;
	pool->name		= info->name;
	pool->type		= type;
	pool->max_elem		= info->max_elem;
	pool->elem_size		= ALIGN(info->size, UPROT_POOL_ALIGN);
	pool->elem_offset	= info->elem_offset;
	pool->cleanup		= info->cleanup;

	atomic_set(&pool->num_elem, 0);

	xa_init_flags(&pool->xa, XA_FLAGS_ALLOC);
	pool->limit.min = info->min_index;
	pool->limit.max = info->max_index;
}

void uprot_pool_cleanup(struct uprot_pool *pool)
{
	WARN_ON(!xa_empty(&pool->xa));
}

int __uprot_add_to_pool(struct uprot_pool *pool,
			struct uprot_pool_elem *elem,
			bool sleepable)
{
	int err;
	gfp_t gfp_flags;

	if (atomic_inc_return(&pool->num_elem) > pool->max_elem)
		goto err_cnt;

	elem->pool = pool;
	elem->obj = (u8 *)elem - pool->elem_offset;
	kref_init(&elem->ref_cnt);
	init_completion(&elem->complete);

	/* AH objects are unique in that the create_ah verb
	 * can be called in atomic context. If the create_ah
	 * call is not sleepable use GFP_ATOMIC.
	 */
	gfp_flags = sleepable ? GFP_KERNEL : GFP_ATOMIC;

	if (sleepable)
		might_sleep();

	err = xa_alloc_cyclic(&pool->xa, &elem->index, NULL, pool->limit,
			      &pool->next, gfp_flags);
	if (err < 0)
		goto err_cnt;

	return 0;

err_cnt:
	atomic_dec(&pool->num_elem);
	return -EINVAL;
}

void *uprot_pool_get_index(struct uprot_pool *pool,
			   u32 index)
{
	struct uprot_pool_elem *elem;
	struct xarray *xa = &pool->xa;
	void *obj;

	rcu_read_lock();

	elem = xa_load(xa, index);
	if (elem && kref_get_unless_zero(&elem->ref_cnt))
		obj = elem->obj;
	else
		obj = NULL;

	rcu_read_unlock();

	return obj;
}

static void uprot_elem_release(struct kref *kref)
{
	struct uprot_pool_elem *elem = container_of(kref, typeof(*elem),
						    ref_cnt);

	complete(&elem->complete);
}

int __uprot_cleanup(struct uprot_pool_elem *elem,
		    bool sleepable)
{
	struct uprot_pool *pool = elem->pool;
	struct xarray *xa = &pool->xa;
	static int timeout = UPROT_POOL_TIMEOUT;
	int ret, err = 0;
	void *xa_ret;

	if (sleepable)
		might_sleep();

	/* Erase the xarray entry to prevent looking up the pool elem from
	 * its index.
	 */
	xa_ret = xa_erase(xa, elem->index);
	WARN_ON(xa_err(xa_ret));

	/* If this is the last call to uprot_put, complete the object. It is
	 * safe to touch obj->elem after this since it is freed below.
	 */
	__uprot_put(elem);

	/* Wait until all references to the object have been dropped before
	 * final object specific cleanup and return to rdma-core.
	 */
	if (sleepable) {
		if (!completion_done(&elem->complete) && timeout) {
			ret = wait_for_completion_timeout(&elem->complete,
							  timeout);

			/* Shouldn't happen. There are still references to
			 * the object but, rather than deadlock, free the
			 * object or pass back to rdma-core.
			 */
			if (WARN_ON(!ret))
				err = -EINVAL;
		}
	} else {
		unsigned long until = (jiffies + timeout);

		/* AH objects are unique in that the destroy_ah verb can be
		 * called in atomic context. This delay replaces the
		 * wait_for_completion call above when the destroy_ah call
		 * is not sleepable
		 */
		while (!completion_done(&elem->complete) &&
		       time_before(jiffies, until))
			mdelay(1);

		if (WARN_ON(!completion_done(&elem->complete)))
			err = -EINVAL;
	}

	if (pool->cleanup)
		pool->cleanup(elem);

	atomic_dec(&pool->num_elem);

	return err;
}

int __uprot_get(struct uprot_pool_elem *elem)
{
	return kref_get_unless_zero(&elem->ref_cnt);
}

int __uprot_put(struct uprot_pool_elem *elem)
{
	return kref_put(&elem->ref_cnt, uprot_elem_release);
}

void __uprot_finalize(struct uprot_pool_elem *elem)
{
	void *xa_ret;

	xa_ret = xa_store(&elem->pool->xa, elem->index, elem, GFP_KERNEL);
	WARN_ON(xa_err(xa_ret));
}

