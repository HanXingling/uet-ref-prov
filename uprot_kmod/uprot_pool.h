/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * Copyright (c) 2025, Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

#ifndef UPROT_POOL_H
#define UPROT_POOL_H

enum uprot_elem_type {
	UPROT_TYPE_UC,
	UPROT_TYPE_PD,
	UPROT_NUM_TYPES,		/* keep me last */
};

struct uprot_pool_elem {
	struct uprot_pool	*pool;
	void			*obj;
	struct kref		ref_cnt;
	struct list_head	list;
	struct completion	complete;
	u32			index;
};

struct uprot_pool {
	struct uprot_dev	*uprot;
	const char		*name;
	void			(*cleanup)(struct uprot_pool_elem *elem);
	enum uprot_elem_type	type;

	unsigned int		max_elem;
	atomic_t		num_elem;
	size_t			elem_size;
	size_t			elem_offset;

	struct xarray		xa;
	struct xa_limit		limit;
	u32			next;
};

/* Initialize a pool of objects with given limit on number of elements. Gets
 * parameters from uprot_type_info pool elements will be allocated out of a
 * slab cache.
 */
void uprot_pool_init(struct uprot_dev *uprot,
		     struct uprot_pool *pool,
		     enum uprot_elem_type type);

/* free resources from object pool */
void uprot_pool_cleanup(struct uprot_pool *pool);

/* connect already allocated object to a pool */
int __uprot_add_to_pool(struct uprot_pool *pool,
			struct uprot_pool_elem *elem,
			bool sleepable);
#define uprot_add_to_pool(pool, obj) \
	__uprot_add_to_pool(pool, &(obj)->elem, true)

/* lookup an indexed object, takes a reference on the object */
void *uprot_pool_get_index(struct uprot_pool *pool,
			   u32 index);

int __uprot_get(struct uprot_pool_elem *elem);
#define uprot_get(obj) __uprot_get(&(obj)->elem)

int __uprot_put(struct uprot_pool_elem *elem);
#define uprot_put(obj) __uprot_put(&(obj)->elem)

int __uprot_cleanup(struct uprot_pool_elem *elem,
		    bool sleepable);
#define uprot_cleanup(obj) __uprot_cleanup(&(obj)->elem, true)

#define uprot_read(obj) kref_read(&(obj)->elem.ref_cnt)

void __uprot_finalize(struct uprot_pool_elem *elem);
#define uprot_finalize(obj) __uprot_finalize(&(obj)->elem)

#endif /* UPROT_POOL_H */
