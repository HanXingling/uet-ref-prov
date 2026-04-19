/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include <ofi_list.h>

#include "uet_log.h"
#include "uet_nic.h"
#include "tomlc17.h"
#include "imp_shim.h"

/* initial number of packet buffers to pre-allocate per plane */
#define IMP_POOL_INIT_PER_PLANE 32

/* packet entry */
struct imp_pkt {
	struct slist_entry entry;      /* list linkage (free pool or tx queue) */
	size_t             pkt_size;   /* the size of the packet */
	size_t             iphdr_off;  /* offset of IP header from pkt_data */
	struct timespec    tx_time;    /* calculated transmit time */
	uint8_t            pkt_data[]; /* flexible size for max_pkt_size */
};

/* per-plane Tx queue */
struct imp_plane {
	struct slist    list;  /* packet list */
	pthread_mutex_t lock;  /* mutex for list management */
	uint32_t        depth; /* current number of packets on the queue */
};

/* packet entry free pool - grows as needed, never shrinks */
struct imp_pool {
	struct slist    free_list;  /* free list */
	pthread_mutex_t lock;       /* mutex for list management */
	size_t          entry_size; /* sizeof(imp_pkt) + max_pkt_size */
	uint32_t        free_count; /* current number of free entries */
	uint32_t        total;      /* total number of entries allocated */
};

/* impairment shim state */
struct imp_shim_state {
	bool              enabled;
	struct uet_nic   *nic;

	bool              running;
	pthread_t         tx_thread;

	int               num_planes; /* number of Tx queues */
	bool              random_enq; /* random vs round-robin selection */
	int               drop_rate;  /* hundredths of a percent */
	uint64_t          delay_max;  /* nanoseconds (random 0..delay_max) */

	struct imp_plane *planes;     /* Tx queues */
	uint32_t          enq_idx;    /* round-robin enqueue index */
	struct imp_pool   pool;       /* packet buffer free pool */
};

static struct imp_shim_state imp_state;

/*
 * Allocate a single pool entry. Called during init to seed the pool and at
 * runtime when the free list is exhausted.
 */
static struct imp_pkt *imp_pool_alloc_entry(struct imp_pool *pool)
{
	struct imp_pkt *pkt;

	pkt = calloc(1, pool->entry_size);
	if (pkt != NULL)
		pool->total++;

	return pkt;
}

/*
 * Get a packet buffer from the pool. If the free list is empty, a new entry
 * is allocated (the pool grows but never shrinks).
 */
static struct imp_pkt *imp_pool_get(struct imp_pool *pool)
{
	struct imp_pkt *pkt = NULL;

	pthread_mutex_lock(&pool->lock);

	if (!slist_empty(&pool->free_list)) {
		slist_remove_head_container(&pool->free_list,
					    struct imp_pkt, pkt, entry);
		pool->free_count--;
	} else {
		pkt = imp_pool_alloc_entry(pool);
		if (pkt != NULL)
			UET_IMP_INFO("pool grew to %u entries", pool->total);
	}

	pthread_mutex_unlock(&pool->lock);

	return pkt;
}

/* Return a packet buffer to the pool's free list. */
static void imp_pool_put(struct imp_pool *pool,
			 struct imp_pkt *pkt)
{
	pthread_mutex_lock(&pool->lock);

	slist_insert_head(&pkt->entry, &pool->free_list);
	pool->free_count++;

	pthread_mutex_unlock(&pool->lock);
}

/*
 * Initialize the packet buffer free pool. Pre-allocates entries based on
 * (num_planes * IMP_POOL_INIT_PER_PLANE).
 */
static int imp_pool_init(struct imp_pool *pool,
			 size_t max_pkt_size,
			 int num_planes)
{
	struct imp_pkt *pkt;
	int count;
	int i;

	memset(pool, 0, sizeof(*pool));
	pthread_mutex_init(&pool->lock, NULL);
	slist_init(&pool->free_list);
	pool->entry_size = (sizeof(struct imp_pkt) + max_pkt_size);

	count = (num_planes * IMP_POOL_INIT_PER_PLANE);

	for (i = 0; i < count; i++) {
		pkt = imp_pool_alloc_entry(pool);
		if (pkt == NULL) {
			UET_IMP_ERR("failed to pre-allocate pool entry");
			return -ENOMEM;
		}

		slist_insert_head(&pkt->entry, &pool->free_list);
		pool->free_count++;
	}

	UET_IMP_INFO("pool: pre-allocated %d entries (size = %zu bytes)",
		     count, pool->entry_size);

	return 0;
}

/*
 * Free all packet buffer free pool entries (any entries still on the plane
 * queues must be drained before calling this function).
 */
static void imp_pool_finalize(struct imp_pool *pool)
{
	struct imp_pkt *pkt;

	while (!slist_empty(&pool->free_list)) {
		slist_remove_head_container(&pool->free_list,
					    struct imp_pkt, pkt, entry);
		free(pkt);
	}

	pool->free_count = 0;
	pool->total = 0;

	pthread_mutex_destroy(&pool->lock);
}

/* Enqueue a packet onto a plane's Tx queue. */
static void imp_plane_enqueue(struct imp_plane *plane,
			      struct imp_pkt *pkt)
{
	pthread_mutex_lock(&plane->lock);

	slist_insert_tail(&pkt->entry, &plane->list);
	plane->depth++;

	pthread_mutex_unlock(&plane->lock);
}

/*
 * Try to dequeue a packet from the front of a plane's Tx queue if its transmit
 * time has been reached. Returns the packet if dequeued, NULL otherwise.
 */
static struct imp_pkt *imp_plane_try_dequeue(struct imp_plane *plane,
					     struct timespec *now)
{
	struct imp_pkt *pkt;

	pthread_mutex_lock(&plane->lock);

	if (slist_empty(&plane->list)) {
		pthread_mutex_unlock(&plane->lock);
		return NULL;
	}

	/* peek at the head packet */
	pkt = container_of(plane->list.head, struct imp_pkt, entry);

	/* check if the head packet's transmit time has been reached */
	if ((now->tv_sec > pkt->tx_time.tv_sec) ||
	    ((now->tv_sec == pkt->tx_time.tv_sec) &&
	     (now->tv_nsec >= pkt->tx_time.tv_nsec))) {
		slist_remove_head(&plane->list);
		plane->depth--;
		pthread_mutex_unlock(&plane->lock);
		return pkt;
	}

	pthread_mutex_unlock(&plane->lock);

	UET_IMP_DBG("packet skipped");
	return NULL;
}

/*
 * Transmit thread.
 *
 * Processes all planes in round-robin fashion. For each plane, attempt to
 * dequeue and transmit the head packet if its transmit time has been
 * reached. After transmission, the packet buffer is returned to the pool.
 */
static void *imp_tx_thread(void *arg)
{
	struct imp_shim_state *st = (struct imp_shim_state *)arg;
	struct timespec now;
	struct imp_pkt *pkt;
	int plane_idx;

	UET_IMP_INFO("Tx thread started");

	while (st->running) {
		for (plane_idx = 0; plane_idx < st->num_planes; plane_idx++) {
			clock_gettime(CLOCK_MONOTONIC, &now);

			pkt = imp_plane_try_dequeue(&st->planes[plane_idx],
						    &now);
			if (pkt == NULL)
				continue;

			uet_nic_tx_pkt(st->nic,
				       pkt->pkt_data,
				       (pkt->pkt_data + pkt->iphdr_off),
				       pkt->pkt_size);

			imp_pool_put(&st->pool, pkt);
		}

		sched_yield(); /* Don't hog the CPU... */
	}

	UET_IMP_INFO("Tx thread exiting");
	return NULL;
}

/* Read and validate the TOML configuration file. */
static int imp_read_config(const char *config_path)
{
	toml_result_t result;
	toml_datum_t val;

	result = toml_parse_file_ex(config_path);
	if (!result.ok) {
		UET_IMP_ERR("failed to parse config '%s': %s",
			    config_path, result.errmsg);
		return -EINVAL;
	}

	/* num_planes (required) */
	val = toml_seek(result.toptab, "config.num_planes");
	if (val.type != TOML_INT64 || val.u.int64 < 1) {
		UET_IMP_ERR("config: num_planes must be a positive integer");
		toml_free(result);
		return -EINVAL;
	}
	imp_state.num_planes = (int)val.u.int64;

	/* random_enq (required) */
	val = toml_seek(result.toptab, "config.random_enq");
	if (val.type != TOML_BOOLEAN) {
		UET_IMP_ERR("config: random_enq must be a boolean");
		toml_free(result);
		return -EINVAL;
	}
	imp_state.random_enq = val.u.boolean;

	/* drop_rate (required) */
	val = toml_seek(result.toptab, "config.drop_rate");
	if (val.type != TOML_INT64 || val.u.int64 < 0) {
		UET_IMP_ERR("config: drop_rate must be a non-negative integer");
		toml_free(result);
		return -EINVAL;
	}
	imp_state.drop_rate = (int)val.u.int64;

	/* delay_max (required) */
	val = toml_seek(result.toptab, "config.delay_max");
	if (val.type != TOML_INT64 || val.u.int64 < 0) {
		UET_IMP_ERR("config: delay_max must be a non-negative integer");
		toml_free(result);
		return -EINVAL;
	}
	imp_state.delay_max = (uint64_t)val.u.int64;

	toml_free(result);

	UET_IMP_INFO("config: num_planes=%d drop_rate=%d delay_max=%lu "
		     "random_enq=%s",
		     imp_state.num_planes, imp_state.drop_rate,
		     (unsigned long)imp_state.delay_max,
		     imp_state.random_enq ? "true" : "false");

	return 0;
}

int imp_shim_init(struct uet_nic *nic)
{
	const char *config_path;
	int i, rc;

	memset(&imp_state, 0, sizeof(imp_state));
	imp_state.enabled = false;

	config_path = getenv(UET_IMPAIRMENT_SHIM);
	if (config_path == NULL)
		return 0;

	UET_IMP_INFO("initializing with config '%s'", config_path);

	/* seed random number generator */
	srand(time(NULL) ^ (uintptr_t)nic);

	/* read the config file */
	rc = imp_read_config(config_path);
	if (rc != 0)
		return rc;

	/* initialize the packet buffer pool */
	rc = imp_pool_init(&imp_state.pool, nic->max_pkt_size,
			   imp_state.num_planes);
	if (rc != 0)
		return rc;

	/* allocate the per-plane Tx queues */
	imp_state.planes = calloc(imp_state.num_planes,
				  sizeof(struct imp_plane));
	if (imp_state.planes == NULL) {
		UET_IMP_ERR("failed to allocate %d planes",
			    imp_state.num_planes);
		imp_pool_finalize(&imp_state.pool);
		return -ENOMEM;
	}

	for (i = 0; i < imp_state.num_planes; i++) {
		slist_init(&imp_state.planes[i].list);
		pthread_mutex_init(&imp_state.planes[i].lock, NULL);
	}

	imp_state.enabled = true;
	imp_state.nic = nic;

	/* spawn the Tx thread */
	imp_state.running = true;
	rc = pthread_create(&imp_state.tx_thread, NULL, imp_tx_thread,
			    &imp_state);
	if (rc != 0) {
		UET_IMP_ERR("failed to create Tx thread: %s", strerror(rc));
		free(imp_state.planes);
		imp_state.planes = NULL;
		imp_pool_finalize(&imp_state.pool);
		imp_state.enabled = false;
		return -rc;
	}

	UET_IMP_INFO("initialized successfully");
	return 0;
}

void imp_shim_finalize(void)
{
	struct imp_pkt *pkt;
	int i;

	if (!imp_state.enabled)
		return;

	UET_IMP_INFO("finalizing");

	/* stop the Tx thread */
	imp_state.running = false;
	pthread_join(imp_state.tx_thread, NULL);

	/* drain all the per-plane Tx queues back to the pool */
	for (i = 0; i < imp_state.num_planes; i++) {
		while (!slist_empty(&imp_state.planes[i].list)) {
			slist_remove_head_container(&imp_state.planes[i].list,
						    struct imp_pkt, pkt,
						    entry);
			imp_pool_put(&imp_state.pool, pkt);
		}

		pthread_mutex_destroy(&imp_state.planes[i].lock);
	}

	/* free the per-plane Tx queues */
	free(imp_state.planes);
	imp_state.planes = NULL;

	/* free all pool entries */
	UET_IMP_INFO("pool: %u total entries allocated", imp_state.pool.total);
	imp_pool_finalize(&imp_state.pool);

	imp_state.enabled = false;

	UET_IMP_INFO("finalized");
}

int imp_shim_tx_pkt(struct uet_nic *nic,
		    void *pkt,
		    void *iphdr,
		    size_t pkt_size)
{
	struct imp_pkt *imp_pkt;
	struct timespec now;
	uint64_t delay_ns;
	uint32_t plane_idx;

	/* random drop check */
	if ((imp_state.drop_rate > 0) &&
	    ((rand() % 10000) < imp_state.drop_rate)) {
		UET_IMP_INFO("dropped packet (%zu bytes)", pkt_size);
		return 0;
	}

	/* get a packet buffer from the pool */
	imp_pkt = imp_pool_get(&imp_state.pool);
	if (imp_pkt == NULL) {
		UET_IMP_ERR("failed to get packet buffer from pool");
		return -ENOMEM;
	}

	memcpy(imp_pkt->pkt_data, pkt, pkt_size);
	imp_pkt->pkt_size  = pkt_size;
	imp_pkt->iphdr_off = (size_t)((uint8_t *)iphdr - (uint8_t *)pkt);

	/* calculate random delay and transmit time */
	clock_gettime(CLOCK_MONOTONIC, &now);

	delay_ns = (imp_state.delay_max > 0)
			? ((uint64_t)rand() % imp_state.delay_max) : 0;
	UET_IMP_DBG("delay packet (%lu)", delay_ns);

	/*
	 * Add the random delay to the current time to get the transmit time.
	 * Since tv_nsec is the sum of two sub-second values (each up to
	 * 999999999), it can overflow into the next second. If so, carry the
	 * extra second into tv_sec and normalize tv_nsec.
	 */
#define ONE_SEC 1000000000ULL
	imp_pkt->tx_time.tv_sec  = (now.tv_sec + (delay_ns / ONE_SEC));
	imp_pkt->tx_time.tv_nsec = (now.tv_nsec + (delay_ns % ONE_SEC));
	if (imp_pkt->tx_time.tv_nsec >= ONE_SEC) {
		imp_pkt->tx_time.tv_sec++;
		imp_pkt->tx_time.tv_nsec -= ONE_SEC;
	}

	/* select a plane for packet enqueue */
	if (imp_state.random_enq)
		plane_idx = (rand() % imp_state.num_planes);
	else
		plane_idx = (imp_state.enq_idx++ % imp_state.num_planes);

	imp_plane_enqueue(&imp_state.planes[plane_idx], imp_pkt);

	return 0;
}

bool imp_shim_is_enabled(void)
{
	return imp_state.enabled;
}

