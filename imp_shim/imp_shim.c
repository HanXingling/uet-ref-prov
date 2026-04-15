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

#include "uet_log.h"
#include "uet_nic.h"
#include "tomlc17.h"
#include "imp_shim.h"

/* initial number of packet buffers to pre-allocate per path */
#define IMP_POOL_INIT_PER_PATH 32

/* packet entry */
struct imp_pkt {
	struct imp_pkt  *next;       /* list pointer (free pool or tx queue) */
	size_t           pkt_size;   /* the size of the packet */
	size_t           iphdr_off;  /* offset of IP header from pkt_data */
	struct timespec  tx_time;    /* calculated transmit time */
	uint8_t          pkt_data[]; /* flexible size for max_pkt_size */
};

/* per-path Tx queue */
struct imp_path {
	struct imp_pkt  *head;  /* packet list */
	struct imp_pkt  *tail;
	pthread_mutex_t  lock;  /* mutex for list management */
	uint32_t         depth; /* current number of packets on the queue */
};

/* packet entry free pool - grows as needed, never shrinks */
struct imp_pool {
	struct imp_pkt  *free_head;  /* free list */
	pthread_mutex_t  lock;       /* mutex for list management */
	size_t           entry_size; /* sizeof(imp_pkt) + max_pkt_size */
	uint32_t         free_count; /* current number of free entries */
	uint32_t         total;      /* total number of entries allocated */
};

/* impairment shim state */
struct imp_shim_state {
	bool             enabled;
	struct uet_nic  *nic;

	bool             running;
	pthread_t        tx_thread;

	int              num_paths; /* number of Tx queues */
	int              drop_rate; /* hundredths of a percent */
	uint64_t         delay_max; /* nanoseconds (random 0..delay_max) */

	struct imp_path *paths;     /* Tx queues */
	uint32_t         enq_idx;   /* round-robin enqueue index */
	struct imp_pool  pool;      /* packet buffer free pool */
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
	struct imp_pkt *pkt;

	pthread_mutex_lock(&pool->lock);

	if (pool->free_head != NULL) {
		pkt = pool->free_head;
		pool->free_head = pkt->next;
		pkt->next = NULL;
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

	pkt->next = pool->free_head;
	pool->free_head = pkt;
	pool->free_count++;

	pthread_mutex_unlock(&pool->lock);
}

/*
 * Initialize the packet buffer free pool. Pre-allocates entries based on
 * (num_paths * IMP_POOL_INIT_PER_PATH).
 */
static int imp_pool_init(struct imp_pool *pool,
			 size_t max_pkt_size,
			 int num_paths)
{
	struct imp_pkt *pkt;
	int count;
	int i;

	memset(pool, 0, sizeof(*pool));
	pthread_mutex_init(&pool->lock, NULL);
	pool->entry_size = (sizeof(struct imp_pkt) + max_pkt_size);

	count = (num_paths * IMP_POOL_INIT_PER_PATH);

	for (i = 0; i < count; i++) {
		pkt = imp_pool_alloc_entry(pool);
		if (pkt == NULL) {
			UET_IMP_ERR("failed to pre-allocate pool entry");
			return -ENOMEM;
		}

		pkt->next = pool->free_head;
		pool->free_head = pkt;
		pool->free_count++;
	}

	UET_IMP_INFO("pool: pre-allocated %d entries (size = %zu bytes)",
		     count, pool->entry_size);

	return 0;
}

/*
 * Free all packet buffer free pool entries (any entries still on the path
 * queues must be drained before calling this function).
 */
static void imp_pool_finalize(struct imp_pool *pool)
{
	struct imp_pkt *pkt, *next;

	pkt = pool->free_head;
	while (pkt) {
		next = pkt->next;
		free(pkt);
		pkt = next;
	}

	pool->free_head = NULL;
	pool->free_count = 0;
	pool->total = 0;

	pthread_mutex_destroy(&pool->lock);
}

/* Enqueue a packet onto a path's Tx queue. */
static void imp_path_enqueue(struct imp_path *path,
			     struct imp_pkt *pkt)
{
	pthread_mutex_lock(&path->lock);

	pkt->next = NULL;

	if (path->tail)
		path->tail->next = pkt;
	else
		path->head = pkt;

	path->tail = pkt;
	path->depth++;

	pthread_mutex_unlock(&path->lock);
}

/*
 * Try to dequeue a packet from the front of a path's Tx queue if its transmit
 * time has been reached. Returns the packet if dequeued, NULL otherwise.
 */
static struct imp_pkt *imp_path_try_dequeue(struct imp_path *path,
					    struct timespec *now)
{
	struct imp_pkt *pkt = NULL;

	pthread_mutex_lock(&path->lock);

	if (path->head == NULL) {
		pthread_mutex_unlock(&path->lock);
		return NULL;
	}

	/* check if the head packet's transmit time has been reached */
	if ((now->tv_sec > path->head->tx_time.tv_sec) ||
	    ((now->tv_sec == path->head->tx_time.tv_sec) &&
	     (now->tv_nsec >= path->head->tx_time.tv_nsec))) {
		pkt = path->head;
		path->head = pkt->next;
		if (path->head == NULL)
			path->tail = NULL;
		pkt->next = NULL;
		path->depth--;
	}

	if (pkt == NULL) {
		pthread_mutex_unlock(&path->lock);
		UET_IMP_DBG("packet skipped");
		return NULL;
	}

	pthread_mutex_unlock(&path->lock);
	return pkt;
}

/*
 * Transmit thread.
 *
 * Processes all paths in round-robin fashion. For each path, attempts to
 * dequeue and transmit the head packet if its transmit time has been
 * reached. After transmission, the packet buffer is returned to the pool.
 */
static void *imp_tx_thread(void *arg)
{
	struct imp_shim_state *st = (struct imp_shim_state *)arg;
	struct timespec now;
	struct imp_pkt *pkt;
	int path_idx;

	UET_IMP_INFO("Tx thread started");

	while (st->running) {
		for (path_idx = 0; path_idx < st->num_paths; path_idx++) {
			clock_gettime(CLOCK_MONOTONIC, &now);

			pkt = imp_path_try_dequeue(&st->paths[path_idx], &now);
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

	/* num_paths (required) */
	val = toml_seek(result.toptab, "config.num_paths");
	if (val.type != TOML_INT64 || val.u.int64 < 1) {
		UET_IMP_ERR("config: num_paths must be a positive integer");
		toml_free(result);
		return -EINVAL;
	}
	imp_state.num_paths = (int)val.u.int64;

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

	UET_IMP_INFO("config: num_paths=%d drop_rate=%d delay_max=%lu ns",
		     imp_state.num_paths, imp_state.drop_rate,
		     (unsigned long)imp_state.delay_max);

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
			   imp_state.num_paths);
	if (rc != 0)
		return rc;

	/* allocate the per-path Tx queues */
	imp_state.paths = calloc(imp_state.num_paths,
				 sizeof(struct imp_path));
	if (imp_state.paths == NULL) {
		UET_IMP_ERR("failed to allocate %d paths",
			    imp_state.num_paths);
		imp_pool_finalize(&imp_state.pool);
		return -ENOMEM;
	}

	for (i = 0; i < imp_state.num_paths; i++)
		pthread_mutex_init(&imp_state.paths[i].lock, NULL);

	imp_state.enabled = true;
	imp_state.nic = nic;

	/* spawn the Tx thread */
	imp_state.running = true;
	rc = pthread_create(&imp_state.tx_thread, NULL, imp_tx_thread,
			    &imp_state);
	if (rc != 0) {
		UET_IMP_ERR("failed to create Tx thread: %s", strerror(rc));
		free(imp_state.paths);
		imp_state.paths = NULL;
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

	/* drain all the per-path Tx queues back to the pool */
	for (i = 0; i < imp_state.num_paths; i++) {
		while ((pkt = imp_state.paths[i].head) != NULL) {
			imp_state.paths[i].head = pkt->next;
			imp_pool_put(&imp_state.pool, pkt);
		}

		pthread_mutex_destroy(&imp_state.paths[i].lock);
	}

	/* free the per-path Tx queues */
	free(imp_state.paths);
	imp_state.paths = NULL;

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
	uint32_t path_idx;

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
	imp_pkt->next      = NULL;

	/* calculate random delay and transmit time */
	clock_gettime(CLOCK_MONOTONIC, &now);

	delay_ns = (imp_state.delay_max > 0)
			? ((uint64_t)rand() % imp_state.delay_max) : 0;
	UET_IMP_DBG("delay packet (%lu ns)", delay_ns);

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

	/* round-robin path selection and pkt insertion */
	//path_idx = (imp_state.enq_idx++ % imp_state.num_paths);
	/* random path selection and pkt insertion */
	path_idx = (rand() % imp_state.num_paths);
	imp_path_enqueue(&imp_state.paths[path_idx], imp_pkt);

	return 0;
}

bool imp_shim_is_enabled(void)
{
	return imp_state.enabled;
}

