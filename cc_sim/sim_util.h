#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>

struct spsc_ring {
	void *buf;
	uint32_t cap;
	uint32_t head;
	uint32_t tail;
};

struct red_cfg {
	uint32_t low_thresh;
	uint32_t high_thresh;
	float avg_len;
	float pmax;
	float ewm;
};

static __always_inline void ring_deq_head(struct spsc_ring *ring, void *dst, size_t len)
{
	memcpy(dst, ring->buf + ring->head * len, len);

	if (ring->head < ring->cap)
		ring->head = ring->head + 1;
	else
		ring->head = 0;
}

static __always_inline void ring_enq_tail(struct spsc_ring *ring, void *src, size_t len)
{
	if (ring->tail < ring->cap) {
		memcpy(ring->buf + ring->tail * len, src, len);
		ring->tail = ring->tail + 1;
		return;
	}

	memcpy(ring->buf + ring->cap * len, src, len);
	ring->tail = 0;
}

static __always_inline bool ring_peek_head(struct spsc_ring *ring, void *dst, size_t len)
{
	if (ring->tail == ring->head)
		return false;

	memcpy(dst, ring->buf + ring->head * len, len);

	return true;
}

static __always_inline bool ring_peek_tail(struct spsc_ring *ring, void *dst, size_t len)
{
	if (ring->tail == ring->head)
		return false;
	uint32_t pos;

	if (ring->tail)
		pos = ring->tail - 1;
	else
		pos = ring->cap;

	memcpy(dst, ring->buf + pos * len, len);

	return true;
}

static __always_inline uint32_t ring_count(struct spsc_ring *ring)
{
	if (ring->tail >= ring->head)
		return ring->tail - ring->head;
	return ring->tail + ring->cap + 1 - ring->head;
}

static __always_inline bool red_mark(uint32_t qlen, struct red_cfg *red)
{
	red->avg_len = (1 - red->ewm) * qlen + red->ewm * red->avg_len;

	if (red->avg_len >= red->high_thresh)
		return true;

	if (red->avg_len <= red->low_thresh)
		return false;

	float p = red->pmax * (red->avg_len - red->low_thresh)
			/ (red->high_thresh - red->low_thresh);

	return (float) rand() / RAND_MAX < p;
}

static __always_inline bool later_than(struct timespec lhs, struct timespec rhs)
{
	return lhs.tv_sec > rhs.tv_sec || (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec >= rhs.tv_nsec);
}

static __always_inline struct timespec add_time(struct timespec base, uint32_t nsec)
{
	base.tv_nsec += nsec;
	while (base.tv_nsec >= 1000000000) {
		base.tv_nsec -= 1000000000;
		base.tv_sec++;
	}
	return base;
}

static inline uint32_t elapsed_usec(struct timespec start, struct timespec end)
{
	uint64_t delta_nsec = end.tv_nsec - start.tv_nsec
						+ (end.tv_sec - start.tv_sec) * 1000000000;

	return delta_nsec / 1000;
}

static inline bool mod_lower_than(uint32_t a, uint32_t b)
{
	return b != a && b - a < (1 << 31);
}
