/* SPDX-License-Identifier: BSD-2-Clause */

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

struct hsr_prp_node {
	uint8_t  mac[ETH_ALEN];
	uint8_t  valid;
	uint8_t  _pad;
	uint64_t last_seen_a;
	uint64_t last_seen_b;
	uint16_t last_seq;
};

struct hsr_prp_nodetable {
	struct hsr_prp_node *entries;
	uint32_t capacity;
	uint32_t count;
	uint32_t timeout_ms;
	pthread_mutex_t lock;
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

struct hsr_prp_nodetable *hsr_prp_nodetable_create(uint32_t capacity,
						   uint32_t timeout_ms)
{
	struct hsr_prp_nodetable *nt;

	if (capacity == 0)
		return NULL;

	nt = calloc(1, sizeof(*nt));
	if (!nt)
		return NULL;

	nt->entries = calloc(capacity, sizeof(struct hsr_prp_node));
	if (!nt->entries) {
		free(nt);
		return NULL;
	}

	nt->capacity = capacity;
	nt->timeout_ms = timeout_ms;
	pthread_mutex_init(&nt->lock, NULL);

	return nt;
}

void hsr_prp_nodetable_destroy(struct hsr_prp_nodetable *nt)
{
	if (!nt)
		return;

	pthread_mutex_destroy(&nt->lock);
	free(nt->entries);
	free(nt);
}

static struct hsr_prp_node *find_node(const struct hsr_prp_nodetable *nt,
				      const uint8_t *mac)
{
	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (nt->entries[i].valid &&
		    memcmp(nt->entries[i].mac, mac, ETH_ALEN) == 0)
			return &nt->entries[i];
	}
	return NULL;
}

static struct hsr_prp_node *find_free_slot(const struct hsr_prp_nodetable *nt)
{
	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (!nt->entries[i].valid)
			return &nt->entries[i];
	}
	return NULL;
}

static struct hsr_prp_node *find_oldest(const struct hsr_prp_nodetable *nt)
{
	struct hsr_prp_node *oldest = NULL;
	uint64_t oldest_ts = UINT64_MAX;

	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (!nt->entries[i].valid)
			continue;

		uint64_t ts = nt->entries[i].last_seen_a;
		if (nt->entries[i].last_seen_b > ts)
			ts = nt->entries[i].last_seen_b;

		if (ts < oldest_ts) {
			oldest_ts = ts;
			oldest = &nt->entries[i];
		}
	}
	return oldest;
}

int hsr_prp_nodetable_add(struct hsr_prp_nodetable *nt,
			  const uint8_t *mac, uint8_t port,
			  uint16_t seq_nr)
{
	struct hsr_prp_node *node;
	uint64_t ts;

	if (!nt || !mac)
		return -EINVAL;

	ts = now_ns();

	pthread_mutex_lock(&nt->lock);

	/* Check if node already exists */
	node = find_node(nt, mac);
	if (node) {
		if (port == 0)
			node->last_seen_a = ts;
		else
			node->last_seen_b = ts;
		node->last_seq = seq_nr;
		pthread_mutex_unlock(&nt->lock);
		return 0;
	}

	/* Find a free slot */
	node = find_free_slot(nt);
	if (!node) {
		/* Table full — evict oldest */
		node = find_oldest(nt);
		if (!node) {
			pthread_mutex_unlock(&nt->lock);
			return -ENOMEM;
		}
		nt->count--;
	}

	memcpy(node->mac, mac, ETH_ALEN);
	node->valid = 1;
	node->last_seq = seq_nr;

	if (port == 0) {
		node->last_seen_a = ts;
		node->last_seen_b = 0;
	} else {
		node->last_seen_a = 0;
		node->last_seen_b = ts;
	}

	nt->count++;
	pthread_mutex_unlock(&nt->lock);
	return 0;
}

int hsr_prp_nodetable_remove(struct hsr_prp_nodetable *nt,
			     const uint8_t *mac)
{
	struct hsr_prp_node *node;

	if (!nt || !mac)
		return -EINVAL;

	pthread_mutex_lock(&nt->lock);

	node = find_node(nt, mac);
	if (!node) {
		pthread_mutex_unlock(&nt->lock);
		return -ENOENT;
	}

	node->valid = 0;
	nt->count--;
	pthread_mutex_unlock(&nt->lock);
	return 0;
}

bool hsr_prp_nodetable_lookup(const struct hsr_prp_nodetable *nt,
			      const uint8_t *mac)
{
	bool found;

	if (!nt || !mac)
		return false;

	pthread_mutex_lock((pthread_mutex_t *)&nt->lock);
	found = find_node(nt, mac) != NULL;
	pthread_mutex_unlock((pthread_mutex_t *)&nt->lock);
	return found;
}

int hsr_prp_nodetable_timeout_scan(struct hsr_prp_nodetable *nt)
{
	uint64_t ts;
	uint64_t timeout_ns;
	int removed = 0;

	if (!nt)
		return -EINVAL;

	ts = now_ns();
	timeout_ns = (uint64_t)nt->timeout_ms * 1000000ULL;

	pthread_mutex_lock(&nt->lock);

	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (!nt->entries[i].valid)
			continue;

		uint64_t last = nt->entries[i].last_seen_a;
		if (nt->entries[i].last_seen_b > last)
			last = nt->entries[i].last_seen_b;

		if (ts - last > timeout_ns) {
			nt->entries[i].valid = 0;
			nt->count--;
			removed++;
		}
	}

	pthread_mutex_unlock(&nt->lock);
	return removed;
}

int hsr_prp_nodetable_dump(const struct hsr_prp_nodetable *nt,
			   void (*cb)(const uint8_t *mac,
				      uint64_t last_a, uint64_t last_b,
				      uint16_t last_seq, void *arg),
			   void *arg)
{
	int count = 0;

	if (!nt || !cb)
		return -EINVAL;

	pthread_mutex_lock((pthread_mutex_t *)&nt->lock);

	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (!nt->entries[i].valid)
			continue;

		cb(nt->entries[i].mac,
		   nt->entries[i].last_seen_a,
		   nt->entries[i].last_seen_b,
		   nt->entries[i].last_seq,
		   arg);
		count++;
	}

	pthread_mutex_unlock((pthread_mutex_t *)&nt->lock);
	return count;
}

int hsr_prp_nodetable_ring_break_check(const struct hsr_prp_nodetable *nt,
					uint32_t threshold_ms)
{
	uint64_t ts;
	uint64_t threshold_ns;
	int result = 0;

	if (!nt || threshold_ms == 0)
		return -EINVAL;

	ts = now_ns();
	threshold_ns = (uint64_t)threshold_ms * 1000000ULL;

	pthread_mutex_lock((pthread_mutex_t *)&nt->lock);

	for (uint32_t i = 0; i < nt->capacity; i++) {
		if (!nt->entries[i].valid)
			continue;

		/*
		 * A node seen recently on one port but not the other
		 * indicates a ring break on the missing port's path.
		 */
		int a_recent = nt->entries[i].last_seen_a != 0 &&
			       (ts - nt->entries[i].last_seen_a) < threshold_ns;
		int b_recent = nt->entries[i].last_seen_b != 0 &&
			       (ts - nt->entries[i].last_seen_b) < threshold_ns;

		if (a_recent && !b_recent)
			result |= 0x02; /* port B missing */
		if (b_recent && !a_recent)
			result |= 0x01; /* port A missing */
	}

	pthread_mutex_unlock((pthread_mutex_t *)&nt->lock);
	return result;
}
