/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

/*
 * test_nodetable — Node table correctness tests.
 *
 * Verifies:
 *   - Add and lookup by MAC
 *   - Update existing entry (same MAC, different port)
 *   - Remove entry
 *   - Lookup miss for unknown MAC
 *   - Capacity eviction (oldest entry replaced)
 *   - Timeout scan removes stale entries
 *   - Dump iterates all valid entries
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hsr_prp/hsr_prp_userspace.h>

static int failures;

#define CHECK(cond, ...)                                                \
	do {                                                            \
		if (!(cond)) {                                          \
			fprintf(stderr, "FAIL: " __VA_ARGS__);          \
			fprintf(stderr, "\n");                          \
			failures++;                                     \
		}                                                       \
	} while (0)

static void test_create_destroy(void)
{
	struct hsr_prp_nodetable *nt;

	nt = hsr_prp_nodetable_create(16, 60000);
	CHECK(nt != NULL, "create should succeed");
	hsr_prp_nodetable_destroy(nt);

	nt = hsr_prp_nodetable_create(0, 60000);
	CHECK(nt == NULL, "create with capacity 0 should fail");
}

static void test_add_lookup(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	uint8_t mac2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	uint8_t mac3[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};

	nt = hsr_prp_nodetable_create(16, 60000);
	CHECK(nt != NULL, "create");

	CHECK(hsr_prp_nodetable_add(nt, mac1, 0, 100) == 0,
	      "add mac1 should succeed");
	CHECK(hsr_prp_nodetable_add(nt, mac2, 1, 200) == 0,
	      "add mac2 should succeed");

	CHECK(hsr_prp_nodetable_lookup(nt, mac1) == true,
	      "lookup mac1 should find it");
	CHECK(hsr_prp_nodetable_lookup(nt, mac2) == true,
	      "lookup mac2 should find it");
	CHECK(hsr_prp_nodetable_lookup(nt, mac3) == false,
	      "lookup unknown mac3 should miss");

	hsr_prp_nodetable_destroy(nt);
}

static void test_update_existing(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

	nt = hsr_prp_nodetable_create(16, 60000);

	/* Add on port A */
	CHECK(hsr_prp_nodetable_add(nt, mac, 0, 100) == 0, "add port A");

	/* Update on port B — same MAC, different port */
	CHECK(hsr_prp_nodetable_add(nt, mac, 1, 101) == 0, "update port B");

	/* Should still be found */
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == true, "lookup after update");

	hsr_prp_nodetable_destroy(nt);
}

static void test_remove(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	uint8_t mac2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

	nt = hsr_prp_nodetable_create(16, 60000);

	hsr_prp_nodetable_add(nt, mac, 0, 100);
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == true, "before remove");

	CHECK(hsr_prp_nodetable_remove(nt, mac) == 0, "remove should succeed");
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == false, "after remove");

	CHECK(hsr_prp_nodetable_remove(nt, mac2) == -2 /* ENOENT */,
	      "remove unknown should fail");

	hsr_prp_nodetable_destroy(nt);
}

static void test_eviction(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};

	/* Capacity 3 — fourth add should evict oldest */
	nt = hsr_prp_nodetable_create(3, 60000);

	mac[5] = 0x01;
	hsr_prp_nodetable_add(nt, mac, 0, 1);
	usleep(1000);

	mac[5] = 0x02;
	hsr_prp_nodetable_add(nt, mac, 0, 2);
	usleep(1000);

	mac[5] = 0x03;
	hsr_prp_nodetable_add(nt, mac, 0, 3);
	usleep(1000);

	/* Table full — add fourth, should evict mac[5]=0x01 (oldest) */
	mac[5] = 0x04;
	CHECK(hsr_prp_nodetable_add(nt, mac, 0, 4) == 0,
	      "add beyond capacity should succeed via eviction");

	mac[5] = 0x01;
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == false,
	      "oldest entry should be evicted");

	mac[5] = 0x04;
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == true,
	      "new entry should exist");

	mac[5] = 0x02;
	CHECK(hsr_prp_nodetable_lookup(nt, mac) == true,
	      "second entry should survive");

	hsr_prp_nodetable_destroy(nt);
}

static void test_timeout_scan(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	uint8_t mac2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	int removed;

	/* 10ms timeout — entries added now will expire after sleep */
	nt = hsr_prp_nodetable_create(16, 10);

	hsr_prp_nodetable_add(nt, mac1, 0, 100);
	hsr_prp_nodetable_add(nt, mac2, 1, 200);

	/* Wait for timeout */
	usleep(20000); /* 20ms > 10ms timeout */

	removed = hsr_prp_nodetable_timeout_scan(nt);
	CHECK(removed == 2, "timeout scan should remove 2 entries (got %d)",
	      removed);

	CHECK(hsr_prp_nodetable_lookup(nt, mac1) == false,
	      "mac1 should be timed out");
	CHECK(hsr_prp_nodetable_lookup(nt, mac2) == false,
	      "mac2 should be timed out");

	hsr_prp_nodetable_destroy(nt);
}

struct dump_ctx {
	int count;
	uint8_t last_mac[6];
};

static void dump_cb(const uint8_t *mac,
		    uint64_t last_a, uint64_t last_b,
		    uint16_t last_seq, void *arg)
{
	struct dump_ctx *ctx = arg;

	(void)last_a;
	(void)last_b;
	(void)last_seq;

	memcpy(ctx->last_mac, mac, 6);
	ctx->count++;
}

static void test_dump(void)
{
	struct hsr_prp_nodetable *nt;
	uint8_t mac1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	uint8_t mac2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	struct dump_ctx ctx = {0};

	nt = hsr_prp_nodetable_create(16, 60000);

	hsr_prp_nodetable_add(nt, mac1, 0, 100);
	hsr_prp_nodetable_add(nt, mac2, 1, 200);

	int ret = hsr_prp_nodetable_dump(nt, dump_cb, &ctx);
	CHECK(ret == 2, "dump should return 2 entries (got %d)", ret);
	CHECK(ctx.count == 2, "callback should be called twice");

	hsr_prp_nodetable_destroy(nt);
}

static void test_null_safety(void)
{
	CHECK(hsr_prp_nodetable_create(0, 0) == NULL,
	      "create(0,0) should return NULL");
	CHECK(hsr_prp_nodetable_add(NULL, NULL, 0, 0) == -22 /* EINVAL */,
	      "add(NULL) should fail");
	CHECK(hsr_prp_nodetable_remove(NULL, NULL) == -22 /* EINVAL */,
	      "remove(NULL) should fail");
	CHECK(hsr_prp_nodetable_lookup(NULL, NULL) == false,
	      "lookup(NULL) should return false");
	CHECK(hsr_prp_nodetable_timeout_scan(NULL) == -22 /* EINVAL */,
	      "timeout_scan(NULL) should fail");
	CHECK(hsr_prp_nodetable_dump(NULL, NULL, NULL) == -22 /* EINVAL */,
	      "dump(NULL) should fail");

	hsr_prp_nodetable_destroy(NULL); /* should not crash */
}

int main(void)
{
	printf("test_nodetable: node table correctness tests\n\n");

	test_create_destroy();
	test_add_lookup();
	test_update_existing();
	test_remove();
	test_eviction();
	test_timeout_scan();
	test_dump();
	test_null_safety();

	printf("\n");
	if (failures > 0) {
		printf("  %d FAILURES\n", failures);
		return 1;
	}

	printf("  ALL PASSED\n");
	return 0;
}
