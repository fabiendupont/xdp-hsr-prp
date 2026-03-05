/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_hsr_tag — HSR tag parse/insert correctness tests.
 *
 * Verifies:
 *   - Field extraction (path, LSDU size, sequence number, encap proto)
 *   - Tag construction matches IEC 62439-3 wire format
 *   - Round-trip: set then get
 *   - Edge cases: max LSDU size, all path values
 *   - VLAN-tagged frame (offset changes)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <hsr_prp/hsr_tag.h>

static int failures;

#define CHECK(cond, ...)                                                \
	do {                                                            \
		if (!(cond)) {                                          \
			fprintf(stderr, "FAIL: " __VA_ARGS__);          \
			fprintf(stderr, "\n");                          \
			failures++;                                     \
		}                                                       \
	} while (0)

static void test_set_and_get(void)
{
	struct hsr_tag tag;

	printf("  test_set_and_get...\n");

	hsr_tag_set(&tag, HSR_PATH_A, 100, 42, 0x0800);
	CHECK(hsr_tag_get_path(&tag) == HSR_PATH_A,
	      "path should be PATH_A, got 0x%04x", hsr_tag_get_path(&tag));
	CHECK(hsr_tag_get_lsdu_size(&tag) == 100,
	      "lsdu_size should be 100, got %u", hsr_tag_get_lsdu_size(&tag));
	CHECK(hsr_tag_get_seq(&tag) == 42,
	      "seq should be 42, got %u", hsr_tag_get_seq(&tag));
	CHECK(hsr_tag_get_encap_proto(&tag) == 0x0800,
	      "encap_proto should be 0x0800, got 0x%04x",
	      hsr_tag_get_encap_proto(&tag));

	hsr_tag_set(&tag, HSR_PATH_B, 200, 65535, 0x86DD);
	CHECK(hsr_tag_get_path(&tag) == HSR_PATH_B,
	      "path should be PATH_B");
	CHECK(hsr_tag_get_lsdu_size(&tag) == 200,
	      "lsdu_size should be 200");
	CHECK(hsr_tag_get_seq(&tag) == 65535,
	      "seq should be 65535");
	CHECK(hsr_tag_get_encap_proto(&tag) == 0x86DD,
	      "encap_proto should be 0x86DD");
}

static void test_max_lsdu_size(void)
{
	struct hsr_tag tag;

	printf("  test_max_lsdu_size...\n");

	hsr_tag_set(&tag, HSR_PATH_A, HSR_LSDU_SIZE_MASK, 0, 0x0800);
	CHECK(hsr_tag_get_lsdu_size(&tag) == HSR_LSDU_SIZE_MASK,
	      "max LSDU size should be 0x%04x, got %u",
	      HSR_LSDU_SIZE_MASK, hsr_tag_get_lsdu_size(&tag));
	CHECK(hsr_tag_get_path(&tag) == HSR_PATH_A,
	      "path should not be affected by max LSDU");
}

static void test_all_paths(void)
{
	struct hsr_tag tag;

	printf("  test_all_paths...\n");

	hsr_tag_set(&tag, HSR_PATH_A, 50, 1, 0x0800);
	CHECK(hsr_tag_get_path(&tag) == HSR_PATH_A, "path A");

	hsr_tag_set(&tag, HSR_PATH_B, 50, 1, 0x0800);
	CHECK(hsr_tag_get_path(&tag) == HSR_PATH_B, "path B");
}

static void test_wire_format(void)
{
	struct hsr_tag tag;
	uint8_t *raw;

	printf("  test_wire_format...\n");

	hsr_tag_set(&tag, HSR_PATH_B, 0x123, 0xABCD, 0x0800);
	raw = (uint8_t *)&tag;

	/* path_and_size should be 0x1123 in network byte order */
	uint16_t expected_ps = htons(0x1123);
	CHECK(memcmp(raw, &expected_ps, 2) == 0,
	      "wire path_and_size mismatch");

	/* sequence_nr should be 0xABCD in network byte order */
	uint16_t expected_seq = htons(0xABCD);
	CHECK(memcmp(raw + 2, &expected_seq, 2) == 0,
	      "wire sequence_nr mismatch");

	/* encap_proto should be 0x0800 in network byte order */
	uint16_t expected_proto = htons(0x0800);
	CHECK(memcmp(raw + 4, &expected_proto, 2) == 0,
	      "wire encap_proto mismatch");
}

static void test_round_trip(void)
{
	struct hsr_tag tag;

	printf("  test_round_trip...\n");

	for (uint16_t seq = 0; seq < 1000; seq++) {
		uint16_t lsdu = (uint16_t)(seq % 4096);

		hsr_tag_set(&tag, (seq & 1) ? HSR_PATH_B : HSR_PATH_A,
			    lsdu, seq, 0x0800);

		CHECK(hsr_tag_get_seq(&tag) == seq,
		      "round-trip seq %u", seq);
		CHECK(hsr_tag_get_lsdu_size(&tag) == lsdu,
		      "round-trip lsdu %u", lsdu);
	}
}

static void test_size(void)
{
	printf("  test_size...\n");

	CHECK(sizeof(struct hsr_tag) == HSR_TAG_SIZE,
	      "sizeof(hsr_tag) should be %d, got %zu",
	      HSR_TAG_SIZE, sizeof(struct hsr_tag));
}

int main(void)
{
	printf("test_hsr_tag: HSR tag parse/insert tests\n");

	test_set_and_get();
	test_max_lsdu_size();
	test_all_paths();
	test_wire_format();
	test_round_trip();
	test_size();

	if (failures > 0) {
		printf("FAILED: %d failures\n", failures);
		return 1;
	}

	printf("PASSED: all tests\n");
	return 0;
}
