/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_prp_rct — PRP RCT parse/append correctness tests.
 *
 * Verifies:
 *   - Field extraction (sequence, LAN ID, LSDU size)
 *   - RCT construction matches IEC 62439-3 wire format
 *   - prp_rct_valid() returns true for valid RCT, false otherwise
 *   - Round-trip: set then get
 *   - False positive: 0x88FB in payload but LSDU mismatch
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include <hsr_prp/prp_rct.h>

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
	struct prp_rct rct;

	printf("  test_set_and_get...\n");

	prp_rct_set(&rct, 42, PRP_LAN_A, 100);
	CHECK(prp_rct_get_seq(&rct) == 42,
	      "seq should be 42, got %u", prp_rct_get_seq(&rct));
	CHECK(prp_rct_get_lan(&rct) == PRP_LAN_A,
	      "LAN should be LAN_A, got 0x%04x", prp_rct_get_lan(&rct));
	CHECK(prp_rct_get_lsdu_size(&rct) == 100,
	      "lsdu_size should be 100, got %u", prp_rct_get_lsdu_size(&rct));
	CHECK(prp_rct_valid(&rct), "should be valid PRP RCT");

	prp_rct_set(&rct, 65535, PRP_LAN_B, 200);
	CHECK(prp_rct_get_seq(&rct) == 65535, "seq should be 65535");
	CHECK(prp_rct_get_lan(&rct) == PRP_LAN_B, "LAN should be LAN_B");
	CHECK(prp_rct_get_lsdu_size(&rct) == 200, "lsdu_size should be 200");
	CHECK(prp_rct_valid(&rct), "should be valid PRP RCT");
}

static void test_valid(void)
{
	struct prp_rct rct;

	printf("  test_valid...\n");

	/* Valid RCT */
	prp_rct_set(&rct, 0, PRP_LAN_A, 50);
	CHECK(prp_rct_valid(&rct), "valid RCT should return true");

	/* Invalid: wrong suffix */
	rct.prp_suffix = htons(0x1234);
	CHECK(!prp_rct_valid(&rct), "wrong suffix should return false");

	/* Invalid: zero suffix */
	rct.prp_suffix = 0;
	CHECK(!prp_rct_valid(&rct), "zero suffix should return false");
}

static void test_wire_format(void)
{
	struct prp_rct rct;
	uint8_t *raw;

	printf("  test_wire_format...\n");

	prp_rct_set(&rct, 0xABCD, PRP_LAN_B, 0x123);
	raw = (uint8_t *)&rct;

	/* sequence_nr should be 0xABCD in network byte order */
	uint16_t expected_seq = htons(0xABCD);
	CHECK(memcmp(raw, &expected_seq, 2) == 0,
	      "wire sequence_nr mismatch");

	/* lan_and_size should be 0xB123 in network byte order */
	uint16_t expected_ls = htons(0xB123);
	CHECK(memcmp(raw + 2, &expected_ls, 2) == 0,
	      "wire lan_and_size mismatch");

	/* prp_suffix should be 0x88FB in network byte order */
	uint16_t expected_suffix = htons(0x88FB);
	CHECK(memcmp(raw + 4, &expected_suffix, 2) == 0,
	      "wire prp_suffix mismatch");
}

static void test_round_trip(void)
{
	struct prp_rct rct;

	printf("  test_round_trip...\n");

	for (uint16_t seq = 0; seq < 1000; seq++) {
		uint16_t lsdu = (uint16_t)(seq % 4096);
		uint16_t lan = (seq & 1) ? PRP_LAN_B : PRP_LAN_A;

		prp_rct_set(&rct, seq, lan, lsdu);

		CHECK(prp_rct_get_seq(&rct) == seq,
		      "round-trip seq %u", seq);
		CHECK(prp_rct_get_lsdu_size(&rct) == lsdu,
		      "round-trip lsdu %u", lsdu);
		CHECK(prp_rct_get_lan(&rct) == lan,
		      "round-trip lan 0x%04x", lan);
		CHECK(prp_rct_valid(&rct), "round-trip valid");
	}
}

static void test_false_positive(void)
{
	printf("  test_false_positive...\n");

	/*
	 * Scenario: payload happens to end with 0x88FB but LSDU size
	 * does not match actual frame length. The LSDU consistency check
	 * should reject this as a false positive.
	 *
	 * Simulate a 100-byte payload (after Ethernet header) where the
	 * last 2 bytes happen to be 0x88FB but the LSDU_size field
	 * (bytes -4 to -3 from end) contains a wrong value.
	 */
	uint8_t frame[114]; /* 14 (eth) + 100 (payload) */
	struct prp_rct *rct;

	memset(frame, 0xAA, sizeof(frame));

	/* Plant 0x88FB at the end */
	frame[112] = 0x88;
	frame[113] = 0xFB;

	/* RCT would be at frame[108..113] */
	rct = (struct prp_rct *)&frame[108];

	/* The suffix is correct */
	CHECK(prp_rct_valid(rct), "suffix matches");

	/*
	 * But the LSDU_size won't match 100 (the actual payload size)
	 * because the "lan_and_size" bytes are 0xAAAA, giving
	 * LSDU size = 0x0AAA = 2730, not 100.
	 */
	uint16_t lsdu = prp_rct_get_lsdu_size(rct);
	uint16_t expected = 100; /* payload after Ethernet header */
	CHECK(lsdu != expected,
	      "false positive: LSDU %u should not match %u", lsdu, expected);
}

static void test_size(void)
{
	printf("  test_size...\n");

	CHECK(sizeof(struct prp_rct) == PRP_RCT_SIZE,
	      "sizeof(prp_rct) should be %d, got %zu",
	      PRP_RCT_SIZE, sizeof(struct prp_rct));
}

int main(void)
{
	printf("test_prp_rct: PRP RCT parse/append tests\n");

	test_set_and_get();
	test_valid();
	test_wire_format();
	test_round_trip();
	test_false_positive();
	test_size();

	if (failures > 0) {
		printf("FAILED: %d failures\n", failures);
		return 1;
	}

	printf("PASSED: all tests\n");
	return 0;
}
