/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_seq_after — Exhaustive test of seq_after() for 16-bit circular
 * sequence comparison.
 *
 * Tests all 7 properties that CBMC also proves:
 *   1. Reflexivity:     seq_after(x, x) == false
 *   2. Increment:       seq_after(x+1, x) == true
 *   3. Reverse:         seq_after(x, x+1) == false
 *   4. Anti-symmetry:   !(seq_after(a,b) && seq_after(b,a))
 *   5. Wraparound:      seq_after(0, 65535) == true
 *   6. Boundary:        seq_after(32768, 0) == false
 *   7. Boundary offset: seq_after(x, x+32768) == false for all x
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../../src/bpf/seq_check.bpf.h"

static int failures;

#define CHECK(cond, ...)                                                \
	do {                                                            \
		if (!(cond)) {                                          \
			fprintf(stderr, "FAIL: " __VA_ARGS__);          \
			fprintf(stderr, "\n");                          \
			failures++;                                     \
		}                                                       \
	} while (0)

static void test_reflexivity(void)
{
	printf("  Property 1: reflexivity...\n");
	for (uint32_t x = 0; x <= 65535; x++) {
		CHECK(!seq_after((__u16)x, (__u16)x),
		      "seq_after(%u, %u) should be false", x, x);
	}
}

static void test_increment(void)
{
	printf("  Property 2: increment...\n");
	for (uint32_t x = 0; x <= 65535; x++) {
		__u16 xp1 = (__u16)(x + 1);
		CHECK(seq_after(xp1, (__u16)x),
		      "seq_after(%u, %u) should be true", xp1, (__u16)x);
	}
}

static void test_reverse(void)
{
	printf("  Property 3: reverse...\n");
	for (uint32_t x = 0; x <= 65535; x++) {
		__u16 xp1 = (__u16)(x + 1);
		CHECK(!seq_after((__u16)x, xp1),
		      "seq_after(%u, %u) should be false", (__u16)x, xp1);
	}
}

static void test_anti_symmetry(void)
{
	printf("  Property 4: anti-symmetry (sampled)...\n");
	/*
	 * Full enumeration of 2^32 pairs is done by CBMC.
	 * Here we sample representative cases.
	 */
	for (uint32_t a = 0; a <= 65535; a += 7) {
		for (uint32_t b = 0; b <= 65535; b += 7) {
			if (seq_after((__u16)a, (__u16)b) &&
			    seq_after((__u16)b, (__u16)a)) {
				CHECK(0, "anti-symmetry violated: "
				      "seq_after(%u,%u) && seq_after(%u,%u)",
				      a, b, b, a);
			}
		}
	}
}

static void test_wraparound(void)
{
	printf("  Property 5: wraparound...\n");
	CHECK(seq_after(0, 65535),
	      "seq_after(0, 65535) should be true");
	CHECK(seq_after(1, 65535),
	      "seq_after(1, 65535) should be true");
	CHECK(seq_after(2, 65534),
	      "seq_after(2, 65534) should be true");
}

static void test_boundary(void)
{
	printf("  Property 6: boundary (32768 apart -> false)...\n");
	CHECK(!seq_after(32768, 0),
	      "seq_after(32768, 0) should be false");
	CHECK(!seq_after(0, 32768),
	      "seq_after(0, 32768) should be false");
}

static void test_boundary_offset(void)
{
	printf("  Property 7: boundary offset...\n");
	for (uint32_t x = 0; x <= 65535; x++) {
		__u16 xp = (__u16)(x + 32768);
		CHECK(!seq_after((__u16)x, xp),
		      "seq_after(%u, %u) should be false", (__u16)x, xp);
	}
}

int main(void)
{
	printf("test_seq_after: testing all 7 properties\n");

	test_reflexivity();
	test_increment();
	test_reverse();
	test_anti_symmetry();
	test_wraparound();
	test_boundary();
	test_boundary_offset();

	if (failures > 0) {
		printf("FAILED: %d failures\n", failures);
		return 1;
	}

	printf("PASSED: all properties verified\n");
	return 0;
}
