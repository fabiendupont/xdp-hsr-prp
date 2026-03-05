/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * CBMC harness for seq_after() — exhaustive proof over all 2^32 inputs.
 *
 * Proves 7 properties of 16-bit circular sequence comparison:
 *   1. Reflexivity:     seq_after(x, x) == false
 *   2. Increment:       seq_after(x+1, x) == true
 *   3. Reverse:         seq_after(x, x+1) == false
 *   4. Anti-symmetry:   !(seq_after(a,b) && seq_after(b,a))
 *   5. Wraparound:      seq_after(0, 65535) == true
 *   6. Boundary:        seq_after(x+32768, x) == false for all x
 *   7. Window:          if 0 < d < 32768 then seq_after(x+d, x) == true
 *
 * Run with:
 *   cbmc --unwind 1 --unwinding-assertions seq_after_harness.c
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

typedef uint16_t __u16;
typedef int16_t  __s16;

/* Include the function under test */
static inline bool seq_after(__u16 a, __u16 b)
{
	__s16 diff = (__s16)(a - b);

	if (diff == (__s16)(-32768))
		return false;

	return diff > 0;
}

/* CBMC nondet */
__u16 nondet_u16(void);

void harness_reflexivity(void)
{
	__u16 x = nondet_u16();

	assert(!seq_after(x, x));
}

void harness_increment(void)
{
	__u16 x = nondet_u16();
	__u16 xp1 = (__u16)(x + 1);

	assert(seq_after(xp1, x));
}

void harness_reverse(void)
{
	__u16 x = nondet_u16();
	__u16 xp1 = (__u16)(x + 1);

	assert(!seq_after(x, xp1));
}

void harness_anti_symmetry(void)
{
	__u16 a = nondet_u16();
	__u16 b = nondet_u16();

	assert(!(seq_after(a, b) && seq_after(b, a)));
}

void harness_wraparound(void)
{
	assert(seq_after(0, 65535));
}

void harness_boundary(void)
{
	__u16 x = nondet_u16();
	__u16 xp = (__u16)(x + 32768);

	assert(!seq_after(xp, x));
}

void harness_window(void)
{
	__u16 x = nondet_u16();
	__u16 d = nondet_u16();

	/* Constrain d to valid window: 0 < d < 32768 */
	__CPROVER_assume(d > 0 && d < 32768);

	__u16 y = (__u16)(x + d);

	assert(seq_after(y, x));
}

int main(void)
{
	harness_reflexivity();
	harness_increment();
	harness_reverse();
	harness_anti_symmetry();
	harness_wraparound();
	harness_boundary();
	harness_window();

	return 0;
}
