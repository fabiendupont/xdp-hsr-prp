/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Frama-C/WP specification for seq_after().
 *
 * Verifies function contracts via deductive verification (WP plugin).
 * Complements the CBMC exhaustive proof with an independent proof
 * technique based on weakest precondition calculus + SMT solvers.
 *
 * Run with:
 *   frama-c -wp -wp-rte seq_after_spec.c
 */

#include <stdint.h>

typedef uint16_t __u16;
typedef int16_t  __s16;

/*@
  requires \true;
  assigns \nothing;

  behavior equal:
    assumes a == b;
    ensures \result == 0;

  behavior after:
    assumes a != b;
    assumes (int16_t)((__u16)(a - b)) > 0;
    ensures \result == 1;

  behavior boundary:
    assumes (int16_t)((__u16)(a - b)) == -32768;
    ensures \result == 0;

  behavior before:
    assumes a != b;
    assumes (int16_t)((__u16)(a - b)) < 0;
    assumes (int16_t)((__u16)(a - b)) != -32768;
    ensures \result == 0;
*/
int seq_after(__u16 a, __u16 b)
{
	__s16 diff = (__s16)((__u16)(a - b));

	if (diff == (__s16)(-32768))
		return 0;

	return diff > 0 ? 1 : 0;
}
