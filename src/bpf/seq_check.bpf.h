/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_SEQ_CHECK_BPF_H
#define HSR_PRP_SEQ_CHECK_BPF_H

#include <stdbool.h>

#ifdef __BPF__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint16_t __u16;
typedef int16_t  __s16;
#endif

/*
 * seq_after - 16-bit circular sequence comparison.
 *
 * Returns true if @a is sequentially after @b in 16-bit circular space.
 * Uses signed difference to handle wraparound correctly.
 *
 * The ambiguous boundary (diff == INT16_MIN, i.e., exactly 32768 apart)
 * is treated as NOT after, to avoid false positives in duplicate detection.
 *
 * Properties (proven by CBMC for all 2^32 input combinations):
 *   1. seq_after(x, x) == false                          (reflexivity)
 *   2. seq_after(x+1, x) == true                         (increment)
 *   3. seq_after(x, x+1) == false                        (reverse)
 *   4. anti-symmetry: !(seq_after(a,b) && seq_after(b,a))
 *   5. seq_after(0, 65535) == true                        (wraparound)
 *   6. seq_after(32768, 0) == false                       (boundary)
 *   7. seq_after(x, x+32768) == false for all x          (boundary offset)
 */
static inline bool seq_after(__u16 a, __u16 b)
{
	__s16 diff = (__s16)(a - b);

	if (diff == (__s16)(-32768))
		return false;

	return diff > 0;
}

#endif /* HSR_PRP_SEQ_CHECK_BPF_H */
