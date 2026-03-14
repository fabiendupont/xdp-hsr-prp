/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_PRP_RCT_H
#define HSR_PRP_PRP_RCT_H

#include <linux/types.h>
#include <stdbool.h>

#include "hsr_prp_common.h"

/*
 * PRP Redundancy Control Trailer: 6 bytes, appended after payload.
 *
 * Wire layout (IEC 62439-3 clause 5.3.2):
 *   Byte 0-1: sequence_nr   — 16-bit sequence number
 *   Byte 2-3: lan_and_size  — bits[15:12]=LAN_ID, bits[11:0]=LSDU size
 *   Byte 4-5: prp_suffix    — must be 0x88FB
 *
 * LSDU size includes the RCT itself (6 bytes).
 */
struct prp_rct {
	__be16 sequence_nr;
	__be16 lan_and_size;
	__be16 prp_suffix;
} __attribute__((packed));

#define PRP_SUFFIX           0x88FB
#define PRP_RCT_SIZE         6

/* LAN ID values (upper 4 bits of lan_and_size, network byte order) */
#define PRP_LAN_A            0xA000
#define PRP_LAN_B            0xB000
#define PRP_LAN_MASK         0xF000
#define PRP_LSDU_SIZE_MASK   0x0FFF

static inline __u16 prp_rct_get_seq(const struct prp_rct *rct)
{
	return hsr_prp_ntohs(rct->sequence_nr);
}

static inline __u16 prp_rct_get_lan(const struct prp_rct *rct)
{
	return hsr_prp_ntohs(rct->lan_and_size) & PRP_LAN_MASK;
}

static inline __u16 prp_rct_get_lsdu_size(const struct prp_rct *rct)
{
	return hsr_prp_ntohs(rct->lan_and_size) & PRP_LSDU_SIZE_MASK;
}

static inline bool prp_rct_valid(const struct prp_rct *rct)
{
	return hsr_prp_ntohs(rct->prp_suffix) == PRP_SUFFIX;
}

static inline void prp_rct_set(struct prp_rct *rct, __u16 seq,
			       __u16 lan_id, __u16 lsdu_size)
{
	rct->sequence_nr = hsr_prp_htons(seq);
	rct->lan_and_size = hsr_prp_htons((__u16)((lan_id & PRP_LAN_MASK) |
						  (lsdu_size & PRP_LSDU_SIZE_MASK)));
	rct->prp_suffix = hsr_prp_htons(PRP_SUFFIX);
}

#endif /* HSR_PRP_PRP_RCT_H */
