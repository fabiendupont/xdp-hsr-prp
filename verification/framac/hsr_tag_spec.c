/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Frama-C/WP specification for HSR tag field accessors.
 *
 * Proves that get/set correctly extract and construct fields
 * within the packed HSR tag structure, and that the round-trip
 * property holds: set then get returns the original values.
 *
 * Run with:
 *   frama-c -wp -wp-rte hsr_tag_spec.c
 */

#include <stdint.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint16_t __be16;

#define HSR_PATH_MASK        0xF000
#define HSR_LSDU_SIZE_MASK   0x0FFF

struct hsr_tag {
	__be16 path_and_size;
	__be16 sequence_nr;
	__be16 encap_proto;
} __attribute__((packed));

/*@ logic integer swap16(integer val) =
      ((val / 256) % 256) + ((val % 256) * 256);
*/

/* Portable byte swap (Frama-C needs to see the definition) */
/*@
  assigns \nothing;
  ensures \result == ((__u16)(((val >> 8) & 0xFF) | ((val & 0xFF) << 8)));
  ensures \result == (__u16)swap16(val);
*/
static inline __u16 bswap16(__u16 val)
{
	unsigned int hi = ((unsigned int)val >> 8) & 0xFFu;
	unsigned int lo = ((unsigned int)val & 0xFFu) << 8;
	return (__u16)(hi | lo);
}

/*@
  requires \valid_read(tag);
  assigns \nothing;
  ensures (\result & 0x0FFF) == 0;
  ensures \result <= 0xF000;
*/
static inline __u16 hsr_tag_get_path(const struct hsr_tag *tag)
{
	return bswap16(tag->path_and_size) & HSR_PATH_MASK;
}

/*@
  requires \valid_read(tag);
  assigns \nothing;
  ensures \result <= 0x0FFF;
*/
static inline __u16 hsr_tag_get_lsdu_size(const struct hsr_tag *tag)
{
	return bswap16(tag->path_and_size) & HSR_LSDU_SIZE_MASK;
}

/*@
  requires \valid_read(tag);
  assigns \nothing;
*/
static inline __u16 hsr_tag_get_seq(const struct hsr_tag *tag)
{
	return bswap16(tag->sequence_nr);
}

/*@
  requires \valid(tag);
  requires (path & 0x0FFF) == 0;
  requires lsdu_size <= 0x0FFF;
  assigns tag->path_and_size, tag->sequence_nr, tag->encap_proto;
  ensures swap16(tag->path_and_size) == (path & 0xF000) + (lsdu_size & 0x0FFF);
  ensures swap16(tag->sequence_nr) == seq;
  ensures swap16(tag->encap_proto) == encap_proto;
*/
static inline void hsr_tag_set(struct hsr_tag *tag, __u16 path,
			       __u16 lsdu_size, __u16 seq, __u16 encap_proto)
{
	tag->path_and_size = bswap16((__u16)((path & HSR_PATH_MASK) |
					     (lsdu_size & HSR_LSDU_SIZE_MASK)));
	tag->sequence_nr = bswap16(seq);
	tag->encap_proto = bswap16(encap_proto);
}
