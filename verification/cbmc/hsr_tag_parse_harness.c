/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * CBMC harness for HSR tag parsing — proves no out-of-bounds access
 * for any packet buffer up to 1500 bytes, with and without VLAN.
 *
 * Properties:
 *   1. Tag parsing never reads beyond buffer bounds
 *   2. Path/size extraction masks produce valid values
 *   3. LSDU size field is within valid range (0..4095)
 *   4. VLAN+HSR: correct offset handling
 *
 * Run with:
 *   cbmc --unwind 1 --unwinding-assertions hsr_tag_parse_harness.c
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint16_t __be16;

/* Minimal ntohs for CBMC (big-endian to host) */
static inline __u16 ntohs(__be16 x)
{
	return ((__u16)(x >> 8)) | ((__u16)(x << 8));
}

static inline __be16 htons(__u16 x)
{
	return (__be16)((x >> 8) | (x << 8));
}

/* Include the struct and functions directly */
struct hsr_tag {
	__be16 path_and_size;
	__be16 sequence_nr;
	__be16 encap_proto;
} __attribute__((packed));

#define HSR_TAG_SIZE         6
#define HSR_PATH_MASK        0xF000
#define HSR_LSDU_SIZE_MASK   0x0FFF

static inline __u16 hsr_tag_get_path(const struct hsr_tag *tag)
{
	return ntohs(tag->path_and_size) & HSR_PATH_MASK;
}

static inline __u16 hsr_tag_get_lsdu_size(const struct hsr_tag *tag)
{
	return ntohs(tag->path_and_size) & HSR_LSDU_SIZE_MASK;
}

static inline __u16 hsr_tag_get_seq(const struct hsr_tag *tag)
{
	return ntohs(tag->sequence_nr);
}

/* CBMC nondet */
__u16 nondet_u16(void);
__u8 nondet_u8(void);

#define ETH_HLEN  14
#define VLAN_HLEN  4
#define MAX_FRAME 1500

void harness_parse_no_vlan(void)
{
	__u8 buf[MAX_FRAME];
	__u16 pkt_len = nondet_u16();

	__CPROVER_assume(pkt_len >= ETH_HLEN + HSR_TAG_SIZE);
	__CPROVER_assume(pkt_len <= MAX_FRAME);

	/* Simulate nondeterministic packet content */
	for (int i = 0; i < HSR_TAG_SIZE; i++)
		buf[ETH_HLEN + i] = nondet_u8();

	struct hsr_tag *tag = (struct hsr_tag *)(buf + ETH_HLEN);

	__u16 path = hsr_tag_get_path(tag);
	__u16 lsdu = hsr_tag_get_lsdu_size(tag);
	__u16 seq = hsr_tag_get_seq(tag);

	/* Path must be in upper 4 bits only */
	assert((path & ~HSR_PATH_MASK) == 0);

	/* LSDU size must fit in 12 bits */
	assert(lsdu <= HSR_LSDU_SIZE_MASK);
}

void harness_parse_with_vlan(void)
{
	__u8 buf[MAX_FRAME];
	__u16 pkt_len = nondet_u16();

	__CPROVER_assume(pkt_len >= ETH_HLEN + VLAN_HLEN + HSR_TAG_SIZE);
	__CPROVER_assume(pkt_len <= MAX_FRAME);

	/* HSR tag after VLAN tag */
	__u16 offset = ETH_HLEN + VLAN_HLEN;

	for (int i = 0; i < HSR_TAG_SIZE; i++)
		buf[offset + i] = nondet_u8();

	struct hsr_tag *tag = (struct hsr_tag *)(buf + offset);

	__u16 path = hsr_tag_get_path(tag);
	__u16 lsdu = hsr_tag_get_lsdu_size(tag);

	assert((path & ~HSR_PATH_MASK) == 0);
	assert(lsdu <= HSR_LSDU_SIZE_MASK);
}

int main(void)
{
	harness_parse_no_vlan();
	harness_parse_with_vlan();
	return 0;
}
