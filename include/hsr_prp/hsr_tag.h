/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_HSR_TAG_H
#define HSR_PRP_HSR_TAG_H

#include <linux/types.h>

#ifdef __BPF__
#include <bpf/bpf_endian.h>
#define hsr_prp_ntohs(x) bpf_ntohs(x)
#define hsr_prp_htons(x) bpf_htons(x)
#else
#include <arpa/inet.h>
#define hsr_prp_ntohs(x) ntohs(x)
#define hsr_prp_htons(x) htons(x)
#endif

/*
 * HSR tag: 6 bytes, inserted after Ethernet source MAC.
 *
 * Wire layout (IEC 62439-3 clause 5.2.2):
 *   Byte 0-1: path_and_size  — bits[15:12]=path, bits[11:0]=LSDU size
 *   Byte 2-3: sequence_nr    — 16-bit sequence number
 *   Byte 4-5: encap_proto    — original EtherType of encapsulated frame
 *
 * The Ethernet header's EtherType field is rewritten to 0x892F.
 * The original EtherType is saved in encap_proto.
 */
struct hsr_tag {
	__be16 path_and_size;
	__be16 sequence_nr;
	__be16 encap_proto;
} __attribute__((packed));

#define HSR_ETHERTYPE        0x892F
#define HSR_TAG_SIZE         6

/* Path field values (upper 4 bits of path_and_size, network byte order) */
#define HSR_PATH_A           0x0000
#define HSR_PATH_B           0x1000
#define HSR_PATH_MASK        0xF000
#define HSR_LSDU_SIZE_MASK   0x0FFF

static inline __u16 hsr_tag_get_path(const struct hsr_tag *tag)
{
	return hsr_prp_ntohs(tag->path_and_size) & HSR_PATH_MASK;
}

static inline __u16 hsr_tag_get_lsdu_size(const struct hsr_tag *tag)
{
	return hsr_prp_ntohs(tag->path_and_size) & HSR_LSDU_SIZE_MASK;
}

static inline __u16 hsr_tag_get_seq(const struct hsr_tag *tag)
{
	return hsr_prp_ntohs(tag->sequence_nr);
}

static inline __u16 hsr_tag_get_encap_proto(const struct hsr_tag *tag)
{
	return hsr_prp_ntohs(tag->encap_proto);
}

static inline void hsr_tag_set(struct hsr_tag *tag, __u16 path,
			       __u16 lsdu_size, __u16 seq, __u16 encap_proto)
{
	tag->path_and_size = hsr_prp_htons((__u16)((path & HSR_PATH_MASK) |
					       (lsdu_size & HSR_LSDU_SIZE_MASK)));
	tag->sequence_nr = hsr_prp_htons(seq);
	tag->encap_proto = hsr_prp_htons(encap_proto);
}

#endif /* HSR_PRP_HSR_TAG_H */
