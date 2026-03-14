/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * node_hsr_ingress — HSR ingress processing (XDP).
 *
 * Receives frames with EtherType 0x892F dispatched from node_eth_input
 * via ext_dispatch. Parses the HSR tag, performs duplicate detection,
 * strips the tag, and re-enters node_eth_input for inner frame processing.
 *
 * Tag stripping saves and restores the 12-byte MAC header to avoid
 * corruption (same pattern as groutx VLAN strip, ISSUE-7).
 *
 * Node index is read from hsr_prp_node_config map at runtime to avoid
 * hardcoded PROG_ARRAY index collisions.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include "hsr_prp_maps.bpf.h"
#include "seq_check.bpf.h"

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

XGL_NODE(node_hsr_ingress)
{
	struct xgl_meta *meta;
	void *data, *data_end;
	struct ethhdr *eth;
	struct hsr_tag *tag;
	struct dup_key dkey;
	struct dup_entry dval;
	__u32 pkt_len;
	__u16 seq_nr;
	__u8 saved_dst[ETH_ALEN];
	__u8 saved_src[ETH_ALEN];
	__u32 role;
	__u32 *self_idx;
	__u32 *eth_idx;
	int ret;

	/* Read our own index from config map for stats */
	role = HSR_PRP_ROLE_HSR_INGRESS;
	self_idx = bpf_map_lookup_elem(&hsr_prp_node_config, &role);
	if (!self_idx) {
		XGL_DROP();
	}

	meta = XGL_META_GET(ctx);
	if (!meta) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	/* Bounds check: Ethernet header + HSR tag */
	if ((void *)(eth + 1) + sizeof(struct hsr_tag) > data_end) {
		XGL_STATS_INC_DROP(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	pkt_len = (__u32)(data_end - data);
	XGL_STATS_INC_RX(hsr_prp_stats, *self_idx, pkt_len);

	tag = (struct hsr_tag *)((void *)(eth + 1));

	/* Validate LSDU size against actual packet length.
	 * LSDU size = frame length after Ethernet header (includes HSR tag).
	 * Strict equality rejects truncated or padded-beyond-LSDU frames. */
	__u16 lsdu_size = hsr_tag_get_lsdu_size(tag);
	__u16 expected = (__u16)(pkt_len - sizeof(struct ethhdr));

	if (lsdu_size != expected) {
		XGL_STATS_INC_DROP(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	/* Extract sequence number for duplicate detection */
	seq_nr = hsr_tag_get_seq(tag);

	/* Build duplicate detection key: source MAC + sequence number */
	__builtin_memcpy(dkey.src_mac, eth->h_source, ETH_ALEN);
	dkey.seq_nr = seq_nr;

	/* Check for duplicate */
	if (bpf_map_lookup_elem(&dup_table, &dkey)) {
		/* Duplicate frame — drop */
		XGL_STATS_INC_DROP(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	/* First copy: insert into duplicate table.
	 * BPF_NOEXIST ensures atomicity — if another CPU raced us,
	 * only the first insertion succeeds. */
	dval.timestamp_ns = bpf_ktime_get_ns();
	dval.ingress_port = port_from_ifindex(ctx->ingress_ifindex);
	__builtin_memset(dval._pad, 0, sizeof(dval._pad));

	ret = bpf_map_update_elem(&dup_table, &dkey, &dval, BPF_NOEXIST);
	if (ret != 0 && ret != -17 /* EEXIST */) {
		/* Map full or error — drop conservatively */
		XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}
	if (ret == -17) {
		/* Another CPU inserted first — this is a duplicate */
		XGL_STATS_INC_DROP(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	/*
	 * Strip HSR tag: save 12-byte MAC header, shift head forward by 6,
	 * then restore MACs. This is the same pattern as groutx VLAN strip
	 * (node_eth_output.bpf.c lines 135-167).
	 */

	/* Save the encapsulated EtherType before stripping */
	__u16 encap_proto = tag->encap_proto; /* already in network byte order */

	/* Save MAC addresses */
	__builtin_memcpy(saved_dst, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(saved_src, eth->h_source, ETH_ALEN);

	/* Shift head forward by HSR_TAG_SIZE (6 bytes), removing the tag */
	if (bpf_xdp_adjust_head(ctx, HSR_TAG_SIZE) != 0) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	/* Re-read data pointers after adjust */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	if ((void *)(eth + 1) > data_end) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	/* Restore MAC addresses and set original EtherType */
	__builtin_memcpy(eth->h_dest, saved_dst, ETH_ALEN);
	__builtin_memcpy(eth->h_source, saved_src, ETH_ALEN);
	eth->h_proto = encap_proto;

	/* Update metadata for inner frame */
	meta = XGL_META_GET(ctx);
	if (!meta) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	meta->l2_proto = bpf_ntohs(encap_proto);

	/* Check depth before re-entering the graph */
	if (EGL_DEPTH_EXCEEDED(hsr_prp_depth, HSR_PRP_MAX_DEPTH)) {
		XGL_STATS_INC_DROP(hsr_prp_stats, *self_idx);
		XGL_DROP();
	}

	pkt_len = (__u32)(data_end - data);
	XGL_STATS_INC_TX(hsr_prp_stats, *self_idx, pkt_len);

	/* Read eth_input index from config map */
	role = HSR_PRP_ROLE_ETH_INPUT;
	eth_idx = bpf_map_lookup_elem(&hsr_prp_node_config, &role);
	if (eth_idx)
		XGL_NEXT(ctx, egl_prog_array, *eth_idx);

	/* Config not populated or tail call failed — pass to kernel stack */
	XGL_STATS_INC_ERROR(hsr_prp_stats, *self_idx);
	XGL_PASS();
}
