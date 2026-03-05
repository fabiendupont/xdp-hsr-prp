/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * node_prp_ingress — PRP ingress processing (XDP, index 13).
 *
 * Receives frames from PRP-designated ports (dispatched from
 * node_port_rx via prp_ports map, ISSUE-3).
 *
 * Checks for PRP RCT trailer: last 2 bytes == 0x88FB.
 * Validates LSDU size consistency to reject false positives
 * (0x88FB can appear in legitimate payload).
 * Performs duplicate detection, strips the RCT, and continues
 * to node_eth_input for normal processing.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include "hsr_prp_maps.bpf.h"
#include "seq_check.bpf.h"

#include <hsr_prp/prp_rct.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

static __always_inline __u8 port_from_ifindex(__u32 ifindex)
{
	struct ring_port_config *cfg;

	cfg = bpf_map_lookup_elem(&tc_ring_config, &ifindex);
	if (cfg)
		return cfg->path_id;

	return 0;
}

XGL_NODE(node_prp_ingress)
{
	struct xgl_meta *meta;
	void *data, *data_end;
	struct ethhdr *eth;
	struct prp_rct *rct;
	struct dup_key dkey;
	struct dup_entry dval;
	__u32 pkt_len;
	__u16 seq_nr;
	__u16 lsdu_size;
	int ret;

	meta = XGL_META_GET(ctx);
	if (!meta) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	/* Need at least Ethernet header + PRP RCT */
	pkt_len = (__u32)(data_end - data);
	if (pkt_len < sizeof(struct ethhdr) + PRP_RCT_SIZE) {
		/* Too short for PRP — pass through as normal frame */
		XGL_STATS_INC_RX(hsr_prp_stats, NODE_PRP_INGRESS, pkt_len);
		goto pass_through;
	}

	XGL_STATS_INC_RX(hsr_prp_stats, NODE_PRP_INGRESS, pkt_len);

	/* RCT is at the end of the frame, last 6 bytes */
	rct = (struct prp_rct *)(data_end - PRP_RCT_SIZE);

	/* Bounds check for verifier */
	if ((void *)rct < data || (void *)(rct + 1) > data_end) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	/* Check PRP suffix: must be 0x88FB */
	if (!prp_rct_valid(rct)) {
		/* Not a PRP frame — pass through as normal frame */
		goto pass_through;
	}

	/*
	 * Validate LSDU size against actual packet length.
	 * LSDU size in PRP includes the RCT itself.
	 * Expected: pkt_len - 14 (Ethernet header) = LSDU size.
	 * This check rejects false positives where 0x88FB appears
	 * in payload but the size doesn't match.
	 */
	lsdu_size = prp_rct_get_lsdu_size(rct);
	__u16 expected_lsdu = (__u16)(pkt_len - sizeof(struct ethhdr));

	if (lsdu_size != expected_lsdu) {
		/* LSDU mismatch — not a real PRP RCT (false positive) */
		goto pass_through;
	}

	/* Extract sequence number for duplicate detection */
	seq_nr = prp_rct_get_seq(rct);

	/* Bounds check for source MAC access */
	if ((void *)(eth + 1) > data_end) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	/* Build duplicate detection key */
	__builtin_memcpy(dkey.src_mac, eth->h_source, ETH_ALEN);
	dkey.seq_nr = seq_nr;

	/* Check for duplicate */
	if (bpf_map_lookup_elem(&dup_table, &dkey)) {
		XGL_STATS_INC_DROP(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	/* First copy: insert into duplicate table */
	dval.timestamp_ns = bpf_ktime_get_ns();
	dval.ingress_port = port_from_ifindex(ctx->ingress_ifindex);
	__builtin_memset(dval._pad, 0, sizeof(dval._pad));

	ret = bpf_map_update_elem(&dup_table, &dkey, &dval, BPF_NOEXIST);
	if (ret != 0 && ret != -17) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}
	if (ret == -17) {
		XGL_STATS_INC_DROP(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	/* Strip RCT by shrinking the tail by 6 bytes */
	if (bpf_xdp_adjust_tail(ctx, -(int)PRP_RCT_SIZE) != 0) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	/* Re-read data pointers after adjust */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Update metadata */
	meta = XGL_META_GET(ctx);
	if (!meta) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

pass_through:
	/* Check depth before re-entering the graph */
	if (EGL_DEPTH_EXCEEDED(hsr_prp_depth, HSR_PRP_MAX_DEPTH)) {
		XGL_STATS_INC_DROP(hsr_prp_stats, NODE_PRP_INGRESS);
		XGL_DROP();
	}

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	pkt_len = (__u32)(data_end - data);

	XGL_STATS_INC_TX(hsr_prp_stats, NODE_PRP_INGRESS, pkt_len);

	/* Continue to node_eth_input for normal processing */
	XGL_NEXT(ctx, egl_prog_array, NODE_ETH_INPUT);

	XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_PRP_INGRESS);
	XGL_PASS();
}
