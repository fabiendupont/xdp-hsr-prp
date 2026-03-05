/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * node_hsr_forward — HSR ring forwarding (XDP, index 12).
 *
 * Forwards HSR-tagged frames to the peer ring port.
 * Received on port A → forward to port B, and vice versa.
 *
 * Uses DEVMAP_HASH (ring_ports) for bpf_redirect_map().
 *
 * Design limitation (ISSUE-8): XDP can return only ONE action.
 * A frame destined for the local node AND requiring forwarding
 * cannot be handled in a single XDP program. The chosen approach:
 *
 *   - node_hsr_ingress handles local delivery: strips tag, delivers
 *     to upper layers via XDP_PASS (after re-entering node_eth_input).
 *   - node_hsr_forward handles ring forwarding: redirects the
 *     still-tagged frame to the peer port via XDP_REDIRECT.
 *
 * For frames that need BOTH actions (local + forward), the current
 * design delivers locally only. Forwarding of frames destined for
 * this node is NOT performed — this matches the "consume at
 * destination" behavior of IEC 62439-3. Intermediate nodes that
 * only forward (not the destination) use this node exclusively.
 */

#ifndef __BPF__
#define __BPF__
#endif

#include "hsr_prp_maps.bpf.h"

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

XGL_NODE(node_hsr_forward)
{
	struct xgl_meta *meta;
	void *data, *data_end;
	struct ethhdr *eth;
	struct ring_port_config *cfg;
	__u32 ingress_ifindex;
	__u32 pkt_len;
	__u32 peer_ifindex;

	meta = XGL_META_GET(ctx);
	if (!meta) {
		XGL_STATS_INC_ERROR(hsr_prp_stats, NODE_HSR_FORWARD);
		XGL_DROP();
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	/* Bounds check: Ethernet header + HSR tag */
	if ((void *)(eth + 1) + sizeof(struct hsr_tag) > data_end) {
		XGL_STATS_INC_DROP(hsr_prp_stats, NODE_HSR_FORWARD);
		XGL_DROP();
	}

	pkt_len = (__u32)(data_end - data);
	XGL_STATS_INC_RX(hsr_prp_stats, NODE_HSR_FORWARD, pkt_len);

	/*
	 * Do not forward frames originated by us.
	 * The source MAC check happens at a higher level;
	 * here we just forward if we have a valid peer.
	 */

	/* Determine peer port from ingress ifindex */
	ingress_ifindex = ctx->ingress_ifindex;

	cfg = bpf_map_lookup_elem(&tc_ring_config, &ingress_ifindex);
	if (!cfg) {
		/* Unknown ingress port — drop */
		XGL_STATS_INC_DROP(hsr_prp_stats, NODE_HSR_FORWARD);
		XGL_DROP();
	}

	peer_ifindex = cfg->peer_ifindex;

	XGL_STATS_INC_TX(hsr_prp_stats, NODE_HSR_FORWARD, pkt_len);

	/* Forward to peer ring port via DEVMAP */
	return XGL_REDIRECT_MAP(ring_ports, peer_ifindex, 0);
}
