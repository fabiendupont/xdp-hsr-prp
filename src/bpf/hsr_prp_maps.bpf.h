/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_MAPS_BPF_H
#define HSR_PRP_MAPS_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <hsr_prp/hsr_prp_common.h>
#include <hsr_prp/hsr_prp_node_ids.h>

#include <xgl/bpf/xgl_common.bpf.h>

/*
 * Duplicate detection table.
 * LRU hash auto-evicts oldest entries, preventing unbounded growth.
 * 65536 entries covers ~1 second at 65535 frames/sec per source.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, HSR_PRP_DUP_TABLE_SIZE);
	__type(key, struct dup_key);
	__type(value, struct dup_entry);
} dup_table SEC(".maps");

/*
 * Per-source sequence counter for egress.
 * Value includes bpf_spin_lock for atomic updates (ISSUE-5).
 * Key is source MAC address.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HSR_PRP_SEQ_TABLE_SIZE);
	__type(key, __u8[ETH_ALEN]);
	__type(value, struct seq_counter_val);
} seq_counters SEC(".maps");

/*
 * Ring port mapping for XDP ingress forwarding.
 * DEVMAP_HASH for bpf_redirect_map() in node_hsr_forward.
 * Key: ifindex, Value: bpf_devmap_val.
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
} ring_ports SEC(".maps");

/*
 * TC ring port configuration (ISSUE-4).
 * Separate from DEVMAP since bpf_clone_redirect() takes raw ifindex.
 * Key: local ifindex, Value: peer config with path_id.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct ring_port_config);
} tc_ring_config SEC(".maps");

/*
 * PRP ports map (ISSUE-3).
 * Interfaces that are PRP ports get dispatched to the PRP ingress node
 * instead of eth_input by node_port_rx.
 * Key: ifindex, Value: 1 if PRP port.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} prp_ports SEC(".maps");

/*
 * Determine port index (0=A, 1=B) from ingress ifindex.
 * Looks up tc_ring_config which maps local ifindex to path_id.
 */
static __always_inline __u8 port_from_ifindex(__u32 ifindex)
{
	struct ring_port_config *cfg;

	cfg = bpf_map_lookup_elem(&tc_ring_config, &ifindex);
	if (cfg)
		return cfg->path_id;

	return 0;
}

/*
 * Local MAC address for source MAC filtering.
 * Key: 0, Value: 6-byte MAC address.
 * Used by node_hsr_forward to drop frames originated by this node,
 * preventing forwarding our own frames around the ring.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[ETH_ALEN]);
} local_mac SEC(".maps");

/*
 * Node index indirection table.
 * Maps role IDs (HSR_PRP_ROLE_*) to actual PROG_ARRAY indices,
 * populated by userspace at registration time.
 * Avoids hardcoded indices that collide with other graph extensions.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HSR_PRP_NODE_CONFIG_SIZE);
	__type(key, __u32);
	__type(value, __u32);
} hsr_prp_node_config SEC(".maps");

/*
 * Per-node statistics using ebpf-graph-lib stats infrastructure.
 */
EGL_DECLARE_STATS(hsr_prp_stats);

/*
 * Depth counter for tail call chain tracking.
 * Prevents infinite loops when re-entering the graph.
 */
EGL_DECLARE_DEPTH_MAP(hsr_prp_depth);

#endif /* HSR_PRP_MAPS_BPF_H */
