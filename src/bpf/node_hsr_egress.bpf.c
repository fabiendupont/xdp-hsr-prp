/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * node_hsr_egress — HSR tag insertion (TC egress program).
 *
 * Attached to TC egress on both ring ports. Inserts a 6-byte HSR tag
 * after the Ethernet header, clones the frame to the peer ring port,
 * and transmits the original on the local port.
 *
 * Clone loop prevention (ISSUE-1, ISSUE-2):
 *   - Original frames: insert tag, set skb->mark, clone to peer, transmit
 *   - Cloned frames (mark == HSR_PRP_CLONE_MARK): patch path field only,
 *     do NOT re-clone
 *
 * Sequence counter atomicity (ISSUE-5):
 *   - seq_counters value includes bpf_spin_lock
 *   - Requires kernel >= 5.1
 */

#ifndef __BPF__
#define __BPF__
#endif

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <hsr_prp/hsr_tag.h>
#include <hsr_prp/hsr_prp_common.h>

#include <egl/bpf/egl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-2-Clause";

/*
 * Maps shared with XDP programs via pinning.
 * Redeclared here since TC programs can't use xgl_common.bpf.h.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HSR_PRP_SEQ_TABLE_SIZE);
	__type(key, __u8[ETH_ALEN]);
	__type(value, struct seq_counter_val);
} seq_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct ring_port_config);
} tc_ring_config SEC(".maps");

/*
 * Offset of path_and_size field within the HSR tag,
 * relative to the start of the Ethernet frame.
 * eth header (14) + path_and_size is at byte 14.
 */
#define HSR_PATH_OFFSET  (sizeof(struct ethhdr))

SEC("tc")
int node_hsr_egress(struct __sk_buff *skb)
{
	struct ring_port_config *cfg;
	struct ethhdr eth_copy;
	struct hsr_tag tag;
	__u32 ifindex;
	__u8 src_mac[ETH_ALEN];
	struct seq_counter_val *seq_val;
	__u16 seq_nr;
	__u16 path;
	__u16 lsdu_size;
	int ret;

	ifindex = skb->ifindex;

	/* Look up our ring port configuration */
	cfg = bpf_map_lookup_elem(&tc_ring_config, &ifindex);
	if (!cfg) {
		/* Not a ring port — pass through */
		return TC_ACT_OK;
	}

	/*
	 * Clone detection (ISSUE-2):
	 * If skb->mark == HSR_PRP_CLONE_MARK, this is a cloned frame
	 * that already has an HSR tag. We only need to patch the path field.
	 */
	if (skb->mark == HSR_PRP_CLONE_MARK) {
		/*
		 * Patch path field: read current path_and_size, replace
		 * the path bits with our local path.
		 */
		__be16 path_and_size;

		ret = bpf_skb_load_bytes(skb, HSR_PATH_OFFSET,
					 &path_and_size, sizeof(path_and_size));
		if (ret != 0)
			return TC_ACT_SHOT;

		/* Replace path bits with our path */
		path = (cfg->path_id == 0) ? HSR_PATH_A : HSR_PATH_B;
		__u16 host_val = bpf_ntohs(path_and_size);
		host_val = (host_val & ~HSR_PATH_MASK) | path;
		path_and_size = bpf_htons(host_val);

		ret = bpf_skb_store_bytes(skb, HSR_PATH_OFFSET,
					  &path_and_size,
					  sizeof(path_and_size), 0);
		if (ret != 0)
			return TC_ACT_SHOT;

		/* Clear the clone mark */
		skb->mark = 0;

		return TC_ACT_OK;
	}

	/*
	 * Original frame: insert HSR tag.
	 */

	/* Read source MAC for sequence counter lookup */
	ret = bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source),
				 src_mac, ETH_ALEN);
	if (ret != 0)
		return TC_ACT_SHOT;

	/* Get and increment sequence counter atomically (ISSUE-5) */
	seq_val = bpf_map_lookup_elem(&seq_counters, src_mac);
	if (!seq_val) {
		/* First frame from this source — initialize counter */
		struct seq_counter_val init_val = {};
		init_val.seq_nr = 0;

		bpf_map_update_elem(&seq_counters, src_mac, &init_val,
				    BPF_NOEXIST);
		seq_val = bpf_map_lookup_elem(&seq_counters, src_mac);
		if (!seq_val)
			return TC_ACT_SHOT;
	}

	bpf_spin_lock(&seq_val->lock);
	seq_nr = seq_val->seq_nr;
	seq_val->seq_nr = seq_nr + 1;
	bpf_spin_unlock(&seq_val->lock);

	/* Save the original Ethernet header */
	ret = bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy));
	if (ret != 0)
		return TC_ACT_SHOT;

	/* Insert 6 bytes after the Ethernet header for the HSR tag */
	ret = bpf_skb_adjust_room(skb, HSR_TAG_SIZE, BPF_ADJ_ROOM_MAC, 0);
	if (ret != 0)
		return TC_ACT_SHOT;

	/*
	 * Construct HSR tag.
	 * LSDU size = frame length after Ethernet header (including HSR tag).
	 */
	path = (cfg->path_id == 0) ? HSR_PATH_A : HSR_PATH_B;
	lsdu_size = (__u16)(skb->len - sizeof(struct ethhdr));

	hsr_tag_set(&tag, path, lsdu_size, seq_nr,
		    bpf_ntohs(eth_copy.h_proto));

	/* Rewrite Ethernet EtherType to HSR (0x892F) */
	__be16 hsr_proto = bpf_htons(HSR_ETHERTYPE);
	ret = bpf_skb_store_bytes(skb,
				  offsetof(struct ethhdr, h_proto),
				  &hsr_proto, sizeof(hsr_proto), 0);
	if (ret != 0)
		return TC_ACT_SHOT;

	/* Write the HSR tag after the Ethernet header */
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr),
				  &tag, sizeof(tag), 0);
	if (ret != 0)
		return TC_ACT_SHOT;

	/*
	 * Clone to peer ring port (ISSUE-1):
	 * 1. Set clone mark to prevent re-cloning
	 * 2. Clone to peer port's TC egress
	 * 3. Clear mark on original
	 */
	skb->mark = HSR_PRP_CLONE_MARK;

	/* Clone failure is non-fatal: original still transmits on local port */
	(void)bpf_clone_redirect(skb, cfg->peer_ifindex, 0);

	/* Clear mark on the original — it transmits on the local port */
	skb->mark = 0;

	return TC_ACT_OK;
}
