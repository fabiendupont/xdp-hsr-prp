/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * node_prp_egress — PRP RCT append (TC egress program).
 *
 * Attached to TC egress on both LAN ports. Appends a 6-byte PRP
 * Redundancy Control Trailer at the end of the frame, clones to
 * the peer LAN port, and transmits the original on the local port.
 *
 * Same clone mark pattern as HSR egress (ISSUE-1, ISSUE-2):
 *   - Original: append RCT, set mark, clone to peer, transmit
 *   - Clone (mark set): patch LAN_ID field only, do NOT re-clone
 */

#ifndef __BPF__
#define __BPF__
#endif

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <hsr_prp/prp_rct.h>
#include <hsr_prp/hsr_prp_common.h>
#include <hsr_prp/hsr_prp_node_ids.h>

#include <egl/bpf/egl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

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
 * Offset of lan_and_size field within the PRP RCT.
 * RCT is at the end: frame_len - 6 + 2 (after sequence_nr).
 */
#define PRP_LAN_OFFSET_FROM_END  4  /* 6 - 2 = 4 bytes from end */

SEC("tc")
int node_prp_egress(struct __sk_buff *skb)
{
	struct ring_port_config *cfg;
	__u32 ifindex;
	__u8 src_mac[ETH_ALEN];
	struct seq_counter_val *seq_val;
	__u16 seq_nr;
	__u16 lan_id;
	__u16 lsdu_size;
	int ret;

	ifindex = skb->ifindex;

	cfg = bpf_map_lookup_elem(&tc_ring_config, &ifindex);
	if (!cfg)
		return TC_ACT_OK;

	/*
	 * Clone detection (ISSUE-2):
	 * Cloned frames already have the RCT — patch LAN_ID only.
	 */
	if (skb->mark == HSR_PRP_CLONE_MARK) {
		__be16 lan_and_size;
		__u32 offset = skb->len - PRP_LAN_OFFSET_FROM_END;

		ret = bpf_skb_load_bytes(skb, offset,
					 &lan_and_size, sizeof(lan_and_size));
		if (ret != 0)
			return TC_ACT_SHOT;

		/* Replace LAN ID bits with our LAN */
		lan_id = (cfg->path_id == 0) ? PRP_LAN_A : PRP_LAN_B;
		__u16 host_val = bpf_ntohs(lan_and_size);
		host_val = (host_val & ~PRP_LAN_MASK) | lan_id;
		lan_and_size = bpf_htons(host_val);

		ret = bpf_skb_store_bytes(skb, offset,
					  &lan_and_size,
					  sizeof(lan_and_size), 0);
		if (ret != 0)
			return TC_ACT_SHOT;

		skb->mark = 0;
		return TC_ACT_OK;
	}

	/*
	 * Original frame: append PRP RCT.
	 */

	/* Read source MAC for sequence counter */
	ret = bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source),
				 src_mac, ETH_ALEN);
	if (ret != 0)
		return TC_ACT_SHOT;

	/* Get and increment sequence counter atomically */
	seq_val = bpf_map_lookup_elem(&seq_counters, src_mac);
	if (!seq_val) {
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

	/*
	 * LSDU size includes the RCT (6 bytes).
	 * LSDU = payload after Ethernet header + RCT size.
	 */
	lsdu_size = (__u16)(skb->len - sizeof(struct ethhdr) + PRP_RCT_SIZE);
	lan_id = (cfg->path_id == 0) ? PRP_LAN_A : PRP_LAN_B;

	/* Extend frame by 6 bytes at the tail for the RCT */
	ret = bpf_skb_change_tail(skb, skb->len + PRP_RCT_SIZE, 0);
	if (ret != 0)
		return TC_ACT_SHOT;

	/* Construct and write the RCT at the new tail */
	struct prp_rct rct;
	prp_rct_set(&rct, seq_nr, lan_id, lsdu_size);

	ret = bpf_skb_store_bytes(skb, skb->len - PRP_RCT_SIZE,
				  &rct, sizeof(rct), 0);
	if (ret != 0)
		return TC_ACT_SHOT;

	/*
	 * Clone to peer LAN port.
	 */
	skb->mark = HSR_PRP_CLONE_MARK;

	/* Clone failure is non-fatal: original still transmits on local port */
	(void)bpf_clone_redirect(skb, cfg->peer_ifindex, 0);

	skb->mark = 0;

	return TC_ACT_OK;
}
