/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_COMMON_H
#define HSR_PRP_COMMON_H

#include <linux/types.h>

#ifdef __BPF__
#include <linux/if_ether.h>
#else
#include <stdint.h>
#include <linux/if_ether.h>
#endif

#include "hsr_tag.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/*
 * Duplicate detection key: source MAC + sequence number.
 * Used as key for the LRU hash map.
 */
struct dup_key {
	__u8  src_mac[ETH_ALEN];
	__u16 seq_nr;
} __attribute__((packed));

/*
 * Duplicate detection value: when and where the first copy was seen.
 */
struct dup_entry {
	__u64 timestamp_ns;
	__u8  ingress_port;   /* 0 = port A, 1 = port B */
	__u8  _pad[7];
};

/*
 * Node table entry: tracks known HSR/PRP nodes.
 * Populated from received supervision frames.
 */
struct node_entry {
	__u8  mac[ETH_ALEN];
	__u8  _pad[2];
	__u64 last_seen_a;    /* last timestamp on port A */
	__u64 last_seen_b;    /* last timestamp on port B */
	__u16 last_seq;
	__u8  flags;
	__u8  _pad2;
};

#define NODE_FLAG_HSR   0x01
#define NODE_FLAG_PRP   0x02

/*
 * Sequence counter value with spin lock for atomic updates.
 * Required because multi-queue NICs run TC concurrently (ISSUE-5).
 * Requires kernel >= 5.1.
 */
struct seq_counter_val {
#ifdef __BPF__
	struct bpf_spin_lock lock;
#else
	__u32 _lock_placeholder;
#endif
	__u16 seq_nr;
	__u16 _pad;
};

/*
 * TC ring port configuration (ISSUE-4).
 * Separate from DEVMAP — bpf_clone_redirect() takes raw ifindex.
 */
struct ring_port_config {
	__u32 peer_ifindex;
	__u8  path_id;       /* 0 = path A / LAN A, 1 = path B / LAN B */
	__u8  _pad[3];
};

/*
 * Clone mark for TC egress (ISSUE-1, ISSUE-2).
 * Set on skb->mark before bpf_clone_redirect() to prevent re-cloning.
 */
#define HSR_PRP_CLONE_MARK  0x48535250  /* "HSRP" */

/*
 * Supervision frame (IEC 62439-3 clause 5.2.3.3).
 * HSR supervision: multicast to 01:15:4E:00:01:xx with HSR tag.
 * PRP supervision: multicast to 01:15:4E:00:01:xx without HSR tag.
 */
#define HSR_SUP_ETHERTYPE   0x88FB

#define HSR_SUP_TYPE        0x04
#define PRP_SUP_TYPE        0x05
#define HSR_SUP_VERSION     0x01

/* Supervision multicast prefix: 01:15:4E:00:01:xx */
#define HSR_SUP_MCAST_PREFIX { 0x01, 0x15, 0x4E, 0x00, 0x01 }

/*
 * Supervision TLV types (IEC 62439-3 clause 5.2.3.3).
 */
#define HSR_TLV_TYPE_DANP    0x14   /* TLV type for DANP MAC */
#define HSR_TLV_TYPE_REDBOX  0x1E   /* TLV type for RedBox MAC */
#define HSR_TLV_LEN_MAC      6     /* MAC address length */

struct hsr_sup_tlv {
	__u8  type;
	__u8  length;
} __attribute__((packed));

struct hsr_sup_payload {
	__u8  sup_path;         /* supervision path: 0x00 */
	__u8  sup_ver;          /* version: 0x01 */
	__be16 seq_nr;          /* supervision sequence number */
	struct hsr_sup_tlv tlv1;
	__u8  mac_danp[ETH_ALEN];
} __attribute__((packed));

/*
 * PRP ports map key: ifindex.
 * Value: 1 if this interface is a PRP port (ISSUE-3).
 * Used by node_port_rx to dispatch PRP frames.
 */

/* Default intervals (milliseconds) */
#define HSR_PRP_SUPERVISION_INTERVAL_MS  2000
#define HSR_PRP_NODE_TIMEOUT_MS          60000

/* Duplicate table capacity */
#define HSR_PRP_DUP_TABLE_SIZE           65536

/* Sequence counter table capacity */
#define HSR_PRP_SEQ_TABLE_SIZE           256

#endif /* HSR_PRP_COMMON_H */
