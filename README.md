# xdp-hsr-prp

IEC 62439-3 HSR and PRP redundancy protocols as pluggable
xdp-graph-lib extension nodes.

## Overview

Implements High-availability Seamless Redundancy (HSR) and Parallel
Redundancy Protocol (PRP) using XDP for fast-path ingress processing
and TC for egress packet duplication. Integrates as extension nodes
in the xdp-graph-lib / groutx pipeline.

HSR provides zero-recovery-time redundancy on ring topologies by
sending each frame on both ring ports and discarding duplicates.
PRP achieves the same on dual independent LANs using a trailer-based
tagging scheme.

## Architecture

```
                        Ingress (XDP)                    Egress (TC)
                   ┌─────────────────────┐         ┌──────────────────┐
                   │                     │         │                  │
  Port A ──────────┤  node_hsr_ingress   │         │ node_hsr_egress  ├──── Port A
  (EtherType       │  - parse HSR tag    │         │ - insert HSR tag │
   0x892F)         │  - dup detect (LRU) │         │ - clone to peer  │
                   │  - strip tag        │         │ - patch path     │
                   │  - re-enter graph   │         │                  │
                   │                     │         │                  │
  Port B ──────────┤  node_hsr_forward   │         │ node_hsr_egress  ├──── Port B
  (ring forward)   │  - redirect to peer │         │ (same program)   │
                   │                     │         │                  │
                   └─────────────────────┘         └──────────────────┘

  PRP ports ───────┤  node_prp_ingress   │         │ node_prp_egress  ├──── LAN A/B
  (per-ifindex     │  - check RCT suffix │         │ - append RCT     │
   dispatch)       │  - validate LSDU    │         │ - clone to peer  │
                   │  - dup detect       │         │ - patch LAN_ID   │
                   │  - strip trailer    │         │                  │
                   └─────────────────────┘         └──────────────────┘
```

### Why XDP + TC?

XDP cannot clone packets. HSR/PRP egress requires sending the same
frame on both ports with different path/LAN fields. TC programs use
`bpf_skb_clone_redirect()` for this. XDP handles fast-path ingress
(duplicate detection + tag stripping) where per-packet overhead matters
most.

### Dependency Chain

```
ebpf-graph-lib (egl_*)    ← generic: PROG_ARRAY, DAG, stats
└── xdp-graph-lib (xgl_*) ← XDP: metadata, actions, DEVMAP
    └── xdp-hsr-prp        ← this project
```

## Node Indices

Extension node indices are allocated dynamically at runtime via
`egl_graph_alloc_index()`. BPF programs read their own index and
tail-call targets from the `hsr_prp_node_config` map (an indirection
table from role to PROG_ARRAY index). This avoids collisions with
other graph extensions.

| Role                  | Node               | Type | Description                     |
|-----------------------|--------------------|------|---------------------------------|
| HSR_PRP_ROLE_HSR_INGRESS | node_hsr_ingress | XDP  | HSR tag parse, dup detect, strip|
| HSR_PRP_ROLE_HSR_FORWARD | node_hsr_forward | XDP  | Ring forwarding (XDP_REDIRECT)  |
| HSR_PRP_ROLE_PRP_INGRESS | node_prp_ingress | XDP  | PRP RCT check, dup detect, strip|
| —                     | node_hsr_egress    | TC   | HSR tag insert, clone to peer   |
| —                     | node_prp_egress    | TC   | PRP RCT append, clone to peer   |

## BPF Maps

| Map              | Type         | Purpose                              |
|------------------|--------------|--------------------------------------|
| dup_table        | LRU_HASH     | Duplicate detection (src_mac + seq)   |
| seq_counters     | HASH         | Per-source sequence counter (spinlock)|
| ring_ports       | DEVMAP_HASH  | XDP forwarding (bpf_redirect_map)     |
| tc_ring_config   | HASH         | TC peer ifindex + path_id             |
| prp_ports        | HASH         | PRP per-interface dispatch            |
| local_mac        | ARRAY        | Source MAC for forward filtering       |
| hsr_prp_stats    | PERCPU_ARRAY | Per-node statistics                   |
| hsr_prp_depth    | PERCPU_ARRAY | Tail call depth tracking              |

Maps shared between XDP and TC programs (seq_counters, tc_ring_config)
are shared via BPF map pinning at `/sys/fs/bpf/egl/hsr_prp/`. The
instance API handles pinning and reuse automatically.

## Building

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir                   # unit tests + CBMC + TLA+
sudo meson test -C builddir --suite integration  # requires root
```

### Build with ASAN/UBSAN

```sh
meson setup builddir-asan -Db_sanitize=address,undefined
meson compile -C builddir-asan
meson test -C builddir-asan --suite unit
```

## Dependencies

| Dependency      | Version | Purpose                              |
|-----------------|---------|--------------------------------------|
| xdp-graph-lib   | —       | XDP graph infrastructure (XGL_*)     |
| ebpf-graph-lib  | —       | Generic graph infrastructure (EGL_*) |
| libbpf          | >= 1.0  | BPF program loading, map operations  |
| libelf          | —       | ELF parsing (libbpf dependency)      |
| clang           | —       | BPF program compilation              |
| CBMC            | —       | Formal verification (optional)       |
| TLC             | —       | TLA+ model checking (optional)       |

**Minimum kernel version: 5.1** (required for `bpf_spin_lock` in
sequence counters).

## Testing

### Unit Tests

| Test            | What it verifies                                |
|-----------------|-------------------------------------------------|
| test_seq_after  | 7 properties of 16-bit circular comparison      |
| test_hsr_tag    | HSR tag set/get, wire format, round-trip, VLAN  |
| test_prp_rct    | PRP RCT set/get, valid/invalid, false positives |
| test_nodetable  | Add/lookup/remove, eviction, timeout, dump      |

### CBMC Proofs

| Harness                  | Scope                                    |
|--------------------------|------------------------------------------|
| seq_after_harness        | All 2^32 input pairs, 7 properties       |
| hsr_tag_parse_harness    | Bounds safety for all packet sizes ±VLAN |
| prp_rct_strip_harness    | No buffer underflow, false positive rejection |

### TLA+ Specifications

| Spec             | Model                | States  | Properties              |
|------------------|----------------------|---------|-------------------------|
| HSRDupDiscard    | 3-node ring + failure| —       | TypeOK, DeliveryIntegrity, DupTableConsistency, NoDuplicateDelivery, EventualDelivery |
| PRPDupDiscard    | Dual LAN + failure   | —       | TypeOK, DeliveryIntegrity, DupTableConsistency, NoDuplicateDelivery, EventualDelivery |

### Integration Tests (root required)

| Test              | What it verifies                               |
|-------------------|------------------------------------------------|
| tc_egress_loads    | BPF object loads, program found                |
| map_population     | tc_ring_config and seq_counters read/write     |
| hsr_tag_insertion  | TC egress produces 0x892F frame, correct fields|
| seq_increments     | Sequence numbers 0, 1, 2 across 3 frames      |
| prp_rct_append     | PRP trailer with 0x88FB suffix, correct LAN_ID |
| instance_lifecycle | Instance create/destroy with veth pair         |

## Userspace API

### Instance API (recommended)

The instance API handles the full lifecycle: graph creation, BPF
program loading with pinned map sharing, map population, XDP/TC
attachment, and supervision management.

```c
#include <hsr_prp/hsr_prp_userspace.h>

/* Configure */
struct hsr_prp_config cfg;
hsr_prp_config_init(&cfg, HSR_PRP_MODE_HSR, "eth0", "eth1");

/* Create instance (loads BPF programs, allocates indices, populates maps) */
struct hsr_prp_instance *inst =
    hsr_prp_instance_create(&cfg, "/usr/lib/bpf");

/* Attach XDP + TC to both ports */
hsr_prp_instance_attach(inst);

/* Start supervision TX + RX and node table maintenance */
hsr_prp_instance_start(inst);

/* Access node table */
struct hsr_prp_nodetable *nt = hsr_prp_instance_get_nodetable(inst);

/* Teardown (stops supervision, detaches BPF, frees resources) */
hsr_prp_instance_stop(inst);
hsr_prp_instance_destroy(inst);
```

### Low-level API

Individual functions for manual control over BPF loading and map
population are available via `hsr_prp_config_*`, `hsr_prp_stats_*`,
and `hsr_prp_supervision_*`. See `hsr_prp_userspace.h` for details.

## Known Limitations

1. **HSR forwarding vs local delivery (ISSUE-8)**: XDP can return
   only one action per packet. Frames destined for the local node
   are delivered locally (tag stripped, passed to stack). Ring
   forwarding is performed only for frames NOT destined locally.
   This matches the IEC 62439-3 "consume at destination" behavior.

2. **PRP false positive detection**: PRP uses a trailer (not a
   header tag), so the suffix 0x88FB can appear in legitimate
   payload. The LSDU size consistency check mitigates this but
   cannot eliminate all false positives.

3. **No RedBox support**: QuadBox and RedBox interworking modes
   are not implemented. The design is forward-compatible.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
