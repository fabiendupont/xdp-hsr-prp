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
  (per-ifindex      │  - check RCT suffix │         │ - append RCT     │
   dispatch)       │  - validate LSDU   │         │ - clone to peer  │
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

Extension nodes occupy reserved indices 11-29 in the groutx XDP graph:

| Index | Node               | Type | Description                     |
|-------|--------------------|------|---------------------------------|
| 11    | node_hsr_ingress   | XDP  | HSR tag parse, dup detect, strip|
| 12    | node_hsr_forward   | XDP  | Ring forwarding (XDP_REDIRECT)  |
| 13    | node_prp_ingress   | XDP  | PRP RCT check, dup detect, strip|
| —     | node_hsr_egress    | TC   | HSR tag insert, clone to peer   |
| —     | node_prp_egress    | TC   | PRP RCT append, clone to peer   |

## BPF Maps

| Map              | Type         | Purpose                              |
|------------------|--------------|--------------------------------------|
| dup_table        | LRU_HASH     | Duplicate detection (src_mac + seq)   |
| seq_counters     | HASH         | Per-source sequence counter (spinlock)|
| ring_ports       | DEVMAP_HASH  | XDP forwarding (bpf_redirect_map)     |
| tc_ring_config   | HASH         | TC peer ifindex + path_id             |
| prp_ports        | HASH         | PRP per-interface dispatch            |
| hsr_prp_stats    | PERCPU_ARRAY | Per-node statistics                   |
| hsr_prp_depth    | PERCPU_ARRAY | Tail call depth tracking              |

Maps shared between XDP and TC programs (dup_table, seq_counters)
are shared via BPF map pinning.

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

### CBMC Proofs

| Harness                  | Scope                                    |
|--------------------------|------------------------------------------|
| seq_after_harness        | All 2^32 input pairs, 7 properties       |
| hsr_tag_parse_harness    | Bounds safety for all packet sizes ±VLAN |
| prp_rct_strip_harness    | No buffer underflow, false positive rejection |

### TLA+ Specifications

| Spec             | Model                | States  | Properties              |
|------------------|----------------------|---------|-------------------------|
| HSRDupDiscard    | 3-node ring + failure| 761,956 | TypeOK, DeliveryIntegrity, DupTableConsistency |
| PRPDupDiscard    | Dual LAN + failure   | 4,248   | TypeOK, DeliveryIntegrity, DupTableConsistency |

### Integration Tests (root required)

| Test              | What it verifies                               |
|-------------------|------------------------------------------------|
| tc_egress_loads   | BPF object loads, program found                |
| map_population    | tc_ring_config and seq_counters read/write     |
| hsr_tag_insertion | TC egress produces 0x892F frame, correct fields|
| seq_increments    | Sequence numbers 0, 1, 2 across 3 frames      |
| prp_rct_append    | PRP trailer with 0x88FB suffix, correct LAN_ID |

## Userspace API

```c
#include <hsr_prp/hsr_prp_userspace.h>

/* Initialize configuration */
struct hsr_prp_config cfg;
hsr_prp_config_init(&cfg, HSR_PRP_MODE_HSR, "eth0", "eth1");

/* Register HSR EtherType in groutx ext_dispatch */
hsr_prp_config_setup_ext_dispatch(ext_dispatch_fd);

/* Populate BPF maps after loading programs */
uint8_t local_mac[6] = { /* interface MAC */ };
hsr_prp_config_apply_maps(&cfg, tc_ring_config_fd,
                          ring_ports_fd, prp_ports_fd,
                          local_mac_fd, local_mac);

/* Attach TC egress programs */
hsr_prp_config_attach_tc("eth0", egress_prog_fd);
hsr_prp_config_attach_tc("eth1", egress_prog_fd);

/* Start supervision frame generation */
struct hsr_prp_supervision *sup =
    hsr_prp_supervision_create(&cfg, local_mac);
hsr_prp_supervision_start(sup);
```

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

BSD-3-Clause. See [LICENSE](LICENSE).
