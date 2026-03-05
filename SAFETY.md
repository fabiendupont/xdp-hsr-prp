# Safety Analysis — xdp-hsr-prp

This document covers functional safety considerations for using
xdp-hsr-prp in IEC 62439-3 HSR and PRP redundancy systems.

## Scope

xdp-hsr-prp implements protocol-level redundancy in the BPF data
path. It is intended as a building block in systems requiring
zero-recovery-time network redundancy (IEC 62439-3). It does NOT
implement application-level safety functions; those are the
responsibility of higher layers (e.g., IEC 61850 GOOSE/SV).

## Verification Strategy

### Formal Proofs (CBMC)

The `seq_after()` function is the core of duplicate detection
correctness. It performs 16-bit circular sequence comparison with
a signed-difference algorithm. An incorrect implementation would
cause either:
- **False accept**: delivering duplicate frames (safety impact:
  depends on application)
- **False reject**: dropping valid frames (availability impact:
  loss of redundancy)

**Proof**: CBMC exhaustively verifies all 2^32 (a, b) input pairs
against 7 properties:

| # | Property        | What it prevents                        |
|---|-----------------|----------------------------------------|
| 1 | Reflexivity     | Self-comparison never triggers accept   |
| 2 | Increment       | Next sequence is always detected        |
| 3 | Reverse         | Previous sequence is never "after"      |
| 4 | Anti-symmetry   | No contradictory ordering               |
| 5 | Wraparound      | 0 correctly follows 65535               |
| 6 | Boundary        | Ambiguous offset (32768) → conservative |
| 7 | Window          | All valid offsets < 32768 detected      |

Property 6 is a deliberate design choice: when two sequence numbers
are exactly 32768 apart, `seq_after()` returns false (conservative).
For protection systems where frame LOSS is worse than frame
DUPLICATION, this is the safer choice — it may occasionally accept
a duplicate rather than reject a valid frame.

### Bounds Safety (CBMC)

- **hsr_tag_parse_harness**: Proves HSR tag field extraction never
  reads out of bounds for any packet size (0–1500 bytes), with and
  without 802.1Q VLAN tags.
- **prp_rct_strip_harness**: Proves RCT trailer removal never
  underflows the buffer below minimum Ethernet frame size (14 bytes).
  Also proves the false-positive rejection logic is well-defined.

### Protocol Correctness (TLA+)

Two TLA+ specifications model the duplicate discard state machines:

**HSRDupDiscard** — 3-node ring topology:
- Explicit node-to-node links with directed forwarding
- Single link failure injection
- LRU eviction with bounded table size
- **Verified**: TypeOK, DeliveryIntegrity (every delivered frame was
  actually sent), DupTableConsistency (every delivery is recorded in
  the dup table)
- **State space**: 761,956 states, depth 22

**PRPDupDiscard** — Dual independent LANs:
- Separate LAN-A and LAN-B failure
- LRU eviction modeling
- **Verified**: Same invariants as HSR
- **State space**: 4,248 states, depth 13

### Runtime Safety Mechanisms

| Mechanism              | Failure mode prevented              |
|------------------------|-------------------------------------|
| LRU hash (dup_table)   | Unbounded memory growth             |
| bpf_spin_lock          | Sequence counter race (multi-queue) |
| BPF_NOEXIST flag       | Duplicate insert race (multi-CPU)   |
| skb->mark clone check  | Infinite clone loops                |
| EGL_DEPTH_EXCEEDED     | Infinite tail call chains           |
| LSDU size validation   | PRP false positive acceptance       |

## FMEA — Failure Modes and Effects Analysis

### FM-1: Duplicate frame delivered to application

| Attribute  | Value |
|------------|-------|
| Cause      | Race condition in dup_table lookup/insert |
| Effect     | Application receives same frame twice |
| Severity   | Medium (application-dependent) |
| Mitigation | `BPF_NOEXIST` flag on map insert ensures only one CPU succeeds; second CPU sees EEXIST and drops |
| Residual   | Negligible — BPF map operations are atomic |

### FM-2: Valid frame dropped (false duplicate)

| Attribute  | Value |
|------------|-------|
| Cause      | LRU eviction removes an entry that is then re-received |
| Effect     | Loss of one frame copy (redundancy still provides the other) |
| Severity   | Low (one copy lost, other copy delivers) |
| Mitigation | LRU table sized to cover window of in-flight frames (65536 entries ≈ 1s at wire rate) |
| Residual   | Possible under sustained overload exceeding table capacity |

### FM-3: Sequence counter wraparound mishandling

| Attribute  | Value |
|------------|-------|
| Cause      | Incorrect circular comparison at 16-bit boundary |
| Effect     | Either false accept (duplicate delivered) or false reject (valid frame dropped) |
| Severity   | High (silent data corruption or availability loss) |
| Mitigation | `seq_after()` proven correct by CBMC for ALL 2^32 inputs |
| Residual   | None — exhaustive proof covers entire input space |

### FM-4: Clone loop (infinite frame multiplication)

| Attribute  | Value |
|------------|-------|
| Cause      | TC egress on port A clones to port B, which clones back |
| Effect     | Network storm, resource exhaustion |
| Severity   | Critical |
| Mitigation | `skb->mark = HSR_PRP_CLONE_MARK` set before clone; peer checks mark and patches path only, never re-clones |
| Residual   | None if mark is preserved across clone (kernel guarantees this) |

### FM-5: Sequence counter race (duplicate sequence numbers)

| Attribute  | Value |
|------------|-------|
| Cause      | Multi-queue NIC runs TC egress concurrently on multiple CPUs |
| Effect     | Two frames get the same sequence number; receiver may drop one |
| Severity   | Medium (one frame lost per occurrence) |
| Mitigation | `struct seq_counter_val` includes `bpf_spin_lock`; increment is atomic |
| Residual   | None — spin_lock serializes access (kernel ≥ 5.1) |

### FM-6: PRP false positive (payload contains 0x88FB)

| Attribute  | Value |
|------------|-------|
| Cause      | Non-PRP frame has 0x88FB at trailer position |
| Effect     | Frame incorrectly treated as PRP; last 6 bytes stripped |
| Severity   | High (data corruption) |
| Mitigation | LSDU size consistency check: `prp_rct_get_lsdu_size()` must match `pkt_len - ETH_HLEN` |
| Residual   | Statistically possible if payload coincidentally matches both suffix AND size field. Probability: ~1 in 2^28 per frame |

### FM-7: HSR tag strip corrupts MAC header

| Attribute  | Value |
|------------|-------|
| Cause      | `bpf_xdp_adjust_head()` shifts data pointer without preserving MACs |
| Effect     | Corrupted destination/source MAC in delivered frame |
| Severity   | Critical (silent data corruption) |
| Mitigation | 12-byte MAC save/restore pattern (same as groutx VLAN strip) |
| Residual   | None — save before adjust, restore after |

### FM-8: Tail call depth exceeded

| Attribute  | Value |
|------------|-------|
| Cause      | HSR ingress re-enters node_eth_input, creating a chain |
| Effect     | Kernel drops packet (max 33 tail calls) or infinite loop |
| Severity   | Low (packet drop, not corruption) |
| Mitigation | `EGL_DEPTH_EXCEEDED(hsr_prp_depth, 16)` check before re-entry |
| Residual   | None — depth counter checked before every tail call |

### FM-9: Map memory exhaustion

| Attribute  | Value |
|------------|-------|
| Cause      | More unique (src_mac, seq) pairs than dup_table capacity |
| Effect     | Oldest entries evicted; may cause FM-2 |
| Severity   | Low |
| Mitigation | `BPF_MAP_TYPE_LRU_HASH` auto-evicts; 65536 entries covers typical traffic |
| Residual   | See FM-2 |

## Design Decisions with Safety Rationale

### Ambiguous boundary (offset = 32768)

When `a - b == INT16_MIN` (exactly half the sequence space apart),
the relationship is genuinely ambiguous. Two design choices:

1. **Return true** (aggressive): risk accepting a very old frame as new
2. **Return false** (conservative): risk dropping a valid new frame

We chose **false** (conservative). Rationale: in redundancy systems,
both paths carry the same frame. Dropping one copy on one path still
delivers via the other path. Accepting a stale frame as new could
cause application-level confusion. This is the safer trade-off for
protection-class traffic (IEC 61850 GOOSE/SV).

### LRU vs fixed hash for duplicate table

Fixed-size hash maps require manual eviction and can deadlock under
overload. `BPF_MAP_TYPE_LRU_HASH` provides automatic eviction of
oldest entries, preventing memory exhaustion at the cost of
potentially increased false-duplicate rate under extreme load.
For safety-critical systems, the bounded-memory guarantee outweighs
the marginal increase in false duplicates.

### Spin lock vs per-CPU counters

Per-CPU sequence counters would avoid locking but produce
per-CPU sequence spaces, complicating duplicate detection. A single
atomic counter with `bpf_spin_lock` ensures globally unique sequence
numbers at the cost of serialization. For typical HSR/PRP traffic
rates (< 10 Gbps), the lock contention is negligible.

## Compliance Notes

### IEC 62439-3

This implementation covers the core data-plane mechanisms of
IEC 62439-3 HSR (clause 5.2) and PRP (clause 5.3). The following
aspects are NOT implemented and must be provided by the integrating
system:

- RedBox / QuadBox interworking
- SNMP MIB mapping
- Ring break detection and recovery signaling
- EntryForgetTime enforcement (400ms default per IEC 62439-3)

### Verification Coverage

| Technique   | What is covered                          | What is NOT covered      |
|-------------|------------------------------------------|--------------------------|
| CBMC        | seq_after() correctness, bounds safety   | Full BPF program logic   |
| TLA+        | Protocol state machine, dup discard      | Real-time constraints    |
| Frama-C/WP  | seq_after() contract, hsr_tag accessors  | bswap16 round-trip (Alt-Ergo limitation) |
| Unit tests  | Header parse/format, field extraction    | Concurrency, packet I/O  |
| Integration | TC tag insertion, seq increment, RCT     | Multi-node ring topology |
| ASAN/UBSAN  | Memory safety, undefined behavior        | BPF programs (userspace only) |
| cppcheck    | MISRA C:2012 advisory + required rules   | BPF-only code (kernel types) |

### Frama-C Deductive Verification

ACSL contracts verified by the WP plugin provide an independent proof
technique (weakest precondition + SMT) complementing the CBMC bounded
model checking proofs.

**seq_after_spec.c** — 12/12 goals proved:
- Four behaviors (equal, after, boundary, before) with postconditions
- All RTE annotations (signed overflow, division by zero) discharged

**hsr_tag_spec.c** — 41/43 goals proved:
- Field accessor contracts (get_path, get_lsdu_size, get_seq)
- Setter postconditions (round-trip property)
- All pointer dereference and bounds RTE annotations
- 2 unproven: `bswap16` round-trip and `hsr_tag_set` composite
  postcondition — Alt-Ergo timeout on bitvector reasoning.
  These same properties ARE proven by CBMC (hsr_tag_parse_harness).

### MISRA C:2012 Compliance

Scanned with cppcheck 2.19.1 `--addon=misra`. Results:

- **Zero violations** on project source files (headers, userspace,
  unit tests)
- **Configuration notes** (not violations): `LIBBPF_OPTS` macro and
  `BPF_ANY` constant from libbpf headers not resolvable by static
  analysis — these are third-party API macros, not project code

**Deliberate deviations** (documented, not violations):

| Rule   | Deviation                                    | Rationale                |
|--------|----------------------------------------------|--------------------------|
| Dir 4.6 | `__u16`, `__be16` etc. from `<linux/types.h>` | Required for BPF/kernel API compatibility |
| Rule 1.2 | `__attribute__((packed))` on protocol structs | Required for wire-format correctness |
| Rule 21.6 | `fprintf(stderr, ...)` in test code          | Test output only, not production code |

## FMECA — Criticality Rankings

Risk Priority Number: **RPN = Severity × Occurrence × Detection**

Scale: 1 (lowest) to 10 (highest).

| FM   | Failure Mode              | Sev | Occ | Det | RPN | Mitigation Status      |
|------|---------------------------|-----|-----|-----|-----|------------------------|
| FM-1 | Duplicate frame delivered  |  4  |  2  |  2  |  16 | Mitigated (BPF_NOEXIST)|
| FM-2 | Valid frame dropped (LRU) |  3  |  3  |  5  |  45 | Mitigated (table sizing)|
| FM-3 | Wraparound mishandled     |  9  |  1  |  1  |   9 | Eliminated (CBMC proof)|
| FM-4 | Clone loop                | 10  |  1  |  1  |  10 | Eliminated (skb->mark) |
| FM-5 | Sequence counter race     |  5  |  1  |  1  |   5 | Eliminated (spin_lock) |
| FM-6 | PRP false positive        |  8  |  2  |  3  |  48 | Mitigated (LSDU check) |
| FM-7 | MAC header corruption     | 10  |  1  |  1  |  10 | Eliminated (save/restore)|
| FM-8 | Tail call depth exceeded  |  2  |  1  |  1  |   2 | Eliminated (depth counter)|
| FM-9 | Map memory exhaustion     |  3  |  2  |  3  |  18 | Mitigated (LRU eviction)|

**Severity justification**:
- 10: Silent data corruption or network storm (FM-4, FM-7)
- 9: Safety-critical function silently wrong (FM-3)
- 8: Data corruption detectable by upper layers (FM-6)
- 4-5: Availability impact, redundancy still provides protection (FM-1, FM-5)
- 2-3: Graceful degradation, single frame affected (FM-2, FM-8, FM-9)

**Highest residual risk**: FM-6 (RPN 48) — PRP false positive.
The LSDU size check reduces but cannot eliminate false positives
where payload coincidentally matches both suffix and size. The
integrating system should consider application-layer integrity
checks (e.g., IEC 61850 GOOSE/SV sequence counters) as defense
in depth.

## Minimum Kernel Version

**Linux 5.1** — required for `bpf_spin_lock` in BPF map values.
Earlier kernels cannot use atomic sequence counters, making the
implementation unsafe for multi-queue NICs (FM-5).
