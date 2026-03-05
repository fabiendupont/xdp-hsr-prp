# xdp-hsr-prp

IEC 62439-3 HSR and PRP redundancy protocols as pluggable
xdp-graph-lib nodes.

## Overview

Implements High-availability Seamless Redundancy (HSR) and Parallel
Redundancy Protocol (PRP) using XDP for ingress processing and TC for
egress packet duplication. Integrates as extension nodes in the
xdp-graph-lib / groutx pipeline.

## Features

- HSR tag insertion/removal and ring forwarding
- PRP Redundancy Control Trailer (RCT) append/strip
- Duplicate detection via LRU hash map (sequence number tracking)
- Supervision frame generation and node table management
- CBMC-proven `seq_after()` for 16-bit circular sequence comparison
- TLA+ verified duplicate discard state machines

## Building

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir
```

## Dependencies

- xdp-graph-lib
- libbpf >= 1.0
- libelf
- clang (BPF compilation)

## License

BSD-3-Clause
