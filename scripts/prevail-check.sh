#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# prevail-check.sh — bytecode-level verification gate.
#
# Runs the PREVAIL eBPF verifier (vbpf/prevail) on every BPF object
# under a build directory.  Deterministic and kernel-independent:
# the same object either verifies or it does not, on any machine,
# regardless of the host kernel version.
#
# Programs listed in prevail-expected-failures.txt (format:
# "file basename  section/function") are known to be rejected by
# PREVAIL's conservative analysis while being accepted by the kernel
# verifier.  The gate asserts they STILL fail — if one starts
# passing, the entry is stale and must be removed (the gate fails to
# prompt the cleanup), mirroring vbpf/prevail's own CI inventory.
#
# Usage: prevail-check.sh <prevail-binary> <build-dir> [expected-failures-file]
#
# Exits 0 if every program has its expected verdict, 1 otherwise.

set -u

PREVAIL=${1:?usage: prevail-check.sh <prevail-binary> <build-dir> [expected-file]}
BUILDDIR=${2:?usage: prevail-check.sh <prevail-binary> <build-dir> [expected-file]}
EXPECTED=${3:-$(dirname "$0")/prevail-expected-failures.txt}

fail=0
checked=0
expected_total=0

is_expected_failure() {
    # $1 = "basename" $2 = "section/function"
    [ -f "$EXPECTED" ] || return 1
    grep -qE "^\s*$1\s+$2(\s|#|\$)" "$EXPECTED"
}

# subprojects carry their own gates in their own repositories
for obj in $(find "$BUILDDIR" -name '*.bpf.o' -type f \
        -not -path '*/subprojects/*' | sort); do
    listing=$("$PREVAIL" -l "$obj" 2>/dev/null) || {
        echo "FAIL (parse): $obj"
        fail=1
        continue
    }

    [ -z "$listing" ] && continue

    while IFS= read -r line; do
        section=${line#section=}
        section=${section%% *}
        func=${line##* function=}
        label="$section/$func"

        checked=$((checked + 1))
        base=$(basename "$obj")
        if is_expected_failure "$base" "$label"; then
            expected_total=$((expected_total + 1))
            if "$PREVAIL" -q "$obj" "$section" "$func"; then
                echo "STALE-EXPECTED-FAILURE: ${obj#$BUILDDIR/} $label now PASSES — remove it from $(basename "$EXPECTED")"
                fail=1
            else
                echo "EXPECTED-FAIL: ${obj#$BUILDDIR/} $label (PREVAIL too imprecise; kernel verifier accepts)"
            fi
        elif "$PREVAIL" -q "$obj" "$section" "$func"; then
            echo "PASS: ${obj#$BUILDDIR/} $label"
        else
            echo "FAIL: ${obj#$BUILDDIR/} $label"
            "$PREVAIL" "$obj" "$section" "$func" || true
            fail=1
        fi
    done <<< "$listing"
done

echo "---"
echo "prevail: $checked program(s) checked ($expected_total expected failure(s)), $([ $fail -eq 0 ] && echo all as expected || echo FAILURES)"
exit $fail
