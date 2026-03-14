---------------------------- MODULE PRPDupDiscard ----------------------------
(*
 * PRP Duplicate Discard — TLA+ specification.
 *
 * Models PRP with:
 *   - Dual independent LANs (LAN-A, LAN-B)
 *   - Independent failure on each LAN
 *   - LRU eviction with bounded duplicate table
 *
 * Safety:  NoDuplicateDelivery — no frame delivered twice to same destination
 * Liveness: EventualDelivery — under single LAN failure, frames reach dest
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Nodes,          \* Set of node identifiers, e.g., {"n1", "n2"}
    MaxSeq,         \* Maximum sequence number
    TableSize,      \* Maximum duplicate table entries per node
    Src,            \* Source node
    Dst             \* Destination node

VARIABLES
    seq_counter,    \* seq_counter[n] : next sequence number for node n
    dup_table,      \* dup_table[n] : set of {src, seq} pairs seen by node n
    lan_a_frames,   \* Frames in transit on LAN A
    lan_b_frames,   \* Frames in transit on LAN B
    delivered,      \* delivered[n] : set of {src, seq} delivered to node n
    deliver_count,  \* deliver_count[n] : function from {src, seq} -> Nat
    lan_a_up,       \* Boolean: is LAN A operational?
    lan_b_up        \* Boolean: is LAN B operational?

vars == <<seq_counter, dup_table, lan_a_frames, lan_b_frames,
          delivered, deliver_count, lan_a_up, lan_b_up>>

TypeOK ==
    /\ seq_counter \in [Nodes -> 0..MaxSeq]
    /\ \A n \in Nodes : dup_table[n] \subseteq [src: Nodes, seq: 0..MaxSeq]
    /\ \A n \in Nodes : delivered[n] \subseteq [src: Nodes, seq: 0..MaxSeq]
    /\ lan_a_up \in BOOLEAN
    /\ lan_b_up \in BOOLEAN

Init ==
    /\ seq_counter = [n \in Nodes |-> 0]
    /\ dup_table = [n \in Nodes |-> {}]
    /\ lan_a_frames = {}
    /\ lan_b_frames = {}
    /\ delivered = [n \in Nodes |-> {}]
    /\ deliver_count = [n \in Nodes |-> [e \in [src: Nodes, seq: 0..MaxSeq] |-> 0]]
    /\ lan_a_up = TRUE
    /\ lan_b_up = TRUE

\* --- Actions ---

\* Send: source sends frame on both LANs
Send(n) ==
    /\ n = Src
    /\ seq_counter[n] < MaxSeq
    /\ LET seq == seq_counter[n]
           frame == [src |-> n, seq |-> seq, dst |-> Dst]
       IN
       /\ seq_counter' = [seq_counter EXCEPT ![n] = seq + 1]
       /\ lan_a_frames' = lan_a_frames \cup {frame}
       /\ lan_b_frames' = lan_b_frames \cup {frame}
       /\ UNCHANGED <<dup_table, delivered, deliver_count, lan_a_up, lan_b_up>>

\* ReceiveA: destination receives a frame from LAN A
ReceiveA(n, frame) ==
    /\ n = frame.dst
    /\ frame \in lan_a_frames
    /\ lan_a_up
    /\ LET entry == [src |-> frame.src, seq |-> frame.seq]
       IN
       IF entry \in dup_table[n]
       THEN
           \* Duplicate — discard
           /\ lan_a_frames' = lan_a_frames \ {frame}
           /\ UNCHANGED <<seq_counter, dup_table, lan_b_frames,
                          delivered, deliver_count, lan_a_up, lan_b_up>>
       ELSE
           \* First copy — accept
           /\ LET evicted == IF Cardinality(dup_table[n]) >= TableSize
                              THEN {CHOOSE e \in dup_table[n] : TRUE}
                              ELSE {}
                  new_table == (dup_table[n] \ evicted) \cup {entry}
              IN
              /\ dup_table' = [dup_table EXCEPT ![n] = new_table]
              /\ delivered' = [delivered EXCEPT ![n] =
                               delivered[n] \cup {entry}]
              /\ deliver_count' = [deliver_count EXCEPT
                                    ![n] = [deliver_count[n] EXCEPT
                                             ![entry] = @ + 1]]
              /\ lan_a_frames' = lan_a_frames \ {frame}
              /\ UNCHANGED <<seq_counter, lan_b_frames, lan_a_up, lan_b_up>>

\* ReceiveB: destination receives a frame from LAN B
ReceiveB(n, frame) ==
    /\ n = frame.dst
    /\ frame \in lan_b_frames
    /\ lan_b_up
    /\ LET entry == [src |-> frame.src, seq |-> frame.seq]
       IN
       IF entry \in dup_table[n]
       THEN
           /\ lan_b_frames' = lan_b_frames \ {frame}
           /\ UNCHANGED <<seq_counter, dup_table, lan_a_frames,
                          delivered, deliver_count, lan_a_up, lan_b_up>>
       ELSE
           /\ LET evicted == IF Cardinality(dup_table[n]) >= TableSize
                              THEN {CHOOSE e \in dup_table[n] : TRUE}
                              ELSE {}
                  new_table == (dup_table[n] \ evicted) \cup {entry}
              IN
              /\ dup_table' = [dup_table EXCEPT ![n] = new_table]
              /\ delivered' = [delivered EXCEPT ![n] =
                               delivered[n] \cup {entry}]
              /\ deliver_count' = [deliver_count EXCEPT
                                    ![n] = [deliver_count[n] EXCEPT
                                             ![entry] = @ + 1]]
              /\ lan_b_frames' = lan_b_frames \ {frame}
              /\ UNCHANGED <<seq_counter, lan_a_frames, lan_a_up, lan_b_up>>

\* FailLAN: fail one LAN
FailLanA ==
    /\ lan_a_up
    /\ lan_a_up' = FALSE
    /\ lan_a_frames' = {}
    /\ UNCHANGED <<seq_counter, dup_table, lan_b_frames,
                   delivered, deliver_count, lan_b_up>>

FailLanB ==
    /\ lan_b_up
    /\ lan_b_up' = FALSE
    /\ lan_b_frames' = {}
    /\ UNCHANGED <<seq_counter, dup_table, lan_a_frames,
                   delivered, deliver_count, lan_a_up>>

\* --- Specification ---

Next ==
    \/ \E n \in Nodes : Send(n)
    \/ \E n \in Nodes : \E f \in lan_a_frames : ReceiveA(n, f)
    \/ \E n \in Nodes : \E f \in lan_b_frames : ReceiveB(n, f)
    \/ FailLanA
    \/ FailLanB

Fairness ==
    /\ WF_vars(\E n \in Nodes : \E f \in lan_a_frames : ReceiveA(n, f))
    /\ WF_vars(\E n \in Nodes : \E f \in lan_b_frames : ReceiveB(n, f))

Spec == Init /\ [][Next]_vars /\ Fairness

\* --- Safety Properties ---

\* Every delivered entry was actually sent by the source
DeliveryIntegrity ==
    \A n \in Nodes :
        \A e \in delivered[n] :
            /\ e.src \in Nodes
            /\ e.seq < seq_counter[e.src]

\* Every delivered entry is also in the dup_table.
\* Only valid when TableSize >= MaxSeq — with smaller tables, LRU
\* eviction can remove a delivered entry before its duplicate arrives.
DupTableConsistency ==
    (TableSize >= MaxSeq) =>
        \A n \in Nodes :
            delivered[n] \subseteq dup_table[n]

\* No frame delivered more than once to the same destination
NoDuplicateDelivery ==
    \A n \in Nodes :
        \A e \in [src: Nodes, seq: 0..MaxSeq] :
            deliver_count[n][e] <= 1

\* --- Liveness Properties ---

\* Under single LAN failure, frames eventually reach destination.
\* Guarded by [](lan_a_up \/ lan_b_up): only checked on behaviors
\* where at least one LAN remains up throughout (dual failure is
\* out of scope for PRP guarantees).
EventualDelivery ==
    [](lan_a_up \/ lan_b_up) =>
        (\A seq_val \in 0..MaxSeq :
            (seq_counter[Src] > seq_val) ~>
                [src |-> Src, seq |-> seq_val] \in delivered[Dst])

=============================================================================
