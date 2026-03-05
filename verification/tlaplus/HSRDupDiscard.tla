---------------------------- MODULE HSRDupDiscard ----------------------------
(*
 * HSR Duplicate Discard — TLA+ specification.
 *
 * Models a 3-node HSR ring with:
 *   - Explicit ring topology with node-to-node links
 *   - Frame origination with sequence numbers
 *   - Forwarding around the ring
 *   - Duplicate detection and discard
 *   - Single link failure
 *   - LRU eviction with bounded table size
 *
 * Safety:  NoDuplicateDelivery — no frame delivered twice to same destination
 * Liveness: EventualDelivery — under single failure, frames reach destination
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Nodes,          \* Set of node identifiers, e.g., {"n1", "n2", "n3"}
    MaxSeq,         \* Maximum sequence number (e.g., 7 for bounded model)
    TableSize,      \* Maximum duplicate table entries per node
    Src,            \* Source node
    Dst             \* Destination node

VARIABLES
    seq_counter,    \* seq_counter[n] : next sequence number for node n
    dup_table,      \* dup_table[n] : set of {src, seq} pairs seen by node n
    in_transit,     \* Set of frames currently in the ring
    delivered,      \* delivered[n] : set of {src, seq} delivered to node n
    deliver_count,  \* deliver_count[n] : function from {src, seq} -> Nat
    failed_link     \* The currently failed link (or {} if none)

vars == <<seq_counter, dup_table, in_transit, delivered, deliver_count, failed_link>>

\* Ring topology: n1 -- n2 -- n3 -- n1
Links == {{"n1", "n2"}, {"n2", "n3"}, {"n3", "n1"}}

\* Directed neighbors
NextCW(n) == CASE n = "n1" -> "n2"
               [] n = "n2" -> "n3"
               [] n = "n3" -> "n1"

NextCCW(n) == CASE n = "n1" -> "n3"
                [] n = "n2" -> "n1"
                [] n = "n3" -> "n2"

LinkBetween(a, b) == {a, b}

LinkActive(a, b) == LinkBetween(a, b) # failed_link

TypeOK ==
    /\ seq_counter \in [Nodes -> 0..MaxSeq]
    /\ \A n \in Nodes : dup_table[n] \subseteq [src: Nodes, seq: 0..MaxSeq]
    /\ \A n \in Nodes : delivered[n] \subseteq [src: Nodes, seq: 0..MaxSeq]

Init ==
    /\ seq_counter = [n \in Nodes |-> 0]
    /\ dup_table = [n \in Nodes |-> {}]
    /\ in_transit = {}
    /\ delivered = [n \in Nodes |-> {}]
    /\ deliver_count = [n \in Nodes |-> [e \in [src: Nodes, seq: 0..MaxSeq] |-> 0]]
    /\ failed_link = {}

\* --- Actions ---

\* Send: source node originates a frame, sends on both paths
Send(n) ==
    /\ n = Src
    /\ seq_counter[n] < MaxSeq
    /\ LET seq == seq_counter[n]
           frame_cw  == [src |-> n, seq |-> seq, path |-> "A",
                         current |-> n, next |-> NextCW(n)]
           frame_ccw == [src |-> n, seq |-> seq, path |-> "B",
                         current |-> n, next |-> NextCCW(n)]
       IN
       /\ seq_counter' = [seq_counter EXCEPT ![n] = seq + 1]
       /\ in_transit' = in_transit \cup {frame_cw, frame_ccw}
       /\ UNCHANGED <<dup_table, delivered, deliver_count, failed_link>>

\* Receive: node receives a frame from in_transit
Receive(n, frame) ==
    /\ frame \in in_transit
    /\ frame.next = n
    /\ LinkActive(frame.current, n)
    /\ LET entry == [src |-> frame.src, seq |-> frame.seq]
       IN
       IF entry \in dup_table[n]
       THEN
           \* Duplicate — discard
           /\ in_transit' = in_transit \ {frame}
           /\ UNCHANGED <<seq_counter, dup_table, delivered, deliver_count, failed_link>>
       ELSE
           \* First copy — accept
           /\ LET evicted == IF Cardinality(dup_table[n]) >= TableSize
                              THEN {CHOOSE e \in dup_table[n] : TRUE}
                              ELSE {}
                  new_table == (dup_table[n] \ evicted) \cup {entry}
              IN
              /\ dup_table' = [dup_table EXCEPT ![n] = new_table]
              /\ IF n = Dst /\ frame.src = Src
                 THEN /\ delivered' = [delivered EXCEPT ![n] =
                                        delivered[n] \cup {entry}]
                      /\ deliver_count' = [deliver_count EXCEPT
                                            ![n] = [deliver_count[n] EXCEPT
                                                     ![entry] = @ + 1]]
                 ELSE /\ delivered' = delivered
                      /\ deliver_count' = deliver_count
              \* Forward around the ring (if not source)
              /\ IF n # frame.src
                 THEN LET next_node == IF frame.path = "A"
                                       THEN NextCW(n)
                                       ELSE NextCCW(n)
                          fwd_frame == [frame EXCEPT
                                        !.current = n,
                                        !.next = next_node]
                      IN
                      in_transit' = (in_transit \ {frame}) \cup {fwd_frame}
                 ELSE in_transit' = in_transit \ {frame}
              /\ UNCHANGED <<seq_counter, failed_link>>

\* FailLink: fail a single link
FailLink(link) ==
    /\ failed_link = {}
    /\ link \in Links
    /\ failed_link' = link
    /\ UNCHANGED <<seq_counter, dup_table, in_transit, delivered, deliver_count>>

\* --- Specification ---

Next ==
    \/ \E n \in Nodes : Send(n)
    \/ \E n \in Nodes : \E f \in in_transit : Receive(n, f)
    \/ \E l \in Links : FailLink(l)

Fairness ==
    WF_vars(\E n \in Nodes : \E f \in in_transit : Receive(n, f))

Spec == Init /\ [][Next]_vars /\ Fairness

\* --- Safety Properties ---

\* Every delivered entry was actually sent by the source
DeliveryIntegrity ==
    \A n \in Nodes :
        \A e \in delivered[n] :
            /\ e.src \in Nodes
            /\ e.seq < seq_counter[e.src]

\* Every delivered entry is also in the dup_table (detection worked)
DupTableConsistency ==
    \A n \in Nodes :
        delivered[n] \subseteq dup_table[n]

\* No frame delivered more than once to the same destination
NoDuplicateDelivery ==
    \A n \in Nodes :
        \A e \in [src: Nodes, seq: 0..MaxSeq] :
            deliver_count[n][e] <= 1

\* --- Liveness Properties ---

\* Under single failure, every originated frame eventually reaches destination
EventualDelivery ==
    \A seq_val \in 0..MaxSeq :
        (seq_counter[Src] > seq_val) ~>
            [src |-> Src, seq |-> seq_val] \in delivered[Dst]

=============================================================================
