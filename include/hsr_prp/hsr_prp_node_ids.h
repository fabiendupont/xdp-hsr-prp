/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_NODE_IDS_H
#define HSR_PRP_NODE_IDS_H

/*
 * Extension node indices in the groutx XDP graph.
 * Indices 11-13 are used by groutx core (NODE_BRIDGE_INPUT, etc.).
 * Indices 14-29 are available for extension nodes.
 *
 * These are XDP graph nodes only. HSR/PRP egress are TC programs
 * attached separately and do not occupy graph indices.
 */
#define NODE_HSR_INGRESS     14
#define NODE_HSR_FORWARD     15
#define NODE_PRP_INGRESS     16

/*
 * groutx core node indices (referenced by HSR/PRP nodes).
 */
#define NODE_PORT_RX          0
#define NODE_ETH_INPUT        1
#define NODE_DROP            31

/*
 * Maximum depth for tail call chains when re-entering the graph.
 * Prevents infinite loops when HSR ingress tail-calls back to eth_input.
 */
#define HSR_PRP_MAX_DEPTH    16

#endif /* HSR_PRP_NODE_IDS_H */
