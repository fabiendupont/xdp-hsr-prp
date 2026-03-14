/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_NODE_IDS_H
#define HSR_PRP_NODE_IDS_H

/*
 * Dynamic node index allocation roles.
 *
 * BPF programs read their own index and tail-call targets from the
 * hsr_prp_node_config map at runtime. This avoids hardcoded PROG_ARRAY
 * indices that collide with other graph extensions (e.g. groutx K8s
 * nodes NODE_SNAT=14, NODE_NDP=15).
 *
 * Userspace allocates indices dynamically and populates the config map.
 */
#define HSR_PRP_ROLE_ETH_INPUT     0  /* tail-call target: eth_input */
#define HSR_PRP_ROLE_HSR_INGRESS   1  /* self index: node_hsr_ingress */
#define HSR_PRP_ROLE_HSR_FORWARD   2  /* self index: node_hsr_forward */
#define HSR_PRP_ROLE_PRP_INGRESS   3  /* self index: node_prp_ingress */
#define HSR_PRP_NODE_CONFIG_SIZE   4

/*
 * groutx core node indices (referenced for default config map values).
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
