/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef HSR_PRP_USERSPACE_H
#define HSR_PRP_USERSPACE_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

/*
 * Operating mode.
 */
enum hsr_prp_mode {
	HSR_PRP_MODE_HSR,
	HSR_PRP_MODE_PRP,
};

/*
 * Configuration structure for HSR/PRP operation.
 */
struct hsr_prp_config {
	enum hsr_prp_mode mode;
	char port_a[IFNAMSIZ];
	char port_b[IFNAMSIZ];
	uint32_t port_a_ifindex;
	uint32_t port_b_ifindex;
	uint32_t supervision_interval_ms;  /* default: 2000 */
	uint32_t node_timeout_ms;          /* default: 60000 */
};

/*
 * Configuration API.
 */
int hsr_prp_config_init(struct hsr_prp_config *cfg,
			enum hsr_prp_mode mode,
			const char *port_a, const char *port_b);
int hsr_prp_config_validate(const struct hsr_prp_config *cfg);
int hsr_prp_config_apply(const struct hsr_prp_config *cfg);

/*
 * Map population — call after loading BPF programs.
 * FDs obtained via xgl_graph_get_map_fd() or bpf_obj_get().
 */
int hsr_prp_config_apply_maps(const struct hsr_prp_config *cfg,
			      int tc_ring_config_fd,
			      int ring_ports_fd,
			      int prp_ports_fd,
			      int local_mac_fd,
			      const uint8_t *mac);

/*
 * ext_dispatch setup — registers EtherType 0x892F -> NODE_HSR_INGRESS
 * in the groutx node_eth_input ext_dispatch map.
 */
int hsr_prp_config_setup_ext_dispatch(int ext_dispatch_fd);

/*
 * TC egress attachment — attach/detach TC BPF programs on ring ports.
 */
int hsr_prp_config_attach_tc(const char *ifname, int prog_fd);
int hsr_prp_config_detach_tc(const char *ifname);

/*
 * Node table API.
 */
struct hsr_prp_nodetable;

struct hsr_prp_nodetable *hsr_prp_nodetable_create(uint32_t capacity,
						   uint32_t timeout_ms);
void hsr_prp_nodetable_destroy(struct hsr_prp_nodetable *nt);
int hsr_prp_nodetable_add(struct hsr_prp_nodetable *nt,
			  const uint8_t *mac, uint8_t port,
			  uint16_t seq_nr);
int hsr_prp_nodetable_remove(struct hsr_prp_nodetable *nt,
			     const uint8_t *mac);
bool hsr_prp_nodetable_lookup(const struct hsr_prp_nodetable *nt,
			      const uint8_t *mac);
int hsr_prp_nodetable_timeout_scan(struct hsr_prp_nodetable *nt);
int hsr_prp_nodetable_dump(const struct hsr_prp_nodetable *nt,
			   void (*cb)(const uint8_t *mac,
				      uint64_t last_a, uint64_t last_b,
				      uint16_t last_seq, void *arg),
			   void *arg);

/*
 * Supervision frame API.
 */
struct hsr_prp_supervision;

struct hsr_prp_supervision *hsr_prp_supervision_create(
	const struct hsr_prp_config *cfg,
	const uint8_t *local_mac);
void hsr_prp_supervision_destroy(struct hsr_prp_supervision *sup);
int hsr_prp_supervision_send(struct hsr_prp_supervision *sup);
int hsr_prp_supervision_start(struct hsr_prp_supervision *sup);
void hsr_prp_supervision_stop(struct hsr_prp_supervision *sup);

/*
 * Supervision frame reception — parses incoming supervision frames
 * and updates the node table with discovered peers.
 */
struct hsr_prp_sup_rx;

struct hsr_prp_sup_rx *hsr_prp_sup_rx_create(
	const struct hsr_prp_config *cfg,
	struct hsr_prp_nodetable *nodetable);
void hsr_prp_sup_rx_destroy(struct hsr_prp_sup_rx *rx);
int hsr_prp_sup_rx_start(struct hsr_prp_sup_rx *rx);
void hsr_prp_sup_rx_stop(struct hsr_prp_sup_rx *rx);

/*
 * Statistics API.
 */
struct hsr_prp_stats {
	uint64_t rx_count;
	uint64_t rx_bytes;
	uint64_t tx_count;
	uint64_t tx_bytes;
	uint64_t dup_drops;
	uint64_t errors;
};

int hsr_prp_stats_read(int stats_map_fd, int node_id,
		       struct hsr_prp_stats *out);
int hsr_prp_stats_reset(int stats_map_fd, int node_id);
int hsr_prp_stats_dump(int stats_map_fd,
		       void (*cb)(int node_id,
				  const struct hsr_prp_stats *stats,
				  void *arg),
		       void *arg);

/*
 * Instance API — end-to-end HSR/PRP setup.
 *
 * Creates the XDP graph, loads BPF programs (XDP ingress + TC egress)
 * with pinned map sharing, populates maps, and manages supervision
 * and node table subsystems.
 */
struct hsr_prp_instance;

struct hsr_prp_instance *hsr_prp_instance_create(
	const struct hsr_prp_config *cfg,
	const char *bpf_obj_dir);
int hsr_prp_instance_attach(struct hsr_prp_instance *inst);
int hsr_prp_instance_start(struct hsr_prp_instance *inst);
void hsr_prp_instance_stop(struct hsr_prp_instance *inst);
struct hsr_prp_nodetable *hsr_prp_instance_get_nodetable(
	struct hsr_prp_instance *inst);
int hsr_prp_instance_get_stats(struct hsr_prp_instance *inst,
			       int node_id, struct hsr_prp_stats *out);
void hsr_prp_instance_destroy(struct hsr_prp_instance *inst);

#endif /* HSR_PRP_USERSPACE_H */
