/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * hsr_prp_instance — End-to-end HSR/PRP integration.
 *
 * Orchestrates: graph creation, XDP node loading, TC program loading
 * with pinned map reuse, map population, XDP/TC attachment,
 * ext_dispatch registration, supervision, and node table maintenance.
 */

#define _DEFAULT_SOURCE

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>
#include <hsr_prp/hsr_prp_node_ids.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <xgl/xgl_graph.h>
#include <egl/egl_graph.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct hsr_prp_instance {
	struct hsr_prp_config cfg;
	uint8_t local_mac[ETH_ALEN];

	/* Graph and programs */
	struct xgl_graph *graph;
	struct bpf_object *tc_obj;
	int tc_prog_fd;

	/* Dynamically allocated node indices */
	int node_indices[HSR_PRP_NODE_CONFIG_SIZE];

	/* Subsystems */
	struct hsr_prp_supervision *sup;
	struct hsr_prp_sup_rx *sup_rx;
	struct hsr_prp_nodetable *nodetable;
};

/*
 * Read the MAC address of an interface via ioctl.
 */
static int get_interface_mac(const char *ifname, uint8_t *mac)
{
	struct ifreq ifr;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		int err = errno;
		close(sock);
		return -err;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(sock);
	return 0;
}

/*
 * Load a TC BPF program while reusing maps pinned by the graph.
 *
 * The graph's egl_graph_add_node() pins all maps from XDP programs.
 * TC programs redeclare shared maps (seq_counters, tc_ring_config);
 * this function opens the TC object, reuses pinned maps, loads it,
 * and returns the program FD.
 */
static int load_tc_with_pinned_maps(struct hsr_prp_instance *inst,
				    const char *obj_path,
				    const char *prog_name,
				    struct bpf_object **out_obj)
{
	struct egl_graph *egl;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_program *prog;
	int ret;

	egl = xgl_graph_get_egl(inst->graph);
	if (!egl)
		return -EINVAL;

	obj = bpf_object__open(obj_path);
	if (!obj)
		return -errno;

	/*
	 * For each map in the TC object, check if it exists as a
	 * pinned map in the graph. If so, reuse the pinned FD.
	 */
	bpf_object__for_each_map(map, obj) {
		const char *map_name = bpf_map__name(map);
		int pinned_fd;

		pinned_fd = egl_graph_get_map_fd(egl, map_name);
		if (pinned_fd >= 0) {
			ret = bpf_map__reuse_fd(map, pinned_fd);
			if (ret < 0) {
				bpf_object__close(obj);
				return ret;
			}
		}
	}

	ret = bpf_object__load(obj);
	if (ret != 0) {
		bpf_object__close(obj);
		return -errno;
	}

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		bpf_object__close(obj);
		return -ENOENT;
	}

	*out_obj = obj;
	return bpf_program__fd(prog);
}

/*
 * Populate the hsr_prp_node_config BPF map with allocated indices.
 * This map is the indirection table: role -> PROG_ARRAY index.
 */
static int populate_node_config(struct hsr_prp_instance *inst)
{
	struct egl_graph *egl;
	int config_fd;

	egl = xgl_graph_get_egl(inst->graph);
	if (!egl)
		return -EINVAL;

	config_fd = egl_graph_get_map_fd(egl, "hsr_prp_node_config");
	if (config_fd < 0)
		return -ENOENT;

	for (uint32_t i = 0; i < HSR_PRP_NODE_CONFIG_SIZE; i++) {
		uint32_t role = i;
		uint32_t idx = (uint32_t)inst->node_indices[i];

		if (bpf_map_update_elem(config_fd, &role, &idx, BPF_ANY) != 0)
			return -errno;
	}

	return 0;
}

struct hsr_prp_instance *hsr_prp_instance_create(
	const struct hsr_prp_config *cfg,
	const char *bpf_obj_dir)
{
	struct hsr_prp_instance *inst;
	struct egl_graph *egl;
	const char *tc_prog_name;
	char obj_path[512];
	int ret;

	if (!cfg || !bpf_obj_dir)
		return NULL;

	ret = hsr_prp_config_validate(cfg);
	if (ret != 0)
		return NULL;

	inst = calloc(1, sizeof(*inst));
	if (!inst)
		return NULL;

	inst->cfg = *cfg;
	inst->tc_prog_fd = -1;

	/* Get local MAC from port A */
	ret = get_interface_mac(cfg->port_a, inst->local_mac);
	if (ret != 0)
		goto err_free;

	/* Create XDP graph */
	inst->graph = xgl_graph_create("hsr_prp", 0);
	if (!inst->graph)
		goto err_free;

	egl = xgl_graph_get_egl(inst->graph);

	/* Reserve eth_input index so alloc_index() won't hand it out */
	ret = egl_graph_reserve_index(egl, NODE_ETH_INPUT);
	if (ret != 0 && ret != -EALREADY)
		goto err_graph;
	inst->node_indices[HSR_PRP_ROLE_ETH_INPUT] = NODE_ETH_INPUT;

	/* Allocate dynamic indices and load XDP ingress nodes */
	if (cfg->mode == HSR_PRP_MODE_HSR) {
		int hsr_ingress_idx = egl_graph_alloc_index(egl);
		if (hsr_ingress_idx < 0)
			goto err_graph;
		int hsr_forward_idx = egl_graph_alloc_index(egl);
		if (hsr_forward_idx < 0)
			goto err_graph;

		inst->node_indices[HSR_PRP_ROLE_HSR_INGRESS] = hsr_ingress_idx;
		inst->node_indices[HSR_PRP_ROLE_HSR_FORWARD] = hsr_forward_idx;

		snprintf(obj_path, sizeof(obj_path),
			 "%s/node_hsr_ingress.bpf.o", bpf_obj_dir);
		ret = xgl_graph_add_node(inst->graph, hsr_ingress_idx,
					 obj_path, "node_hsr_ingress");
		if (ret != 0)
			goto err_graph;

		snprintf(obj_path, sizeof(obj_path),
			 "%s/node_hsr_forward.bpf.o", bpf_obj_dir);
		ret = xgl_graph_add_node(inst->graph, hsr_forward_idx,
					 obj_path, "node_hsr_forward");
		if (ret != 0)
			goto err_graph;
	} else {
		int prp_ingress_idx = egl_graph_alloc_index(egl);
		if (prp_ingress_idx < 0)
			goto err_graph;

		inst->node_indices[HSR_PRP_ROLE_PRP_INGRESS] = prp_ingress_idx;

		snprintf(obj_path, sizeof(obj_path),
			 "%s/node_prp_ingress.bpf.o", bpf_obj_dir);
		ret = xgl_graph_add_node(inst->graph, prp_ingress_idx,
					 obj_path, "node_prp_ingress");
		if (ret != 0)
			goto err_graph;
	}

	/* Load TC egress with pinned map reuse */
	if (cfg->mode == HSR_PRP_MODE_HSR) {
		snprintf(obj_path, sizeof(obj_path),
			 "%s/node_hsr_egress.bpf.o", bpf_obj_dir);
		tc_prog_name = "node_hsr_egress";
	} else {
		snprintf(obj_path, sizeof(obj_path),
			 "%s/node_prp_egress.bpf.o", bpf_obj_dir);
		tc_prog_name = "node_prp_egress";
	}

	inst->tc_prog_fd = load_tc_with_pinned_maps(inst, obj_path,
						     tc_prog_name,
						     &inst->tc_obj);
	if (inst->tc_prog_fd < 0)
		goto err_graph;

	/* Populate node config map (indirection table) */
	ret = populate_node_config(inst);
	if (ret != 0)
		goto err_tc;

	/* Populate data path maps */
	{
		int tc_cfg_fd = egl_graph_get_map_fd(
			xgl_graph_get_egl(inst->graph), "tc_ring_config");
		int ring_fd = egl_graph_get_map_fd(
			xgl_graph_get_egl(inst->graph), "ring_ports");
		int prp_fd = egl_graph_get_map_fd(
			xgl_graph_get_egl(inst->graph), "prp_ports");
		int mac_fd = egl_graph_get_map_fd(
			xgl_graph_get_egl(inst->graph), "local_mac");

		ret = hsr_prp_config_apply_maps(cfg, tc_cfg_fd, ring_fd,
						prp_fd, mac_fd,
						inst->local_mac);
		if (ret != 0)
			goto err_tc;
	}

	/* Register ext_dispatch for HSR EtherType with dynamic index */
	if (cfg->mode == HSR_PRP_MODE_HSR) {
		int ext_fd = egl_graph_get_map_fd(
			xgl_graph_get_egl(inst->graph), "ext_dispatch");
		if (ext_fd >= 0) {
			int hsr_idx = inst->node_indices[HSR_PRP_ROLE_HSR_INGRESS];
			ret = hsr_prp_config_setup_ext_dispatch(ext_fd,
								(uint32_t)hsr_idx);
			if (ret != 0)
				goto err_tc;
		}
	}

	/* Create node table */
	inst->nodetable = hsr_prp_nodetable_create(256,
						   cfg->node_timeout_ms);
	if (!inst->nodetable)
		goto err_tc;

	/* Create supervision subsystem */
	inst->sup = hsr_prp_supervision_create(cfg, inst->local_mac);
	if (!inst->sup)
		goto err_nt;

	/* Create supervision frame receiver */
	inst->sup_rx = hsr_prp_sup_rx_create(cfg, inst->nodetable);
	if (!inst->sup_rx)
		goto err_sup;

	return inst;

err_sup:
	hsr_prp_supervision_destroy(inst->sup);
err_nt:
	hsr_prp_nodetable_destroy(inst->nodetable);
err_tc:
	bpf_object__close(inst->tc_obj);
err_graph:
	xgl_graph_destroy(inst->graph);
err_free:
	free(inst);
	return NULL;
}

int hsr_prp_instance_attach(struct hsr_prp_instance *inst)
{
	int ret;

	if (!inst)
		return -EINVAL;

	/* Attach XDP to both ring ports */
	ret = xgl_graph_attach(inst->graph, inst->cfg.port_a);
	if (ret != 0)
		return ret;

	ret = xgl_graph_attach(inst->graph, inst->cfg.port_b);
	if (ret != 0) {
		xgl_graph_detach(inst->graph, inst->cfg.port_a);
		return ret;
	}

	/* Attach TC egress to both ring ports */
	ret = hsr_prp_config_attach_tc(inst->cfg.port_a, inst->tc_prog_fd);
	if (ret != 0) {
		xgl_graph_detach(inst->graph, inst->cfg.port_b);
		xgl_graph_detach(inst->graph, inst->cfg.port_a);
		return ret;
	}

	ret = hsr_prp_config_attach_tc(inst->cfg.port_b, inst->tc_prog_fd);
	if (ret != 0) {
		hsr_prp_config_detach_tc(inst->cfg.port_a);
		xgl_graph_detach(inst->graph, inst->cfg.port_b);
		xgl_graph_detach(inst->graph, inst->cfg.port_a);
		return ret;
	}

	return 0;
}

int hsr_prp_instance_start(struct hsr_prp_instance *inst)
{
	int ret;

	if (!inst)
		return -EINVAL;

	ret = hsr_prp_supervision_start(inst->sup);
	if (ret != 0)
		return ret;

	ret = hsr_prp_sup_rx_start(inst->sup_rx);
	if (ret != 0) {
		hsr_prp_supervision_stop(inst->sup);
		return ret;
	}

	return 0;
}

void hsr_prp_instance_stop(struct hsr_prp_instance *inst)
{
	if (!inst)
		return;

	hsr_prp_sup_rx_stop(inst->sup_rx);
	hsr_prp_supervision_stop(inst->sup);
}

struct hsr_prp_nodetable *hsr_prp_instance_get_nodetable(
	struct hsr_prp_instance *inst)
{
	if (!inst)
		return NULL;
	return inst->nodetable;
}

int hsr_prp_instance_get_stats(struct hsr_prp_instance *inst,
			       int node_id, struct hsr_prp_stats *out)
{
	int stats_fd;

	if (!inst || !out)
		return -EINVAL;

	stats_fd = xgl_graph_get_stats_map_fd(inst->graph);
	if (stats_fd < 0)
		return -ENOENT;

	return hsr_prp_stats_read(stats_fd, node_id, out);
}

void hsr_prp_instance_destroy(struct hsr_prp_instance *inst)
{
	if (!inst)
		return;

	hsr_prp_sup_rx_stop(inst->sup_rx);
	hsr_prp_sup_rx_destroy(inst->sup_rx);
	hsr_prp_supervision_stop(inst->sup);
	hsr_prp_supervision_destroy(inst->sup);
	hsr_prp_nodetable_destroy(inst->nodetable);

	/* Detach TC egress */
	hsr_prp_config_detach_tc(inst->cfg.port_a);
	hsr_prp_config_detach_tc(inst->cfg.port_b);

	/* Detach XDP */
	xgl_graph_detach(inst->graph, inst->cfg.port_a);
	xgl_graph_detach(inst->graph, inst->cfg.port_b);

	if (inst->tc_obj)
		bpf_object__close(inst->tc_obj);

	xgl_graph_destroy(inst->graph);
	free(inst);
}
