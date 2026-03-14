/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int hsr_prp_config_init(struct hsr_prp_config *cfg,
			enum hsr_prp_mode mode,
			const char *port_a, const char *port_b)
{
	if (!cfg || !port_a || !port_b)
		return -EINVAL;

	memset(cfg, 0, sizeof(*cfg));
	cfg->mode = mode;

	if (strlen(port_a) >= IFNAMSIZ || strlen(port_b) >= IFNAMSIZ)
		return -ENAMETOOLONG;

	strncpy(cfg->port_a, port_a, IFNAMSIZ - 1);
	strncpy(cfg->port_b, port_b, IFNAMSIZ - 1);

	cfg->port_a_ifindex = if_nametoindex(port_a);
	cfg->port_b_ifindex = if_nametoindex(port_b);

	cfg->supervision_interval_ms = HSR_PRP_SUPERVISION_INTERVAL_MS;
	cfg->node_timeout_ms = HSR_PRP_NODE_TIMEOUT_MS;

	return 0;
}

int hsr_prp_config_validate(const struct hsr_prp_config *cfg)
{
	if (!cfg)
		return -EINVAL;

	if (cfg->mode != HSR_PRP_MODE_HSR && cfg->mode != HSR_PRP_MODE_PRP)
		return -EINVAL;

	if (cfg->port_a_ifindex == 0)
		return -ENODEV;

	if (cfg->port_b_ifindex == 0)
		return -ENODEV;

	if (cfg->port_a_ifindex == cfg->port_b_ifindex)
		return -EINVAL;

	if (cfg->supervision_interval_ms == 0)
		return -EINVAL;

	if (cfg->node_timeout_ms == 0)
		return -EINVAL;

	return 0;
}

/*
 * Populate the tc_ring_config map with peer port information.
 * Each port maps to its peer's ifindex and its own path_id.
 */
static int populate_tc_ring_config(int map_fd,
				   const struct hsr_prp_config *cfg)
{
	struct ring_port_config port_a_cfg = {
		.peer_ifindex = cfg->port_b_ifindex,
		.path_id = 0,  /* path A / LAN A */
	};
	struct ring_port_config port_b_cfg = {
		.peer_ifindex = cfg->port_a_ifindex,
		.path_id = 1,  /* path B / LAN B */
	};
	int ret;

	ret = bpf_map_update_elem(map_fd, &cfg->port_a_ifindex,
				  &port_a_cfg, BPF_ANY);
	if (ret != 0)
		return -errno;

	ret = bpf_map_update_elem(map_fd, &cfg->port_b_ifindex,
				  &port_b_cfg, BPF_ANY);
	if (ret != 0)
		return -errno;

	return 0;
}

/*
 * Populate the ring_ports DEVMAP_HASH for XDP forwarding.
 * Maps ifindex -> bpf_devmap_val for bpf_redirect_map().
 */
static int populate_ring_ports(int map_fd,
			       const struct hsr_prp_config *cfg)
{
	struct bpf_devmap_val val_a = { .ifindex = cfg->port_a_ifindex };
	struct bpf_devmap_val val_b = { .ifindex = cfg->port_b_ifindex };
	int ret;

	ret = bpf_map_update_elem(map_fd, &cfg->port_a_ifindex,
				  &val_a, BPF_ANY);
	if (ret != 0)
		return -errno;

	ret = bpf_map_update_elem(map_fd, &cfg->port_b_ifindex,
				  &val_b, BPF_ANY);
	if (ret != 0)
		return -errno;

	return 0;
}

/*
 * Populate the prp_ports map for PRP per-interface dispatch (ISSUE-3).
 * Marks both ports as PRP ports so node_port_rx dispatches to
 * the PRP ingress node instead of eth_input.
 */
static int populate_prp_ports(int map_fd,
			      const struct hsr_prp_config *cfg)
{
	uint32_t val = 1;
	int ret;

	ret = bpf_map_update_elem(map_fd, &cfg->port_a_ifindex,
				  &val, BPF_ANY);
	if (ret != 0)
		return -errno;

	ret = bpf_map_update_elem(map_fd, &cfg->port_b_ifindex,
				  &val, BPF_ANY);
	if (ret != 0)
		return -errno;

	return 0;
}

/*
 * Populate ext_dispatch map in node_eth_input to route
 * EtherType 0x892F to the HSR ingress node at the given index.
 */
int hsr_prp_config_setup_ext_dispatch(int ext_dispatch_fd,
				      uint32_t hsr_ingress_idx)
{
	uint32_t ethertype = HSR_ETHERTYPE;

	if (ext_dispatch_fd < 0)
		return -EINVAL;

	if (bpf_map_update_elem(ext_dispatch_fd, &ethertype,
				&hsr_ingress_idx, BPF_ANY) != 0)
		return -errno;

	return 0;
}

/*
 * Populate the local_mac map used by node_hsr_forward for
 * source MAC filtering (prevents forwarding our own frames).
 */
static int populate_local_mac(int map_fd, const uint8_t *mac)
{
	uint32_t key = 0;

	if (bpf_map_update_elem(map_fd, &key, mac, BPF_ANY) != 0)
		return -errno;

	return 0;
}

/*
 * Populate BPF maps for the configured HSR/PRP mode.
 *
 * Map FDs are obtained from the xdp-graph-lib graph after loading
 * the BPF programs:
 *   tc_ring_config_fd = xgl_graph_get_map_fd(g, "tc_ring_config");
 *   ring_ports_fd     = xgl_graph_get_map_fd(g, "ring_ports");
 *   prp_ports_fd      = xgl_graph_get_map_fd(g, "prp_ports");
 *   local_mac_fd      = xgl_graph_get_map_fd(g, "local_mac");
 */
int hsr_prp_config_apply_maps(const struct hsr_prp_config *cfg,
			      int tc_ring_config_fd,
			      int ring_ports_fd,
			      int prp_ports_fd,
			      int local_mac_fd,
			      const uint8_t *mac)
{
	int ret;

	ret = hsr_prp_config_validate(cfg);
	if (ret != 0)
		return ret;

	/* TC ring config: both HSR and PRP modes need peer port mapping */
	if (tc_ring_config_fd >= 0) {
		ret = populate_tc_ring_config(tc_ring_config_fd, cfg);
		if (ret != 0)
			return ret;
	}

	/* DEVMAP: HSR mode needs ring forwarding */
	if (cfg->mode == HSR_PRP_MODE_HSR && ring_ports_fd >= 0) {
		ret = populate_ring_ports(ring_ports_fd, cfg);
		if (ret != 0)
			return ret;
	}

	/* PRP ports: PRP mode needs per-interface dispatch (ISSUE-3) */
	if (cfg->mode == HSR_PRP_MODE_PRP && prp_ports_fd >= 0) {
		ret = populate_prp_ports(prp_ports_fd, cfg);
		if (ret != 0)
			return ret;
	}

	/* Local MAC: HSR mode needs source MAC filtering in forward */
	if (cfg->mode == HSR_PRP_MODE_HSR && local_mac_fd >= 0 && mac) {
		ret = populate_local_mac(local_mac_fd, mac);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/*
 * Attach a TC egress BPF program to an interface.
 *
 * Uses libbpf tc hook API. The BPF object must be loaded first
 * and the program FD obtained.
 */
int hsr_prp_config_attach_tc(const char *ifname, int prog_fd)
{
	unsigned int ifindex;

	if (!ifname || prog_fd < 0)
		return -EINVAL;

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return -ENODEV;

	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = (int)ifindex,
		    .attach_point = BPF_TC_EGRESS);

	/* Create clsact qdisc (ignore EEXIST) */
	int ret = bpf_tc_hook_create(&hook);
	if (ret != 0 && ret != -EEXIST)
		return ret;

	LIBBPF_OPTS(bpf_tc_opts, opts,
		    .prog_fd = prog_fd);

	return bpf_tc_attach(&hook, &opts);
}

/*
 * Detach TC egress BPF program from an interface.
 */
int hsr_prp_config_detach_tc(const char *ifname)
{
	unsigned int ifindex;

	if (!ifname)
		return -EINVAL;

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return -ENODEV;

	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = (int)ifindex,
		    .attach_point = BPF_TC_EGRESS);

	return bpf_tc_hook_destroy(&hook);
}
