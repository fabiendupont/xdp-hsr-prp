/* SPDX-License-Identifier: BSD-2-Clause */

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>
#include <hsr_prp/hsr_prp_node_ids.h>

#include <string.h>
#include <errno.h>
#include <net/if.h>

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

int hsr_prp_config_apply(const struct hsr_prp_config *cfg)
{
	int ret;

	ret = hsr_prp_config_validate(cfg);
	if (ret != 0)
		return ret;

	/*
	 * Apply configuration to BPF maps:
	 * - Populate tc_ring_config with peer ifindex and path_id
	 * - Populate ring_ports DEVMAP for XDP forwarding
	 * - For PRP mode: populate prp_ports map
	 *
	 * Actual map population is done by the graph setup code
	 * using libbpf map FDs. This function validates only.
	 */

	return 0;
}
