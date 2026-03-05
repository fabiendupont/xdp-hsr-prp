/* SPDX-License-Identifier: BSD-2-Clause */

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_node_ids.h>

#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * egl_node_stats layout (from ebpf-graph-lib):
 *   u64 in_count, in_bytes, out_count, out_bytes, drops, errors
 */
struct egl_node_stats_us {
	uint64_t in_count;
	uint64_t in_bytes;
	uint64_t out_count;
	uint64_t out_bytes;
	uint64_t drops;
	uint64_t errors;
};

int hsr_prp_stats_read(int stats_map_fd, int node_id,
		       struct hsr_prp_stats *out)
{
	struct egl_node_stats_us stats;
	uint32_t key;

	if (stats_map_fd < 0 || !out)
		return -EINVAL;

	key = (uint32_t)node_id;

	if (bpf_map_lookup_elem(stats_map_fd, &key, &stats) != 0)
		return -errno;

	out->rx_count = stats.in_count;
	out->rx_bytes = stats.in_bytes;
	out->tx_count = stats.out_count;
	out->tx_bytes = stats.out_bytes;
	out->dup_drops = stats.drops;
	out->errors = stats.errors;

	return 0;
}

int hsr_prp_stats_reset(int stats_map_fd, int node_id)
{
	struct egl_node_stats_us stats;
	uint32_t key;

	if (stats_map_fd < 0)
		return -EINVAL;

	key = (uint32_t)node_id;
	memset(&stats, 0, sizeof(stats));

	if (bpf_map_update_elem(stats_map_fd, &key, &stats, BPF_ANY) != 0)
		return -errno;

	return 0;
}

int hsr_prp_stats_dump(int stats_map_fd,
		       void (*cb)(int node_id,
				  const struct hsr_prp_stats *stats,
				  void *arg),
		       void *arg)
{
	struct hsr_prp_stats out;
	int node_ids[] = { NODE_HSR_INGRESS, NODE_HSR_FORWARD,
			   NODE_PRP_INGRESS };
	int count = 0;

	if (stats_map_fd < 0 || !cb)
		return -EINVAL;

	for (int i = 0; i < 3; i++) {
		if (hsr_prp_stats_read(stats_map_fd, node_ids[i], &out) == 0) {
			cb(node_ids[i], &out, arg);
			count++;
		}
	}

	return count;
}
