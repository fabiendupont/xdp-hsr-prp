/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>

struct hsr_prp_supervision {
	struct hsr_prp_config cfg;
	uint8_t  local_mac[ETH_ALEN];
	uint16_t sup_seq_nr;
	int      sock_a;
	int      sock_b;
	pthread_t thread;
	atomic_int running;
};

static int create_raw_socket(uint32_t ifindex)
{
	struct sockaddr_ll addr;
	int sock;

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = (int)ifindex;
	addr.sll_protocol = htons(ETH_P_ALL);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int err = errno;
		close(sock);
		return -err;
	}

	return sock;
}

static int send_supervision_frame(struct hsr_prp_supervision *sup, int sock,
				  uint32_t ifindex)
{
	uint8_t frame[128];
	struct ethhdr *eth;
	struct hsr_sup_payload *payload;
	size_t frame_len;
	struct sockaddr_ll addr;
	uint8_t sup_mcast[] = HSR_SUP_MCAST_PREFIX;

	memset(frame, 0, sizeof(frame));
	eth = (struct ethhdr *)frame;

	/* Destination: HSR supervision multicast */
	memcpy(eth->h_dest, sup_mcast, 5);
	eth->h_dest[5] = 0x00;

	/* Source: local MAC */
	memcpy(eth->h_source, sup->local_mac, ETH_ALEN);

	if (sup->cfg.mode == HSR_PRP_MODE_HSR) {
		/*
		 * HSR supervision: send with EtherType 0x88FB.
		 * TC egress (node_hsr_egress) will insert the HSR tag
		 * and rewrite EtherType to 0x892F. Do NOT manually add
		 * the HSR tag here — that would result in a double tag.
		 */
		eth->h_proto = htons(HSR_SUP_ETHERTYPE);

		payload = (struct hsr_sup_payload *)(frame +
			sizeof(struct ethhdr));
		payload->sup_path = 0x00;
		payload->sup_ver = HSR_SUP_VERSION;
		payload->seq_nr = htons(sup->sup_seq_nr);
		payload->tlv1.type = HSR_TLV_TYPE_DANP;
		payload->tlv1.length = HSR_TLV_LEN_MAC;
		memcpy(payload->mac_danp, sup->local_mac, ETH_ALEN);
		payload->tlv0.type = HSR_TLV_TYPE_END;
		payload->tlv0.length = 0x00;

		frame_len = sizeof(struct ethhdr) +
			    sizeof(struct hsr_sup_payload);
	} else {
		/* PRP supervision: EtherType = 0x88FB (no HSR tag) */
		eth->h_proto = htons(HSR_SUP_ETHERTYPE);

		payload = (struct hsr_sup_payload *)(frame +
			sizeof(struct ethhdr));
		payload->sup_path = 0x00;
		payload->sup_ver = HSR_SUP_VERSION;
		payload->seq_nr = htons(sup->sup_seq_nr);
		payload->tlv1.type = HSR_TLV_TYPE_DANP;
		payload->tlv1.length = HSR_TLV_LEN_MAC;
		memcpy(payload->mac_danp, sup->local_mac, ETH_ALEN);
		payload->tlv0.type = HSR_TLV_TYPE_END;
		payload->tlv0.length = 0x00;

		frame_len = sizeof(struct ethhdr) +
			    sizeof(struct hsr_sup_payload);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = (int)ifindex;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, eth->h_dest, ETH_ALEN);

	if (sendto(sock, frame, frame_len, 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -errno;

	return 0;
}

static void *supervision_thread(void *arg)
{
	struct hsr_prp_supervision *sup = arg;

	while (sup->running) {
		send_supervision_frame(sup, sup->sock_a,
				       sup->cfg.port_a_ifindex);
		send_supervision_frame(sup, sup->sock_b,
				       sup->cfg.port_b_ifindex);

		sup->sup_seq_nr++;

		usleep(sup->cfg.supervision_interval_ms * 1000);
	}

	return NULL;
}

struct hsr_prp_supervision *hsr_prp_supervision_create(
	const struct hsr_prp_config *cfg,
	const uint8_t *local_mac)
{
	struct hsr_prp_supervision *sup;

	if (!cfg || !local_mac)
		return NULL;

	sup = calloc(1, sizeof(*sup));
	if (!sup)
		return NULL;

	sup->cfg = *cfg;
	memcpy(sup->local_mac, local_mac, ETH_ALEN);

	sup->sock_a = create_raw_socket(cfg->port_a_ifindex);
	if (sup->sock_a < 0) {
		free(sup);
		return NULL;
	}

	sup->sock_b = create_raw_socket(cfg->port_b_ifindex);
	if (sup->sock_b < 0) {
		close(sup->sock_a);
		free(sup);
		return NULL;
	}

	return sup;
}

void hsr_prp_supervision_destroy(struct hsr_prp_supervision *sup)
{
	if (!sup)
		return;

	hsr_prp_supervision_stop(sup);

	if (sup->sock_a >= 0)
		close(sup->sock_a);
	if (sup->sock_b >= 0)
		close(sup->sock_b);

	free(sup);
}

int hsr_prp_supervision_send(struct hsr_prp_supervision *sup)
{
	int ret;

	if (!sup)
		return -EINVAL;

	ret = send_supervision_frame(sup, sup->sock_a,
				     sup->cfg.port_a_ifindex);
	if (ret != 0)
		return ret;

	ret = send_supervision_frame(sup, sup->sock_b,
				     sup->cfg.port_b_ifindex);
	if (ret != 0)
		return ret;

	sup->sup_seq_nr++;
	return 0;
}

int hsr_prp_supervision_start(struct hsr_prp_supervision *sup)
{
	if (!sup)
		return -EINVAL;

	if (sup->running)
		return -EALREADY;

	sup->running = 1;

	if (pthread_create(&sup->thread, NULL, supervision_thread, sup) != 0) {
		sup->running = 0;
		return -errno;
	}

	return 0;
}

void hsr_prp_supervision_stop(struct hsr_prp_supervision *sup)
{
	if (!sup || !sup->running)
		return;

	sup->running = 0;
	pthread_join(sup->thread, NULL);
}
