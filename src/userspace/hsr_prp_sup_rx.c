/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * hsr_prp_sup_rx — Supervision frame reception and node table update.
 *
 * Listens on raw sockets for incoming supervision frames (EtherType
 * 0x88FB for PRP, or 0x892F with encapsulated 0x88FB for HSR after
 * XDP ingress strips the tag). Parses the DANP TLV to extract the
 * source node MAC and updates the node table.
 *
 * For HSR: by the time frames reach userspace (after XDP ingress
 * processing), the HSR tag has been stripped. The supervision frame
 * arrives with EtherType 0x88FB.
 *
 * For PRP: after XDP ingress strips the RCT, the supervision frame
 * arrives with EtherType 0x88FB.
 */

#define _DEFAULT_SOURCE

#include <hsr_prp/hsr_prp_userspace.h>
#include <hsr_prp/hsr_prp_common.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>

struct hsr_prp_sup_rx {
	struct hsr_prp_config cfg;
	struct hsr_prp_nodetable *nodetable;
	int sock_a;
	int sock_b;
	int stop_fd;	/* eventfd for immediate shutdown signaling */
	pthread_t thread;
	atomic_int running;
};

static int create_rx_socket(uint32_t ifindex)
{
	struct sockaddr_ll addr;
	struct timeval tv;
	int sock;
	uint16_t proto = (uint16_t)HSR_SUP_ETHERTYPE;

	sock = socket(AF_PACKET, SOCK_RAW, htons(proto));
	if (sock < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = (int)ifindex;
	addr.sll_protocol = htons(proto);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int err = errno;
		close(sock);
		return -err;
	}

	/* Short timeout for poll loop */
	tv.tv_sec = 0;
	tv.tv_usec = 500000; /* 500ms */
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return sock;
}

/*
 * Check if the destination MAC is the HSR/PRP supervision multicast.
 * Prefix: 01:15:4E:00:01:xx
 */
static int is_supervision_mcast(const uint8_t *dst)
{
	uint8_t prefix[] = HSR_SUP_MCAST_PREFIX;

	return memcmp(dst, prefix, 5) == 0;
}

/*
 * Parse a supervision frame and update the node table.
 * The frame has already been de-tagged by XDP ingress.
 * Expected layout: Ethernet header + supervision payload (EtherType 0x88FB).
 */
static void process_supervision_frame(struct hsr_prp_sup_rx *rx,
				      const uint8_t *frame, size_t len,
				      uint8_t port)
{
	const struct ethhdr *eth;
	const struct hsr_sup_payload *payload;
	uint16_t seq_nr;

	if (len < sizeof(struct ethhdr) + sizeof(struct hsr_sup_payload))
		return;

	eth = (const struct ethhdr *)frame;

	/* Verify supervision multicast destination */
	if (!is_supervision_mcast(eth->h_dest))
		return;

	/* Verify EtherType is supervision (0x88FB) */
	if (ntohs(eth->h_proto) != HSR_SUP_ETHERTYPE)
		return;

	payload = (const struct hsr_sup_payload *)(frame +
		sizeof(struct ethhdr));

	/* Verify TLV type is DANP */
	if (payload->tlv1.type != HSR_TLV_TYPE_DANP)
		return;

	if (payload->tlv1.length != HSR_TLV_LEN_MAC)
		return;

	seq_nr = ntohs(payload->seq_nr);

	/* Update node table with DANP MAC */
	hsr_prp_nodetable_add(rx->nodetable, payload->mac_danp,
			      port, seq_nr);
}

static void receive_on_socket(struct hsr_prp_sup_rx *rx, int sock,
			      uint8_t port)
{
	uint8_t buf[256];
	ssize_t n;

	n = recv(sock, buf, sizeof(buf), 0);
	if (n <= 0)
		return;

	process_supervision_frame(rx, buf, (size_t)n, port);
}

static void *sup_rx_thread(void *arg)
{
	struct hsr_prp_sup_rx *rx = arg;
	fd_set rfds;
	struct timeval tv;
	int maxfd;

	maxfd = (rx->sock_a > rx->sock_b) ? rx->sock_a : rx->sock_b;
	if (rx->stop_fd > maxfd)
		maxfd = rx->stop_fd;

	while (rx->running) {
		FD_ZERO(&rfds);
		FD_SET(rx->sock_a, &rfds);
		FD_SET(rx->sock_b, &rfds);
		FD_SET(rx->stop_fd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (ret <= 0)
			continue;

		/* Stop signaled — exit immediately */
		if (FD_ISSET(rx->stop_fd, &rfds))
			break;

		if (FD_ISSET(rx->sock_a, &rfds))
			receive_on_socket(rx, rx->sock_a, 0);

		if (FD_ISSET(rx->sock_b, &rfds))
			receive_on_socket(rx, rx->sock_b, 1);

		/* Periodic timeout scan */
		hsr_prp_nodetable_timeout_scan(rx->nodetable);
	}

	return NULL;
}

struct hsr_prp_sup_rx *hsr_prp_sup_rx_create(
	const struct hsr_prp_config *cfg,
	struct hsr_prp_nodetable *nodetable)
{
	struct hsr_prp_sup_rx *rx;

	if (!cfg || !nodetable)
		return NULL;

	rx = calloc(1, sizeof(*rx));
	if (!rx)
		return NULL;

	rx->cfg = *cfg;
	rx->nodetable = nodetable;

	rx->stop_fd = eventfd(0, EFD_NONBLOCK);
	if (rx->stop_fd < 0) {
		free(rx);
		return NULL;
	}

	rx->sock_a = create_rx_socket(cfg->port_a_ifindex);
	if (rx->sock_a < 0) {
		close(rx->stop_fd);
		free(rx);
		return NULL;
	}

	rx->sock_b = create_rx_socket(cfg->port_b_ifindex);
	if (rx->sock_b < 0) {
		close(rx->sock_a);
		close(rx->stop_fd);
		free(rx);
		return NULL;
	}

	return rx;
}

void hsr_prp_sup_rx_destroy(struct hsr_prp_sup_rx *rx)
{
	if (!rx)
		return;

	hsr_prp_sup_rx_stop(rx);

	if (rx->stop_fd >= 0)
		close(rx->stop_fd);
	if (rx->sock_a >= 0)
		close(rx->sock_a);
	if (rx->sock_b >= 0)
		close(rx->sock_b);

	free(rx);
}

int hsr_prp_sup_rx_start(struct hsr_prp_sup_rx *rx)
{
	if (!rx)
		return -EINVAL;

	if (rx->running)
		return -EALREADY;

	rx->running = 1;

	if (pthread_create(&rx->thread, NULL, sup_rx_thread, rx) != 0) {
		rx->running = 0;
		return -errno;
	}

	return 0;
}

void hsr_prp_sup_rx_stop(struct hsr_prp_sup_rx *rx)
{
	uint64_t val = 1;

	if (!rx || !rx->running)
		return;

	rx->running = 0;

	/* Signal the eventfd to wake select() immediately */
	(void)write(rx->stop_fd, &val, sizeof(val));

	pthread_join(rx->thread, NULL);
}
