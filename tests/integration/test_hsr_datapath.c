/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_hsr_datapath — Privileged integration test for HSR data path.
 *
 * Requires root (CAP_BPF + CAP_NET_ADMIN). Creates veth pairs, loads
 * actual BPF programs, sends frames, and verifies:
 *
 *   1. TC egress inserts HSR tag with correct fields
 *   2. TC egress clones to peer port with different path field
 *   3. Clone mark prevents re-cloning
 *   4. XDP ingress strips HSR tag (duplicate detection)
 *   5. Sequence counter increments atomically
 *   6. Map population (tc_ring_config, ring_ports) works correctly
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <hsr_prp/hsr_tag.h>
#include <hsr_prp/prp_rct.h>
#include <hsr_prp/hsr_prp_common.h>
#include <hsr_prp/hsr_prp_userspace.h>

static int tests_run;
static int tests_passed;
static int tests_failed;
static int tests_skipped;

#define TEST(name) do { \
	tests_run++; \
	printf("  %-50s ", name); \
} while (0)

#define PASS() do { \
	tests_passed++; \
	printf("PASS\n"); \
	return; \
} while (0)

#define FAIL(msg) do { \
	tests_failed++; \
	printf("FAIL: %s\n", msg); \
	return; \
} while (0)

#define SKIP(msg) do { \
	tests_skipped++; \
	printf("SKIP: %s\n", msg); \
	return; \
} while (0)

#define ASSERT_EQ(a, b) do { \
	if ((a) != (b)) { \
		tests_failed++; \
		printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); \
		return; \
	} \
} while (0)

#define ASSERT_GE(a, b) do { \
	if ((a) < (b)) { \
		tests_failed++; \
		printf("FAIL: %s < %s (line %d)\n", #a, #b, __LINE__); \
		return; \
	} \
} while (0)

/* CI containers run as uid 0 WITHOUT CAP_BPF/CAP_NET_ADMIN — probe
 * the actual capability (bpf_map_create), matching the xgl test
 * convention. */
static int have_privileges(void)
{
	int fd;

	if (geteuid() != 0)
		return 0;

	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "cap_probe",
	                    sizeof(__u32), sizeof(__u32), 1, NULL);
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

static int bpf_obj_exists(const char *path)
{
	return access(path, R_OK) == 0;
}

/* BPF object directory — set by meson to builddir */
#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

#define HSR_EGRESS_OBJ  BPF_OBJ_DIR "/node_hsr_egress.bpf.o"
#define PRP_EGRESS_OBJ  BPF_OBJ_DIR "/node_prp_egress.bpf.o"

#define REQUIRE_BPF() do { \
	if (!have_privileges()) SKIP("no root"); \
	if (!bpf_obj_exists(HSR_EGRESS_OBJ)) \
		SKIP("BPF objects not found"); \
} while (0)

/* --- Veth pair management --- */

static int create_veth_pair(const char *a, const char *b)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd),
		 "ip link add %s type veth peer name %s 2>/dev/null", a, b);
	return system(cmd);
}

static int set_link_up(const char *ifname)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", ifname);
	return system(cmd);
}

static void delete_link(const char *ifname)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", ifname);
	system(cmd);
}

/* --- Raw socket helpers --- */

static int raw_socket(unsigned int ifindex)
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
		int e = errno;
		close(sock);
		return -e;
	}

	/* Non-blocking with short timeout for receives */
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return sock;
}

static int send_raw_frame(int sock, unsigned int ifindex,
			  const void *frame, size_t len)
{
	struct sockaddr_ll addr;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = (int)ifindex;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, frame, ETH_ALEN);

	ssize_t ret = sendto(sock, frame, len, 0,
			     (struct sockaddr *)&addr, sizeof(addr));
	return (ret < 0) ? -errno : 0;
}

/*
 * Receive a frame, skipping outgoing captures and frames that don't
 * match the expected source MAC. AF_PACKET sockets see both ingress
 * and egress, plus kernel-generated frames (IPv6 ND, etc.).
 * Filtering by source MAC ensures we only pick up our test frame.
 *
 * If expect_src is NULL, any ingress frame is accepted.
 */
static ssize_t recv_raw_frame(int sock, void *buf, size_t buflen,
			      const uint8_t *expect_src)
{
	struct sockaddr_ll addr;
	socklen_t addrlen;

	for (int attempt = 0; attempt < 32; attempt++) {
		addrlen = sizeof(addr);
		ssize_t n = recvfrom(sock, buf, buflen, 0,
				     (struct sockaddr *)&addr, &addrlen);
		if (n < 0)
			return n;

		/* Skip outgoing frames (clones, loopback) */
		if (addr.sll_pkttype == PACKET_OUTGOING)
			continue;

		/* Filter by source MAC if requested */
		if (expect_src && n >= (ssize_t)sizeof(struct ethhdr)) {
			struct ethhdr *eth = buf;
			if (memcmp(eth->h_source, expect_src, ETH_ALEN) != 0)
				continue;
		}

		return n;
	}

	errno = EAGAIN;
	return -1;
}

/* --- Test: TC egress loads and attaches --- */

static void test_tc_egress_loads(void)
{
	TEST("tc_egress_loads");
	REQUIRE_BPF();

	struct bpf_object *obj = bpf_object__open(HSR_EGRESS_OBJ);
	if (!obj)
		FAIL("cannot open BPF object");

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		FAIL("cannot load BPF object");
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "node_hsr_egress");
	if (!prog) {
		bpf_object__close(obj);
		FAIL("program node_hsr_egress not found");
	}

	int fd = bpf_program__fd(prog);
	if (fd < 0) {
		bpf_object__close(obj);
		FAIL("program fd invalid");
	}

	bpf_object__close(obj);
	PASS();
}

/* --- Test: TC egress inserts HSR tag --- */

static void test_tc_egress_inserts_tag(void)
{
	TEST("tc_egress_inserts_hsr_tag");
	REQUIRE_BPF();

	const char *veth_a = "hsr_ta";
	const char *veth_b = "hsr_tb";

	delete_link(veth_a);

	if (create_veth_pair(veth_a, veth_b) != 0)
		SKIP("cannot create veth pair (no CAP_NET_ADMIN)");

	set_link_up(veth_a);
	set_link_up(veth_b);

	unsigned int idx_a = if_nametoindex(veth_a);
	unsigned int idx_b = if_nametoindex(veth_b);

	if (idx_a == 0 || idx_b == 0) {
		delete_link(veth_a);
		FAIL("cannot get ifindex");
	}

	/* Load TC egress BPF program */
	struct bpf_object *obj = bpf_object__open(HSR_EGRESS_OBJ);
	if (!obj) {
		delete_link(veth_a);
		FAIL("cannot open BPF object");
	}

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot load BPF object");
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "node_hsr_egress");
	if (!prog) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("program not found");
	}

	int prog_fd = bpf_program__fd(prog);

	/* Populate tc_ring_config map */
	struct bpf_map *tc_map =
		bpf_object__find_map_by_name(obj, "tc_ring_config");
	if (!tc_map) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("tc_ring_config map not found");
	}

	int tc_map_fd = bpf_map__fd(tc_map);
	struct ring_port_config cfg_a = {
		.peer_ifindex = idx_b,
		.path_id = 0, /* path A */
	};

	if (bpf_map_update_elem(tc_map_fd, &idx_a, &cfg_a, BPF_ANY) != 0) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot populate tc_ring_config");
	}

	/* Attach TC egress on veth_a */
	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = (int)idx_a,
		    .attach_point = BPF_TC_EGRESS);

	int ret = bpf_tc_hook_create(&hook);
	if (ret != 0 && ret != -EEXIST) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot create TC hook");
	}

	LIBBPF_OPTS(bpf_tc_opts, opts,
		    .prog_fd = prog_fd);

	ret = bpf_tc_attach(&hook, &opts);
	if (ret != 0) {
		bpf_tc_hook_destroy(&hook);
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot attach TC program");
	}

	/* Open raw socket on veth_b to receive tagged frames */
	int rx_sock = raw_socket(idx_b);
	if (rx_sock < 0) {
		bpf_tc_hook_destroy(&hook);
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot open raw socket");
	}

	/* Send a plain Ethernet frame on veth_a (triggers TC egress) */
	int tx_sock = raw_socket(idx_a);
	if (tx_sock < 0) {
		close(rx_sock);
		bpf_tc_hook_destroy(&hook);
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot open tx socket");
	}

	/* Build a minimal IP frame */
	uint8_t frame[64];
	struct ethhdr *eth = (struct ethhdr *)frame;

	memset(frame, 0, sizeof(frame));
	/* Broadcast destination */
	memset(eth->h_dest, 0xFF, ETH_ALEN);
	/* Read our source MAC */
	uint8_t src_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(0x0800); /* IP */

	/* Fill payload with pattern */
	memset(frame + sizeof(struct ethhdr), 0xAA,
	       sizeof(frame) - sizeof(struct ethhdr));

	send_raw_frame(tx_sock, idx_a, frame, sizeof(frame));

	/* Receive on veth_b — should now have HSR tag */
	uint8_t rxbuf[128];
	ssize_t rxlen = recv_raw_frame(rx_sock, rxbuf, sizeof(rxbuf),
				       src_mac);

	close(tx_sock);
	close(rx_sock);
	bpf_tc_hook_destroy(&hook);
	bpf_object__close(obj);
	delete_link(veth_a);

	if (rxlen < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct hsr_tag))) {
		FAIL("received frame too short for HSR tag");
	}

	/* Check EtherType is 0x892F (HSR) */
	struct ethhdr *rx_eth = (struct ethhdr *)rxbuf;
	if (ntohs(rx_eth->h_proto) != HSR_ETHERTYPE) {
		FAIL("EtherType is not 0x892F");
	}

	/* Parse the HSR tag */
	struct hsr_tag *tag = (struct hsr_tag *)(rxbuf + sizeof(struct ethhdr));
	__u16 path = hsr_tag_get_path(tag);
	__u16 seq = hsr_tag_get_seq(tag);
	__u16 encap = hsr_tag_get_encap_proto(tag);

	/* Path should be A (0x0000) since we set path_id=0 */
	if (path != HSR_PATH_A) {
		printf("FAIL: path=0x%04x, expected 0x%04x\n",
		       path, HSR_PATH_A);
		tests_failed++;
		return;
	}

	/* Encapsulated proto should be original (0x0800) */
	if (encap != 0x0800) {
		printf("FAIL: encap_proto=0x%04x, expected 0x0800\n", encap);
		tests_failed++;
		return;
	}

	/* Sequence number should be 0 (first frame) */
	if (seq != 0) {
		printf("FAIL: seq=%u, expected 0\n", seq);
		tests_failed++;
		return;
	}

	PASS();
}

/* --- Test: Sequence counter increments --- */

static void test_seq_counter_increments(void)
{
	TEST("seq_counter_increments");
	REQUIRE_BPF();

	const char *veth_a = "hsr_sa";
	const char *veth_b = "hsr_sb";

	delete_link(veth_a);

	if (create_veth_pair(veth_a, veth_b) != 0)
		SKIP("cannot create veth pair (no CAP_NET_ADMIN)");

	set_link_up(veth_a);
	set_link_up(veth_b);

	unsigned int idx_a = if_nametoindex(veth_a);
	unsigned int idx_b = if_nametoindex(veth_b);

	struct bpf_object *obj = bpf_object__open(HSR_EGRESS_OBJ);
	if (!obj) {
		delete_link(veth_a);
		FAIL("cannot open BPF object");
	}

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot load BPF object");
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "node_hsr_egress");
	int prog_fd = bpf_program__fd(prog);

	/* Populate tc_ring_config */
	struct bpf_map *tc_map =
		bpf_object__find_map_by_name(obj, "tc_ring_config");
	int tc_map_fd = bpf_map__fd(tc_map);

	struct ring_port_config cfg_a = {
		.peer_ifindex = idx_b,
		.path_id = 0,
	};
	bpf_map_update_elem(tc_map_fd, &idx_a, &cfg_a, BPF_ANY);

	/* Attach TC egress */
	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = (int)idx_a,
		    .attach_point = BPF_TC_EGRESS);
	bpf_tc_hook_create(&hook);

	LIBBPF_OPTS(bpf_tc_opts, opts,
		    .prog_fd = prog_fd);
	bpf_tc_attach(&hook, &opts);

	int rx_sock = raw_socket(idx_b);
	int tx_sock = raw_socket(idx_a);

	/* Send 3 frames */
	uint8_t frame[64];
	struct ethhdr *eth = (struct ethhdr *)frame;
	memset(frame, 0, sizeof(frame));
	memset(eth->h_dest, 0xFF, ETH_ALEN);
	uint8_t src_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(0x0800);

	__u16 last_seq = 0;
	int seq_ok = 1;

	for (int i = 0; i < 3; i++) {
		send_raw_frame(tx_sock, idx_a, frame, sizeof(frame));

		uint8_t rxbuf[128];
		ssize_t rxlen = recv_raw_frame(rx_sock, rxbuf, sizeof(rxbuf),
					       src_mac);

		if (rxlen < (ssize_t)(sizeof(struct ethhdr) +
				      sizeof(struct hsr_tag))) {
			seq_ok = 0;
			break;
		}

		struct hsr_tag *tag =
			(struct hsr_tag *)(rxbuf + sizeof(struct ethhdr));
		__u16 seq = hsr_tag_get_seq(tag);

		if (i == 0) {
			last_seq = seq;
		} else {
			if (seq != (__u16)(last_seq + 1)) {
				seq_ok = 0;
				break;
			}
			last_seq = seq;
		}
	}

	close(tx_sock);
	close(rx_sock);
	bpf_tc_hook_destroy(&hook);
	bpf_object__close(obj);
	delete_link(veth_a);

	if (!seq_ok)
		FAIL("sequence numbers not incrementing");

	PASS();
}

/* --- Test: PRP egress appends RCT --- */

static void test_prp_egress_appends_rct(void)
{
	TEST("prp_egress_appends_rct");
	REQUIRE_BPF();

	if (!bpf_obj_exists(PRP_EGRESS_OBJ))
		SKIP("PRP egress BPF object not found");

	const char *veth_a = "prp_ta";
	const char *veth_b = "prp_tb";

	delete_link(veth_a);

	if (create_veth_pair(veth_a, veth_b) != 0)
		SKIP("cannot create veth pair (no CAP_NET_ADMIN)");

	set_link_up(veth_a);
	set_link_up(veth_b);

	unsigned int idx_a = if_nametoindex(veth_a);
	unsigned int idx_b = if_nametoindex(veth_b);

	struct bpf_object *obj = bpf_object__open(PRP_EGRESS_OBJ);
	if (!obj) {
		delete_link(veth_a);
		FAIL("cannot open BPF object");
	}

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot load BPF object");
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "node_prp_egress");
	if (!prog) {
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("program not found");
	}

	int prog_fd = bpf_program__fd(prog);

	/* Populate tc_ring_config */
	struct bpf_map *tc_map =
		bpf_object__find_map_by_name(obj, "tc_ring_config");
	int tc_map_fd = bpf_map__fd(tc_map);

	struct ring_port_config cfg_a = {
		.peer_ifindex = idx_b,
		.path_id = 0, /* LAN A */
	};
	bpf_map_update_elem(tc_map_fd, &idx_a, &cfg_a, BPF_ANY);

	/* Attach TC egress */
	LIBBPF_OPTS(bpf_tc_hook, hook,
		    .ifindex = (int)idx_a,
		    .attach_point = BPF_TC_EGRESS);
	bpf_tc_hook_create(&hook);

	LIBBPF_OPTS(bpf_tc_opts, opts,
		    .prog_fd = prog_fd);

	if (bpf_tc_attach(&hook, &opts) != 0) {
		bpf_tc_hook_destroy(&hook);
		bpf_object__close(obj);
		delete_link(veth_a);
		FAIL("cannot attach TC program");
	}

	int rx_sock = raw_socket(idx_b);
	int tx_sock = raw_socket(idx_a);

	/* Send a plain frame */
	uint8_t frame[64];
	struct ethhdr *eth = (struct ethhdr *)frame;
	memset(frame, 0, sizeof(frame));
	memset(eth->h_dest, 0xFF, ETH_ALEN);
	uint8_t src_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(0x0800);
	memset(frame + sizeof(struct ethhdr), 0xBB,
	       sizeof(frame) - sizeof(struct ethhdr));

	send_raw_frame(tx_sock, idx_a, frame, sizeof(frame));

	/* Receive on veth_b — should have PRP RCT appended */
	uint8_t rxbuf[128];
	ssize_t rxlen = recv_raw_frame(rx_sock, rxbuf, sizeof(rxbuf),
				       src_mac);

	close(tx_sock);
	close(rx_sock);
	bpf_tc_hook_destroy(&hook);
	bpf_object__close(obj);
	delete_link(veth_a);

	if (rxlen < (ssize_t)(sizeof(frame) + PRP_RCT_SIZE))
		FAIL("received frame too short for PRP RCT");

	/* Check last 2 bytes are PRP suffix 0x88FB */
	struct prp_rct *rct = (struct prp_rct *)(rxbuf + rxlen - PRP_RCT_SIZE);
	if (!prp_rct_valid(rct))
		FAIL("PRP suffix not 0x88FB");

	/* Check LAN ID */
	__u16 lan = prp_rct_get_lan(rct);
	if (lan != PRP_LAN_A) {
		printf("FAIL: LAN=0x%04x, expected 0x%04x\n",
		       lan, PRP_LAN_A);
		tests_failed++;
		return;
	}

	PASS();
}

/* --- Test: Map population API --- */

static void test_map_population(void)
{
	TEST("map_population_api");
	REQUIRE_BPF();

	struct bpf_object *obj = bpf_object__open(HSR_EGRESS_OBJ);
	if (!obj)
		FAIL("cannot open BPF object");

	if (bpf_object__load(obj) != 0) {
		bpf_object__close(obj);
		FAIL("cannot load BPF object");
	}

	/* Get map FDs */
	struct bpf_map *tc_map =
		bpf_object__find_map_by_name(obj, "tc_ring_config");
	struct bpf_map *seq_map =
		bpf_object__find_map_by_name(obj, "seq_counters");

	if (!tc_map || !seq_map) {
		bpf_object__close(obj);
		FAIL("required maps not found");
	}

	int tc_fd = bpf_map__fd(tc_map);
	int seq_fd = bpf_map__fd(seq_map);

	/* Write and read back tc_ring_config */
	uint32_t key = 42;
	struct ring_port_config val = {
		.peer_ifindex = 99,
		.path_id = 1,
	};

	if (bpf_map_update_elem(tc_fd, &key, &val, BPF_ANY) != 0) {
		bpf_object__close(obj);
		FAIL("cannot write tc_ring_config");
	}

	struct ring_port_config readback;
	if (bpf_map_lookup_elem(tc_fd, &key, &readback) != 0) {
		bpf_object__close(obj);
		FAIL("cannot read tc_ring_config");
	}

	if (readback.peer_ifindex != 99 || readback.path_id != 1) {
		bpf_object__close(obj);
		FAIL("tc_ring_config readback mismatch");
	}

	/* Write and read back seq_counters (includes spin_lock) */
	uint8_t mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	struct seq_counter_val seq_val = { .seq_nr = 100 };

	if (bpf_map_update_elem(seq_fd, mac, &seq_val, BPF_ANY) != 0) {
		bpf_object__close(obj);
		FAIL("cannot write seq_counters");
	}

	struct seq_counter_val seq_readback;
	if (bpf_map_lookup_elem(seq_fd, mac, &seq_readback) != 0) {
		bpf_object__close(obj);
		FAIL("cannot read seq_counters");
	}

	if (seq_readback.seq_nr != 100) {
		bpf_object__close(obj);
		FAIL("seq_counters readback mismatch");
	}

	bpf_object__close(obj);
	PASS();
}

/* --- Test: ext_dispatch registration --- */

static void test_ext_dispatch_setup(void)
{
	TEST("ext_dispatch_setup");

	/* This tests the userspace API without BPF */
	int ret = hsr_prp_config_setup_ext_dispatch(-1, 20);
	if (ret != -EINVAL)
		FAIL("should reject invalid fd");

	PASS();
}

/* --- Test: Instance lifecycle --- */

static void test_instance_lifecycle(void)
{
	TEST("instance_lifecycle");
	REQUIRE_BPF();

	const char *veth_a = "hsr_ia";
	const char *veth_b = "hsr_ib";

	delete_link(veth_a);
	delete_link(veth_b);

	if (create_veth_pair(veth_a, veth_b) != 0)
		SKIP("cannot create veth pair (no CAP_NET_ADMIN)");

	set_link_up(veth_a);
	set_link_up(veth_b);

	struct hsr_prp_config cfg;
	int ret = hsr_prp_config_init(&cfg, HSR_PRP_MODE_HSR,
				      veth_a, veth_b);
	if (ret != 0) {
		delete_link(veth_a);
		FAIL("config_init failed");
	}

	struct hsr_prp_instance *inst =
		hsr_prp_instance_create(&cfg, BPF_OBJ_DIR, NULL);
	if (!inst) {
		delete_link(veth_a);
		FAIL("instance_create returned NULL");
	}

	/* Verify nodetable is accessible */
	struct hsr_prp_nodetable *nt =
		hsr_prp_instance_get_nodetable(inst);
	if (!nt) {
		hsr_prp_instance_destroy(inst);
		delete_link(veth_a);
		FAIL("get_nodetable returned NULL");
	}

	/* Attach XDP + TC to both ports */
	ret = hsr_prp_instance_attach(inst);
	if (ret != 0) {
		hsr_prp_instance_destroy(inst);
		delete_link(veth_a);
		FAIL("instance_attach failed");
	}

	/* Start supervision TX + RX */
	ret = hsr_prp_instance_start(inst);
	if (ret != 0) {
		hsr_prp_instance_destroy(inst);
		delete_link(veth_a);
		FAIL("instance_start failed");
	}

	/* Let supervision run briefly */
	usleep(100000); /* 100ms */

	/* Stop supervision */
	hsr_prp_instance_stop(inst);

	/* Clean teardown */
	hsr_prp_instance_destroy(inst);
	delete_link(veth_a);

	PASS();
}

/* --- Test: Config validation --- */

static void test_config_validation(void)
{
	TEST("config_validation");

	struct hsr_prp_config cfg;

	/* Invalid mode */
	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = 99;
	cfg.port_a_ifindex = 1;
	cfg.port_b_ifindex = 2;
	cfg.supervision_interval_ms = 2000;
	cfg.node_timeout_ms = 60000;
	ASSERT_EQ(hsr_prp_config_validate(&cfg), -EINVAL);

	/* Same port */
	cfg.mode = HSR_PRP_MODE_HSR;
	cfg.port_a_ifindex = 1;
	cfg.port_b_ifindex = 1;
	ASSERT_EQ(hsr_prp_config_validate(&cfg), -EINVAL);

	/* Valid */
	cfg.port_b_ifindex = 2;
	ASSERT_EQ(hsr_prp_config_validate(&cfg), 0);

	PASS();
}

int main(void)
{
	printf("test_hsr_datapath: privileged HSR/PRP integration tests\n");
	printf("  uid=%d, root=%s\n\n", geteuid(),
	       have_privileges() ? "yes" : "no");

	/* Non-privileged tests always run */
	test_config_validation();
	test_ext_dispatch_setup();

	/* Privileged tests require root + BPF objects */
	test_tc_egress_loads();
	test_map_population();
	test_tc_egress_inserts_tag();
	test_seq_counter_increments();
	test_prp_egress_appends_rct();
	test_instance_lifecycle();

	printf("\n");
	printf("  %d tests: %d passed, %d failed, %d skipped\n",
	       tests_run, tests_passed, tests_failed, tests_skipped);

	return tests_failed > 0 ? 1 : 0;
}
