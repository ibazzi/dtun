/* Build this file in iproute2/ip/ to enable `ip link add ... type dtun`. */
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "ip_common.h"

enum {
	IFLA_DTUN_UNSPEC,
	IFLA_DTUN_LOCAL,
	IFLA_DTUN_UDP_PORT,
	IFLA_DTUN_NODE_ID,
	IFLA_DTUN_HUB,
	IFLA_DTUN_HUB_PORT,
	__IFLA_DTUN_MAX,
};
#define IFLA_DTUN_MAX (__IFLA_DTUN_MAX - 1)

static void explain(void)
{
	fprintf(stderr, "Usage: ... type dtun local ADDR udp_port PORT node_id ID [hub ADDR hub_port PORT]\n");
}

static int parse_ipv4(__u32 *addr, const char *text)
{
	return inet_pton(AF_INET, text, addr) == 1 ? 0 : -1;
}

static int dtun_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	__u32 addr;
	__u16 port;
	__u64 node;
	int seen = 0;

	while (argc > 0) {
		if (matches(*argv, "local") == 0) {
			NEXT_ARG();
			if (parse_ipv4(&addr, *argv))
				invarg("invalid local address", *argv);
			addattr_l(n, 1024, IFLA_DTUN_LOCAL, &addr, sizeof(addr));
			seen |= 1;
		} else if (matches(*argv, "udp_port") == 0) {
			NEXT_ARG();
			if (get_u16(&port, *argv, 0))
				invarg("invalid UDP port", *argv);
			port = htons(port);
			addattr_l(n, 1024, IFLA_DTUN_UDP_PORT, &port, sizeof(port));
			seen |= 2;
		} else if (matches(*argv, "node_id") == 0) {
			NEXT_ARG();
			if (get_u64(&node, *argv, 0))
				invarg("invalid node id", *argv);
			addattr_l(n, 1024, IFLA_DTUN_NODE_ID, &node, sizeof(node));
			seen |= 4;
		} else if (matches(*argv, "hub") == 0) {
			NEXT_ARG();
			if (parse_ipv4(&addr, *argv))
				invarg("invalid hub address", *argv);
			addattr_l(n, 1024, IFLA_DTUN_HUB, &addr, sizeof(addr));
		} else if (matches(*argv, "hub_port") == 0) {
			NEXT_ARG();
			if (get_u16(&port, *argv, 0))
				invarg("invalid hub UDP port", *argv);
			port = htons(port);
			addattr_l(n, 1024, IFLA_DTUN_HUB_PORT, &port, sizeof(port));
		} else {
			explain();
			return -1;
		}
		argc--;
		argv++;
	}
	if (seen != 7) {
		explain();
		return -1;
	}
	return 0;
}

struct link_util dtun_link_util = {
	.id = "dtun",
	.maxattr = IFLA_DTUN_MAX,
	.parse_opt = dtun_parse_opt,
};
