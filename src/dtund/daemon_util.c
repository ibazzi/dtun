#include <dtun/config.h>
#include <dtun/log.h>
#include <dtun/netlink.h>

#include "daemon_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

volatile sig_atomic_t g_running = 1;
dtund_ha_service_t *g_ha_service;
int g_raw_transport = 1;

void handle_signal(int sig) {
  (void)sig;
  g_running = 0;
}

int parse_psk(const char *hex, uint8_t out[32]) {
  size_t i;

  memset(out, 0, 32);
  if (!hex || !*hex) {
    dtun_log_info(
        "[dtund] PSK not specified: Zero-HMAC development mode enabled.");
    return 0;
  }
  if (strlen(hex) != 64) {
    dtun_log_err("Error: psk must be 64 hexadecimal characters");
    return -1;
  }
  for (i = 0; i < 32; i++) {
    unsigned int value;
    char byte[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
    char *end = NULL;

    errno = 0;
    value = (unsigned int)strtoul(byte, &end, 16);
    if (errno || !end || *end || value > 255) {
      dtun_log_err("Error: psk contains non-hexadecimal characters");
      return -1;
    }
    out[i] = (uint8_t)value;
  }
  return 1;
}

int parse_cidr(const char *cidr, struct in_addr *addr, uint8_t *prefix_len) {
  char buf[64];
  char *slash;
  char *end = NULL;
  long prefix = 32;

  if (!cidr || strlen(cidr) >= sizeof(buf))
    return -1;
  memcpy(buf, cidr, strlen(cidr) + 1);
  slash = strchr(buf, '/');
  if (slash) {
    *slash++ = '\0';
    errno = 0;
    prefix = strtol(slash, &end, 10);
    if (errno || !end || *end || prefix < 0 || prefix > 32)
      return -1;
  }
  if (inet_pton(AF_INET, buf, addr) != 1)
    return -1;
  *prefix_len = (uint8_t)prefix;
  return 0;
}

uint32_t prefix_mask(uint8_t prefix_len) {
  return prefix_len ? (UINT32_MAX << (32 - prefix_len)) : 0;
}

struct in_addr network_prefix(struct in_addr addr, uint8_t prefix_len) {
  struct in_addr network;
  network.s_addr = htonl(ntohl(addr.s_addr) & prefix_mask(prefix_len));
  return network;
}

int same_endpoint(const struct sockaddr_in *left,
                  const struct sockaddr_in *right) {
  return left->sin_family == right->sin_family &&
         left->sin_addr.s_addr == right->sin_addr.s_addr &&
         left->sin_port == right->sin_port;
}

int open_route_monitor(void) {
  struct sockaddr_nl address;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
  if (fd < 0)
    return -1;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int route_change_pending(int fd, uint32_t dtun_ifindex) {
  char buffer[8192];
  int changed = 0;
  ssize_t length;

  if (fd < 0)
    return 0;
  while ((length = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT)) > 0) {
    struct nlmsghdr *nlh;
    int remaining = (int)length;
    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining);
         nlh = NLMSG_NEXT(nlh, remaining)) {
      if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
        struct ifinfomsg *ifi = NLMSG_DATA(nlh);
        if ((uint32_t)ifi->ifi_index != dtun_ifindex)
          changed = 1;
      } else if (nlh->nlmsg_type == RTM_NEWADDR ||
                 nlh->nlmsg_type == RTM_DELADDR) {
        struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
        if (ifa->ifa_family == AF_INET && ifa->ifa_index != dtun_ifindex)
          changed = 1;
      } else if (nlh->nlmsg_type == RTM_NEWROUTE ||
                 nlh->nlmsg_type == RTM_DELROUTE) {
        struct rtmsg *route = NLMSG_DATA(nlh);
        if (route->rtm_family == AF_INET && route->rtm_dst_len == 0 &&
            route->rtm_table == RT_TABLE_MAIN)
          changed = 1;
      }
    }
  }
  return changed;
}

void trigger_tunnel_warmup(struct in_addr address) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in dst;
  char dummy = 0;

  if (sock < 0)
    return;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(9);
  dst.sin_addr = address;
  (void)sendto(sock, &dummy, 1, 0, (struct sockaddr *)&dst, sizeof(dst));
  close(sock);
}

int program_peer(const dtun_nl_peer_info_t *peer) {
  dtun_nl_peer_info_t update;
  if (dtun_nl_peer_add(peer) == 0)
    return 0;
  update = *peer;
  update.has_key = 0;
  return dtun_nl_peer_set(&update);
}

int program_route(uint32_t ifindex, uint32_t tunnel_id, struct in_addr prefix,
                  uint8_t prefix_len) {
  int result = dtun_nl_route_add(ifindex, tunnel_id, prefix, prefix_len);
  return result == -EEXIST ? 0 : result;
}
