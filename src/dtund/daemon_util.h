#ifndef DTUND_DAEMON_UTIL_H
#define DTUND_DAEMON_UTIL_H

#include "ha_service.h"
#include <dtun/config.h>
#include <dtun/netlink.h>

#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>

extern volatile sig_atomic_t g_running;
extern dtund_ha_service_t *g_ha_service;
extern int g_raw_transport;

void handle_signal(int sig);
int parse_psk(const char *hex, uint8_t out[32]);
int parse_cidr(const char *cidr, struct in_addr *addr, uint8_t *prefix_len);
uint32_t prefix_mask(uint8_t prefix_len);
struct in_addr network_prefix(struct in_addr addr, uint8_t prefix_len);
int same_endpoint(const struct sockaddr_in *left,
                  const struct sockaddr_in *right);
int open_route_monitor(void);
int route_change_pending(int fd, uint32_t dtun_ifindex);
void trigger_tunnel_warmup(struct in_addr address);
int program_peer(const dtun_nl_peer_info_t *peer);
int program_route(uint32_t ifindex, uint32_t tunnel_id, struct in_addr prefix,
                  uint8_t prefix_len);

#endif /* DTUND_DAEMON_UTIL_H */
