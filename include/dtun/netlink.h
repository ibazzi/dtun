#ifndef DTUN_NETLINK_H
#define DTUN_NETLINK_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t ifindex;
  uint32_t tunnel_id;
  uint32_t remote_tunnel_id;
  uint64_t node_id;
  struct in_addr raw_addr;
  struct in_addr udp_addr;
  uint16_t udp_port;
  uint64_t candidate_generation;
  int has_generation;
  int dynamic_raw;
  int has_dynamic_raw;
  uint8_t key[32];
  int has_key;
} dtun_nl_peer_info_t;

typedef struct {
  uint32_t ifindex;
  uint32_t tunnel_id;
  uint32_t remote_tunnel_id;
  uint64_t node_id;
  struct in_addr raw_addr;
  struct in_addr raw_validated_addr;
  struct in_addr udp_addr;
  uint16_t udp_port;
  struct in_addr direct_udp_addr;
  uint16_t direct_udp_port;
  uint64_t candidate_generation;
  int dynamic_raw;
  int raw_up;
  int udp_up;
  int selected_path;
  uint8_t raw_health;
  uint8_t udp_health;
  uint64_t raw_srtt_us;
  uint64_t udp_srtt_us;
  uint64_t raw_rttvar_us;
  uint64_t udp_rttvar_us;
  uint32_t raw_loss_ppm;
  uint32_t udp_loss_ppm;
  uint32_t raw_threshold_ms;
  uint32_t udp_threshold_ms;
  uint32_t raw_last_ack_ms;
  uint32_t udp_last_ack_ms;
} dtun_nl_peer_status_t;

typedef struct {
  uint32_t ifindex;
  char ifname[16];
} dtun_nl_link_info_t;

/* Initialize Netlink connection. Resolves Generic Netlink DTUN family ID. */
int dtun_nl_init(void);
void dtun_nl_close(void);

/* Check if interface exists and return ifindex (>0) or 0 if not found. */
uint32_t dtun_link_get_ifindex(const char *ifname);
int dtun_link_list(dtun_nl_link_info_t **links, size_t *count);

/* Create dtun interface via RTNL. Returns ifindex or < 0 on error. */
int dtun_link_create(const char *ifname, struct in_addr local_addr,
                     uint16_t udp_port, uint64_t node_id,
                     struct in_addr hub_addr, uint16_t hub_port);

/* Delete dtun interface via RTNL RTM_DELLINK. */
int dtun_link_delete_by_name(const char *ifname);

/* Assign IPv4 address & prefix to interface, and set interface UP. */
int dtun_link_setup(uint32_t ifindex, const char *ifname, struct in_addr addr,
                    uint8_t prefix_len);

/* Netlink peer commands */
int dtun_nl_peer_add(const dtun_nl_peer_info_t *peer);
int dtun_nl_peer_set(const dtun_nl_peer_info_t *peer);
int dtun_nl_peer_del(uint32_t ifindex, uint32_t tunnel_id);
int dtun_nl_peer_get(uint32_t ifindex, uint32_t tunnel_id,
                     dtun_nl_peer_status_t *status);
int dtun_nl_peer_list(uint32_t ifindex, dtun_nl_peer_status_t **statuses,
                      size_t *count);
int dtun_nl_rebind(uint32_t ifindex);
int dtun_nl_hub_set(uint32_t ifindex, struct in_addr hub_addr,
                    uint16_t hub_port);
int dtun_nl_hub_migrate(uint32_t ifindex, struct in_addr hub_addr,
                        uint16_t hub_port, uint64_t term);
int dtun_nl_role_set(uint32_t ifindex, int operational);

/* Kernel module management functions */
int dtun_module_ensure_loaded(void);
void dtun_module_unload_if_needed(void);

/* Netlink route commands */
int dtun_nl_route_add(uint32_t ifindex, uint32_t tunnel_id,
                      struct in_addr prefix, uint8_t prefix_len);
int dtun_nl_route_del(uint32_t ifindex, uint32_t tunnel_id,
                      struct in_addr prefix, uint8_t prefix_len);

#endif /* DTUN_NETLINK_H */
