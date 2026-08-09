#ifndef DTUND_HUB_STATE_H
#define DTUND_HUB_STATE_H

#include <dtun/config.h>
#include <dtun/proto.h>

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct dtund_hub {
  int initialized;
} dtund_hub_t;

typedef struct {
  uint64_t node_id;
  uint32_t tunnel_id;
  uint32_t hub_tunnel_id;
  struct in_addr address;
  uint8_t prefix_len;
  struct in_addr raw;
  struct in_addr udp_addr;
  uint16_t udp_port;
  uint64_t generation;
  uint8_t online;
} dtund_hub_node_view_t;

void dtund_hub_init(dtund_hub_t *hub);
int dtund_hub_load(dtund_hub_t *hub, const char *path);
int dtund_hub_save(dtund_hub_t *hub, const char *path);
int dtund_hub_validate(dtund_hub_t *hub, const dtun_config_t *config,
                       struct in_addr hub_address);
int dtund_hub_allocate(dtund_hub_t *hub, const dtun_config_t *config,
                       struct in_addr hub_address, uint64_t requested_node,
                       struct in_addr requested_address, uint8_t prefix_len,
                       dtund_hub_node_view_t *view, char *error,
                       size_t error_len);
int dtund_hub_update_node(dtund_hub_t *hub, uint64_t node_id,
                          struct in_addr udp_address, uint16_t udp_port,
                          uint64_t generation, int online);
int dtund_hub_get_node(const dtund_hub_t *hub, uint64_t node_id,
                       dtund_hub_node_view_t *view);
int dtund_hub_remove_node(dtund_hub_t *hub, uint64_t node_id);
uint32_t dtund_hub_node_count(const dtund_hub_t *hub);
uint32_t dtund_hub_session_count(const dtund_hub_t *hub);
uint64_t dtund_hub_candidate_epoch(const dtund_hub_t *hub);
uint16_t dtund_hub_build_refresh_page(dtund_hub_t *hub, uint64_t requester,
                                      uint64_t requested_epoch, uint16_t offset,
                                      dtrg_sync_peer_t peers[20],
                                      uint8_t *flags, uint16_t *next_offset);

#endif /* DTUND_HUB_STATE_H */
