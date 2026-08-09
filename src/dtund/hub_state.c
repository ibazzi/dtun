#include "hub_internal.h"
#include "hub_sync.h"

#include <string.h>

static void view_node(const hub_node_record_t *node,
                      dtund_hub_node_view_t *view) {
  memset(view, 0, sizeof(*view));
  view->node_id = node->node_id;
  view->tunnel_id = node->tunnel_id;
  view->hub_tunnel_id = node->hub_tunnel_id;
  view->address = node->address;
  view->prefix_len = node->prefix_len;
  view->raw = node->raw;
  view->udp_addr = node->udp_addr;
  view->udp_port = node->udp_port;
  view->generation = node->generation;
  view->online = node->online;
}

void dtund_hub_init(dtund_hub_t *hub) {
  hub_state_init();
  if (hub)
    hub->initialized = 1;
}

int dtund_hub_load(dtund_hub_t *hub, const char *path) {
  int result = hub_load_state(path);
  if (hub && result == 0)
    hub->initialized = 1;
  return result;
}

int dtund_hub_save(dtund_hub_t *hub, const char *path) {
  (void)hub;
  return hub_save_state(path);
}

int dtund_hub_validate(dtund_hub_t *hub, const dtun_config_t *config,
                       struct in_addr hub_address) {
  (void)hub;
  return hub_validate_state(config, hub_address);
}

int dtund_hub_allocate(dtund_hub_t *hub, const dtun_config_t *config,
                       struct in_addr hub_address, uint64_t requested_node,
                       struct in_addr requested_address, uint8_t prefix_len,
                       dtund_hub_node_view_t *view, char *error,
                       size_t error_len) {
  hub_node_record_t *node;

  (void)hub;
  node = hub_allocate_node(config, hub_address, requested_node,
                           requested_address, prefix_len, error, error_len);
  if (!node)
    return -1;
  if (view)
    view_node(node, view);
  return 0;
}

int dtund_hub_update_node(dtund_hub_t *hub, uint64_t node_id,
                          struct in_addr udp_address, uint16_t udp_port,
                          uint64_t generation, int online) {
  hub_node_record_t *node;

  (void)hub;
  node = node_by_id(node_id);
  if (!node)
    return -1;
  node->udp_addr = udp_address;
  node->raw = udp_address;
  node->udp_port = udp_port;
  node->generation = generation;
  node->online = !!online;
  hub_note_change(node_id);
  return 0;
}

int dtund_hub_get_node(const dtund_hub_t *hub, uint64_t node_id,
                       dtund_hub_node_view_t *view) {
  hub_node_record_t *node;

  (void)hub;
  if (!view)
    return -1;
  node = node_by_id(node_id);
  if (!node)
    return -1;
  view_node(node, view);
  return 0;
}

int dtund_hub_remove_node(dtund_hub_t *hub, uint64_t node_id) {
  uint32_t i;

  (void)hub;
  for (i = 0; i < g_hub_state.node_count; i++)
    if (g_hub_state.nodes[i].node_id == node_id) {
      hub_remove_node_at(i);
      hub_note_change(node_id);
      return 0;
    }
  return -1;
}

uint32_t dtund_hub_node_count(const dtund_hub_t *hub) {
  (void)hub;
  return g_hub_state.node_count;
}

uint32_t dtund_hub_session_count(const dtund_hub_t *hub) {
  (void)hub;
  return g_hub_state.session_count;
}

uint64_t dtund_hub_candidate_epoch(const dtund_hub_t *hub) {
  (void)hub;
  return g_hub_state.candidate_epoch;
}

uint16_t dtund_hub_build_refresh_page(dtund_hub_t *hub, uint64_t requester,
                                      uint64_t requested_epoch, uint16_t offset,
                                      dtrg_sync_peer_t peers[20],
                                      uint8_t *flags, uint16_t *next_offset) {
  (void)hub;
  return build_refresh_page(requester, requested_epoch, offset, peers, flags,
                            next_offset);
}
