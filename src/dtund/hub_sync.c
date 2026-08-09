#include <dtun/netlink.h>
#include <dtun/proto.h>

#include "daemon_util.h"
#include "hub_internal.h"
#include "hub_sync.h"

#include <string.h>

uint16_t build_peer_sync(uint32_t ifindex, uint64_t node_id,
                         dtrg_sync_peer_t peers[MAX_PEERS]) {
  uint16_t count = 0;
  uint32_t i;

  for (i = 0; i < g_hub_state.node_count && count < MAX_PEERS; i++) {
    hub_node_record_t *other = &g_hub_state.nodes[i];
    hub_session_record_t *session;
    dtun_nl_peer_status_t status;

    if (other->node_id == node_id || !other->online)
      continue;
    if (dtun_nl_peer_get(ifindex, other->hub_tunnel_id, &status) < 0 ||
        !status.udp_up || !status.direct_udp_addr.s_addr ||
        !status.direct_udp_port)
      continue;
    if (other->udp_addr.s_addr != status.direct_udp_addr.s_addr ||
        other->udp_port != status.direct_udp_port) {
      other->udp_addr = status.direct_udp_addr;
      other->udp_port = status.direct_udp_port;
      other->raw = status.direct_udp_addr;
      other->generation++;
      if (!other->generation)
        other->generation++;
      hub_note_change(other->node_id);
    }
    session = hub_session(node_id, other->node_id);
    if (!session)
      break;
    peers[count].node_id = other->node_id;
    peers[count].address = other->address;
    peers[count].raw = other->raw;
    peers[count].udp_addr = other->udp_addr;
    peers[count].udp_port = other->udp_port;
    peers[count].generation = other->generation;
    peers[count].flags = DTRG_PEER_ONLINE;
    if (node_id == session->first_node) {
      peers[count].tunnel_id = session->first_tunnel_id;
      peers[count].remote_tunnel_id = session->second_tunnel_id;
    } else {
      peers[count].tunnel_id = session->second_tunnel_id;
      peers[count].remote_tunnel_id = session->first_tunnel_id;
    }
    count++;
  }
  return count;
}

int refresh_hub_candidates(uint32_t ifindex) {
  uint32_t i;
  int changed = 0;

  for (i = 0; i < g_hub_state.node_count; i++) {
    hub_node_record_t *node = &g_hub_state.nodes[i];
    dtun_nl_peer_status_t status;
    if (!node->online ||
        dtun_nl_peer_get(ifindex, node->hub_tunnel_id, &status) < 0 ||
        !status.udp_up || !status.direct_udp_addr.s_addr ||
        !status.direct_udp_port)
      continue;
    if (node->udp_addr.s_addr == status.direct_udp_addr.s_addr &&
        node->udp_port == status.direct_udp_port)
      continue;
    node->udp_addr = status.direct_udp_addr;
    node->udp_port = status.direct_udp_port;
    node->raw.s_addr = g_raw_transport ? status.direct_udp_addr.s_addr : 0;
    node->generation++;
    if (!node->generation)
      node->generation++;
    hub_note_change(node->node_id);
    changed = 1;
  }
  return changed;
}

static int fill_sync_peer(uint64_t requester, uint64_t other_id,
                          dtrg_sync_peer_t *peer) {
  hub_node_record_t *other = node_by_id(other_id);
  hub_session_record_t *session;

  memset(peer, 0, sizeof(*peer));
  peer->node_id = other_id;
  if (!other) {
    peer->flags = DTRG_PEER_TOMBSTONE;
    return 0;
  }
  session = hub_session(requester, other_id);
  if (!session)
    return -1;
  peer->address = other->address;
  if (g_raw_transport)
    peer->raw = other->raw;
  peer->udp_addr = other->udp_addr;
  peer->udp_port = other->udp_port;
  peer->generation = other->generation;
  if (other->online && other->udp_addr.s_addr && other->udp_port)
    peer->flags = DTRG_PEER_ONLINE;
  if (requester == session->first_node) {
    peer->tunnel_id = session->first_tunnel_id;
    peer->remote_tunnel_id = session->second_tunnel_id;
  } else {
    peer->tunnel_id = session->second_tunnel_id;
    peer->remote_tunnel_id = session->first_tunnel_id;
  }
  return 0;
}

uint16_t build_refresh_page(uint64_t requester, uint64_t requested_epoch,
                            uint16_t offset, dtrg_sync_peer_t *peers,
                            uint8_t *flags, uint16_t *next_offset) {
  uint64_t ids[MAX_PEERS + HUB_CHANGE_LOG_SIZE];
  size_t total = 0, i, start;
  int snapshot = 0;

  *flags = 0;
  *next_offset = 0;
  if (requested_epoch == g_hub_state.candidate_epoch)
    return 0;
  if (!g_hub_change_count ||
      requested_epoch < g_hub_changes[g_hub_change_head].epoch - 1)
    snapshot = 1;
  if (snapshot) {
    *flags |= DTRG_REFRESH_SNAPSHOT;
    for (i = 0; i < g_hub_state.node_count; i++)
      if (g_hub_state.nodes[i].node_id != requester)
        ids[total++] = g_hub_state.nodes[i].node_id;
  } else {
    for (i = 0; i < g_hub_change_count; i++) {
      hub_change_t *change =
          &g_hub_changes[(g_hub_change_head + i) % HUB_CHANGE_LOG_SIZE];
      size_t j;
      if (change->epoch <= requested_epoch || change->node_id == requester)
        continue;
      for (j = 0; j < total; j++)
        if (ids[j] == change->node_id)
          break;
      if (j == total)
        ids[total++] = change->node_id;
    }
  }
  start = offset < total ? offset : total;
  for (i = start; i < total && i - start < REFRESH_PEERS_PER_PAGE; i++)
    if (fill_sync_peer(requester, ids[i], &peers[i - start]) < 0)
      break;
  if (i < total) {
    *flags |= DTRG_REFRESH_MORE;
    *next_offset = (uint16_t)i;
  }
  return (uint16_t)(i - start);
}
