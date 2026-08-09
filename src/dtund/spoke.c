#include "spoke.h"
#include "daemon_util.h"
#include "spoke_ha.h"
#include <dtun/config.h>
#include <dtun/liveness.h>
#include <dtun/log.h>
#include <dtun/netlink.h>
#include <dtun/proto.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_PEERS DTRG_MAX_SYNC_PEERS

typedef struct {
  uint64_t node_id;
  uint32_t tunnel_id;
  struct in_addr address;
  uint64_t generation;
  int seen;
} applied_peer_t;

static void remove_applied_peer(uint32_t ifindex, applied_peer_t *peer) {
  (void)dtun_nl_route_del(ifindex, peer->tunnel_id, peer->address, 32);
  (void)dtun_nl_peer_del(ifindex, peer->tunnel_id);
  memset(peer, 0, sizeof(*peer));
}

static applied_peer_t *find_applied_peer(applied_peer_t applied[MAX_PEERS],
                                         uint16_t count, uint64_t node_id) {
  uint16_t i;
  for (i = 0; i < count; i++)
    if (applied[i].node_id == node_id)
      return &applied[i];
  return NULL;
}

static void delete_applied_node(uint32_t ifindex,
                                applied_peer_t applied[MAX_PEERS],
                                uint16_t *count, uint64_t node_id) {
  uint16_t i;
  for (i = 0; i < *count; i++) {
    if (applied[i].node_id != node_id)
      continue;
    remove_applied_peer(ifindex, &applied[i]);
    if (i + 1 < *count)
      memmove(&applied[i], &applied[i + 1],
              (size_t)(*count - i - 1) * sizeof(applied[0]));
    (*count)--;
    return;
  }
}

static int apply_peer_item(uint32_t ifindex, const dtrg_sync_peer_t *item,
                           const uint8_t psk[32], int has_psk,
                           applied_peer_t applied[MAX_PEERS], uint16_t *count) {
  applied_peer_t *slot = find_applied_peer(applied, *count, item->node_id);
  dtun_nl_peer_info_t peer;

  if (item->flags & DTRG_PEER_TOMBSTONE) {
    delete_applied_node(ifindex, applied, count, item->node_id);
    return 0;
  }
  if (!(item->flags & DTRG_PEER_ONLINE)) {
    if (slot)
      slot->seen = 1;
    return 0; /* Retain the peer so the kernel can use Hub fallback. */
  }
  if (!item->node_id || !item->tunnel_id || !item->remote_tunnel_id ||
      !item->address.s_addr || !item->udp_addr.s_addr || !item->udp_port)
    return 0;
  if (slot && item->generation < slot->generation)
    return 0;
  if (slot && (slot->tunnel_id != item->tunnel_id ||
               slot->address.s_addr != item->address.s_addr)) {
    delete_applied_node(ifindex, applied, count, item->node_id);
    slot = NULL;
  }
  if (!slot) {
    if (*count >= MAX_PEERS)
      return -1;
    slot = &applied[(*count)++];
    memset(slot, 0, sizeof(*slot));
    slot->node_id = item->node_id;
    slot->tunnel_id = item->tunnel_id;
    slot->address = item->address;
  }
  memset(&peer, 0, sizeof(peer));
  peer.ifindex = ifindex;
  peer.tunnel_id = item->tunnel_id;
  peer.remote_tunnel_id = item->remote_tunnel_id;
  peer.node_id = item->node_id;
  if (g_raw_transport)
    peer.raw_addr = item->raw;
  peer.udp_addr = item->udp_addr;
  peer.udp_port = item->udp_port;
  peer.dynamic_raw = 1;
  peer.has_dynamic_raw = 1;
  peer.candidate_generation = item->generation;
  peer.has_generation = 1;
  peer.has_key = has_psk;
  if (has_psk)
    memcpy(peer.key, psk, sizeof(peer.key));
  if (program_peer(&peer) < 0 ||
      program_route(ifindex, item->tunnel_id, item->address, 32) < 0)
    return -1;
  slot->generation = item->generation;
  slot->seen = 1;
  return 0;
}

static int apply_sync(uint32_t ifindex, const dtrg_msg_t *sync,
                      const uint8_t psk[32], int has_psk,
                      applied_peer_t applied[MAX_PEERS],
                      uint16_t *applied_count) {
  uint16_t i;

  for (i = 0; i < *applied_count; i++)
    applied[i].seen = 0;
  for (i = 0; i < sync->peer_count; i++) {
    const dtrg_sync_peer_t *item = &sync->peers[i];
    if (apply_peer_item(ifindex, item, psk, has_psk, applied, applied_count) <
        0)
      return -1;
  }
  for (i = 0; i < *applied_count;) {
    if (applied[i].seen) {
      i++;
      continue;
    }
    remove_applied_peer(ifindex, &applied[i]);
    if (i + 1 < *applied_count)
      memmove(&applied[i], &applied[i + 1],
              (size_t)(*applied_count - i - 1) * sizeof(applied[0]));
    (*applied_count)--;
  }
  return 0;
}

static int apply_refresh_delta(uint32_t ifindex, const dtrg_msg_t *reply,
                               const uint8_t psk[32], int has_psk,
                               applied_peer_t applied[MAX_PEERS],
                               uint16_t *applied_count) {
  uint16_t i;
  for (i = 0; i < reply->peer_count; i++)
    if (apply_peer_item(ifindex, &reply->peers[i], psk, has_psk, applied,
                        applied_count) < 0)
      return -1;
  return 0;
}

int run_spoke(dtun_config_t *config, const uint8_t psk[32], int has_psk) {
  int sock = -1;
  int route_fd = -1;
  struct sockaddr_in local_address, hub_control;
  struct timeval timeout;
  struct in_addr requested_address = {0}, raw_claim = {0};
  uint8_t requested_prefix = 24;
  uint16_t local_data_port =
      config->data_port ? (uint16_t)config->data_port : 49000;
  uint8_t tx[DTRG_MAX_PACKET], rx[DTRG_MAX_PACKET];
  uint32_t ifindex = 0, hub_tunnel_id = 0;
  uint16_t hub_data_port = 0;
  struct in_addr assigned_address = {0};
  uint8_t assigned_prefix = 0;
  uint64_t assigned_node = 0;
  applied_peer_t applied[MAX_PEERS];
  uint16_t applied_count = 0;
  uint8_t lease_token[DTRG_LEASE_TOKEN_LEN] = {0};
  uint64_t refresh_epoch = 0, refresh_counter = 0;
  uint64_t applied_hub_term = 0;
  int have_lease = 0, refresh_failures = 0;
  int registered_once = 0;
  int bootstrap_attempted = 0;
  int result = 1;
  dtund_spoke_ha_t spoke_ha;

  memset(applied, 0, sizeof(applied));
  dtund_spoke_ha_init(&spoke_ha, dtun_monotonic_ms());
  if (config->spoke_state_file)
    (void)dtund_spoke_ha_load(&spoke_ha, config->spoke_state_file,
                              dtun_monotonic_ms());
  if (!config->hub_address ||
      inet_pton(AF_INET, config->hub_address, &hub_control.sin_addr) != 1 ||
      parse_cidr(config->address, &requested_address, &requested_prefix) < 0) {
    dtun_log_err("Invalid Spoke Hub or inner address");
    return 1;
  }
  if (strcmp(config->local_outer_ip, "0.0.0.0")) {
    fprintf(stderr,
            "adaptive recovery requires local_outer_ip=0.0.0.0 on a Spoke\n");
    return 1;
  }
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return 1;
  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons((uint16_t)config->local_port);
  local_address.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock, (struct sockaddr *)&local_address, sizeof(local_address)) <
      0) {
    dtun_log_err("Spoke control socket bind failed: %s", strerror(errno));
    goto out;
  }
  hub_control.sin_family = AF_INET;
  hub_control.sin_port = htons((uint16_t)config->hub_port);
  timeout.tv_sec = config->timeout > 0 ? config->timeout : 5;
  timeout.tv_usec = 0;
  (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  route_fd = open_route_monitor();
  if (dtun_module_ensure_loaded() < 0)
    return 1;

  dtun_log_info("[dtund] Spoke registering with %s:%d (DTRG)",
                config->hub_address, config->hub_port);
  fflush(stdout);

  while (g_running) {
    uint8_t nonce[16];
    dtrg_msg_t challenge, ack, sync;
    struct sockaddr_in source;
    socklen_t source_len;
    ssize_t length, packed;
    int success = 0;

    if (ifindex && route_change_pending(route_fd, ifindex)) {
      (void)dtun_nl_rebind(ifindex);
      refresh_failures = 0;
    }

    if (have_lease && ifindex) {
      uint16_t offset = 0;
      int refresh_ok = 1;
      int snapshot = 0;
      int force_register = 0;
      uint64_t refresh_started_us = 0;
      uint64_t refresh_rtt_us = 0;

      timeout.tv_sec = 0;
      timeout.tv_usec =
          (suseconds_t)(dtun_liveness_rto_ms(&spoke_ha.leader_health) * 1000);
      if (timeout.tv_usec > 250000)
        timeout.tv_usec = 250000;
      (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));

      refresh_counter++;
      if (!refresh_counter)
        refresh_counter++;
      do {
        dtrg_msg_t refresh_reply;
        ssize_t refresh_length, refresh_packed;

        memset(&refresh_reply, 0, sizeof(refresh_reply));
        refresh_started_us = dtun_monotonic_us();
        refresh_packed =
            dtrg_pack_refresh(psk, assigned_node, lease_token, refresh_counter,
                              refresh_epoch, offset, tx, sizeof(tx));
        if (refresh_packed < 0 ||
            sendto(sock, tx, (size_t)refresh_packed, 0,
                   (struct sockaddr *)&hub_control, sizeof(hub_control)) < 0) {
          refresh_ok = 0;
          break;
        }
        for (;;) {
          source_len = sizeof(source);
          refresh_length = recvfrom(sock, rx, sizeof(rx), 0,
                                    (struct sockaddr *)&source, &source_len);
          if (refresh_length <= 0 || !same_endpoint(&source, &hub_control) ||
              dtrg_parse(psk, rx, (size_t)refresh_length, &refresh_reply) < 0) {
            dtrg_msg_free(&refresh_reply);
            refresh_ok = 0;
            break;
          }
          /* HUB_LIST follows each ACK.  UDP delivery may leave it
           * queued until the next refresh; consume and persist it
           * instead of permanently shifting the ACK stream by one
           * datagram. */
          if (refresh_reply.kind == DTRG_HUB_LIST &&
              refresh_reply.node_id == assigned_node) {
            if (dtund_spoke_ha_update(&spoke_ha, &refresh_reply,
                                      dtun_monotonic_ms()) == 0 &&
                config->spoke_state_file)
              (void)dtund_spoke_ha_save(&spoke_ha, config->spoke_state_file);
            dtrg_msg_free(&refresh_reply);
            memset(&refresh_reply, 0, sizeof(refresh_reply));
            continue;
          }
          if (refresh_reply.kind != DTRG_REFRESH_ACK ||
              refresh_reply.node_id != assigned_node ||
              refresh_reply.counter != refresh_counter ||
              CRYPTO_memcmp(refresh_reply.lease_token, lease_token,
                            sizeof(lease_token)) != 0) {
            dtrg_msg_free(&refresh_reply);
            refresh_ok = 0;
          }
          if (refresh_reply.kind == DTRG_REFRESH_ACK && refresh_started_us) {
            uint64_t now_us = dtun_monotonic_us();

            refresh_rtt_us =
                now_us > refresh_started_us ? now_us - refresh_started_us : 1;
          }
          break;
        }
        if (!refresh_ok)
          break;
        if (refresh_reply.flags & DTRG_REFRESH_RE_REGISTER) {
          force_register = 1;
          refresh_ok = 0;
          dtrg_msg_free(&refresh_reply);
          break;
        }
        if (refresh_reply.term < applied_hub_term) {
          dtrg_msg_free(&refresh_reply);
          refresh_ok = 0;
          break;
        }
        if ((refresh_reply.flags & DTRG_REFRESH_HUB_SWITCH) &&
            refresh_reply.term > applied_hub_term) {
          if (!refresh_reply.data_port ||
              dtun_nl_hub_migrate(ifindex, hub_control.sin_addr,
                                  refresh_reply.data_port,
                                  refresh_reply.term) < 0) {
            dtrg_msg_free(&refresh_reply);
            refresh_ok = 0;
            break;
          }
          hub_data_port = refresh_reply.data_port;
          applied_hub_term = refresh_reply.term;
          dtun_log_info("[dtund Spoke] Fast-migrated Hub peer to term %llu",
                        (unsigned long long)applied_hub_term);
        }
        if ((refresh_reply.flags & DTRG_REFRESH_SNAPSHOT) && offset == 0) {
          uint16_t k;
          snapshot = 1;
          for (k = 0; k < applied_count; k++)
            applied[k].seen = 0;
        }
        if (apply_refresh_delta(ifindex, &refresh_reply, psk, has_psk, applied,
                                &applied_count) < 0) {
          dtrg_msg_free(&refresh_reply);
          refresh_ok = 0;
          break;
        }
        offset = refresh_reply.offset;
        if (!(refresh_reply.flags & DTRG_REFRESH_MORE)) {
          uint16_t k = 0;
          if (snapshot) {
            while (k < applied_count) {
              if (applied[k].seen) {
                k++;
                continue;
              }
              remove_applied_peer(ifindex, &applied[k]);
              if (k + 1 < applied_count)
                memmove(&applied[k], &applied[k + 1],
                        (size_t)(applied_count - k - 1) * sizeof(applied[0]));
              applied_count--;
            }
          }
          refresh_epoch = refresh_reply.epoch;
          offset = 0;
        }
        snapshot = snapshot || !!(refresh_reply.flags & DTRG_REFRESH_SNAPSHOT);
        {
          int more = !!(refresh_reply.flags & DTRG_REFRESH_MORE);
          dtrg_msg_free(&refresh_reply);
          if (!more)
            break;
        }
      } while (g_running);
      if (refresh_ok) {
        dtrg_msg_t hub_update;
        memset(&hub_update, 0, sizeof(hub_update));
        source_len = sizeof(source);
        ssize_t hub_length = recvfrom(sock, rx, sizeof(rx), MSG_DONTWAIT,
                                      (struct sockaddr *)&source, &source_len);
        if (hub_length > 0 && same_endpoint(&source, &hub_control) &&
            dtrg_parse(psk, rx, (size_t)hub_length, &hub_update) == 0 &&
            hub_update.kind == DTRG_HUB_LIST &&
            hub_update.node_id == assigned_node)
          if (dtund_spoke_ha_update(&spoke_ha, &hub_update,
                                    dtun_monotonic_ms()) == 0 &&
              config->spoke_state_file)
            (void)dtund_spoke_ha_save(&spoke_ha, config->spoke_state_file);
        dtrg_msg_free(&hub_update);
        refresh_failures = 0;
        dtund_spoke_ha_seen(&spoke_ha, refresh_rtt_us ? refresh_rtt_us : 100000,
                            dtun_monotonic_ms());
        result = 0;
        if (config->once)
          break;
        for (int waited = 0; waited < (int)dtun_liveness_probe_interval_ms(
                                          &spoke_ha.leader_health) &&
                             g_running;
             waited += 100)
          usleep(100000);
        continue;
      }
      dtund_spoke_ha_missed(&spoke_ha, dtun_monotonic_ms());
      refresh_failures++;
      if (!force_register && dtund_spoke_ha_failover(&spoke_ha, &hub_control,
                                                     dtun_monotonic_ms())) {
        char endpoint[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &hub_control.sin_addr, endpoint, sizeof(endpoint));
        dtun_log_warn("[dtund Spoke] Leader offline; probing backup Hub %s:%u",
                      endpoint, ntohs(hub_control.sin_port));
        refresh_failures = 0;
        continue;
      }
      if (!force_register &&
          spoke_ha.leader_health.state != DTUN_LIVENESS_OFFLINE) {
        usleep(100000);
        continue;
      }
      have_lease = 0;
      refresh_failures = 0;
    }

    if (!have_lease && bootstrap_attempted &&
        dtund_spoke_ha_failover(&spoke_ha, &hub_control, dtun_monotonic_ms())) {
      char endpoint[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &hub_control.sin_addr, endpoint, sizeof(endpoint));
      printf("[dtund Spoke] Leader timeout; trying backup Hub %s:%u\n",
             endpoint, ntohs(hub_control.sin_port));
      fflush(stdout);
    }

    /* A lost registration ACK can leave the following SYNC/HUB_LIST (or
     * a CHALLENGE from an abandoned nonce) queued on this UDP socket.
     * Reusing such a datagram as the next CHALLENGE keeps the client
     * permanently one packet behind on a lossy WAN.  A full registration
     * has no valid in-flight response yet, so discard stale control
     * datagrams before creating its new nonce. */
    if (!have_lease) {
      uint32_t registration_rto = dtun_liveness_rto_ms(&spoke_ha.leader_health);
      timeout.tv_sec = registration_rto / 1000;
      timeout.tv_usec = (suseconds_t)(registration_rto % 1000) * 1000;
      (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));
      for (;;) {
        source_len = sizeof(source);
        length = recvfrom(sock, rx, sizeof(rx), MSG_DONTWAIT,
                          (struct sockaddr *)&source, &source_len);
        if (length <= 0)
          break;
      }
    }

    memset(&challenge, 0, sizeof(challenge));
    memset(&ack, 0, sizeof(ack));
    memset(&sync, 0, sizeof(sync));
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
      break;
    packed = dtrg_pack_init(psk, config->node_id, requested_address,
                            requested_prefix, raw_claim, nonce, tx, sizeof(tx));
    if (packed < 0 ||
        sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&hub_control,
               sizeof(hub_control)) < 0)
      goto attempt_done;
    source_len = sizeof(source);
    length = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&source,
                      &source_len);
    if (length <= 0 || !same_endpoint(&source, &hub_control) ||
        dtrg_parse(psk, rx, (size_t)length, &challenge) < 0 ||
        challenge.kind != DTRG_CHALLENGE ||
        challenge.node_id != config->node_id ||
        challenge.address.s_addr != requested_address.s_addr ||
        challenge.prefix_len != requested_prefix ||
        challenge.raw.s_addr != raw_claim.s_addr ||
        CRYPTO_memcmp(challenge.nonce, nonce, sizeof(nonce)) != 0)
      goto attempt_done;
    packed = dtrg_pack_confirm(psk, challenge.node_id, challenge.address,
                               challenge.prefix_len, challenge.raw, nonce,
                               challenge.cookie, tx, sizeof(tx));
    if (packed < 0 ||
        sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&hub_control,
               sizeof(hub_control)) < 0)
      goto attempt_done;
    source_len = sizeof(source);
    length = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&source,
                      &source_len);
    if (length <= 0 || !same_endpoint(&source, &hub_control) ||
        dtrg_parse(psk, rx, (size_t)length, &ack) < 0 || ack.kind != DTRG_ACK ||
        !ack.node_id || !ack.tunnel_id || !ack.remote_tunnel_id ||
        !ack.address.s_addr || !ack.data_port ||
        CRYPTO_memcmp(ack.nonce, nonce, sizeof(nonce)) != 0 ||
        (requested_address.s_addr &&
         (ack.address.s_addr != requested_address.s_addr ||
          ack.prefix_len != requested_prefix)))
      goto attempt_done;
    if (!ifindex || assigned_node != ack.node_id ||
        assigned_address.s_addr != ack.address.s_addr ||
        assigned_prefix != ack.prefix_len || hub_data_port != ack.data_port) {
      struct in_addr local_outer;
      if (inet_pton(AF_INET, config->local_outer_ip, &local_outer) != 1)
        goto attempt_done;
      if (ifindex)
        dtun_link_delete_by_name(config->interface);
      int created_ifindex =
          dtun_link_create(config->interface, local_outer, local_data_port,
                           ack.node_id, hub_control.sin_addr, ack.data_port);
      if (created_ifindex <= 0) {
        dtun_log_err("Failed to create Spoke interface: %s",
                     strerror(-created_ifindex));
        ifindex = 0;
        goto attempt_done;
      }
      ifindex = (uint32_t)created_ifindex;
      if (dtun_link_setup(ifindex, config->interface, ack.address,
                          ack.prefix_len) < 0) {
        ifindex = 0;
        goto attempt_done;
      }
      memset(applied, 0, sizeof(applied));
      applied_count = 0;
      hub_tunnel_id = 0;
      assigned_node = ack.node_id;
      assigned_address = ack.address;
      assigned_prefix = ack.prefix_len;
      hub_data_port = ack.data_port;
    }
    /* Reaching a full authenticated registration while a Hub peer already
     * exists means the lightweight lease failed (for example after a Hub
     * restart).  The rebuilt Hub kernel peer starts a fresh transmit
     * sequence, so retaining our old replay window would reject every
     * probe until that sequence caught up.  Recreate the peer only at this
     * authenticated lifecycle boundary; ordinary endpoint changes keep
     * their sequence and replay state intact. */
    if (hub_tunnel_id) {
      struct in_addr old_network =
          network_prefix(assigned_address, assigned_prefix);
      (void)dtun_nl_route_del(ifindex, hub_tunnel_id, old_network,
                              assigned_prefix);
      (void)dtun_nl_peer_del(ifindex, hub_tunnel_id);
      hub_tunnel_id = 0;
    }
    {
      dtun_nl_peer_info_t peer;
      struct in_addr route = network_prefix(ack.address, ack.prefix_len);
      memset(&peer, 0, sizeof(peer));
      peer.ifindex = ifindex;
      peer.tunnel_id = ack.tunnel_id;
      peer.remote_tunnel_id = ack.remote_tunnel_id;
      peer.node_id = 1;
      /* The Hub endpoint is learned and migrated as an address/port
       * pair.  Keep that control-plane contract on UDP: cloud networks
       * may pass raw probes while dropping real raw-IP payloads, which
       * otherwise makes path selection report healthy but blackholes
       * Spoke traffic.  Direct Spoke peers may still negotiate raw. */
      peer.raw_addr.s_addr = 0;
      peer.udp_addr = hub_control.sin_addr;
      peer.udp_port = ack.data_port;
      peer.dynamic_raw = 0;
      peer.has_key = has_psk;
      if (has_psk)
        memcpy(peer.key, psk, sizeof(peer.key));
      if (program_peer(&peer) < 0 ||
          program_route(ifindex, ack.tunnel_id, route, ack.prefix_len) < 0)
        goto attempt_done;
      hub_tunnel_id = ack.tunnel_id;
      trigger_tunnel_warmup(
          (struct in_addr){.s_addr = htonl(ntohl(route.s_addr) + 1)});
    }
    source_len = sizeof(source);
    length = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&source,
                      &source_len);
    if (length > 0 && same_endpoint(&source, &hub_control) &&
        dtrg_parse(psk, rx, (size_t)length, &sync) == 0 &&
        sync.kind == DTRG_SYNC && sync.node_id == ack.node_id &&
        CRYPTO_memcmp(sync.nonce, nonce, sizeof(nonce)) == 0) {
      if (apply_sync(ifindex, &sync, psk, has_psk, applied, &applied_count) < 0)
        goto attempt_done;
    }
    {
      dtrg_msg_t hub_list;
      memset(&hub_list, 0, sizeof(hub_list));
      usleep(10000);
      source_len = sizeof(source);
      length = recvfrom(sock, rx, sizeof(rx), MSG_DONTWAIT,
                        (struct sockaddr *)&source, &source_len);
      if (length > 0 && same_endpoint(&source, &hub_control) &&
          dtrg_parse(psk, rx, (size_t)length, &hub_list) == 0 &&
          hub_list.kind == DTRG_HUB_LIST && hub_list.node_id == ack.node_id) {
        if (dtund_spoke_ha_update(&spoke_ha, &hub_list, dtun_monotonic_ms()) ==
                0 &&
            config->spoke_state_file)
          (void)dtund_spoke_ha_save(&spoke_ha, config->spoke_state_file);
      }
      dtrg_msg_free(&hub_list);
    }
    requested_address = ack.address;
    requested_prefix = ack.prefix_len;
    config->node_id = ack.node_id;
    memcpy(lease_token, ack.lease_token, sizeof(lease_token));
    /* Force the first lightweight refresh to obtain a paginated snapshot;
     * the immediately following SYNC is only a startup latency shortcut. */
    refresh_epoch = 0;
    refresh_counter = 0;
    have_lease = 1;
    applied_hub_term = ack.term;
    dtund_spoke_ha_seen(&spoke_ha, 100000, dtun_monotonic_ms());
    if (ifindex)
      (void)dtun_nl_hub_migrate(ifindex, hub_control.sin_addr, ack.data_port,
                                ack.term ? ack.term : 1);
    success = 1;
    registered_once = 1;
    result = 0;
    {
      char text[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ack.address, text, sizeof(text));
      printf("[dtund Spoke] Registration successful! NodeID=%llu "
             "InnerIP=%s DataPort=%u DirectPeers=%u\n",
             (unsigned long long)ack.node_id, text, ack.data_port,
             applied_count);
      fflush(stdout);
    }

  attempt_done:
    bootstrap_attempted = 1;
    dtrg_msg_free(&challenge);
    dtrg_msg_free(&ack);
    dtrg_msg_free(&sync);
    if (config->once)
      break;
    if (!success) {
      dtund_spoke_ha_missed(&spoke_ha, dtun_monotonic_ms());
      dtun_log_err("[dtund Spoke] Registration failed; retaining existing "
                   "link and retrying");
    }
    if (g_running)
      sleep(1);
  }

out:
  if (route_fd >= 0)
    close(route_fd);
  if (sock >= 0)
    close(sock);
  if (ifindex && !(config->once && registered_once)) {
    dtun_link_delete_by_name(config->interface);
  }
  return result;
}
