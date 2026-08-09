#include "hub.h"
#include "daemon_util.h"
#include "ha_service.h"
#include "hub_internal.h"
#include "hub_sync.h"
#include "spoke_ha.h"
#include <dtun/config.h>
#include <dtun/ha_defaults.h>
#include <dtun/ha_state.h>
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

hub_state_t g_hub_state;
hub_node_health_t g_hub_node_health[MAX_PEERS];

hub_change_t g_hub_changes[HUB_CHANGE_LOG_SIZE];
size_t g_hub_change_head;
size_t g_hub_change_count;
static int g_hub_state_dirty;

void hub_note_change(uint64_t node_id) {
  size_t slot;
  g_hub_state.candidate_epoch++;
  if (!g_hub_state.candidate_epoch)
    g_hub_state.candidate_epoch++;
  slot = (g_hub_change_head + g_hub_change_count) % HUB_CHANGE_LOG_SIZE;
  if (g_hub_change_count == HUB_CHANGE_LOG_SIZE) {
    g_hub_change_head = (g_hub_change_head + 1) % HUB_CHANGE_LOG_SIZE;
    slot = (g_hub_change_head + g_hub_change_count - 1) % HUB_CHANGE_LOG_SIZE;
  } else {
    g_hub_change_count++;
  }
  g_hub_changes[slot].epoch = g_hub_state.candidate_epoch;
  g_hub_changes[slot].node_id = node_id;
  g_hub_state_dirty = 1;
}

static void generate_cookie(const uint8_t cookie_key[32],
                            const struct sockaddr_in *source, uint64_t node_id,
                            struct in_addr address, uint8_t prefix_len,
                            struct in_addr raw, const uint8_t nonce[16],
                            uint64_t bucket, uint8_t cookie[32]) {
  uint8_t body[64];
  uint8_t *p = body;
  uint64_t node_be;
  uint64_t bucket_be;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  node_be = ((uint64_t)htonl((uint32_t)node_id) << 32) |
            htonl((uint32_t)(node_id >> 32));
  bucket_be = ((uint64_t)htonl((uint32_t)bucket) << 32) |
              htonl((uint32_t)(bucket >> 32));
#else
  node_be = node_id;
  bucket_be = bucket;
#endif
  memcpy(p, &source->sin_addr.s_addr, 4);
  p += 4;
  memcpy(p, &source->sin_port, 2);
  p += 2;
  memcpy(p, &node_be, 8);
  p += 8;
  memcpy(p, &address.s_addr, 4);
  p += 4;
  *p++ = prefix_len;
  memcpy(p, &raw.s_addr, 4);
  p += 4;
  memcpy(p, nonce, 16);
  p += 16;
  memcpy(p, &bucket_be, 8);
  p += 8;
  dtrg_hmac(cookie_key, 32, body, (size_t)(p - body), cookie);
  dtrg_hmac(cookie_key, 32, cookie, 16, cookie + 16);
}

static int validate_cookie(const dtun_config_t *config,
                           const struct sockaddr_in *source,
                           const dtrg_msg_t *message) {
  uint64_t seconds =
      config->cookie_seconds > 0 ? (uint64_t)config->cookie_seconds : 30;
  uint64_t bucket = (uint64_t)time(NULL) / seconds;
  uint8_t expected[32];

  generate_cookie(g_hub_state.cookie_key, source, message->node_id,
                  message->address, message->prefix_len, message->raw,
                  message->nonce, bucket, expected);
  if (CRYPTO_memcmp(message->cookie, expected, sizeof(expected)) == 0)
    return 1;
  if (!bucket)
    return 0;
  generate_cookie(g_hub_state.cookie_key, source, message->node_id,
                  message->address, message->prefix_len, message->raw,
                  message->nonce, bucket - 1, expected);
  return CRYPTO_memcmp(message->cookie, expected, sizeof(expected)) == 0;
}

static int make_parent_dirs(const char *path) {
  char copy[PATH_MAX];
  char *p;

  if (!path || strlen(path) >= sizeof(copy))
    return -1;
  memcpy(copy, path, strlen(path) + 1);
  for (p = copy + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(copy, 0750) < 0 && errno != EEXIST)
      return -1;
    *p = '/';
  }
  return 0;
}

void hub_state_init(void) {
  memset(&g_hub_state, 0, sizeof(g_hub_state));
  memset(g_hub_changes, 0, sizeof(g_hub_changes));
  memset(g_hub_node_health, 0, sizeof(g_hub_node_health));
  g_hub_change_head = 0;
  g_hub_change_count = 0;
  g_hub_state_dirty = 0;
  memcpy(g_hub_state.magic, HUB_STATE_MAGIC, 4);
  g_hub_state.version = HUB_STATE_FORMAT;
  g_hub_state.next_tunnel_id = 100;
  g_hub_state.next_node_id = 2;
  g_hub_state.candidate_epoch = 1;
  if (RAND_bytes(g_hub_state.cookie_key, sizeof(g_hub_state.cookie_key)) != 1) {
    dtun_log_err("Failed to generate Hub cookie key");
    exit(1);
  }
}

int hub_load_state(const char *path) {
  struct stat st;
  FILE *file;

  if (stat(path, &st) < 0) {
    if (errno == ENOENT) {
      hub_state_init();
      return 0;
    }
    dtun_log_err("Hub state stat failed: %s", strerror(errno));
    return -1;
  }
  file = fopen(path, "rb");
  if (!file) {
    dtun_log_err("Hub state open failed: %s", strerror(errno));
    return -1;
  }
  memset(g_hub_changes, 0, sizeof(g_hub_changes));
  g_hub_change_head = 0;
  g_hub_change_count = 0;
  g_hub_state_dirty = 0;
  if ((size_t)st.st_size == sizeof(g_hub_state)) {
    if (fread(&g_hub_state, sizeof(g_hub_state), 1, file) != 1 ||
        memcmp(g_hub_state.magic, HUB_STATE_MAGIC, 4) != 0 ||
        g_hub_state.version != HUB_STATE_FORMAT) {
      fclose(file);
      dtun_log_err("Invalid or unsupported Hub state header");
      return -1;
    }
  } else if ((size_t)st.st_size == sizeof(legacy_hub_state_t)) {
    legacy_hub_state_t legacy;
    uint32_t count, i;

    if (fread(&legacy, sizeof(legacy), 1, file) != 1) {
      fclose(file);
      dtun_log_err("Truncated legacy Hub state");
      return -1;
    }
    hub_state_init();
    if (legacy.node_count < 0 || legacy.node_count > MAX_PEERS) {
      fclose(file);
      dtun_log_err("Invalid legacy Hub node count");
      return -1;
    }
    count = (uint32_t)legacy.node_count;
    memcpy(g_hub_state.cookie_key, legacy.cookie_key, 32);
    g_hub_state.next_tunnel_id = legacy.next_tunnel_id;
    g_hub_state.next_node_id = legacy.next_node_id;
    g_hub_state.node_count = count;
    for (i = 0; i < count; i++) {
      hub_node_record_t *dst = &g_hub_state.nodes[i];
      hub_node_record_v2_t *src = &legacy.nodes[i];
      dst->node_id = src->node_id;
      dst->tunnel_id = src->tunnel_id;
      dst->hub_tunnel_id = src->hub_tunnel_id;
      dst->address = src->address;
      dst->prefix_len = src->prefix_len;
      dst->raw = src->raw;
      dst->udp_addr = src->udp_addr;
      dst->udp_port = src->udp_port;
      dst->last_seen = src->last_seen;
      dst->generation = 1;
    }
    dtun_log_info("[dtund Hub] Imported legacy state with %u nodes", count);
  } else {
    fclose(file);
    fprintf(stderr, "Unsupported Hub state size: %lld bytes\n",
            (long long)st.st_size);
    return -1;
  }
  fclose(file);
  if (g_hub_state.node_count > MAX_PEERS ||
      g_hub_state.session_count > MAX_SESSIONS || !g_hub_state.next_tunnel_id ||
      g_hub_state.next_node_id < 2) {
    dtun_log_err("Hub state contains invalid counters");
    return -1;
  }
  for (uint32_t i = 0; i < g_hub_state.node_count; i++) {
    uint64_t now_ms = dtun_monotonic_ms();

    dtun_liveness_init(&g_hub_node_health[i].liveness, DTUN_LIVENESS_DIRECT,
                       now_ms);
    g_hub_node_health[i].last_arrival_ms = now_ms;
    if (g_hub_state.nodes[i].online)
      dtun_liveness_note_success(&g_hub_node_health[i].liveness, 100000,
                                 now_ms);
  }
  return 0;
}

int hub_save_state(const char *path) {
  char temporary[PATH_MAX];
  FILE *file;
  int fd;
  int failed = 0;

  if (make_parent_dirs(path) < 0 ||
      snprintf(temporary, sizeof(temporary), "%s.tmp", path) >=
          (int)sizeof(temporary)) {
    dtun_log_err("Invalid Hub state path");
    return -1;
  }
  file = fopen(temporary, "wb");
  if (!file) {
    dtun_log_err("Hub state temporary open failed: %s", strerror(errno));
    return -1;
  }
  fd = fileno(file);
  if (fwrite(&g_hub_state, sizeof(g_hub_state), 1, file) != 1)
    failed = 1;
  if (fflush(file) != 0 || fsync(fd) != 0)
    failed = 1;
  if (fclose(file) != 0)
    failed = 1;
  if (failed) {
    dtun_log_err("Hub state write failed: %s", strerror(errno));
    unlink(temporary);
    return -1;
  }
  if (rename(temporary, path) < 0) {
    dtun_log_err("Hub state rename failed: %s", strerror(errno));
    unlink(temporary);
    return -1;
  }
  return 0;
}

static int address_is_usable(struct in_addr address, uint8_t prefix_len,
                             struct in_addr pool, struct in_addr hub_address) {
  uint32_t mask = prefix_mask(prefix_len);
  uint32_t base = ntohl(pool.s_addr) & mask;
  uint32_t broadcast = base | ~mask;
  uint32_t host = ntohl(address.s_addr);

  if (prefix_len > 30 || host <= base + 1 || host >= broadcast)
    return 0;
  if ((host & mask) != base || address.s_addr == hub_address.s_addr)
    return 0;
  return 1;
}

int hub_validate_state(const dtun_config_t *config,
                       struct in_addr hub_address) {
  struct in_addr pool;
  uint8_t pool_prefix;
  uint32_t i, j;
  uint32_t ids[MAX_PEERS * 2 + MAX_SESSIONS * 2];
  size_t id_count = 0;
  uint32_t max_tunnel_id = 0;
  uint64_t max_node_id = 1;

  if (parse_cidr(config->pool, &pool, &pool_prefix) < 0) {
    dtun_log_err("Invalid Hub pool: %s", config->pool);
    return -1;
  }
  pool = network_prefix(pool, pool_prefix);
  if (pool_prefix > 30 ||
      (ntohl(hub_address.s_addr) & prefix_mask(pool_prefix)) !=
          ntohl(pool.s_addr) ||
      ntohl(hub_address.s_addr) == ntohl(pool.s_addr) ||
      ntohl(hub_address.s_addr) ==
          (ntohl(pool.s_addr) | ~prefix_mask(pool_prefix))) {
    dtun_log_err("Hub inner address is not usable in the configured pool");
    return -1;
  }
  for (i = 0; i < g_hub_state.node_count; i++) {
    const hub_node_record_t *record = &g_hub_state.nodes[i];
    if (record->node_id <= 1 || !record->tunnel_id || !record->hub_tunnel_id ||
        record->tunnel_id == record->hub_tunnel_id ||
        record->prefix_len != pool_prefix ||
        !address_is_usable(record->address, pool_prefix, pool, hub_address)) {
      dtun_log_err("Invalid persisted Hub node record at index %u", i);
      return -1;
    }
    for (j = 0; j < i; j++) {
      const hub_node_record_t *other = &g_hub_state.nodes[j];
      if (record->node_id == other->node_id ||
          record->address.s_addr == other->address.s_addr ||
          record->tunnel_id == other->tunnel_id ||
          record->hub_tunnel_id == other->hub_tunnel_id) {
        dtun_log_err("Duplicate persisted Hub node record at index %u", i);
        return -1;
      }
    }
    for (j = 0; j < id_count; j++)
      if (ids[j] == record->tunnel_id || ids[j] == record->hub_tunnel_id) {
        dtun_log_err("Duplicate persisted tunnel ID at node index %u", i);
        return -1;
      }
    ids[id_count++] = record->tunnel_id;
    ids[id_count++] = record->hub_tunnel_id;
    if (record->tunnel_id > max_tunnel_id)
      max_tunnel_id = record->tunnel_id;
    if (record->hub_tunnel_id > max_tunnel_id)
      max_tunnel_id = record->hub_tunnel_id;
    if (record->node_id > max_node_id)
      max_node_id = record->node_id;
  }
  for (i = 0; i < g_hub_state.session_count; i++) {
    const hub_session_record_t *session = &g_hub_state.sessions[i];
    int first_found = 0, second_found = 0;
    if (session->first_node >= session->second_node ||
        session->first_node <= 1 || !session->first_tunnel_id ||
        !session->second_tunnel_id ||
        session->first_tunnel_id == session->second_tunnel_id) {
      dtun_log_err("Invalid persisted Hub session at index %u", i);
      return -1;
    }
    for (j = 0; j < g_hub_state.node_count; j++) {
      if (g_hub_state.nodes[j].node_id == session->first_node)
        first_found = 1;
      if (g_hub_state.nodes[j].node_id == session->second_node)
        second_found = 1;
    }
    if (!first_found || !second_found) {
      dtun_log_err("Persisted session references an unknown node");
      return -1;
    }
    for (j = 0; j < i; j++)
      if (g_hub_state.sessions[j].first_node == session->first_node &&
          g_hub_state.sessions[j].second_node == session->second_node) {
        dtun_log_err("Duplicate persisted Hub session pair");
        return -1;
      }
    for (j = 0; j < id_count; j++)
      if (ids[j] == session->first_tunnel_id ||
          ids[j] == session->second_tunnel_id) {
        dtun_log_err("Duplicate persisted session tunnel ID");
        return -1;
      }
    ids[id_count++] = session->first_tunnel_id;
    ids[id_count++] = session->second_tunnel_id;
    if (session->first_tunnel_id > max_tunnel_id)
      max_tunnel_id = session->first_tunnel_id;
    if (session->second_tunnel_id > max_tunnel_id)
      max_tunnel_id = session->second_tunnel_id;
  }
  if (max_tunnel_id == UINT32_MAX || max_node_id == UINT64_MAX) {
    dtun_log_err("Persisted Hub identifier space is exhausted");
    return -1;
  }
  if (g_hub_state.next_tunnel_id <= max_tunnel_id)
    g_hub_state.next_tunnel_id = max_tunnel_id + 1;
  if (g_hub_state.next_node_id <= max_node_id)
    g_hub_state.next_node_id = max_node_id + 1;
  return 0;
}

static int address_in_use(struct in_addr address) {
  uint32_t i;
  for (i = 0; i < g_hub_state.node_count; i++)
    if (g_hub_state.nodes[i].address.s_addr == address.s_addr)
      return 1;
  return 0;
}

hub_node_record_t *node_by_address(struct in_addr address) {
  uint32_t i;
  if (!address.s_addr)
    return NULL;
  for (i = 0; i < g_hub_state.node_count; i++)
    if (g_hub_state.nodes[i].address.s_addr == address.s_addr)
      return &g_hub_state.nodes[i];
  return NULL;
}

hub_node_record_t *node_by_id(uint64_t node_id) {
  uint32_t i;
  for (i = 0; i < g_hub_state.node_count; i++)
    if (g_hub_state.nodes[i].node_id == node_id)
      return &g_hub_state.nodes[i];
  return NULL;
}

static void hub_node_seen(hub_node_record_t *node) {
  ptrdiff_t index;
  uint64_t now_ms, interval_us;

  if (!node)
    return;
  index = node - g_hub_state.nodes;
  if (index < 0 || index >= MAX_PEERS)
    return;
  now_ms = dtun_monotonic_ms();
  interval_us = g_hub_node_health[index].last_arrival_ms &&
                        now_ms > g_hub_node_health[index].last_arrival_ms
                    ? (now_ms - g_hub_node_health[index].last_arrival_ms) * 1000
                    : 100000;
  dtun_liveness_note_success(&g_hub_node_health[index].liveness, interval_us,
                             now_ms);
  g_hub_node_health[index].last_arrival_ms = now_ms;
}

static uint32_t allocate_tunnel_id(void) {
  uint32_t value = g_hub_state.next_tunnel_id++;
  if (!value)
    value = g_hub_state.next_tunnel_id++;
  return value;
}

hub_node_record_t *
hub_allocate_node(const dtun_config_t *config, struct in_addr hub_address,
                  uint64_t requested_node, struct in_addr requested_address,
                  uint8_t requested_prefix, char *error, size_t error_len) {
  struct in_addr pool;
  struct in_addr final_address = requested_address;
  hub_node_record_t *existing;
  uint8_t pool_prefix;
  uint32_t i;

  if (parse_cidr(config->pool, &pool, &pool_prefix) < 0) {
    snprintf(error, error_len, "invalid configured pool");
    return NULL;
  }
  pool = network_prefix(pool, pool_prefix);
  if (requested_node == 1) {
    snprintf(error, error_len, "node ID 1 is reserved for the Hub");
    return NULL;
  }
  existing = requested_node ? node_by_id(requested_node)
                            : (requested_address.s_addr
                                   ? node_by_address(requested_address)
                                   : NULL);
  if (existing) {
    if ((requested_address.s_addr &&
         requested_address.s_addr != existing->address.s_addr) ||
        (requested_address.s_addr &&
         requested_prefix != existing->prefix_len)) {
      snprintf(error, error_len,
               "node ID is already registered with another address");
      return NULL;
    }
    return existing;
  }
  if (requested_address.s_addr) {
    if (requested_prefix != pool_prefix ||
        !address_is_usable(requested_address, pool_prefix, pool, hub_address)) {
      snprintf(error, error_len,
               "requested address is outside the usable pool");
      return NULL;
    }
    if (address_in_use(requested_address)) {
      snprintf(error, error_len, "requested address is already assigned");
      return NULL;
    }
  } else {
    uint32_t base = ntohl(pool.s_addr);
    uint32_t broadcast = base | ~prefix_mask(pool_prefix);
    uint64_t candidate;

    for (candidate = (uint64_t)base + 2; candidate < broadcast; candidate++) {
      struct in_addr item = {.s_addr = htonl((uint32_t)candidate)};
      if (item.s_addr != hub_address.s_addr && !address_in_use(item)) {
        final_address = item;
        break;
      }
    }
    if (!final_address.s_addr) {
      snprintf(error, error_len, "address pool is exhausted");
      return NULL;
    }
  }
  if (g_hub_state.node_count >= MAX_PEERS) {
    snprintf(error, error_len, "peer limit reached");
    return NULL;
  }
  if (!requested_node) {
    do {
      requested_node = g_hub_state.next_node_id++;
    } while (requested_node <= 1 || node_by_id(requested_node));
  }
  for (i = 0; i < g_hub_state.node_count; i++) {
    if (g_hub_state.nodes[i].node_id == requested_node) {
      snprintf(error, error_len, "node ID is already assigned");
      return NULL;
    }
  }
  existing = &g_hub_state.nodes[g_hub_state.node_count];
  memset(existing, 0, sizeof(*existing));
  existing->node_id = requested_node;
  existing->tunnel_id = allocate_tunnel_id();
  existing->hub_tunnel_id = allocate_tunnel_id();
  existing->address = final_address;
  existing->prefix_len = pool_prefix;
  dtun_liveness_init(&g_hub_node_health[g_hub_state.node_count].liveness,
                     DTUN_LIVENESS_DIRECT, dtun_monotonic_ms());
  g_hub_node_health[g_hub_state.node_count].last_arrival_ms =
      dtun_monotonic_ms();
  g_hub_state.node_count++;
  return existing;
}

hub_session_record_t *hub_session(uint64_t node_id, uint64_t other_id) {
  uint64_t first = node_id < other_id ? node_id : other_id;
  uint64_t second = node_id < other_id ? other_id : node_id;
  uint32_t i;
  hub_session_record_t *session;

  for (i = 0; i < g_hub_state.session_count; i++) {
    session = &g_hub_state.sessions[i];
    if (session->first_node == first && session->second_node == second)
      return session;
  }
  if (g_hub_state.session_count >= MAX_SESSIONS)
    return NULL;
  session = &g_hub_state.sessions[g_hub_state.session_count++];
  memset(session, 0, sizeof(*session));
  session->first_node = first;
  session->second_node = second;
  session->first_tunnel_id = allocate_tunnel_id();
  session->second_tunnel_id = allocate_tunnel_id();
  g_hub_state_dirty = 1;
  return session;
}

void hub_remove_node_at(uint32_t index) {
  uint64_t node_id = g_hub_state.nodes[index].node_id;
  uint32_t i;

  for (i = 0; i < g_hub_state.session_count;) {
    hub_session_record_t *session = &g_hub_state.sessions[i];

    if (session->first_node != node_id && session->second_node != node_id) {
      i++;
      continue;
    }
    if (i + 1 < g_hub_state.session_count)
      memmove(&g_hub_state.sessions[i], &g_hub_state.sessions[i + 1],
              (size_t)(g_hub_state.session_count - i - 1) *
                  sizeof(g_hub_state.sessions[0]));
    g_hub_state.session_count--;
  }
  if (index + 1 < g_hub_state.node_count)
    memmove(&g_hub_state.nodes[index], &g_hub_state.nodes[index + 1],
            (size_t)(g_hub_state.node_count - index - 1) *
                sizeof(g_hub_state.nodes[0]));
  if (index + 1 < g_hub_state.node_count)
    memmove(&g_hub_node_health[index], &g_hub_node_health[index + 1],
            (size_t)(g_hub_state.node_count - index - 1) *
                sizeof(g_hub_node_health[0]));
  g_hub_state.node_count--;
  memset(&g_hub_state.nodes[g_hub_state.node_count], 0,
         sizeof(g_hub_state.nodes[0]));
  memset(&g_hub_node_health[g_hub_state.node_count], 0,
         sizeof(g_hub_node_health[0]));
}

static int hub_expire_nodes(const dtun_config_t *config, uint32_t ifindex) {
  time_t now = time(NULL);
  uint64_t now_ms = dtun_monotonic_ms();
  int retention =
      config->identity_retention > 0 ? config->identity_retention : 86400;
  uint32_t i = 0;
  int changed = 0;

  while (i < g_hub_state.node_count) {
    hub_node_record_t *node = &g_hub_state.nodes[i];
    uint64_t node_id;
    uint32_t tunnel_id;
    struct in_addr address;
    int err;

    if (!node->online) {
      if (node->offline_since > 0 && now >= node->offline_since &&
          now - node->offline_since > retention) {
        uint64_t removed_node = node->node_id;
        hub_remove_node_at(i);
        hub_note_change(removed_node);
        changed = 1;
        continue;
      }
      i++;
      continue;
    }
    uint32_t offline_ms =
        dtun_liveness_offline_ms(&g_hub_node_health[i].liveness);
    uint64_t age_ms = now_ms >= g_hub_node_health[i].liveness.last_ack_ms
                          ? now_ms - g_hub_node_health[i].liveness.last_ack_ms
                          : 0;

    if (age_ms < offline_ms) {
      i++;
      continue;
    }
    while (g_hub_node_health[i].liveness.failed_rounds <
           dtun_liveness_miss_budget(&g_hub_node_health[i].liveness))
      dtun_liveness_note_miss(&g_hub_node_health[i].liveness, now_ms);
    if (dtun_liveness_tick(&g_hub_node_health[i].liveness, now_ms) !=
        DTUN_LIVENESS_OFFLINE) {
      i++;
      continue;
    }
    node_id = node->node_id;
    tunnel_id = node->hub_tunnel_id;
    address = node->address;
    err = dtun_nl_peer_del(ifindex, tunnel_id);
    if (err < 0 && err != -ENOENT) {
      fprintf(stderr,
              "[dtund Hub] Failed to remove expired Spoke NodeID=%llu: %s\n",
              (unsigned long long)node_id, strerror(-err));
      i++;
      continue;
    }
    (void)dtun_nl_route_del(ifindex, tunnel_id, address, 32);
    node->online = 0;
    node->offline_since = now;
    node->generation++;
    if (!node->generation)
      node->generation++;
    hub_note_change(node_id);
    changed = 1;
    {
      char text[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &address, text, sizeof(text));
      printf("[dtund Hub] Marked Spoke NodeID=%llu InnerIP=%s offline "
             "after adaptive threshold %ums\n",
             (unsigned long long)node_id, text, offline_ms);
      fflush(stdout);
    }
    i++;
  }
  if (changed && hub_save_state(config->state_file) < 0)
    return -1;
  if (changed)
    g_hub_state_dirty = 0;
  return changed;
}

int run_hub(dtun_config_t *config, const uint8_t psk[32], int has_psk) {
  struct in_addr outer_address, inner_address, no_hub = {0};
  uint8_t prefix_len;
  uint16_t data_port = config->data_port ? (uint16_t)config->data_port : 49000;
  uint32_t ifindex;
  int created_ifindex;
  int sock;
  struct sockaddr_in bind_address;
  struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
  uint8_t rx[DTRG_MAX_PACKET], tx[DTRG_MAX_PACKET];
  int demoted = 0;
  time_t ha_active_since = time(NULL);
  int ha_backoff_reset = 0;
  uint64_t quorum_missing_since_ms = 0;
  uint64_t leader_term = 1;
  char leader_id[DTRG_HUB_ID_LEN] = "standalone";

  if (inet_pton(AF_INET, config->local_outer_ip, &outer_address) != 1 ||
      parse_cidr(config->address, &inner_address, &prefix_len) < 0) {
    dtun_log_err("Invalid Hub outer or inner address");
    return 1;
  }
  if (hub_load_state(config->state_file) < 0 ||
      hub_validate_state(config, inner_address) < 0)
    return 1;
  if (config->ha_enabled) {
    dtun_ha_state_t state;

    if (dtun_ha_state_load(config->ha_state_file, &state) < 0)
      return 1;
    leader_term = state.term;
    snprintf(leader_id, sizeof(leader_id), "%s", state.local_hub_id);
  }
  /* A daemon restart also rebuilds every kernel peer and therefore resets
   * data-plane transmit sequences.  Rotate persisted leases so connected
   * Spokes cannot silently continue REFRESH with replay windows from the
   * previous Hub lifecycle; the subsequent authenticated registration
   * recreates both ends of each peer. */
  if (g_hub_state.node_count && !config->ha_enabled) {
    uint32_t i;
    for (i = 0; i < g_hub_state.node_count; i++) {
      if (RAND_bytes(g_hub_state.nodes[i].lease_token,
                     sizeof(g_hub_state.nodes[i].lease_token)) != 1)
        return 1;
      g_hub_state.nodes[i].refresh_counter = 0;
    }
  }
  /* Persist even a newly initialized, empty state before the HA service
   * serves its first snapshot.  Otherwise a fresh backup cannot complete
   * its initial replication until the first Spoke happens to register. */
  if (hub_save_state(config->state_file) < 0)
    return 1;
  if (dtun_module_ensure_loaded() < 0)
    return 1;
  created_ifindex =
      dtun_link_create(config->interface, outer_address, data_port,
                       config->node_id ? config->node_id : 1, no_hub, 0);
  if (created_ifindex <= 0) {
    dtun_log_err("Failed to create Hub interface %s: %s", config->interface,
                 strerror(-created_ifindex));
    return 1;
  }
  ifindex = (uint32_t)created_ifindex;
  if (dtun_link_setup(ifindex, config->interface, inner_address, prefix_len) <
      0) {
    dtun_log_err("Failed to create Hub interface %s", config->interface);
    return 1;
  }
  /* Restore persisted online peers before accepting REFRESH.  This lets an
   * authenticated data probe update a changed NAT mapping immediately after
   * a Hub restart without forcing every Spoke through full registration. */
  for (uint32_t i = 0; i < g_hub_state.node_count; i++) {
    hub_node_record_t *record = &g_hub_state.nodes[i];
    dtun_nl_peer_info_t peer;
    if (!record->online)
      continue;
    if (!record->node_id || !record->hub_tunnel_id || !record->tunnel_id) {
      record->online = 0;
      record->offline_since = time(NULL);
      continue;
    }
    (void)dtun_nl_route_del(ifindex, record->hub_tunnel_id, record->address,
                            32);
    (void)dtun_nl_peer_del(ifindex, record->hub_tunnel_id);
    memset(&peer, 0, sizeof(peer));
    peer.ifindex = ifindex;
    peer.tunnel_id = record->hub_tunnel_id;
    peer.remote_tunnel_id = record->tunnel_id;
    peer.node_id = record->node_id;
    peer.raw_addr = record->raw;
    peer.udp_addr = record->udp_addr;
    peer.udp_port = record->udp_port ? record->udp_port : data_port;
    peer.dynamic_raw = 1;
    peer.has_dynamic_raw = 1;
    peer.candidate_generation = record->generation;
    peer.has_generation = 1;
    peer.has_key = has_psk;
    if (has_psk)
      memcpy(peer.key, psk, sizeof(peer.key));
    if (program_peer(&peer) < 0 || program_route(ifindex, record->hub_tunnel_id,
                                                 record->address, 32) < 0) {
      dtun_log_warn(
          "[dtund Hub] Failed to restore persisted peer %llu, marking offline",
          (unsigned long long)record->node_id);
      record->online = 0;
      record->offline_since = time(NULL);
    }
  }
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    goto fail_link;
  (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  memset(&bind_address, 0, sizeof(bind_address));
  bind_address.sin_family = AF_INET;
  bind_address.sin_port = htons((uint16_t)config->bind_port);
  if (inet_pton(AF_INET, config->bind_address, &bind_address.sin_addr) != 1 ||
      bind(sock, (struct sockaddr *)&bind_address, sizeof(bind_address)) < 0) {
    dtun_log_err("Hub control socket bind failed: %s", strerror(errno));
    close(sock);
    goto fail_link;
  }
  if (config->ha_enabled) {
    dtun_ha_state_t ha_st;
    if (dtun_ha_state_load(config->ha_state_file, &ha_st) == 0) {
      dtun_log_info(
          "[dtund HA] Local Hub '%s' (role=%s) starting Active Leader "
          "service on %s:%d at term %llu",
          ha_st.local_hub_id, config->ha_role ? config->ha_role : "unknown",
          config->bind_address, config->bind_port,
          (unsigned long long)ha_st.term);
    } else {
      dtun_log_info("[dtund] Hub listening on %s:%d (DTRG)",
                    config->bind_address, config->bind_port);
    }
  } else {
    dtun_log_info("[dtund] Hub listening on %s:%d (DTRG)", config->bind_address,
                  config->bind_port);
  }
  fflush(stdout);
  while (g_running) {
    if (config->ha_enabled) {
      dtun_ha_state_t state;
      int state_loaded = dtun_ha_state_load(config->ha_state_file, &state) == 0;
      dtun_ha_member_t *local_member =
          state_loaded ? dtun_ha_member_find(&state, state.local_hub_id) : NULL;
      if (state_loaded && (!local_member || !local_member->enabled ||
                           local_member->lifecycle != DTUN_HA_MEMBER_ACTIVE)) {
        dtun_log_warn("[dtund HA] Local Hub '%s' is %s; stopping data plane",
                      state.local_hub_id,
                      local_member &&
                              local_member->lifecycle == DTUN_HA_MEMBER_DISABLED
                          ? "disabled"
                          : "evicted");
        demoted = 1;
        break;
      }
      if (state_loaded && strcmp(state.leader_id, state.local_hub_id)) {
        if (config->ha_role && !strcmp(config->ha_role, "primary") &&
            time(NULL) - ha_active_since <= config->failback_probation_time) {
          if (state.failback_level < 3)
            state.failback_level++;
          state.commit_index++;
          (void)dtun_ha_state_save(config->ha_state_file, &state);
        }
        dtun_log_info("[dtund HA] Local Hub '%s' (role=%s) demoted to Standby "
                      "by term %llu leader '%s'",
                      state.local_hub_id,
                      config->ha_role ? config->ha_role : "unknown",
                      (unsigned long long)state.term, state.leader_id);
        fflush(stdout);
        demoted = 1;
        break;
      }
      if (state_loaded && !strcmp(state.leader_id, state.local_hub_id)) {
        uint32_t voters = 0;
        uint64_t now_ms = dtun_monotonic_ms();

        for (uint32_t i = 0; i < state.member_count; i++)
          if (state.members[i].enabled &&
              state.members[i].role == DTUN_HA_VOTER)
            voters++;
        if (voters >= 3 &&
            !dtund_ha_service_has_quorum(g_ha_service, state.term, now_ms)) {
          if (!quorum_missing_since_ms)
            quorum_missing_since_ms = now_ms;
          if (now_ms - quorum_missing_since_ms >= 800) {
            dtun_ha_member_t *target = NULL;

            for (uint32_t i = 0; i < state.member_count; i++) {
              dtun_ha_member_t *m = &state.members[i];

              if (!m->enabled || m->role != DTUN_HA_VOTER ||
                  !strcmp(m->hub_id, state.local_hub_id))
                continue;
              if (!target || m->weight > target->weight ||
                  (m->weight == target->weight &&
                   strcmp(m->hub_id, target->hub_id) < 0))
                target = m;
            }
            if (target) {
              snprintf(state.leader_id, sizeof(state.leader_id), "%s",
                       target->hub_id);
              state.commit_index++;
              (void)dtun_ha_state_save(config->ha_state_file, &state);
            }
            (void)dtun_nl_role_set(ifindex, 0);
            dtun_log_warn("[dtund HA] Leader lost quorum for 800ms; local Hub "
                          "self-fenced");
            demoted = 1;
            break;
          }
        } else {
          quorum_missing_since_ms = 0;
        }
      }
      if (state_loaded && !ha_backoff_reset && config->ha_role &&
          !strcmp(config->ha_role, "primary") && state.failback_level &&
          time(NULL) - ha_active_since >= config->failback_backoff_reset_time) {
        state.failback_level = 0;
        state.commit_index++;
        if (dtun_ha_state_save(config->ha_state_file, &state) == 0)
          ha_backoff_reset = 1;
      }
    }
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    ssize_t length = recvfrom(sock, rx, sizeof(rx), 0,
                              (struct sockaddr *)&source, &source_len);
    dtrg_msg_t message;

    if (length <= 0) {
      (void)hub_expire_nodes(config, ifindex);
      continue;
    }
    if (dtrg_parse(psk, rx, (size_t)length, &message) < 0) {
      (void)hub_expire_nodes(config, ifindex);
      continue;
    }
    if (message.kind == DTRG_INIT) {
      uint64_t seconds =
          config->cookie_seconds > 0 ? (uint64_t)config->cookie_seconds : 30;
      uint8_t cookie[32];
      ssize_t packed;

      generate_cookie(g_hub_state.cookie_key, &source, message.node_id,
                      message.address, message.prefix_len, message.raw,
                      message.nonce, (uint64_t)time(NULL) / seconds, cookie);
      packed = dtrg_pack_challenge(psk, message.node_id, message.address,
                                   message.prefix_len, message.raw,
                                   message.nonce, cookie, tx, sizeof(tx));
      if (packed > 0)
        (void)sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&source,
                     source_len);
    } else if (message.kind == DTRG_CONFIRM &&
               validate_cookie(config, &source, &message)) {
      char allocation_error[160];
      hub_node_record_t *existing_record =
          message.node_id
              ? node_by_id(message.node_id)
              : (message.address.s_addr ? node_by_address(message.address)
                                        : NULL);
      int allocation_is_new = (existing_record == NULL);
      hub_node_record_t *record;

      if (config->ha_enabled && allocation_is_new &&
          !dtund_ha_service_allocation_allowed(g_ha_service, leader_term,
                                               dtun_monotonic_ms())) {
        dtun_log_warn("[dtund HA] Rejected new allocation while direct-pair "
                      "peer is unavailable");
        dtrg_msg_free(&message);
        continue;
      }
      record = hub_allocate_node(config, inner_address, message.node_id,
                                 message.address, message.prefix_len,
                                 allocation_error, sizeof(allocation_error));

      if (!record) {
        fprintf(stderr, "[dtund Hub] Rejected registration: %s\n",
                allocation_error);
      } else {
        dtun_nl_peer_info_t peer;
        dtrg_sync_peer_t sync_peers[MAX_PEERS];
        uint16_t sync_count;
        ssize_t packed;
        int peer_error;

        if (!record->online) {
          record->generation++;
          if (!record->generation)
            record->generation++;
          hub_note_change(record->node_id);
        }
        record->online = 1;
        record->offline_since = 0;
        record->last_seen = time(NULL);
        hub_node_seen(record);
        record->refresh_counter = 0;
        if (RAND_bytes(record->lease_token, sizeof(record->lease_token)) != 1) {
          dtrg_msg_free(&message);
          continue;
        }
        /* A full authenticated registration starts a new Spoke data
         * plane lifecycle.  Recreate the kernel peer so packets from
         * a restarted Spoke are not rejected by the previous
         * lifecycle's replay window.  Endpoint-only changes use
         * REFRESH/PROBE and never take this path. */
        (void)dtun_nl_route_del(ifindex, record->hub_tunnel_id, record->address,
                                32);
        peer_error = dtun_nl_peer_del(ifindex, record->hub_tunnel_id);
        if (peer_error < 0 && peer_error != -ENOENT) {
          fprintf(stderr, "[dtund Hub] Failed to reset registered peer: %s\n",
                  strerror(-peer_error));
          dtrg_msg_free(&message);
          continue;
        }
        memset(&peer, 0, sizeof(peer));
        peer.ifindex = ifindex;
        peer.tunnel_id = record->hub_tunnel_id;
        peer.remote_tunnel_id = record->tunnel_id;
        peer.node_id = record->node_id;
        peer.raw_addr = record->raw.s_addr ? record->raw : source.sin_addr;
        peer.udp_addr =
            record->udp_addr.s_addr ? record->udp_addr : source.sin_addr;
        peer.udp_port = record->udp_port ? record->udp_port : data_port;
        peer.dynamic_raw = 1;
        peer.has_dynamic_raw = 1;
        peer.candidate_generation = record->generation;
        peer.has_generation = 1;
        peer.has_key = has_psk;
        if (has_psk)
          memcpy(peer.key, psk, sizeof(peer.key));
        if (program_peer(&peer) < 0 ||
            program_route(ifindex, record->hub_tunnel_id, record->address, 32) <
                0) {
          dtun_log_err("[dtund Hub] Failed to program registered peer");
          dtrg_msg_free(&message);
          continue;
        }
        memset(sync_peers, 0, sizeof(sync_peers));
        sync_count = build_peer_sync(ifindex, record->node_id, sync_peers);
        if (hub_save_state(config->state_file) < 0) {
          dtrg_msg_free(&message);
          continue;
        }
        if (config->ha_enabled && allocation_is_new &&
            dtund_ha_wait_replicated(g_ha_service, config->state_file,
                                     config->timeout) < 0) {
          fprintf(stderr, "[dtund HA] Registration allocation retained but "
                          "not acknowledged: no synchronized backup\n");
          dtrg_msg_free(&message);
          continue;
        }
        g_hub_state_dirty = 0;
        packed = dtrg_pack_ack(psk, record->node_id, record->tunnel_id,
                               record->hub_tunnel_id, record->address,
                               record->prefix_len, data_port, message.nonce,
                               record->lease_token, g_hub_state.candidate_epoch,
                               leader_term, leader_id, tx, sizeof(tx));
        if (packed > 0)
          (void)sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&source,
                       source_len);
        packed = dtrg_pack_sync(psk, record->node_id, message.nonce, sync_peers,
                                sync_count, tx, sizeof(tx));
        if (packed > 0)
          (void)sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&source,
                       source_len);
        packed = dtund_ha_pack_hub_list(config, psk, record->node_id, tx,
                                        sizeof(tx));
        if (packed > 0)
          (void)sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&source,
                       source_len);
        {
          char text[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &record->address, text, sizeof(text));
          char outer_text[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &peer.udp_addr.s_addr, outer_text,
                    sizeof(outer_text));
          printf("[dtund Hub] Registered/Refreshed Spoke NodeID=%llu "
                 "InnerIP=%s OuterEndpoint=%s:%u DirectPeers=%u\n",
                 (unsigned long long)record->node_id, text, outer_text,
                 ntohs(peer.udp_port), sync_count);
          fflush(stdout);
        }
      }
    } else if (message.kind == DTRG_REFRESH) {
      hub_node_record_t *record = node_by_id(message.node_id);
      dtrg_sync_peer_t page[REFRESH_PEERS_PER_PAGE];
      uint8_t refresh_tx[1200];
      uint8_t flags;
      uint16_t next_offset, count;
      ssize_t packed;
      int candidates_changed;

      if (!record) {
        dtrg_msg_free(&message);
        (void)hub_expire_nodes(config, ifindex);
        continue;
      }
      if (!record->online ||
          CRYPTO_memcmp(record->lease_token, message.lease_token,
                        sizeof(record->lease_token)) != 0 ||
          message.counter < record->refresh_counter ||
          (message.counter == record->refresh_counter && message.offset == 0)) {
        struct in_addr no_address = {0};

        /* Echo only the stale token supplied by the requester.  The
         * authenticated flag tells a legitimate Spoke to perform the
         * full handshake immediately without disclosing the Hub's
         * newly rotated lease token. */
        packed = dtrg_pack_refresh_ack(
            psk, message.node_id, message.lease_token, message.counter,
            g_hub_state.candidate_epoch, no_address, 0,
            DTRG_REFRESH_RE_REGISTER, 0, leader_term, leader_id, data_port,
            NULL, 0, refresh_tx, sizeof(refresh_tx));
        if (packed > 0)
          (void)sendto(sock, refresh_tx, (size_t)packed, 0,
                       (struct sockaddr *)&source, source_len);
        dtrg_msg_free(&message);
        (void)hub_expire_nodes(config, ifindex);
        continue;
      }
      if (message.offset == 0)
        record->refresh_counter = message.counter;
      record->last_seen = time(NULL);
      hub_node_seen(record);
      candidates_changed = refresh_hub_candidates(ifindex);
      memset(page, 0, sizeof(page));
      count = build_refresh_page(record->node_id, message.epoch, message.offset,
                                 page, &flags, &next_offset);
      if (config->ha_enabled)
        flags |= DTRG_REFRESH_HUB_SWITCH;
      packed = dtrg_pack_refresh_ack(
          psk, record->node_id, record->lease_token, message.counter,
          g_hub_state.candidate_epoch, record->udp_addr, record->udp_port,
          flags, next_offset, leader_term, leader_id, data_port, page, count,
          refresh_tx, sizeof(refresh_tx));
      if (packed > 0)
        (void)sendto(sock, refresh_tx, (size_t)packed, 0,
                     (struct sockaddr *)&source, source_len);
      if (!(flags & DTRG_REFRESH_MORE)) {
        packed = dtund_ha_pack_hub_list(config, psk, record->node_id, tx,
                                        sizeof(tx));
        if (packed > 0)
          (void)sendto(sock, tx, (size_t)packed, 0, (struct sockaddr *)&source,
                       source_len);
      }
      if (candidates_changed || g_hub_state_dirty) {
        if (hub_save_state(config->state_file) == 0)
          g_hub_state_dirty = 0;
      }
    }
    dtrg_msg_free(&message);
    (void)hub_expire_nodes(config, ifindex);
  }
  close(sock);
  dtun_link_delete_by_name(config->interface);
  return demoted ? 2 : 0;

fail_link:
  dtun_link_delete_by_name(config->interface);
  return 1;
}
