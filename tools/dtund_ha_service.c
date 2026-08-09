#include "dtund_ha_service.h"
#include "dtun_ha_defaults.h"
#include "dtun_ha_election.h"
#include "dtun_ha_proto.h"
#include "dtun_ha_replication.h"
#include "dtun_ha_state.h"
#include "dtun_liveness.h"
#include "dtun_log.h"
#include "dtun_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct dtund_ha_service {
  pthread_t thread;
  int listener;
  int runtime_lock;
  int stopping;
  char state_path[512];
  char identity_path[512];
  char hub_state_path[512];
  char configuration[4096];
  uint16_t ha_port;
  uint16_t control_port;
  uint16_t data_port;
  pthread_mutex_t lock;
  pthread_cond_t replicated;
  struct {
    char hub_id[DTUN_HA_ID_LEN];
    uint8_t digest[32];
    uint64_t term;
    uint64_t commit_index;
    uint64_t last_seen_ms;
    int valid;
  } replica_acks[DTUN_HA_MAX_MEMBERS];
};

static int file_digest(const char *path, uint8_t digest[32]) {
  FILE *fp = fopen(path, "rb");
  uint8_t buffer[8192];
  size_t n;
  unsigned int len = 0;
  EVP_MD_CTX *ctx;
  if (!fp)
    return -1;
  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fclose(fp);
    return -1;
  }
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    EVP_DigestUpdate(ctx, buffer, n);
  if (ferror(fp)) {
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return -1;
  }
  EVP_DigestFinal_ex(ctx, digest, &len);
  EVP_MD_CTX_free(ctx);
  fclose(fp);
  return len == 32 ? 0 : -1;
}

static int add_joined_member(dtun_ha_state_t *state,
                             const dtun_ha_join_peer_t *peer, uint16_t ha_port,
                             uint16_t control_port, uint16_t data_port) {
  dtun_ha_member_t *member = dtun_ha_member_find(state, peer->hub_id);
  dtun_ha_invite_t *invite = NULL;
  for (uint32_t i = 0; i < state->invite_count; i++)
    if (!strcmp(state->invites[i].hub_id, peer->hub_id) &&
        state->invites[i].status == 1 &&
        !memcmp(state->invites[i].claimed_key, peer->public_key, 32)) {
      invite = &state->invites[i];
      break;
    }
  if (!invite)
    return -1;
  if (!member) {
    if (state->member_count >= DTUN_HA_MAX_MEMBERS)
      return -1;
    member = &state->members[state->member_count++];
    memset(member, 0, sizeof(*member));
    snprintf(member->hub_id, sizeof(member->hub_id), "%s", peer->hub_id);
  }
  memcpy(member->public_key, peer->public_key, 32);
  member->address = peer->observed_address;
  member->weight = invite->weight;
  member->ha_port = ha_port;
  member->control_port = control_port;
  member->data_port = data_port;
  member->enabled = 1;
  member->lifecycle = DTUN_HA_MEMBER_ACTIVE;
  member->role = DTUN_HA_LEARNER;
  member->endpoint_generation++;
  state->manifest_version++;
  state->commit_index++;
  return 0;
}

static void *service_thread(void *argument) {
  dtund_ha_service_t *s = argument;
  while (!s->stopping) {
    struct sockaddr_in source;
    socklen_t slen = sizeof(source);
    int fd = accept(s->listener, (struct sockaddr *)&source, &slen);
    if (fd < 0) {
      if (s->stopping)
        break;
      if (errno == EINTR)
        continue;
      sleep(1);
      continue;
    }
    struct timeval io_timeout = {.tv_sec = 0, .tv_usec = 400000};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io_timeout,
                     sizeof(io_timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io_timeout,
                     sizeof(io_timeout));
    dtun_ha_state_t state;
    dtun_ha_join_peer_t peer;
    char magic[4] = {0};
    memset(&peer, 0, sizeof(peer));
    int state_lock = dtun_ha_state_lock(s->state_path);
    if (state_lock < 0) {
      close(fd);
      continue;
    }
    if (recv(fd, magic, sizeof(magic), MSG_PEEK) == 4 &&
        !memcmp(magic, "DTRP", 4)) {
      uint8_t digest[32];
      char replicated_hub_id[DTUN_HA_ID_LEN];
      uint64_t loaded_commit;
      if (dtun_ha_state_load(s->state_path, &state) == 0 &&
          (loaded_commit = state.commit_index,
           dtun_ha_replica_server(fd, &state, s->identity_path,
                                  s->hub_state_path, digest,
                                  replicated_hub_id)) == 0) {
        /* A normal snapshot request is read-only.  Writing its
         * previously loaded state here can roll back a concurrent
         * election term.  Only learner promotion changes commit. */
        if (state.commit_index != loaded_commit)
          (void)dtun_ha_state_save(s->state_path, &state);
        pthread_mutex_lock(&s->lock);
        uint32_t slot = 0;
        for (; slot < DTUN_HA_MAX_MEMBERS; slot++)
          if (!s->replica_acks[slot].valid ||
              !strcmp(s->replica_acks[slot].hub_id, replicated_hub_id))
            break;
        if (slot < DTUN_HA_MAX_MEMBERS) {
          snprintf(s->replica_acks[slot].hub_id,
                   sizeof(s->replica_acks[slot].hub_id), "%s",
                   replicated_hub_id);
          memcpy(s->replica_acks[slot].digest, digest, 32);
          s->replica_acks[slot].term = state.term;
          s->replica_acks[slot].commit_index = state.commit_index;
          s->replica_acks[slot].last_seen_ms = dtun_monotonic_ms();
          s->replica_acks[slot].valid = 1;
        }
        pthread_cond_broadcast(&s->replicated);
        pthread_mutex_unlock(&s->lock);
      }
      dtun_ha_state_unlock(state_lock);
      close(fd);
      continue;
    }
    if (!memcmp(magic, "DTVQ", 4)) {
      if (dtun_ha_state_load(s->state_path, &state) == 0)
        (void)dtun_ha_vote_server(fd, &state, s->state_path, s->identity_path);
      dtun_ha_state_unlock(state_lock);
      close(fd);
      continue;
    }
    if (!memcmp(magic, "DTHL", 4)) {
      if (dtun_ha_state_load(s->state_path, &state) == 0)
        (void)dtun_ha_leader_server(fd, &state, s->state_path);
      dtun_ha_state_unlock(state_lock);
      close(fd);
      continue;
    }
    if (!memcmp(magic, "DTHA", 4)) {
      if (dtun_ha_state_load(s->state_path, &state) == 0)
        (void)dtun_ha_admin_server(fd, &state, s->state_path, s->identity_path);
      dtun_ha_state_unlock(state_lock);
      close(fd);
      continue;
    }
    if (dtun_ha_state_load(s->state_path, &state) == 0 &&
        dtun_ha_join_server(fd, &state, s->state_path, s->identity_path,
                            s->configuration, &peer) == 0) {
      if (add_joined_member(&state, &peer, s->ha_port, s->control_port,
                            s->data_port) == 0)
        dtun_ha_state_save(s->state_path, &state);
      char text[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &peer.observed_address, text, sizeof(text));
      dtun_log_info("[dtund HA] Enrolled learner %s from %s", peer.hub_id,
                    text);
    }
    dtun_ha_state_unlock(state_lock);
    close(fd);
  }
  return NULL;
}

int dtund_ha_service_start(dtund_ha_service_t **out, const dtun_config_t *c) {
  dtund_ha_service_t *s;
  struct sockaddr_in address;
  int one = 1;
  if (!c->ha_enabled)
    return 0;
  if (!c->ha_identity_key || !c->ha_state_file || !c->ha_hub_id) {
    dtun_log_err("incomplete HA configuration");
    return -1;
  }
  if (c->ha_format_version != DTUN_HA_CONFIG_VERSION) {
    dtun_log_err("unsupported HA configuration format_version=%d; re-run "
                 "dtunctl ha init",
                 c->ha_format_version);
    return -1;
  }
  if (dtun_ha_validate_hub_id(c->ha_hub_id) < 0 || !c->ha_role ||
      (strcmp(c->ha_role, "primary") && strcmp(c->ha_role, "backup")) ||
      c->ha_port < 1 || c->ha_port > 65535 || !c->failback ||
      (strcmp(c->failback, "immediate") && strcmp(c->failback, "sticky")) ||
      c->recovery_stable_time < 1 || c->min_backup_active_time < 0) {
    dtun_log_err("invalid HA role, port, timer, or failback policy");
    return -1;
  }
  s = calloc(1, sizeof(*s));
  if (!s)
    return -1;
  s->listener = -1;
  s->runtime_lock = -1;
  s->ha_port = (uint16_t)c->ha_port;
  s->control_port = (uint16_t)c->bind_port;
  s->data_port = (uint16_t)c->data_port;
  pthread_mutex_init(&s->lock, NULL);
  pthread_cond_init(&s->replicated, NULL);
  snprintf(s->state_path, sizeof(s->state_path), "%s", c->ha_state_file);
  snprintf(s->identity_path, sizeof(s->identity_path), "%s",
           c->ha_identity_key);
  snprintf(s->hub_state_path, sizeof(s->hub_state_path), "%s", c->state_file);
  s->runtime_lock = dtun_ha_runtime_lock(s->state_path, 1);
  if (s->runtime_lock < 0) {
    dtun_log_err("HA state is already in use: %s", s->state_path);
    goto fail;
  }
  snprintf(s->configuration, sizeof(s->configuration),
           "[cluster]\naddress = %s\npool = %s\ndata_port = %d\npsk = %s\n"
           "identity_retention = %d\nfailback = %s\n"
           "recovery_stable_time = %d\nmin_backup_active_time = %d\n"
           "failback_probation_time = %d\nfailback_backoff = %s\n"
           "failback_backoff_reset_time = %d\nleader_id = %s\nha_port = %d\n",
           c->address, c->pool, c->data_port, c->psk_hex ? c->psk_hex : "",
           c->identity_retention, c->failback, c->recovery_stable_time,
           c->min_backup_active_time, c->failback_probation_time,
           c->failback_backoff, c->failback_backoff_reset_time, c->ha_hub_id,
           c->ha_port);
  s->listener = socket(AF_INET, SOCK_STREAM, 0);
  if (s->listener < 0)
    goto fail;
  setsockopt(s->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons((uint16_t)c->ha_port);
  if (bind(s->listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
      listen(s->listener, 16) < 0)
    goto fail;
  if (pthread_create(&s->thread, NULL, service_thread, s) != 0)
    goto fail;
  *out = s;
  dtun_log_info("[dtund HA] Enrollment service listening on 0.0.0.0:%d",
                c->ha_port);
  return 0;
fail:
  if (s->listener >= 0)
    close(s->listener);
  dtun_ha_state_unlock(s->runtime_lock);
  pthread_cond_destroy(&s->replicated);
  pthread_mutex_destroy(&s->lock);
  free(s);
  return -1;
}

void dtund_ha_service_stop(dtund_ha_service_t *s) {
  if (!s)
    return;
  s->stopping = 1;
  shutdown(s->listener, SHUT_RDWR);
  close(s->listener);
  pthread_join(s->thread, NULL);
  dtun_ha_state_unlock(s->runtime_lock);
  pthread_cond_destroy(&s->replicated);
  pthread_mutex_destroy(&s->lock);
  free(s);
}

static int service_has_quorum_locked(dtund_ha_service_t *s,
                                     const dtun_ha_state_t *state,
                                     uint64_t term, uint64_t now_ms) {
  uint32_t voters = 0, recent = 1;

  for (uint32_t i = 0; i < state->member_count; i++) {
    const dtun_ha_member_t *m = &state->members[i];

    if (!m->enabled || m->role != DTUN_HA_VOTER)
      continue;
    voters++;
    if (!strcmp(m->hub_id, state->local_hub_id))
      continue;
    for (uint32_t j = 0; j < DTUN_HA_MAX_MEMBERS; j++)
      if (s->replica_acks[j].valid &&
          !strcmp(s->replica_acks[j].hub_id, m->hub_id) &&
          s->replica_acks[j].term == term &&
          now_ms >= s->replica_acks[j].last_seen_ms &&
          now_ms - s->replica_acks[j].last_seen_ms <= 800) {
        recent++;
        break;
      }
  }
  return voters >= 3 && recent > voters / 2;
}

int dtund_ha_service_has_quorum(dtund_ha_service_t *s, uint64_t term,
                                uint64_t now_ms) {
  dtun_ha_state_t state;
  int result;

  if (!s || dtun_ha_state_load(s->state_path, &state) < 0)
    return 0;
  pthread_mutex_lock(&s->lock);
  result = service_has_quorum_locked(s, &state, term, now_ms);
  pthread_mutex_unlock(&s->lock);
  return result;
}

int dtund_ha_service_allocation_allowed(dtund_ha_service_t *s, uint64_t term,
                                        uint64_t now_ms) {
  dtun_ha_state_t state;
  uint32_t voters = 0;
  int recent_peer = 0;

  if (!s || dtun_ha_state_load(s->state_path, &state) < 0)
    return 0;
  for (uint32_t i = 0; i < state.member_count; i++)
    if (state.members[i].enabled && state.members[i].role == DTUN_HA_VOTER)
      voters++;
  if (voters != 2)
    return 1;
  pthread_mutex_lock(&s->lock);
  for (uint32_t i = 0; i < DTUN_HA_MAX_MEMBERS; i++)
    if (s->replica_acks[i].valid && s->replica_acks[i].term == term &&
        now_ms >= s->replica_acks[i].last_seen_ms &&
        now_ms - s->replica_acks[i].last_seen_ms <= 800) {
      recent_peer = 1;
      break;
    }
  pthread_mutex_unlock(&s->lock);
  return recent_peer;
}

static void note_ha_probe_miss(dtun_liveness_t *health, uint64_t now_ms) {
  dtun_liveness_note_miss(health, now_ms);
  dtun_liveness_probe_sent(health, now_ms);
  (void)dtun_liveness_tick(health, now_ms);
}

static void note_voter_contact(dtund_ha_service_t *s, const char *hub_id,
                               uint64_t term, uint64_t now_ms) {
  uint32_t slot = 0;

  if (!s)
    return;
  pthread_mutex_lock(&s->lock);
  for (; slot < DTUN_HA_MAX_MEMBERS; slot++)
    if (!s->replica_acks[slot].valid ||
        !strcmp(s->replica_acks[slot].hub_id, hub_id))
      break;
  if (slot < DTUN_HA_MAX_MEMBERS) {
    snprintf(s->replica_acks[slot].hub_id, sizeof(s->replica_acks[slot].hub_id),
             "%s", hub_id);
    s->replica_acks[slot].term = term;
    s->replica_acks[slot].last_seen_ms = now_ms;
    s->replica_acks[slot].valid = 1;
  }
  pthread_mutex_unlock(&s->lock);
}

int dtund_ha_standby_step(const dtun_config_t *c,
                          dtun_liveness_t *leader_health,
                          dtund_ha_service_t *service) {
  dtun_ha_state_t state;
  dtun_ha_member_t *leader, *local;
  const char *hub_state_path = c->state_file;
  struct in_addr bootstrap = {0};
  uint64_t now_ms = dtun_monotonic_ms();
  uint64_t started_us;

  (void)dtun_liveness_tick(leader_health, now_ms);
  if (!dtun_liveness_probe_due(leader_health, now_ms))
    return 0;
  dtun_liveness_probe_sent(leader_health, now_ms);
  if (dtun_ha_state_load(c->ha_state_file, &state) < 0)
    return -1;
  leader = dtun_ha_member_find(&state, state.leader_id);
  local = dtun_ha_member_find(&state, state.local_hub_id);
  if (!leader || !local)
    return -1;
  started_us = dtun_monotonic_us();
  if (dtun_ha_replica_client(leader->address, leader->ha_port, &state,
                             c->ha_identity_key, c->ha_state_file,
                             hub_state_path) == 0) {
    uint64_t finished_us = dtun_monotonic_us();

    dtun_liveness_note_success(
        leader_health, finished_us > started_us ? finished_us - started_us : 1,
        dtun_monotonic_ms());
    return 0;
  }
  char old_leader_id[DTUN_HA_ID_LEN];
  snprintf(old_leader_id, sizeof(old_leader_id), "%s", state.leader_id);
  if (c->ha_bootstrap_address &&
      inet_pton(AF_INET, c->ha_bootstrap_address, &bootstrap) == 1 &&
      bootstrap.s_addr != leader->address.s_addr &&
      (local->address.s_addr == 0 ||
       bootstrap.s_addr != local->address.s_addr) &&
      dtun_ha_replica_client(bootstrap, leader->ha_port, &state,
                             c->ha_identity_key, c->ha_state_file,
                             hub_state_path) == 0) {
    uint64_t finished_us = dtun_monotonic_us();

    dtun_liveness_note_success(
        leader_health, finished_us > started_us ? finished_us - started_us : 1,
        dtun_monotonic_ms());
    if (strcmp(state.leader_id, old_leader_id) != 0) {
      dtun_ha_member_t *new_leader =
          dtun_ha_member_find(&state, state.leader_id);
      if (new_leader && !strcmp(new_leader->hub_id, state.local_hub_id))
        return 1;
      if (new_leader && new_leader->address.s_addr &&
          dtun_ha_replica_client(new_leader->address, new_leader->ha_port,
                                 &state, c->ha_identity_key, c->ha_state_file,
                                 hub_state_path) == 0)
        dtun_liveness_note_success(leader_health, 100000, dtun_monotonic_ms());
    }
    return 0;
  }
  now_ms = dtun_monotonic_ms();
  note_ha_probe_miss(leader_health, now_ms);
  if (local->enabled && local->lifecycle == DTUN_HA_MEMBER_ACTIVE &&
      local->role == DTUN_HA_VOTER &&
      leader_health->state == DTUN_LIVENESS_OFFLINE) {
    uint32_t voters = 0, votes = 1, higher = 0;
    uint64_t term;
    for (uint32_t i = 0; i < state.member_count; i++) {
      dtun_ha_member_t *m = &state.members[i];
      if (!m->enabled || m->role != DTUN_HA_VOTER)
        continue;
      voters++;
      if (strcmp(m->hub_id, state.leader_id) &&
          strcmp(m->hub_id, state.local_hub_id) &&
          (m->weight > local->weight || (m->weight == local->weight &&
                                         strcmp(m->hub_id, local->hub_id) < 0)))
        higher++;
    }
    if (now_ms - leader_health->last_ack_ms <
        dtun_liveness_offline_ms(leader_health) +
            (uint64_t)(higher > 2 ? 2 : higher) * 300)
      return 0;
    term = state.term + 1;
    state.term = term;
    state.voted_term = term;
    snprintf(state.voted_for, sizeof(state.voted_for), "%s",
             state.local_hub_id);
    if (voters == 2) {
      state.commit_index++;
      snprintf(state.leader_id, sizeof(state.leader_id), "%s",
               state.local_hub_id);
      if (dtun_ha_state_save(c->ha_state_file, &state) < 0)
        return -1;
      dtun_log_info("[dtund HA] Direct-pair failover at term %llu; hub '%s' "
                    "taking over as leader",
                    (unsigned long long)term, state.local_hub_id);
      return 1;
    }
    if (voters < 3)
      return 0;
    if (dtun_ha_state_save(c->ha_state_file, &state) < 0)
      return -1;
    for (uint32_t i = 0; i < state.member_count && votes <= voters / 2; i++) {
      dtun_ha_member_t *m = &state.members[i];

      if (!m->enabled || m->role != DTUN_HA_VOTER ||
          !strcmp(m->hub_id, state.local_hub_id) || !m->address.s_addr)
        continue;
      int granted = dtun_ha_request_vote(m->address, m->ha_port, &state, m,
                                         term, c->ha_identity_key);

      votes += (uint32_t)granted;
      if (granted)
        note_voter_contact(service, m->hub_id, term, dtun_monotonic_ms());
    }
    if (votes > voters / 2) {
      state.commit_index++;
      snprintf(state.leader_id, sizeof(state.leader_id), "%s",
               state.local_hub_id);
      if (dtun_ha_state_save(c->ha_state_file, &state) < 0)
        return -1;
      for (uint32_t i = 0; i < state.member_count; i++) {
        dtun_ha_member_t *m = &state.members[i];
        if (m->enabled && m->role == DTUN_HA_VOTER &&
            strcmp(m->hub_id, state.local_hub_id) && m->address.s_addr)
          (void)dtun_ha_announce_leader(m->address, m->ha_port, &state, m,
                                        c->ha_identity_key);
      }
      dtun_log_info("[dtund HA] Won quorum election at term %llu with %u/%u "
                    "votes; hub '%s' taking over as leader",
                    (unsigned long long)term, votes, voters,
                    state.local_hub_id);
      return 1;
    }
  }
  return 0;
}

ssize_t dtund_ha_pack_hub_list(const dtun_config_t *c, const uint8_t psk[32],
                               uint64_t node_id, uint8_t *out, size_t out_len) {
  dtun_ha_state_t state;
  dtrg_hub_t hubs[DTRG_MAX_HUBS];
  uint8_t count = 0;
  uint32_t voters = 0;
  if (!c->ha_enabled || dtun_ha_state_load(c->ha_state_file, &state) < 0)
    return 0;
  memset(hubs, 0, sizeof(hubs));
  for (uint32_t i = 0; i < state.member_count && count < DTRG_MAX_HUBS; i++) {
    dtun_ha_member_t *m = &state.members[i];
    if (!m->enabled || m->role != DTUN_HA_VOTER)
      continue;
    voters++;
    if (!m->address.s_addr)
      continue;
    snprintf(hubs[count].hub_id, sizeof(hubs[count].hub_id), "%s", m->hub_id);
    hubs[count].address = m->address;
    hubs[count].control_port = m->control_port;
    hubs[count].data_port = m->data_port;
    hubs[count].weight = m->weight;
    memcpy(hubs[count].public_key, m->public_key, 32);
    if (!strcmp(m->hub_id, state.leader_id))
      hubs[count].flags = DTRG_HUB_ACTIVE;
    count++;
  }
  return dtrg_pack_hub_list(psk, node_id, state.cluster_id, state.term,
                            voters == 2 ? DTRG_HA_MODE_DIRECT_PAIR
                                        : DTRG_HA_MODE_QUORUM,
                            hubs, count, out, out_len);
}

int dtund_ha_wait_replicated(dtund_ha_service_t *s, const char *path,
                             int timeout_seconds) {
  dtun_ha_state_t state;
  uint8_t wanted[32];
  struct timespec deadline;
  uint32_t voters = 0, matched;
  if (!s)
    return 0;
  if (dtun_ha_state_load(s->state_path, &state) < 0 ||
      file_digest(path, wanted) < 0)
    return -1;
  if (memcmp(state.committed_hub_digest, wanted, sizeof(wanted))) {
    memcpy(state.committed_hub_digest, wanted, sizeof(wanted));
    state.commit_index++;
    if (dtun_ha_state_save(s->state_path, &state) < 0)
      return -1;
  }
  for (uint32_t i = 0; i < state.member_count; i++) {
    dtun_ha_member_t *m = &state.members[i];

    if (!m->enabled || m->role != DTUN_HA_VOTER)
      continue;
    voters++;
  }
  if (voters < 2)
    return -1;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += timeout_seconds > 0 ? timeout_seconds : 5;
  pthread_mutex_lock(&s->lock);
  for (;;) {
    matched = 1;
    for (uint32_t i = 0; i < state.member_count; i++) {
      dtun_ha_member_t *m = &state.members[i];
      if (!m->enabled || m->role != DTUN_HA_VOTER ||
          !strcmp(m->hub_id, state.local_hub_id))
        continue;
      for (uint32_t j = 0; j < DTUN_HA_MAX_MEMBERS; j++)
        if (s->replica_acks[j].valid &&
            !strcmp(s->replica_acks[j].hub_id, m->hub_id) &&
            !memcmp(s->replica_acks[j].digest, wanted, 32)) {
          matched++;
          break;
        }
    }
    if (matched > voters / 2)
      break;
    int err = pthread_cond_timedwait(&s->replicated, &s->lock, &deadline);
    if (err == ETIMEDOUT || s->stopping) {
      pthread_mutex_unlock(&s->lock);
      return -1;
    }
  }
  pthread_mutex_unlock(&s->lock);
  return s->stopping ? -1 : 0;
}

int dtund_ha_discover_leader(const dtun_config_t *c) {
  dtun_ha_state_t state, probe;
  const char *hub_state_path = c->state_file;
  if (dtun_ha_state_load(c->ha_state_file, &state) < 0)
    return -1;
  for (uint32_t i = 0; i < state.member_count; i++) {
    dtun_ha_member_t *m = &state.members[i];
    if (!m->enabled || !m->address.s_addr ||
        !strcmp(m->hub_id, state.local_hub_id))
      continue;
    probe = state;
    snprintf(probe.leader_id, sizeof(probe.leader_id), "%s", m->hub_id);
    if (dtun_ha_replica_client(m->address, m->ha_port, &probe,
                               c->ha_identity_key, c->ha_state_file,
                               hub_state_path) == 0)
      (void)dtun_ha_state_load(c->ha_state_file, &state);
  }
  return 0;
}

int dtund_ha_recover_primary_step(const dtun_config_t *c,
                                  time_t *stable_since) {
  dtun_ha_state_t state;
  dtun_ha_member_t *leader;
  time_t now = time(NULL);
  uint32_t voters = 0, votes = 1;
  if (dtun_ha_state_load(c->ha_state_file, &state) < 0)
    return -1;
  if (!strcmp(state.leader_id, state.local_hub_id))
    return 1;
  int requested = state.failback_requested, force = state.failback_force;
  leader = dtun_ha_member_find(&state, state.leader_id);
  if (!leader || !leader->address.s_addr)
    return -1;
  if (dtun_ha_replica_client(leader->address, leader->ha_port, &state,
                             c->ha_identity_key, c->ha_state_file,
                             c->state_file) < 0) {
    *stable_since = 0;
    return 0;
  }
  state.failback_requested = (uint8_t)requested;
  state.failback_force = (uint8_t)force;
  if (requested)
    (void)dtun_ha_state_save(c->ha_state_file, &state);
  if (!*stable_since)
    *stable_since = now;
  if ((!c->failback || strcmp(c->failback, "immediate")) && !requested)
    return 0;
  int required = c->recovery_stable_time > c->min_backup_active_time
                     ? c->recovery_stable_time
                     : c->min_backup_active_time;
  if (state.failback_level) {
    int values[3] = {300, 900, 1800};
    if (c->failback_backoff)
      (void)sscanf(c->failback_backoff, "%d,%d,%d", &values[0], &values[1],
                   &values[2]);
    int level = state.failback_level > 3 ? 3 : (int)state.failback_level;
    if (values[level - 1] > required)
      required = values[level - 1];
  }
  if (force)
    required = 0;
  if (now - *stable_since < required)
    return 0;
  uint64_t term = state.term + 1;
  for (uint32_t i = 0; i < state.member_count; i++)
    if (state.members[i].enabled && state.members[i].role == DTUN_HA_VOTER)
      voters++;
  for (uint32_t i = 0; i < state.member_count; i++) {
    dtun_ha_member_t *m = &state.members[i];
    if (!m->enabled || m->role != DTUN_HA_VOTER ||
        !strcmp(m->hub_id, state.local_hub_id) || !m->address.s_addr)
      continue;
    votes += (uint32_t)dtun_ha_request_vote(m->address, m->ha_port, &state, m,
                                            term, c->ha_identity_key);
  }
  if ((voters == 2 && votes == 2) || (voters >= 3 && votes > voters / 2)) {
    state.term = term;
    state.commit_index++;
    state.voted_term = term;
    state.failback_requested = 0;
    state.failback_force = 0;
    snprintf(state.voted_for, sizeof(state.voted_for), "%s",
             state.local_hub_id);
    snprintf(state.leader_id, sizeof(state.leader_id), "%s",
             state.local_hub_id);
    if (dtun_ha_state_save(c->ha_state_file, &state) < 0)
      return -1;
    for (uint32_t i = 0; i < state.member_count; i++) {
      dtun_ha_member_t *m = &state.members[i];
      if (m->enabled && strcmp(m->hub_id, state.local_hub_id) &&
          m->address.s_addr)
        (void)dtun_ha_announce_leader(m->address, m->ha_port, &state, m,
                                      c->ha_identity_key);
    }
    dtun_log_info(
        "[dtund HA] Recovery stable after %ds; preferred primary '%s' "
        "resumes active leader at term %llu",
        required, state.local_hub_id, (unsigned long long)term);
    return 1;
  }
  *stable_since = 0;
  return 0;
}
