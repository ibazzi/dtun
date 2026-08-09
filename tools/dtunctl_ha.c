#include "dtunctl_ha.h"
#include "dtun_ha_defaults.h"
#include "dtun_ha_proto.h"
#include "dtun_ha_state.h"
#include "dtun_liveness.h"
#include "ini_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_DTUN_CONFIG "/etc/dtun/dtun.conf"
#define DEFAULT_HA_DIR DTUN_HA_DIRECTORY
#define DEFAULT_HA_STATE DTUN_HA_STATE_PATH

enum ha_output_format { HA_FORMAT_HUMAN, HA_FORMAT_JSON, HA_FORMAT_PLAIN };

static const char *option_value(int argc, char **argv, const char *name);

static enum ha_output_format output_format(int argc, char **argv,
                                           int allow_plain) {
  const char *value = option_value(argc, argv, "--format");

  if (!value || !strcmp(value, "human"))
    return HA_FORMAT_HUMAN;
  if (!strcmp(value, "json"))
    return HA_FORMAT_JSON;
  if (allow_plain && !strcmp(value, "plain"))
    return HA_FORMAT_PLAIN;
  return -1;
}

static int ha_error(int argc, char **argv, const char *action, int code,
                    const char *message) {
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"%s\",\"success\":false,\"error\":{\"code\":%d,"
           "\"name\":\"%s\",\"message\":\"%s\"}}\n",
           action, code, code == 2 ? "EINVAL" : "ERROR", message);
  else
    fprintf(stderr, "%s\n", message);
  return code;
}

static const char *option_value(int argc, char **argv, const char *name) {
  size_t length = strlen(name);
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], name))
      return i + 1 < argc ? argv[i + 1] : NULL;
    if (!strncmp(argv[i], name, length) && argv[i][length] == '=')
      return argv[i] + length + 1;
  }
  return NULL;
}

static int has_option(int argc, char **argv, const char *name) {
  for (int i = 1; i < argc; i++)
    if (!strcmp(argv[i], name))
      return 1;
  return 0;
}

static long duration_seconds(const char *text) {
  char *end;
  long value = strtol(text, &end, 10), multiplier = 1;
  if (value <= 0)
    return -1;
  if (!*end)
    return value;
  if (!strcmp(end, "s"))
    multiplier = 1;
  else if (!strcmp(end, "m"))
    multiplier = 60;
  else if (!strcmp(end, "h"))
    multiplier = 3600;
  else
    return -1;
  return value > 86400 / multiplier ? -1 : value * multiplier;
}

static int path_join(char *out, size_t size, const char *dir,
                     const char *name) {
  return snprintf(out, size, "%s/%s", dir, name) < (int)size ? 0 : -1;
}

static int command_init(int argc, char **argv) {
  const char *config_path = option_value(argc, argv, "--config");
  const char *hub_id = option_value(argc, argv, "--hub-id");
  const char *dir = option_value(argc, argv, "--output-dir");
  const char *port_text = option_value(argc, argv, "--ha-port");
  const char *state_override = option_value(argc, argv, "--state-file");
  char key_path[512], ha_path[512], state_path[512], text[4096],
      cluster_hex[33];
  uint8_t public_key[32];
  dtun_config_t config;
  dtun_ha_state_t state;
  dtun_ha_member_t *member;
  int port = port_text ? atoi(port_text) : DTUN_HA_PORT;
  if (!config_path)
    config_path = DEFAULT_DTUN_CONFIG;
  if (dtun_ha_validate_hub_id(hub_id) < 0 || port < 1 || port > 65535) {
    fprintf(stderr,
            "ha init requires --hub-id ID [--config FILE] [--ha-port PORT]\n");
    return 2;
  }
  if (!dir)
    dir = DEFAULT_HA_DIR;
  if (path_join(key_path, sizeof(key_path), dir, "identity.key") < 0 ||
      path_join(ha_path, sizeof(ha_path), dir, "ha.conf") < 0)
    return 1;
  if (state_override)
    snprintf(state_path, sizeof(state_path), "%s", state_override);
  else
    snprintf(state_path, sizeof(state_path), "%s", DEFAULT_HA_STATE);
  if (access(ha_path, F_OK) == 0 || access(state_path, F_OK) == 0) {
    fprintf(stderr, "HA is already initialized; refusing to overwrite %s\n",
            dir);
    return 1;
  }
  if (dtun_config_load_base(&config, config_path) < 0)
    return 1;
  if (!config.mode || strcmp(config.mode, "hub")) {
    fprintf(stderr, "HA init requires mode=hub\n");
    dtun_config_free(&config);
    return 1;
  }
  memset(&state, 0, sizeof(state));
  dtun_ha_random_id(state.cluster_id, 16);
  snprintf(state.local_hub_id, sizeof(state.local_hub_id), "%s", hub_id);
  snprintf(state.primary_hub_id, sizeof(state.primary_hub_id), "%s", hub_id);
  snprintf(state.leader_id, sizeof(state.leader_id), "%s", hub_id);
  state.term = 1;
  state.commit_index = 1;
  state.manifest_version = 1;
  state.member_count = 1;
  member = &state.members[0];
  snprintf(member->hub_id, sizeof(member->hub_id), "%s", hub_id);
  member->weight = 1000;
  member->role = DTUN_HA_VOTER;
  member->enabled = 1;
  member->lifecycle = DTUN_HA_MEMBER_ACTIVE;
  member->ha_port = (uint16_t)port;
  member->control_port = (uint16_t)config.bind_port;
  member->data_port = (uint16_t)config.data_port;
  if (config.local_outer_ip)
    inet_pton(AF_INET, config.local_outer_ip, &member->address);
  if (dtun_ha_identity_generate(key_path, public_key) < 0) {
    fprintf(stderr, "failed to generate identity key\n");
    dtun_config_free(&config);
    return 1;
  }
  memcpy(member->public_key, public_key, 32);
  dtun_ha_hex(state.cluster_id, 16, cluster_hex);
  snprintf(
      text, sizeof(text),
      "# Generated by dtunctl. Do not edit while dtund is running.\n[ha]\n"
      "enabled = true\nformat_version = %d\ncluster_id = %s\nhub_id = %s\nrole "
      "= primary\n"
      "identity_private_key = %s\nha_state_file = %s\nha_port = %d\nweight = "
      "1000\n"
      "failback = immediate\nrecovery_stable_time = 120\n"
      "min_backup_active_time = 300\nfailback_probation_time = 120\n"
      "failback_backoff = 300,900,1800\nfailback_backoff_reset_time = 1800\n",
      DTUN_HA_CONFIG_VERSION, cluster_hex, hub_id, key_path, state_path, port);
  if (dtun_ha_atomic_write(ha_path, text, strlen(text), 0640) < 0 ||
      dtun_ha_state_save(state_path, &state) < 0) {
    fprintf(stderr, "failed to save HA configuration\n");
    dtun_config_free(&config);
    return 1;
  }
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"ha.init\",\"success\":true,\"hub_id\":\"%s\","
           "\"config\":\"%s\",\"state\":\"%s\"}\n",
           hub_id, ha_path, state_path);
  else
    printf("HA initialized.\nConfig: %s\nState:  %s\n", ha_path, state_path);
  if (output_format(argc, argv, 0) != HA_FORMAT_JSON &&
      strcmp(ha_path, DTUN_HA_CONFIG_PATH))
    printf("Add to %s:\n\n[ha]\nha_config = %s\n", config_path, ha_path);
  dtun_config_free(&config);
  return 0;
}

static int command_rebuild(int argc, char **argv) {
  const char *config_path = option_value(argc, argv, "--config");
  dtun_config_t config;
  dtun_ha_state_t old, fresh;
  dtun_ha_member_t *old_local, *member;
  uint8_t public_key[32];
  char cluster[33], key_tmp[560], state_tmp[560], config_tmp[560], text[4096];
  const char *ha_path;
  int old_loaded, runtime_lock = -1, result = 1;

  if (!has_option(argc, argv, "--force")) {
    fprintf(stderr, "ha rebuild is destructive and requires --force\n");
    return 2;
  }
  if (!config_path)
    config_path = DEFAULT_DTUN_CONFIG;
  if (dtun_config_load(&config, config_path) < 0)
    return 1;
  if (!config.ha_enabled || !config.ha_role ||
      strcmp(config.ha_role, "primary") || !config.ha_state_file ||
      !config.ha_identity_key || !config.ha_hub_id) {
    fprintf(stderr, "ha rebuild requires an initialized fixed Primary\n");
    goto out;
  }
  memset(&old, 0, sizeof(old));
  old_loaded = dtun_ha_state_load(config.ha_state_file, &old) == 0;
  if (!old_loaded && output_format(argc, argv, 0) != HA_FORMAT_JSON)
    fprintf(
        stderr,
        "Existing HA state is unavailable; rebuilding from configuration.\n");
  runtime_lock = dtun_ha_runtime_lock(config.ha_state_file, 1);
  if (runtime_lock < 0) {
    fprintf(stderr, "dtund is running; stop it before ha rebuild\n");
    goto out;
  }
  ha_path = config.ha_config ? config.ha_config : DTUN_HA_CONFIG_PATH;
  if (snprintf(key_tmp, sizeof(key_tmp), "%s.rebuild.%ld",
               config.ha_identity_key,
               (long)getpid()) >= (int)sizeof(key_tmp) ||
      snprintf(state_tmp, sizeof(state_tmp), "%s.rebuild.%ld",
               config.ha_state_file,
               (long)getpid()) >= (int)sizeof(state_tmp) ||
      snprintf(config_tmp, sizeof(config_tmp), "%s.rebuild.%ld", ha_path,
               (long)getpid()) >= (int)sizeof(config_tmp))
    goto out;
  unlink(key_tmp);
  unlink(state_tmp);
  unlink(config_tmp);
  if (dtun_ha_identity_generate(key_tmp, public_key) < 0) {
    fprintf(stderr, "failed to generate replacement identity\n");
    goto cleanup;
  }
  memset(&fresh, 0, sizeof(fresh));
  dtun_ha_random_id(fresh.cluster_id, sizeof(fresh.cluster_id));
  snprintf(fresh.local_hub_id, sizeof(fresh.local_hub_id), "%s",
           config.ha_hub_id);
  snprintf(fresh.primary_hub_id, sizeof(fresh.primary_hub_id), "%s",
           config.ha_hub_id);
  snprintf(fresh.leader_id, sizeof(fresh.leader_id), "%s", config.ha_hub_id);
  fresh.term = fresh.commit_index = fresh.manifest_version = 1;
  fresh.member_count = 1;
  member = &fresh.members[0];
  snprintf(member->hub_id, sizeof(member->hub_id), "%s", config.ha_hub_id);
  member->weight = (uint16_t)(config.ha_weight > 0 ? config.ha_weight : 1000);
  member->role = DTUN_HA_VOTER;
  member->enabled = 1;
  member->lifecycle = DTUN_HA_MEMBER_ACTIVE;
  member->ha_port = (uint16_t)config.ha_port;
  member->control_port = (uint16_t)config.bind_port;
  member->data_port = (uint16_t)config.data_port;
  old_local = old_loaded ? dtun_ha_member_find(&old, old.local_hub_id) : NULL;
  if (old_local)
    member->address = old_local->address;
  else if (config.local_outer_ip)
    inet_pton(AF_INET, config.local_outer_ip, &member->address);
  memcpy(member->public_key, public_key, sizeof(member->public_key));
  dtun_ha_hex(fresh.cluster_id, sizeof(fresh.cluster_id), cluster);
  snprintf(text, sizeof(text),
           "# Generated by dtunctl. Do not edit while dtund is running.\n[ha]\n"
           "enabled = true\nformat_version = 1\ncluster_id = %s\nhub_id = %s\n"
           "role = primary\nidentity_private_key = %s\nha_state_file = %s\n"
           "ha_port = %d\nweight = %u\nfailback = %s\n"
           "recovery_stable_time = %d\nmin_backup_active_time = %d\n"
           "failback_probation_time = %d\nfailback_backoff = %s\n"
           "failback_backoff_reset_time = %d\n",
           cluster, config.ha_hub_id, config.ha_identity_key,
           config.ha_state_file, config.ha_port, member->weight,
           config.failback, config.recovery_stable_time,
           config.min_backup_active_time, config.failback_probation_time,
           config.failback_backoff, config.failback_backoff_reset_time);
  if (dtun_ha_state_save(state_tmp, &fresh) < 0 ||
      dtun_ha_atomic_write(config_tmp, text, strlen(text), 0640) < 0 ||
      rename(key_tmp, config.ha_identity_key) < 0 ||
      rename(config_tmp, ha_path) < 0 ||
      rename(state_tmp, config.ha_state_file) < 0) {
    fprintf(stderr, "failed to atomically replace HA files\n");
    goto cleanup;
  }
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"ha.rebuild\",\"success\":true,\"cluster_id\":\"%s\","
           "\"primary\":\"%s\"}\n",
           cluster, config.ha_hub_id);
  else
    printf("HA rebuilt. Cluster=%s Primary=%s\n", cluster, config.ha_hub_id);
  result = 0;
cleanup:
  unlink(key_tmp);
  unlink(state_tmp);
  unlink(config_tmp);
out:
  dtun_ha_state_unlock(runtime_lock);
  dtun_config_free(&config);
  return result;
}

static int load_state_arg(int argc, char **argv, dtun_ha_state_t *state,
                          const char **path) {
  *path = option_value(argc, argv, "--state-file");
  if (!*path)
    *path = DEFAULT_HA_STATE;
  int error = dtun_ha_state_load(*path, state);
  if (error < 0) {
    if (error == -EPROTONOSUPPORT)
      fprintf(stderr,
              "incompatible HA state format: %s; re-run dtunctl ha init\n",
              *path);
    else
      fprintf(stderr, "failed to load HA state: %s\n", *path);
    return -1;
  }
  return 0;
}

static int command_invite_create(int argc, char **argv) {
  const char *hub_id = option_value(argc, argv, "--hub-id"),
             *weight_text = option_value(argc, argv, "--weight");
  const char *expires_text = option_value(argc, argv, "--expires"), *state_path,
             *key_path = option_value(argc, argv, "--identity-key");
  const char *bootstrap_text = option_value(argc, argv, "--bootstrap-address");
  const char *format = option_value(argc, argv, "--format");
  dtun_ha_state_t state;
  dtun_ha_invite_t *invite;
  dtun_ha_member_t *leader;
  uint8_t secret[32];
  char *encoded = NULL, idhex[33];
  long expires;
  int weight, lock_fd = -1, result = 1;
  if (!format)
    format = "human";
  if (strcmp(format, "human") && strcmp(format, "plain") &&
      strcmp(format, "json")) {
    fprintf(stderr, "invalid --format; expected human, plain, or json\n");
    return 2;
  }
  if (dtun_ha_validate_hub_id(hub_id) < 0) {
    fprintf(stderr, "invite create requires --hub-id ID [--weight N]\n");
    return 2;
  }
  weight = weight_text ? atoi(weight_text) : 1;
  expires = duration_seconds(expires_text ? expires_text : "10m");
  if (weight < 1 || weight > 65535 || expires < 1) {
    fprintf(stderr, "invalid weight or expiry\n");
    return 2;
  }
  state_path = option_value(argc, argv, "--state-file");
  if (!state_path)
    state_path = DEFAULT_HA_STATE;
  lock_fd = dtun_ha_state_lock(state_path);
  if (lock_fd < 0) {
    fprintf(stderr, "failed to lock HA state: %s\n", state_path);
    return 1;
  }
  if (dtun_ha_state_load(state_path, &state) < 0) {
    fprintf(stderr, "failed to load HA state: %s\n", state_path);
    goto out;
  }
  if (!key_path)
    key_path = "/etc/dtun/ha/identity.key";
  dtun_ha_member_t *existing = dtun_ha_member_find(&state, hub_id);
  if (existing && existing->lifecycle != DTUN_HA_MEMBER_EVICTED) {
    fprintf(stderr, "Hub ID %s is already an active or disabled member\n",
            hub_id);
    goto out;
  }
  leader = dtun_ha_member_find(&state, state.leader_id);
  if (!leader) {
    fprintf(stderr, "leader member %s is not present in HA state\n",
            state.leader_id);
    goto out;
  }
  struct in_addr bootstrap = leader->address;
  if (bootstrap_text && inet_pton(AF_INET, bootstrap_text, &bootstrap) != 1) {
    fprintf(stderr, "invalid --bootstrap-address\n");
    result = 2;
    goto out;
  }
  if (!bootstrap.s_addr) {
    fprintf(stderr, "leader endpoint is not known; use --bootstrap-address for "
                    "a NATed primary\n");
    goto out;
  }
  if (bootstrap_text && leader->address.s_addr != bootstrap.s_addr) {
    leader->address = bootstrap;
    leader->endpoint_generation++;
    state.manifest_version++;
  }
  if (state.invite_count >= DTUN_HA_MAX_INVITES) {
    fprintf(stderr, "invite table is full\n");
    goto out;
  }
  invite = &state.invites[state.invite_count++];
  memset(invite, 0, sizeof(*invite));
  dtun_ha_random_id(invite->id, 16);
  dtun_ha_random_id(secret, 32);
  SHA256(secret, 32, invite->secret_hash);
  snprintf(invite->hub_id, sizeof(invite->hub_id), "%s", hub_id);
  invite->weight = (uint16_t)weight;
  invite->expires_at = time(NULL) + expires;
  state.commit_index++;
  if (dtun_ha_invite_encode(&state, invite, secret, bootstrap, leader->ha_port,
                            key_path, &encoded) < 0 ||
      dtun_ha_state_save(state_path, &state) < 0) {
    fprintf(stderr, "failed to create invite\n");
    goto out;
  }
  dtun_ha_hex(invite->id, 16, idhex);
  if (!strcmp(format, "plain"))
    printf("%s\n", encoded);
  else if (!strcmp(format, "json"))
    printf("{\"invite_id\":\"%s\",\"hub_id\":\"%s\",\"weight\":%d,"
           "\"expires_at\":%lld,\"id_prefix\":\"%.12s\"}\n",
           encoded, hub_id, weight, (long long)invite->expires_at, idhex);
  else
    printf("Hub ID:    %s\nWeight:    %d\nInvite ID: %s\nID prefix: %.12s\n",
           hub_id, weight, encoded, idhex);
  result = 0;
out:
  free(encoded);
  OPENSSL_cleanse(secret, sizeof(secret));
  dtun_ha_state_unlock(lock_fd);
  return result;
}

static const char *invite_status(uint8_t status, time_t expires) {
  if (status == 2)
    return "revoked";
  if (status == 1)
    return "claimed";
  if (expires < time(NULL))
    return "expired";
  return "unused";
}

static int command_status(int argc, char **argv, int members) {
  dtun_ha_state_t state;
  const char *path;
  char cluster[33], addr[INET_ADDRSTRLEN];
  uint32_t voters = 0;
  enum ha_output_format format = output_format(argc, argv, 0);
  const char *identity = option_value(argc, argv, "--identity-key");
  if (load_state_arg(argc, argv, &state, &path) < 0)
    return 1;
  if (format < 0) {
    fprintf(stderr, "invalid --format; expected human or json\n");
    return 2;
  }
  if (!state.primary_hub_id[0])
    snprintf(state.primary_hub_id, sizeof(state.primary_hub_id), "%s",
             state.members[0].hub_id);
  if (!identity)
    identity = "/etc/dtun/ha/identity.key";
  dtun_ha_hex(state.cluster_id, 16, cluster);
  for (uint32_t i = 0; i < state.member_count; i++)
    if (state.members[i].enabled &&
        state.members[i].lifecycle == DTUN_HA_MEMBER_ACTIVE &&
        state.members[i].role == DTUN_HA_VOTER)
      voters++;
  const char *mode = voters == 2   ? "direct-pair"
                     : voters >= 3 ? "quorum"
                                   : "bootstrap";
  dtun_ha_member_t *local = dtun_ha_member_find(&state, state.local_hub_id);
  const char *configured_role =
      !strcmp(state.local_hub_id, state.primary_hub_id) ? "primary" : "backup";
  const char *runtime_role =
      local && local->lifecycle == DTUN_HA_MEMBER_DISABLED  ? "disabled"
      : local && local->lifecycle == DTUN_HA_MEMBER_EVICTED ? "evicted"
      : local && local->role == DTUN_HA_LEARNER             ? "learner"
      : !strcmp(state.local_hub_id, state.leader_id)        ? "leader"
                                                            : "standby";
  if (format == HA_FORMAT_JSON) {
    printf("{\"cluster\":{\"id\":\"%s\",\"mode\":\"%s\",\"term\":%llu,"
           "\"commit\":%llu,\"manifest\":%u,\"primary\":\"%s\","
           "\"leader\":\"%s\"},\"local\":{\"hub_id\":\"%s\","
           "\"configured_role\":\"%s\",\"runtime_role\":\"%s\"},"
           "\"quorum\":{\"voters\":%u,\"required\":%u},\"members\":[",
           cluster, mode, (unsigned long long)state.term,
           (unsigned long long)state.commit_index, state.manifest_version,
           state.primary_hub_id, state.leader_id, state.local_hub_id,
           configured_role, runtime_role, voters, voters / 2 + 1);
  } else if (!members) {
    printf("Cluster: %s\nLeader: %s\nTerm: %llu\nCommit: %llu\nMode: "
           "%s\nManifest: %u\nPrimary: %s\nLocal: %s (%s, %s)\nVoters: "
           "%u quorum=%u\nMembers: %u\n",
           cluster, state.leader_id, (unsigned long long)state.term,
           (unsigned long long)state.commit_index, mode, state.manifest_version,
           state.primary_hub_id, state.local_hub_id, configured_role,
           runtime_role, voters, voters / 2 + 1, state.member_count);
  }
  for (uint32_t i = 0; i < state.member_count; i++) {
    dtun_ha_member_t *m = &state.members[i];
    const char *ip = inet_ntop(AF_INET, &m->address, addr, sizeof(addr));
    uint64_t rtt = 0, started = dtun_monotonic_us();
    dtun_ha_admin_reply_t probe;
    struct in_addr probe_address = m->address;
    if (!strcmp(m->hub_id, state.local_hub_id))
      probe_address.s_addr = htonl(INADDR_LOOPBACK);
    const char *health =
        m->lifecycle == DTUN_HA_MEMBER_DISABLED ? "disabled"
        : !m->address.s_addr                    ? "unknown"
        : dtun_ha_admin_client(probe_address, m->ha_port, &state, identity,
                               DTUN_HA_ADMIN_STATUS, m->hub_id, 0, &probe) == 0
            ? "online"
            : "offline";
    if (!strcmp(health, "online"))
      rtt = dtun_monotonic_us() - started;
    const char *lifecycle = m->lifecycle == DTUN_HA_MEMBER_EVICTED ? "evicted"
                            : m->lifecycle == DTUN_HA_MEMBER_DISABLED
                                ? "disabled"
                                : "active";
    if (format == HA_FORMAT_JSON) {
      if (i)
        putchar(',');
      printf("{\"hub_id\":\"%s\",\"consensus_role\":\"%s\","
             "\"lifecycle\":\"%s\",\"enabled\":%s,\"weight\":%u,"
             "\"endpoint\":",
             m->hub_id, m->role == DTUN_HA_VOTER ? "voter" : "learner",
             lifecycle, m->enabled ? "true" : "false", m->weight);
      if (ip)
        printf("\"%s:%u\"", ip, m->ha_port);
      else
        printf("null");
      printf(",\"match_index\":%llu,\"health\":\"%s\",\"probe_rtt_us\":",
             (unsigned long long)m->match_index, health);
      if (!strcmp(health, "online"))
        printf("%llu", (unsigned long long)rtt);
      else
        printf("null");
      printf(",\"last_seen_at\":");
      if (!strcmp(health, "online"))
        printf("%lld}", (long long)time(NULL));
      else
        printf("null}");
    } else
      printf("%-24s weight=%u role=%s state=%s health=%s endpoint=%s:%u "
             "match=%llu rtt=%s\n",
             m->hub_id, m->weight,
             m->role == DTUN_HA_VOTER ? "voter" : "learner", lifecycle, health,
             ip ? ip : "unknown", m->ha_port,
             (unsigned long long)m->match_index,
             !strcmp(health, "online") ? "available" : "-");
  }
  if (format == HA_FORMAT_JSON)
    printf("]}\n");
  return 0;
}

static int command_invite_list(int argc, char **argv) {
  dtun_ha_state_t state;
  const char *path;
  char id[33];
  if (load_state_arg(argc, argv, &state, &path) < 0)
    return 1;
  int json = output_format(argc, argv, 0) == HA_FORMAT_JSON;
  if (json)
    putchar('[');
  for (uint32_t i = 0; i < state.invite_count; i++) {
    dtun_ha_invite_t *v = &state.invites[i];
    dtun_ha_hex(v->id, 16, id);
    if (json)
      printf("%s{\"id_prefix\":\"%.12s\",\"hub_id\":\"%s\",\"weight\":%u,"
             "\"status\":\"%s\",\"expires_at\":%lld}",
             i ? "," : "", id, v->hub_id, v->weight,
             invite_status(v->status, v->expires_at), (long long)v->expires_at);
    else
      printf("%.12s hub=%s weight=%u status=%s expires=%lld\n", id, v->hub_id,
             v->weight, invite_status(v->status, v->expires_at),
             (long long)v->expires_at);
  }
  if (json)
    printf("]\n");
  return 0;
}

static int command_invite_revoke(int argc, char **argv) {
  const char *prefix = option_value(argc, argv, "--id-prefix"), *path;
  dtun_ha_state_t state;
  char id[33];
  dtun_ha_invite_t *found = NULL;
  if (!prefix || strlen(prefix) < 6) {
    fprintf(stderr,
            "invite revoke requires --id-prefix with at least 6 characters\n");
    return 2;
  }
  if (load_state_arg(argc, argv, &state, &path) < 0)
    return 1;
  for (uint32_t i = 0; i < state.invite_count; i++) {
    dtun_ha_hex(state.invites[i].id, 16, id);
    if (!strncmp(id, prefix, strlen(prefix))) {
      if (found) {
        fprintf(stderr, "invite prefix is ambiguous\n");
        return 1;
      }
      found = &state.invites[i];
    }
  }
  if (!found) {
    fprintf(stderr, "invite not found\n");
    return 1;
  }
  found->status = 2;
  state.commit_index++;
  if (dtun_ha_state_save(path, &state) < 0)
    return 1;
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"ha.invite.revoke\",\"success\":true,"
           "\"id_prefix\":\"%s\"}\n",
           prefix);
  else
    printf("Invite revoked.\n");
  return 0;
}

static int wait_admin_quorum(const dtun_ha_state_t *state, const char *identity,
                             uint64_t commit) {
  uint32_t voters = 0;

  for (uint32_t i = 0; i < state->member_count; i++)
    if (state->members[i].enabled &&
        state->members[i].lifecycle == DTUN_HA_MEMBER_ACTIVE &&
        state->members[i].role == DTUN_HA_VOTER)
      voters++;
  if (voters < 3)
    return 0;
  for (int attempt = 0; attempt < 30; attempt++) {
    uint32_t confirmed = 0;

    for (uint32_t i = 0; i < state->member_count; i++) {
      const dtun_ha_member_t *member = &state->members[i];
      dtun_ha_admin_reply_t reply;

      if (!member->enabled || member->lifecycle != DTUN_HA_MEMBER_ACTIVE ||
          member->role != DTUN_HA_VOTER || !member->address.s_addr)
        continue;
      if (dtun_ha_admin_client(member->address, member->ha_port, state,
                               identity, DTUN_HA_ADMIN_STATUS, member->hub_id,
                               0, &reply) == 0 &&
          reply.commit_index >= commit)
        confirmed++;
    }
    if (confirmed > voters / 2)
      return 0;
    usleep(100000);
  }
  return -1;
}

static int command_member(int argc, char **argv, const char *operation) {
  const char *id = option_value(argc, argv, "--hub-id"), *path;
  dtun_ha_state_t state;
  dtun_ha_member_t *m, *leader;
  int force = has_option(argc, argv, "--force");
  const char *identity = option_value(argc, argv, "--identity-key");
  dtun_ha_admin_reply_t reply;
  uint8_t action = 0;
  if (!id || load_state_arg(argc, argv, &state, &path) < 0)
    return id ? 1 : 2;
  if (!state.primary_hub_id[0])
    snprintf(state.primary_hub_id, sizeof(state.primary_hub_id), "%s",
             state.members[0].hub_id);
  if (strcmp(state.local_hub_id, state.primary_hub_id)) {
    fprintf(stderr, "member administration is restricted to fixed Primary %s\n",
            state.primary_hub_id);
    return 1;
  }
  m = dtun_ha_member_find(&state, id);
  leader = dtun_ha_member_find(&state, state.leader_id);
  if (!m) {
    fprintf(stderr, "member not found\n");
    return 1;
  }
  if (!leader || !leader->address.s_addr) {
    fprintf(stderr, "current Leader endpoint is unknown\n");
    return 1;
  }
  if (!identity)
    identity = "/etc/dtun/ha/identity.key";
  if (!strcmp(operation, "set-weight")) {
    const char *w = option_value(argc, argv, "--weight");
    int value = w ? atoi(w) : 0;
    if (value < 1 || value > 65535) {
      fprintf(stderr, "set-weight requires --weight 1..65535\n");
      return 2;
    }
    m->weight = (uint16_t)value;
  } else if (!strcmp(operation, "disable")) {
    if (!strcmp(id, state.primary_hub_id)) {
      fprintf(stderr, "cannot disable fixed Primary\n");
      return 1;
    }
    if (!force &&
        dtun_ha_admin_client(m->address, m->ha_port, &state, identity,
                             DTUN_HA_ADMIN_STATUS, id, 0, &reply) < 0) {
      fprintf(
          stderr,
          "target is offline; use --force to disable with split-brain risk\n");
      return 1;
    }
    action = DTUN_HA_ADMIN_DISABLE;
  } else if (!strcmp(operation, "enable")) {
    if (m->lifecycle == DTUN_HA_MEMBER_EVICTED) {
      fprintf(stderr, "kicked member cannot be enabled; create a new invite\n");
      return 1;
    }
    action = DTUN_HA_ADMIN_ENABLE;
  } else if (!strcmp(operation, "kick")) {
    if (!strcmp(id, state.primary_hub_id)) {
      fprintf(stderr, "cannot kick fixed Primary\n");
      return 1;
    }
    if (!force &&
        dtun_ha_admin_client(m->address, m->ha_port, &state, identity,
                             DTUN_HA_ADMIN_STATUS, id, 0, &reply) < 0) {
      fprintf(stderr,
              "target is offline; use --force to kick with split-brain risk\n");
      return 1;
    }
    action = DTUN_HA_ADMIN_KICK;
  } else {
    char message[160];
    snprintf(message, sizeof(message),
             "unsupported member operation '%s'; expected set-weight, disable, "
             "enable, or kick",
             operation);
    return ha_error(argc, argv, "ha.member", 2, message);
  }
  if (!strcmp(operation, "set-weight")) {
    state.manifest_version++;
    state.commit_index++;
    if (dtun_ha_state_save(path, &state) < 0)
      return 1;
  } else if (dtun_ha_admin_client(leader->address, leader->ha_port, &state,
                                  identity, action, id, force, &reply) < 0) {
    fprintf(stderr, "Leader rejected member operation\n");
    return 1;
  } else if (!force && strcmp(id, leader->hub_id) &&
             dtun_ha_admin_client(m->address, m->ha_port, &state, identity,
                                  action, id, 0, &reply) < 0) {
    fprintf(stderr,
            "Leader updated membership but target acknowledgment failed\n");
    return 1;
  }
  if (action && wait_admin_quorum(&state, identity, reply.commit_index) < 0) {
    fprintf(stderr, "member operation was not confirmed by a quorum\n");
    return 1;
  }
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"ha.member.%s\",\"success\":true,\"hub_id\":\"%s\","
           "\"forced\":%s}\n",
           operation, id, force ? "true" : "false");
  else
    printf("Member %s %s.%s\n", id, operation,
           force &&
                   (!strcmp(operation, "disable") || !strcmp(operation, "kick"))
               ? " Warning: an isolated old Hub may continue running"
               : "");
  return 0;
}

static int command_failback(int argc, char **argv) {
  const char *path;
  dtun_ha_state_t state;
  if (load_state_arg(argc, argv, &state, &path) < 0)
    return 1;
  state.failback_requested = 1;
  state.failback_force = has_option(argc, argv, "--force");
  state.commit_index++;
  if (dtun_ha_state_save(path, &state) < 0)
    return 1;
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"ha.failback\",\"success\":true,\"force\":%s}\n",
           state.failback_force ? "true" : "false");
  else
    printf("Failback requested%s.\n",
           state.failback_force ? " with timing override" : "");
  return 0;
}

static int remove_ha_config_reference(const char *path) {
  FILE *file = fopen(path, "r");
  char *output = NULL, line[2048];
  size_t used = 0, capacity = 0;
  int in_ha = 0, result = -1;

  if (!file)
    return -1;
  while (fgets(line, sizeof(line), file)) {
    char section[64];
    const char *p = line;
    size_t length = strlen(line);

    while (*p == ' ' || *p == '\t')
      p++;
    if (sscanf(p, "[%63[^]]]", section) == 1)
      in_ha = !strcmp(section, "ha");
    if (in_ha && !strncmp(p, "ha_config", 9)) {
      p += 9;
      while (*p == ' ' || *p == '\t')
        p++;
      if (*p == '=')
        continue;
    }
    if (used + length + 1 > capacity) {
      size_t next = capacity ? capacity * 2 : 4096;
      while (next < used + length + 1)
        next *= 2;
      char *grown = realloc(output, next);
      if (!grown)
        goto out;
      output = grown;
      capacity = next;
    }
    memcpy(output + used, line, length);
    used += length;
  }
  if (ferror(file))
    goto out;
  if (!output) {
    output = strdup("");
    if (!output)
      goto out;
  }
  result = dtun_ha_atomic_write(path, output, used, 0640);
out:
  free(output);
  fclose(file);
  return result;
}

static int command_leave(int argc, char **argv) {
  const char *config_path = option_value(argc, argv, "--config");
  dtun_config_t config;
  dtun_ha_state_t state;
  dtun_ha_member_t *leader;
  dtun_ha_admin_reply_t reply;
  const char *ha_path;
  int runtime_lock = -1, result = 1;

  if (!config_path)
    config_path = DEFAULT_DTUN_CONFIG;
  if (dtun_config_load(&config, config_path) < 0)
    return 1;
  if (!config.ha_enabled || !config.ha_role ||
      strcmp(config.ha_role, "backup") || !config.ha_state_file ||
      !config.ha_identity_key) {
    fprintf(stderr, "ha leave requires an initialized backup Hub\n");
    goto out;
  }
  if (dtun_ha_state_load(config.ha_state_file, &state) < 0)
    goto out;
  if (!strcmp(state.local_hub_id, state.leader_id)) {
    fprintf(stderr, "active Leader cannot leave; migrate leadership first\n");
    goto out;
  }
  runtime_lock = dtun_ha_runtime_lock(config.ha_state_file, 1);
  if (runtime_lock < 0) {
    fprintf(stderr, "dtund is running; stop it before ha leave\n");
    goto out;
  }
  leader = dtun_ha_member_find(&state, state.leader_id);
  if (!leader || !leader->address.s_addr ||
      dtun_ha_admin_client(leader->address, leader->ha_port, &state,
                           config.ha_identity_key, DTUN_HA_ADMIN_LEAVE,
                           state.local_hub_id, 0, &reply) < 0) {
    fprintf(stderr,
            "Primary/Leader did not confirm HA leave; local files retained\n");
    goto out;
  }
  ha_path = config.ha_config ? config.ha_config : DTUN_HA_CONFIG_PATH;
  if (config.ha_config && remove_ha_config_reference(config_path) < 0) {
    fprintf(stderr, "cluster leave succeeded but failed to update %s\n",
            config_path);
    goto out;
  }
  if (unlink(ha_path) < 0 && errno != ENOENT)
    goto cleanup_failed;
  if (unlink(config.ha_state_file) < 0 && errno != ENOENT)
    goto cleanup_failed;
  if (unlink(config.ha_identity_key) < 0 && errno != ENOENT)
    goto cleanup_failed;
  if (output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf(
        "{\"action\":\"ha.leave\",\"success\":true,\"files_removed\":true}\n");
  else
    printf("Backup Hub left HA and local HA files were removed.\n");
  result = 0;
  goto out;
cleanup_failed:
  fprintf(stderr,
          "cluster leave succeeded but local HA cleanup is incomplete\n");
out:
  dtun_ha_state_unlock(runtime_lock);
  dtun_config_free(&config);
  return result;
}

static int read_invite(char **value, int from_stdin) {
  char line[2048];
  struct termios old, new;
  int tty = isatty(STDIN_FILENO) && !from_stdin;
  if (tty) {
    fprintf(stderr, "Invite ID: ");
    fflush(stderr);
    if (tcgetattr(STDIN_FILENO, &old) == 0) {
      new = old;
      new.c_lflag &= ~ECHO;
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
    }
  }
  if (!fgets(line, sizeof(line), stdin)) {
    if (tty)
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    return -1;
  }
  if (tty) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputc('\n', stderr);
  }
  line[strcspn(line, "\r\n")] = '\0';
  *value = strdup(line);
  return *value ? 0 : -1;
}

static int command_join(int argc, char **argv) {
  const char *config_path = option_value(argc, argv, "--config");
  const char *dir = option_value(argc, argv, "--output-dir");
  char *encoded = NULL, *managed = NULL, ip[INET_ADDRSTRLEN], key_path[512],
       ha_path[512], state_path[512], cluster_hex[33];
  dtun_ha_invite_t invite;
  uint8_t secret[32], cluster[16], leader_key[32], local_key[32];
  struct in_addr address;
  uint16_t port;
  int json = output_format(argc, argv, 0) == HA_FORMAT_JSON;
  if (!config_path)
    config_path = DEFAULT_DTUN_CONFIG;
  if (!dir)
    dir = DEFAULT_HA_DIR;
  if (read_invite(&encoded, has_option(argc, argv, "--invite-id-stdin")) < 0) {
    fprintf(stderr, "failed to read Invite ID\n");
    return 1;
  }
  if (dtun_ha_invite_decode(encoded, &invite, secret, cluster, &address, &port,
                            leader_key) < 0 ||
      invite.expires_at < time(NULL)) {
    free(encoded);
    fprintf(stderr, "invalid or expired Invite ID\n");
    return 1;
  }
  inet_ntop(AF_INET, &address, ip, sizeof(ip));
  if (!json)
    printf("Invite verified: hub=%s weight=%u leader=%s:%u\n", invite.hub_id,
           invite.weight, ip, port);
  if (path_join(key_path, sizeof(key_path), dir, "identity.key") < 0 ||
      path_join(ha_path, sizeof(ha_path), dir, "ha.conf") < 0) {
    free(encoded);
    return 1;
  }
  const char *state_option = option_value(argc, argv, "--state-file");
  snprintf(state_path, sizeof(state_path), "%s",
           state_option ? state_option : "/var/lib/dtun/ha/state");
  if (dtun_ha_identity_generate(key_path, local_key) < 0 &&
      dtun_ha_identity_public(key_path, local_key) < 0) {
    fprintf(stderr, "failed to create or load local identity\n");
    goto fail;
  }
  if (dtun_ha_join_client(address, port, &invite, secret, leader_key, key_path,
                          &managed) < 0) {
    fprintf(stderr, "online enrollment failed\n");
    goto fail;
  }
  dtun_ha_hex(cluster, 16, cluster_hex);
  size_t needed = strlen(managed) + 2048;
  char *output = malloc(needed);
  if (!output)
    goto fail;
  snprintf(
      output, needed,
      "# Generated by dtunctl. Do not edit while dtund is running.\n%s[ha]\n"
      "enabled = true\nformat_version = %d\ncluster_id = %s\nhub_id = %s\nrole "
      "= backup\n"
      "identity_private_key = %s\nha_state_file = %s\nbootstrap_address = %s\n"
      "ha_port = %u\nweight = %u\n\n%s",
      "", DTUN_HA_CONFIG_VERSION, cluster_hex, invite.hub_id, key_path,
      state_path, ip, port, invite.weight, managed);
  if (dtun_ha_atomic_write(ha_path, output, strlen(output), 0640) < 0) {
    free(output);
    goto fail;
  }
  dtun_ha_state_t joined;
  memset(&joined, 0, sizeof(joined));
  memcpy(joined.cluster_id, cluster, 16);
  snprintf(joined.local_hub_id, sizeof(joined.local_hub_id), "%s",
           invite.hub_id);
  const char *leader_line = strstr(managed, "leader_id = ");
  char leader_id[DTUN_HA_ID_LEN] = "hub-primary";
  if (leader_line) {
    leader_line += 12;
    sscanf(leader_line, "%63s", leader_id);
  }
  snprintf(joined.leader_id, sizeof(joined.leader_id), "%s", leader_id);
  snprintf(joined.primary_hub_id, sizeof(joined.primary_hub_id), "%s",
           leader_id);
  joined.term = 1;
  joined.commit_index = 1;
  joined.manifest_version = 1;
  joined.member_count = 2;
  snprintf(joined.members[0].hub_id, sizeof(joined.members[0].hub_id), "%s",
           leader_id);
  memcpy(joined.members[0].public_key, leader_key, 32);
  joined.members[0].address = address;
  joined.members[0].ha_port = port;
  joined.members[0].control_port = DTUN_HA_CONTROL_PORT;
  joined.members[0].data_port = DTUN_HA_DATA_PORT;
  joined.members[0].weight = 1000;
  joined.members[0].enabled = 1;
  joined.members[0].lifecycle = DTUN_HA_MEMBER_ACTIVE;
  joined.members[0].role = DTUN_HA_VOTER;
  snprintf(joined.members[1].hub_id, sizeof(joined.members[1].hub_id), "%s",
           invite.hub_id);
  memcpy(joined.members[1].public_key, local_key, 32);
  joined.members[1].ha_port = port;
  joined.members[1].control_port = DTUN_HA_CONTROL_PORT;
  joined.members[1].data_port = DTUN_HA_DATA_PORT;
  joined.members[1].weight = invite.weight;
  joined.members[1].enabled = 1;
  joined.members[1].lifecycle = DTUN_HA_MEMBER_ACTIVE;
  joined.members[1].role = DTUN_HA_LEARNER;
  if (dtun_ha_state_save(state_path, &joined) < 0) {
    free(output);
    goto fail;
  }
  free(output);
  if (json)
    printf("{\"action\":\"ha.join\",\"success\":true,\"hub_id\":\"%s\","
           "\"leader\":\"%s:%u\",\"config\":\"%s\"}\n",
           invite.hub_id, ip, port, ha_path);
  else
    printf("Backup Hub enrolled.\nConfig: %s\n", ha_path);
  if (!json && strcmp(ha_path, DTUN_HA_CONFIG_PATH))
    printf("Add to %s:\n\n[ha]\nha_config = %s\n", config_path, ha_path);
  OPENSSL_cleanse(secret, sizeof(secret));
  free(managed);
  free(encoded);
  return 0;
fail:
  OPENSSL_cleanse(secret, sizeof(secret));
  free(managed);
  free(encoded);
  return 1;
}

int dtunctl_ha_main(int argc, char **argv) {
  const char *format = option_value(argc, argv, "--format");
  int invite_create =
      argc > 2 && !strcmp(argv[1], "invite") && !strcmp(argv[2], "create");

  if (format && strcmp(format, "human") && strcmp(format, "json") &&
      (!invite_create || strcmp(format, "plain"))) {
    fprintf(stderr, "invalid --format; expected human or json%s\n",
            invite_create ? " or plain" : "");
    return 2;
  }
  if (argc < 2) {
    fprintf(stderr, "Usage: dtunctl ha "
                    "<init|rebuild|invite|join|leave|status|members> ...\n");
    return 2;
  }
  if (!strcmp(argv[1], "init"))
    return command_init(argc - 1, argv + 1);
  if (!strcmp(argv[1], "rebuild"))
    return command_rebuild(argc - 1, argv + 1);
  if (!strcmp(argv[1], "join"))
    return command_join(argc - 1, argv + 1);
  if (!strcmp(argv[1], "leave"))
    return command_leave(argc - 1, argv + 1);
  if (!strcmp(argv[1], "status"))
    return command_status(argc - 1, argv + 1, 0);
  if (!strcmp(argv[1], "members"))
    return command_status(argc - 1, argv + 1, 1);
  if (!strcmp(argv[1], "invite") && argc > 2 && !strcmp(argv[2], "create"))
    return command_invite_create(argc - 2, argv + 2);
  if (!strcmp(argv[1], "invite") && argc > 2 && !strcmp(argv[2], "list"))
    return command_invite_list(argc - 2, argv + 2);
  if (!strcmp(argv[1], "invite") && argc > 2 && !strcmp(argv[2], "revoke"))
    return command_invite_revoke(argc - 2, argv + 2);
  if (!strcmp(argv[1], "member") && argc > 2)
    return command_member(argc - 2, argv + 2, argv[2]);
  if (!strcmp(argv[1], "failback"))
    return command_failback(argc - 1, argv + 1);
  fprintf(stderr, "unsupported HA command\n");
  return 2;
}
