#include "../src/dtund/ha_service.h"
#include "../src/dtund/hub_state.h"
#include <dtun/config.h>
#include <dtun/ha_proto.h>
#include <dtun/ha_state.h>
#include <dtun/liveness.h>
#include <dtun/log.h>
#include <dtun/proto.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "test_daemon_state:%d: check failed: %s\n", __LINE__,    \
              #condition);                                                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int config_tests(void) {
  dtun_config_t config;
  char path[] = "/tmp/dtun-config-test-XXXXXX";
  char path2[] = "/tmp/dtun-config-pool-test-XXXXXX";
  FILE *file;
  int fd;

  dtun_config_init(&config);
  fd = mkstemp(path);
  CHECK(fd >= 0);
  file = fdopen(fd, "w");
  CHECK(file != NULL);
  CHECK(fputs("[global]\nsyslog = true\nsyslog_ident = testdtun\n"
              "syslog_facility = local3\n",
              file) != EOF);
  CHECK(fclose(file) == 0);
  CHECK(dtun_config_load_base(&config, path) == 0);
  CHECK(config.syslog_enabled && !strcmp(config.syslog_ident, "testdtun") &&
        !strcmp(config.syslog_facility, "local3"));
  dtun_log_init(config.syslog_ident, config.syslog_enabled,
                config.syslog_facility);
  CHECK(dtun_log_get_syslog() == 1);
  dtun_log_info("Testing syslog info message");
  dtun_log_err("Testing syslog error message");
  dtun_log_set_syslog(0);
  CHECK(dtun_log_get_syslog() == 0);
  dtun_log_close();
  dtun_config_free(&config);
  unlink(path);

  dtun_config_init(&config);
  fd = mkstemp(path2);
  CHECK(fd >= 0);
  file = fdopen(fd, "w");
  CHECK(file != NULL);
  CHECK(fputs("[global]\naddress = 10.123.45.6/20\n[hub]\n", file) != EOF);
  CHECK(fclose(file) == 0);
  CHECK(dtun_config_load_base(&config, path2) == 0 && config.pool &&
        !strcmp(config.pool, "10.123.32.0/20"));
  dtun_config_free(&config);
  unlink(path2);
  return 0;
}

static int obsolete_key_test(void) {
  dtun_config_t config;
  char path[] = "/tmp/dtun-obsolete-config-test-XXXXXX";
  FILE *file;
  int fd;

  dtun_config_init(&config);
  fd = mkstemp(path);
  CHECK(fd >= 0);
  file = fdopen(fd, "w");
  CHECK(file != NULL);
  CHECK(fputs("[global]\nmode = spoke\nprobe_interval_ms = 1000\n"
              "path_timeout_ms = 3000\n[spoke]\n"
              "hub_address = 192.0.2.1\n",
              file) != EOF);
  CHECK(fclose(file) == 0);
  CHECK(dtun_config_load(&config, path) == 0 && !strcmp(config.mode, "spoke") &&
        !strcmp(config.hub_address, "192.0.2.1") && !config.ha_enabled);
  dtun_config_free(&config);
  unlink(path);
  return 0;
}

static int hub_state_test(void) {
  dtund_hub_t hub;
  dtund_hub_node_view_t node;
  dtun_config_t config;
  struct in_addr hub_address, requested, udp_address;
  dtrg_sync_peer_t peers[20];
  uint8_t flags;
  uint16_t next_offset;
  uint64_t epoch;
  char error[160];
  char path[] = "/tmp/dtun-hub-state-test-XXXXXX";
  FILE *file;
  int fd;

  dtun_config_init(&config);
  free(config.pool);
  config.pool = strdup("10.99.0.0/24");
  CHECK(config.pool != NULL);
  CHECK(inet_pton(AF_INET, "10.99.0.1", &hub_address) == 1);
  CHECK(inet_pton(AF_INET, "10.99.0.2", &requested) == 1);
  dtund_hub_init(&hub);
  CHECK(dtund_hub_validate(&hub, &config, hub_address) == 0);
  CHECK(dtund_hub_allocate(&hub, &config, hub_address, 2, requested, 24, &node,
                           error, sizeof(error)) == 0 &&
        node.node_id == 2);
  CHECK(dtund_hub_allocate(&hub, &config, hub_address, 0, (struct in_addr){0},
                           24, &node, error, sizeof(error)) == 0 &&
        node.node_id != 2);
  CHECK(dtund_hub_node_count(&hub) == 2);
  CHECK(dtund_hub_get_node(&hub, node.node_id, &node) == 0);
  epoch = dtund_hub_candidate_epoch(&hub);
  CHECK(inet_pton(AF_INET, "198.51.100.3", &udp_address) == 1);
  CHECK(dtund_hub_update_node(&hub, node.node_id, udp_address, 41003, 3, 1) ==
        0);
  memset(peers, 0, sizeof(peers));
  CHECK(dtund_hub_build_refresh_page(&hub, 2, epoch, 0, peers, &flags,
                                     &next_offset) == 1 &&
        peers[0].node_id == node.node_id && peers[0].generation == 3 &&
        (peers[0].flags & DTRG_PEER_ONLINE));

  fd = mkstemp(path);
  CHECK(fd >= 0);
  close(fd);
  unlink(path);
  CHECK(dtund_hub_save(&hub, path) == 0);
  dtund_hub_init(&hub);
  CHECK(dtund_hub_load(&hub, path) == 0 && dtund_hub_node_count(&hub) == 2);
  CHECK(dtund_hub_remove_node(&hub, node.node_id) == 0 &&
        dtund_hub_node_count(&hub) == 1);
  file = fopen(path, "wb");
  CHECK(file != NULL && fwrite("bad", 3, 1, file) == 1 && fclose(file) == 0);
  CHECK(dtund_hub_load(&hub, path) < 0);
  unlink(path);
  dtun_config_free(&config);
  return 0;
}

static int standby_step_test(void) {
  dtun_config_t config;
  dtun_ha_state_t state, loaded;
  dtun_liveness_t leader_health;
  char dir[] = "/tmp/dtun-standby-test-XXXXXX";
  char key_path[256], state_path[256], hub_state_path[256];
  uint8_t public_key[32];

  CHECK(mkdtemp(dir) != NULL);
  snprintf(key_path, sizeof(key_path), "%s/identity.key", dir);
  snprintf(state_path, sizeof(state_path), "%s/ha.state", dir);
  snprintf(hub_state_path, sizeof(hub_state_path), "%s/hub.state", dir);
  CHECK(dtun_ha_identity_generate(key_path, public_key) == 0);
  dtun_config_init(&config);
  config.ha_enabled = 1;
  config.ha_hub_id = strdup("hub-primary");
  config.ha_role = strdup("primary");
  config.ha_state_file = strdup(state_path);
  config.ha_identity_key = strdup(key_path);
  config.state_file = strdup(hub_state_path);
  config.ha_bootstrap_address = strdup("192.0.2.1");
  memset(&state, 0, sizeof(state));
  dtun_ha_random_id(state.cluster_id, 16);
  strcpy(state.local_hub_id, "hub-primary");
  strcpy(state.leader_id, "hub-backup-1");
  state.term = 1;
  state.commit_index = 1;
  state.member_count = 2;
  strcpy(state.members[0].hub_id, "hub-primary");
  memcpy(state.members[0].public_key, public_key, 32);
  inet_pton(AF_INET, "192.0.2.1", &state.members[0].address);
  state.members[0].weight = 1000;
  state.members[0].role = DTUN_HA_VOTER;
  state.members[0].enabled = 1;
  strcpy(state.members[1].hub_id, "hub-backup-1");
  memcpy(state.members[1].public_key, public_key, 32);
  inet_pton(AF_INET, "192.0.2.2", &state.members[1].address);
  state.members[1].ha_port = 59999;
  state.members[1].weight = 900;
  state.members[1].role = DTUN_HA_VOTER;
  state.members[1].enabled = 1;
  CHECK(dtun_ha_state_save(state_path, &state) == 0);
  dtun_liveness_init(&leader_health, DTUN_LIVENESS_CRITICAL,
                     dtun_monotonic_ms() - 1000);
  while (leader_health.failed_rounds <
         dtun_liveness_miss_budget(&leader_health))
    dtun_liveness_note_miss(&leader_health, dtun_monotonic_ms());
  leader_health.next_probe_ms = 0;
  CHECK(dtund_ha_standby_step(&config, &leader_health, NULL) == 1);
  CHECK(dtun_ha_state_load(state_path, &loaded) == 0 &&
        !strcmp(loaded.leader_id, "hub-primary") && loaded.term == 2);
  unlink(state_path);
  unlink(hub_state_path);
  unlink(key_path);
  rmdir(dir);
  dtun_config_free(&config);
  return 0;
}

static int hub_list_test(void) {
  dtun_config_t config;
  dtun_ha_state_t state;
  dtrg_msg_t message;
  char path[] = "/tmp/dtun-ha-list-test-XXXXXX";
  uint8_t key[32] = {0}, packet[DTRG_MAX_PACKET];
  ssize_t length;
  int fd;

  fd = mkstemp(path);
  CHECK(fd >= 0);
  close(fd);
  dtun_config_init(&config);
  config.ha_enabled = 1;
  free(config.ha_state_file);
  config.ha_state_file = strdup(path);
  memset(&state, 0, sizeof(state));
  strcpy(state.local_hub_id, "hub-primary");
  strcpy(state.leader_id, "hub-primary");
  state.term = 3;
  state.member_count = 2;
  for (uint32_t i = 0; i < state.member_count; i++) {
    dtun_ha_member_t *member = &state.members[i];
    snprintf(member->hub_id, sizeof(member->hub_id), "hub-%u", i);
    member->address.s_addr = htonl(0xc0000201U + i);
    member->control_port = 49001;
    member->data_port = 49000;
    member->weight = (uint16_t)(1000 - i * 100);
    member->role = DTUN_HA_VOTER;
    member->enabled = 1;
  }
  strcpy(state.members[0].hub_id, "hub-primary");
  CHECK(dtun_ha_state_save(path, &state) == 0);
  length = dtund_ha_pack_hub_list(&config, key, 2, packet, sizeof(packet));
  memset(&message, 0, sizeof(message));
  CHECK(length >= 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0 &&
        message.ha_mode == DTRG_HA_MODE_DIRECT_PAIR);
  dtrg_msg_free(&message);
  state.member_count = 3;
  strcpy(state.members[2].hub_id, "hub-2");
  state.members[2].address.s_addr = htonl(0xc0000203U);
  state.members[2].control_port = 49001;
  state.members[2].data_port = 49000;
  state.members[2].weight = 800;
  state.members[2].role = DTUN_HA_VOTER;
  state.members[2].enabled = 1;
  CHECK(dtun_ha_state_save(path, &state) == 0);
  length = dtund_ha_pack_hub_list(&config, key, 2, packet, sizeof(packet));
  memset(&message, 0, sizeof(message));
  CHECK(length >= 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0 &&
        message.ha_mode == DTRG_HA_MODE_QUORUM);
  dtrg_msg_free(&message);
  unlink(path);
  dtun_config_free(&config);
  return 0;
}

int main(void) {
  CHECK(config_tests() == 0);
  CHECK(obsolete_key_test() == 0);
  CHECK(hub_state_test() == 0);
  CHECK(standby_step_test() == 0);
  CHECK(hub_list_test() == 0);
  puts("C daemon/Hub state tests passed");
  return 0;
}
