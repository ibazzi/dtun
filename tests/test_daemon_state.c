#define main dtund_program_main
#include "../tools/dtund.c"
#undef main

#define STATE_CHECK(condition)                                                 \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "test_daemon_state:%d: check failed: %s\n", __LINE__,    \
              #condition);                                                     \
      result = 1;                                                              \
      goto out;                                                                \
    }                                                                          \
  } while (0)

static int config_syslog_test(void) {
  dtun_config_t config;
  char path[] = "/tmp/dtun-syslog-test-XXXXXX";
  FILE *file = NULL;
  int fd = -1;
  int result = -1;

  memset(&config, 0, sizeof(config));
  fd = mkstemp(path);
  if (fd < 0)
    goto out;
  file = fdopen(fd, "w");
  if (!file)
    goto out;
  fd = -1;
  if (fputs("[global]\nsyslog = true\nsyslog_ident = testdtun\nsyslog_facility "
            "= local3\n",
            file) == EOF) {
    fclose(file);
    file = NULL;
    goto out;
  }
  if (fclose(file) != 0) {
    file = NULL;
    goto out;
  }
  file = NULL;
  if (dtun_config_load_base(&config, path) < 0 || !config.syslog_enabled ||
      !config.syslog_ident || strcmp(config.syslog_ident, "testdtun") ||
      !config.syslog_facility || strcmp(config.syslog_facility, "local3"))
    goto out;

  dtun_log_init(config.syslog_ident, config.syslog_enabled,
                config.syslog_facility);
  if (dtun_log_get_syslog() != 1)
    goto out;
  dtun_log_info("Testing syslog info message");
  dtun_log_err("Testing syslog error message");
  dtun_log_set_syslog(0);
  if (dtun_log_get_syslog() != 0)
    goto out;
  dtun_log_close();

  result = 0;
out:
  if (file)
    fclose(file);
  if (fd >= 0)
    close(fd);
  unlink(path);
  dtun_config_free(&config);
  return result;
}

static int config_pool_default_test(void) {
  dtun_config_t config;
  char path[] = "/tmp/dtun-config-test-XXXXXX";
  FILE *file = NULL;
  int fd = -1;
  int result = -1;

  memset(&config, 0, sizeof(config));
  fd = mkstemp(path);
  if (fd < 0)
    goto out;
  file = fdopen(fd, "w");
  if (!file)
    goto out;
  fd = -1;
  if (fputs("[global]\naddress = 10.123.45.6/20\n[hub]\n", file) == EOF) {
    fclose(file);
    file = NULL;
    goto out;
  }
  if (fclose(file) != 0) {
    file = NULL;
    goto out;
  }
  file = NULL;
  if (dtun_config_load_base(&config, path) < 0 || !config.pool ||
      strcmp(config.pool, "10.123.32.0/20"))
    goto out;
  result = 0;
out:
  if (file)
    fclose(file);
  if (fd >= 0)
    close(fd);
  unlink(path);
  dtun_config_free(&config);
  return result;
}

static int standby_step_failover_test(void) {
  dtun_config_t config;
  dtun_ha_state_t state, loaded;
  char dir[] = "/tmp/dtun-standby-test-XXXXXX";
  char key_path[256], state_path[256], hub_state_path[256];
  uint8_t public_key[32];
  time_t last_seen;
  int result = -1;

  if (!mkdtemp(dir))
    goto out;
  snprintf(key_path, sizeof(key_path), "%s/identity.key", dir);
  snprintf(state_path, sizeof(state_path), "%s/ha.state", dir);
  snprintf(hub_state_path, sizeof(hub_state_path), "%s/hub.state", dir);

  if (dtun_ha_identity_generate(key_path, public_key) < 0)
    goto out;

  dtun_config_init(&config);
  config.ha_enabled = 1;
  config.ha_hub_id = strdup("hub-primary");
  config.ha_role = strdup("primary");
  config.ha_state_file = strdup(state_path);
  config.ha_identity_key = strdup(key_path);
  config.state_file = strdup(hub_state_path);
  config.ha_bootstrap_address = strdup("192.0.2.1");
  config.failover_timeout = 3;

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
  state.members[1].ha_port = 59999; /* Unreachable port */
  state.members[1].weight = 900;
  state.members[1].role = DTUN_HA_VOTER;
  state.members[1].enabled = 1;

  if (dtun_ha_state_save(state_path, &state) < 0)
    goto out;

  /* Set last_seen to 5 seconds ago (exceeding failover_timeout = 3) */
  last_seen = time(NULL) - 5;
  int step = dtund_ha_standby_step(&config, &last_seen);
  if (step != 1)
    goto out;

  if (dtun_ha_state_load(state_path, &loaded) < 0 ||
      strcmp(loaded.leader_id, "hub-primary") != 0)
    goto out;

  result = 0;
out:
  unlink(state_path);
  unlink(hub_state_path);
  unlink(key_path);
  rmdir(dir);
  dtun_config_free(&config);
  return result;
}

int main(void) {
  dtun_config_t config;
  struct in_addr hub, requested, dynamic = {0};
  hub_node_record_t *record;
  legacy_hub_state_t legacy;
  char error[160];
  char path[] = "/tmp/dtun-state-test-XXXXXX";
  uint32_t saved_tunnel;
  FILE *file = NULL;
  int fd = -1;
  int result = 0;

  dtun_config_init(&config);
  STATE_CHECK(config_syslog_test() == 0);
  STATE_CHECK(config_pool_default_test() == 0);
  STATE_CHECK(standby_step_failover_test() == 0);
  STATE_CHECK(config.peer_timeout == 60);
  STATE_CHECK(config.identity_retention == 86400);
  STATE_CHECK(config.probe_interval_ms == 1000);
  STATE_CHECK(config.path_timeout_ms == 3000);
  STATE_CHECK(inet_pton(AF_INET, "10.99.0.1", &hub) == 1);
  STATE_CHECK(inet_pton(AF_INET, "10.99.0.2", &requested) == 1);
  hub_state_init();
  STATE_CHECK(hub_validate_state(&config, hub) == 0);

  record =
      hub_allocate_node(&config, hub, 2, requested, 24, error, sizeof(error));
  STATE_CHECK(record != NULL && record->node_id == 2);
  saved_tunnel = record->tunnel_id;

  STATE_CHECK(inet_pton(AF_INET, "192.168.5.5", &requested) == 1);
  STATE_CHECK(hub_allocate_node(&config, hub, 7, requested, 24, error,
                                sizeof(error)) == NULL);
  requested = hub;
  STATE_CHECK(hub_allocate_node(&config, hub, 8, requested, 24, error,
                                sizeof(error)) == NULL);
  STATE_CHECK(inet_pton(AF_INET, "10.99.0.3", &requested) == 1);
  STATE_CHECK(hub_allocate_node(&config, hub, 2, requested, 24, error,
                                sizeof(error)) == NULL);
  STATE_CHECK(inet_pton(AF_INET, "10.99.0.2", &requested) == 1);
  STATE_CHECK(hub_allocate_node(&config, hub, 3, requested, 24, error,
                                sizeof(error)) == NULL);
  STATE_CHECK(hub_allocate_node(&config, hub, 0, dynamic, 24, error,
                                sizeof(error)) != NULL);
  STATE_CHECK(g_hub_state.nodes[1].address.s_addr !=
              g_hub_state.nodes[0].address.s_addr);

  fd = mkstemp(path);
  STATE_CHECK(fd >= 0);
  close(fd);
  fd = -1;
  unlink(path);
  STATE_CHECK(hub_save_state(path) == 0);
  memset(&g_hub_state, 0, sizeof(g_hub_state));
  STATE_CHECK(hub_load_state(path) == 0);
  STATE_CHECK(g_hub_state.node_count == 2 &&
              g_hub_state.nodes[0].tunnel_id == saved_tunnel);
  STATE_CHECK(hub_validate_state(&config, hub) == 0);

  memset(&legacy, 0, sizeof(legacy));
  memcpy(legacy.cookie_key, g_hub_state.cookie_key, 32);
  legacy.next_tunnel_id = g_hub_state.next_tunnel_id;
  legacy.next_node_id = g_hub_state.next_node_id;
  legacy.node_count = (int)g_hub_state.node_count;
  for (uint32_t i = 0; i < g_hub_state.node_count; i++) {
    legacy.nodes[i].node_id = g_hub_state.nodes[i].node_id;
    legacy.nodes[i].tunnel_id = g_hub_state.nodes[i].tunnel_id;
    legacy.nodes[i].hub_tunnel_id = g_hub_state.nodes[i].hub_tunnel_id;
    legacy.nodes[i].address = g_hub_state.nodes[i].address;
    legacy.nodes[i].prefix_len = g_hub_state.nodes[i].prefix_len;
    legacy.nodes[i].raw = g_hub_state.nodes[i].raw;
    legacy.nodes[i].udp_addr = g_hub_state.nodes[i].udp_addr;
    legacy.nodes[i].udp_port = g_hub_state.nodes[i].udp_port;
    legacy.nodes[i].last_seen = g_hub_state.nodes[i].last_seen;
  }
  file = fopen(path, "wb");
  STATE_CHECK(file != NULL);
  STATE_CHECK(fwrite(&legacy, sizeof(legacy), 1, file) == 1);
  STATE_CHECK(fclose(file) == 0);
  file = NULL;
  memset(&g_hub_state, 0, sizeof(g_hub_state));
  STATE_CHECK(hub_load_state(path) == 0);
  STATE_CHECK(g_hub_state.node_count == 2 && g_hub_state.session_count == 0 &&
              g_hub_state.nodes[0].tunnel_id == saved_tunnel);
  STATE_CHECK(hub_session(g_hub_state.nodes[0].node_id,
                          g_hub_state.nodes[1].node_id) != NULL);
  STATE_CHECK(g_hub_state.session_count == 1);
  {
    dtrg_sync_peer_t page[REFRESH_PEERS_PER_PAGE];
    uint8_t flags = 0;
    uint16_t next = 0;
    uint16_t count;
    uint64_t before = g_hub_state.candidate_epoch;
    g_hub_state.nodes[1].online = 1;
    g_hub_state.nodes[1].generation = 3;
    STATE_CHECK(inet_pton(AF_INET, "198.51.100.3",
                          &g_hub_state.nodes[1].udp_addr) == 1);
    g_hub_state.nodes[1].raw = g_hub_state.nodes[1].udp_addr;
    g_hub_state.nodes[1].udp_port = 41003;
    hub_note_change(g_hub_state.nodes[1].node_id);
    memset(page, 0, sizeof(page));
    count = build_refresh_page(g_hub_state.nodes[0].node_id, before, 0, page,
                               &flags, &next);
    STATE_CHECK(count == 1 && page[0].node_id == 3 && page[0].generation == 3 &&
                (page[0].flags & DTRG_PEER_ONLINE));
    count =
        build_refresh_page(g_hub_state.nodes[0].node_id,
                           g_hub_state.candidate_epoch, 0, page, &flags, &next);
    STATE_CHECK(count == 0);
  }
  g_hub_state.nodes[0].last_seen = 100;
  STATE_CHECK(!hub_node_expired(&g_hub_state.nodes[0], 160, 60));
  STATE_CHECK(hub_node_expired(&g_hub_state.nodes[0], 161, 60));
  STATE_CHECK(hub_node_expired(&g_hub_state.nodes[1], 100, 60));
  hub_remove_node_at(1);
  STATE_CHECK(g_hub_state.node_count == 1 && g_hub_state.session_count == 0 &&
              g_hub_state.nodes[0].node_id == 2);

  file = fopen(path, "wb");
  STATE_CHECK(file != NULL);
  STATE_CHECK(fwrite("bad", 3, 1, file) == 1);
  STATE_CHECK(fclose(file) == 0);
  file = NULL;
  STATE_CHECK(hub_load_state(path) < 0);

  free(config.pool);
  config.pool = strdup("10.100.0.0/30");
  STATE_CHECK(config.pool != NULL);
  STATE_CHECK(inet_pton(AF_INET, "10.100.0.1", &hub) == 1);
  hub_state_init();
  STATE_CHECK(hub_allocate_node(&config, hub, 2, dynamic, 30, error,
                                sizeof(error)) != NULL);
  STATE_CHECK(hub_allocate_node(&config, hub, 3, dynamic, 30, error,
                                sizeof(error)) == NULL);

out:
  if (file)
    fclose(file);
  if (fd >= 0)
    close(fd);
  unlink(path);
  dtun_config_free(&config);
  if (!result)
    puts("C Hub state/allocation tests passed");
  return result;
}
