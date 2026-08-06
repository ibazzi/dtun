#define main dtund_program_main
#include "../tools/dtund.c"
#undef main

#define STATE_CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "test_daemon_state:%d: check failed: %s\n", \
                __LINE__, #condition); \
        result = 1; \
        goto out; \
    } \
} while (0)

int main(void)
{
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
    STATE_CHECK(config.peer_timeout == 60);
    STATE_CHECK(inet_pton(AF_INET, "10.99.0.1", &hub) == 1);
    STATE_CHECK(inet_pton(AF_INET, "10.99.0.2", &requested) == 1);
    hub_state_init();
    STATE_CHECK(hub_validate_state(&config, hub) == 0);
    record = hub_allocate_node(&config, hub, 2, requested, 24,
                               error, sizeof(error));
    STATE_CHECK(record != NULL && record->node_id == 2);
    saved_tunnel = record->tunnel_id;

    STATE_CHECK(inet_pton(AF_INET, "192.168.5.5", &requested) == 1);
    STATE_CHECK(hub_allocate_node(&config, hub, 7, requested, 24,
                                  error, sizeof(error)) == NULL);
    requested = hub;
    STATE_CHECK(hub_allocate_node(&config, hub, 8, requested, 24,
                                  error, sizeof(error)) == NULL);
    STATE_CHECK(inet_pton(AF_INET, "10.99.0.3", &requested) == 1);
    STATE_CHECK(hub_allocate_node(&config, hub, 2, requested, 24,
                                  error, sizeof(error)) == NULL);
    STATE_CHECK(inet_pton(AF_INET, "10.99.0.2", &requested) == 1);
    STATE_CHECK(hub_allocate_node(&config, hub, 3, requested, 24,
                                  error, sizeof(error)) == NULL);
    STATE_CHECK(hub_allocate_node(&config, hub, 0, dynamic, 24,
                                  error, sizeof(error)) != NULL);
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
    memcpy(legacy.nodes, g_hub_state.nodes,
           g_hub_state.node_count * sizeof(legacy.nodes[0]));
    file = fopen(path, "wb");
    STATE_CHECK(file != NULL);
    STATE_CHECK(fwrite(&legacy, sizeof(legacy), 1, file) == 1);
    STATE_CHECK(fclose(file) == 0);
    file = NULL;
    memset(&g_hub_state, 0, sizeof(g_hub_state));
    STATE_CHECK(hub_load_state(path) == 0);
    STATE_CHECK(g_hub_state.node_count == 2 &&
                g_hub_state.session_count == 0 &&
                g_hub_state.nodes[0].tunnel_id == saved_tunnel);
    STATE_CHECK(hub_session(g_hub_state.nodes[0].node_id,
                            g_hub_state.nodes[1].node_id) != NULL);
    STATE_CHECK(g_hub_state.session_count == 1);
    g_hub_state.nodes[0].last_seen = 100;
    STATE_CHECK(!hub_node_expired(&g_hub_state.nodes[0], 160, 60));
    STATE_CHECK(hub_node_expired(&g_hub_state.nodes[0], 161, 60));
    STATE_CHECK(hub_node_expired(&g_hub_state.nodes[1], 100, 60));
    hub_remove_node_at(1);
    STATE_CHECK(g_hub_state.node_count == 1 &&
                g_hub_state.session_count == 0 &&
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
    STATE_CHECK(hub_allocate_node(&config, hub, 2, dynamic, 30,
                                  error, sizeof(error)) != NULL);
    STATE_CHECK(hub_allocate_node(&config, hub, 3, dynamic, 30,
                                  error, sizeof(error)) == NULL);

out:
    if (file) fclose(file);
    if (fd >= 0) close(fd);
    unlink(path);
    dtun_config_free(&config);
    if (!result) puts("C Hub state/allocation tests passed");
    return result;
}
