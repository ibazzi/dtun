#include "daemon_util.h"
#include "ha_service.h"
#include "hub.h"
#include "spoke.h"
#include <dtun/config.h>
#include <dtun/ha_defaults.h>
#include <dtun/ha_state.h>
#include <dtun/liveness.h>
#include <dtun/log.h>
#include <dtun/netlink.h>
#include <openssl/crypto.h>

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  const char *config_file = NULL;
  const char *override_mode = NULL;
  int force_syslog = 0;
  const char *cli_syslog_ident = NULL;
  const char *cli_syslog_facility = NULL;
  dtun_config_t config;
  uint8_t psk[32];
  int has_psk;
  int result;
  dtund_ha_service_t *ha_service = NULL;

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  signal(SIGHUP, handle_signal);
  for (int i = 1; i < argc; i++) {
    if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) &&
        i + 1 < argc)
      config_file = argv[++i];
    else if (!strcmp(argv[i], "--mode") && i + 1 < argc)
      override_mode = argv[++i];
    else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--syslog"))
      force_syslog = 1;
    else if (!strcmp(argv[i], "--syslog-ident") && i + 1 < argc)
      cli_syslog_ident = argv[++i];
    else if (!strcmp(argv[i], "--syslog-facility") && i + 1 < argc)
      cli_syslog_facility = argv[++i];
  }
  dtun_log_init(cli_syslog_ident ? cli_syslog_ident : "dtund", force_syslog,
                cli_syslog_facility);
  if (!config_file) {
    dtun_log_err(
        "Usage: %s -c /path/to/dtun.conf [--mode hub|spoke] [--syslog] "
        "[--syslog-facility <facility>] [--syslog-ident <ident>]",
        argv[0]);
    dtun_log_close();
    return 1;
  }
  if (dtun_config_load(&config, config_file) < 0) {
    dtun_log_close();
    return 1;
  }
  if (force_syslog)
    config.syslog_enabled = 1;
  if (cli_syslog_ident) {
    free(config.syslog_ident);
    config.syslog_ident = strdup(cli_syslog_ident);
  }
  if (cli_syslog_facility) {
    free(config.syslog_facility);
    config.syslog_facility = strdup(cli_syslog_facility);
  }
  dtun_log_init(config.syslog_ident ? config.syslog_ident : "dtund",
                config.syslog_enabled, config.syslog_facility);
  g_raw_transport = config.raw_transport;
  if (override_mode) {
    free(config.mode);
    config.mode = strdup(override_mode);
  }
  if (!config.mode) {
    dtun_log_err("Error: mode must be hub or spoke");
    dtun_config_free(&config);
    return 1;
  }
  has_psk = parse_psk(config.psk_hex, psk);
  if (has_psk < 0) {
    dtun_config_free(&config);
    return 1;
  }
  if (!strcmp(config.mode, "hub") && config.ha_enabled &&
      dtund_ha_service_start(&ha_service, &config) < 0) {
    dtun_log_err("Failed to start HA service");
    result = 1;
  } else if (!strcmp(config.mode, "hub")) {
    g_ha_service = ha_service;
    if (config.ha_enabled) {
      dtun_ha_state_t ha_state;
    ha_cycle:
      (void)dtund_ha_discover_leader(&config);
      if (dtun_ha_state_load(config.ha_state_file, &ha_state) < 0) {
        dtun_log_err("Failed to load HA state");
        result = 1;
        goto daemon_done;
      }
      dtun_ha_member_t *local_member =
          dtun_ha_member_find(&ha_state, ha_state.local_hub_id);
      if (!local_member || local_member->lifecycle == DTUN_HA_MEMBER_EVICTED) {
        dtun_log_warn(
            "[dtund HA] Local Hub was kicked; removing local HA files");
        unlink(config.ha_state_file);
        unlink(config.ha_identity_key);
        unlink(config.ha_config ? config.ha_config : DTUN_HA_CONFIG_PATH);
        result = 0;
        goto daemon_done;
      }
      if (!local_member->enabled ||
          local_member->lifecycle == DTUN_HA_MEMBER_DISABLED) {
        dtun_log_info(
            "[dtund HA] Local Hub '%s' is disabled; management-only mode",
            ha_state.local_hub_id);
        while (g_running) {
          usleep(200000);
          if (dtun_ha_state_load(config.ha_state_file, &ha_state) < 0)
            continue;
          local_member = dtun_ha_member_find(&ha_state, ha_state.local_hub_id);
          if (!local_member ||
              local_member->lifecycle != DTUN_HA_MEMBER_DISABLED)
            break;
        }
        if (g_running)
          goto ha_cycle;
        result = 0;
        goto daemon_done;
      }
      if (strcmp(ha_state.leader_id, ha_state.local_hub_id)) {
        dtun_liveness_t leader_health;
        time_t stable_since = 0;
        int promoted = 0;

        dtun_liveness_init(&leader_health, DTUN_LIVENESS_CRITICAL,
                           dtun_monotonic_ms());
        dtun_log_info(
            "[dtund HA] Standby Hub '%s' (role=%s) waiting for active "
            "leader '%s' (term %llu)",
            ha_state.local_hub_id, config.ha_role ? config.ha_role : "unknown",
            ha_state.leader_id, (unsigned long long)ha_state.term);
        while (g_running && !promoted) {
          int step;
          if (config.ha_role && !strcmp(config.ha_role, "primary")) {
            step = dtund_ha_recover_primary_step(&config, &stable_since);
            /* A recovered preferred primary remains a normal standby
             * while the backup is active.  If that active backup now
             * fails, do not wait forever for a cooperative failback:
             * apply the same direct-pair/quorum failover timer. */
            if (step == 0)
              step = dtund_ha_standby_step(&config, &leader_health, ha_service);
          } else
            step = dtund_ha_standby_step(&config, &leader_health, ha_service);
          if (step < 0) {
            result = 1;
            break;
          }
          promoted = step > 0;
          if (!promoted)
            usleep(100000);
        }
        if (promoted && g_running)
          result = run_hub(&config, psk, has_psk);
        else if (!g_running)
          result = 0;
      } else {
        result = run_hub(&config, psk, has_psk);
      }
      if (result == 2 && g_running)
        goto ha_cycle;
    } else {
      result = run_hub(&config, psk, has_psk);
    }
  } else if (!strcmp(config.mode, "spoke"))
    result = run_spoke(&config, psk, has_psk);
  else {
    dtun_log_err("Unknown mode: %s", config.mode);
    result = 1;
  }
daemon_done:
  dtund_ha_service_stop(ha_service);
  g_ha_service = NULL;
  OPENSSL_cleanse(psk, sizeof(psk));
  dtun_nl_close();
  dtun_config_free(&config);
  dtun_log_close();
  return result;
}
