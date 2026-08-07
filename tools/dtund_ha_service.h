#ifndef DTUND_HA_SERVICE_H
#define DTUND_HA_SERVICE_H

#include "ini_parser.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

typedef struct dtund_ha_service dtund_ha_service_t;

int dtund_ha_service_start(dtund_ha_service_t **service,
                           const dtun_config_t *config);
void dtund_ha_service_stop(dtund_ha_service_t *service);
int dtund_ha_standby_step(const dtun_config_t *config, time_t *last_seen);
ssize_t dtund_ha_pack_hub_list(const dtun_config_t *config,
                               const uint8_t psk[32], uint64_t node_id,
                               uint8_t *out, size_t out_len);
int dtund_ha_wait_replicated(dtund_ha_service_t *service,
                             const char *hub_state_path, int timeout_seconds);
int dtund_ha_discover_leader(const dtun_config_t *config);
int dtund_ha_recover_primary_step(const dtun_config_t *config,
                                  time_t *stable_since);

#endif
