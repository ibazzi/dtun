#ifndef DTUND_HA_SERVICE_H
#define DTUND_HA_SERVICE_H

#include <dtun/config.h>
#include <dtun/liveness.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct dtund_ha_service dtund_ha_service_t;

int dtund_ha_service_start(dtund_ha_service_t **service,
                           const dtun_config_t *config);
void dtund_ha_service_stop(dtund_ha_service_t *service);
int dtund_ha_service_has_quorum(dtund_ha_service_t *service, uint64_t term,
                                uint64_t now_ms);
int dtund_ha_service_allocation_allowed(dtund_ha_service_t *service,
                                        uint64_t term, uint64_t now_ms);
int dtund_ha_standby_step(const dtun_config_t *config,
                          dtun_liveness_t *leader_health,
                          dtund_ha_service_t *service);
ssize_t dtund_ha_pack_hub_list(const dtun_config_t *config,
                               const uint8_t psk[32], uint64_t node_id,
                               uint8_t *out, size_t out_len);
int dtund_ha_wait_replicated(dtund_ha_service_t *service,
                             const char *hub_state_path, int timeout_seconds);
int dtund_ha_discover_leader(const dtun_config_t *config);
int dtund_ha_recover_primary_step(const dtun_config_t *config,
                                  time_t *stable_since);

#endif
