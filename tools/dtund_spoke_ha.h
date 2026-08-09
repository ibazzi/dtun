#ifndef DTUND_SPOKE_HA_H
#define DTUND_SPOKE_HA_H

#include "dtun_liveness.h"
#include "dtun_proto.h"
#include <netinet/in.h>

typedef struct {
  dtrg_hub_t hubs[DTRG_MAX_HUBS];
  uint8_t hub_count;
  uint8_t mode;
  uint64_t term;
  dtun_liveness_t leader_health;
  char active_hub_id[DTRG_HUB_ID_LEN];
  uint8_t force_switch;
} dtund_spoke_ha_t;

void dtund_spoke_ha_init(dtund_spoke_ha_t *state, uint64_t now_ms);
int dtund_spoke_ha_update(dtund_spoke_ha_t *state, const dtrg_msg_t *message,
                          uint64_t now_ms);
void dtund_spoke_ha_seen(dtund_spoke_ha_t *state, uint64_t rtt_us,
                         uint64_t now_ms);
void dtund_spoke_ha_missed(dtund_spoke_ha_t *state, uint64_t now_ms);
int dtund_spoke_ha_failover(dtund_spoke_ha_t *state,
                            struct sockaddr_in *current, uint64_t now_ms);
int dtund_spoke_ha_load(dtund_spoke_ha_t *state, const char *path,
                        uint64_t now_ms);
int dtund_spoke_ha_save(const dtund_spoke_ha_t *state, const char *path);

#endif
