#ifndef DTUND_HA_H
#define DTUND_HA_H

#include <dtun/config.h>
#include <dtun/ha_state.h>

enum dtund_ha_phase {
  DTUND_HA_DISABLED,
  DTUND_HA_PRIMARY_ACTIVE,
  DTUND_HA_STANDBY,
  DTUND_HA_BACKUP_HOLDDOWN,
  DTUND_HA_RECOVERY_OBSERVING,
  DTUND_HA_FAILBACK_PREPARE,
  DTUND_HA_PRIMARY_PROBATION
};

typedef struct {
  char hub_id[DTUN_HA_ID_LEN];
  uint64_t last_heartbeat_ms;
  uint64_t term;
  uint64_t match_index;
  int reachable;
} dtund_ha_peer_health_t;

typedef struct {
  dtun_ha_state_t persistent;
  enum dtund_ha_phase phase;
  dtund_ha_peer_health_t health[DTUN_HA_MAX_MEMBERS];
  uint32_t health_count;
  int recovery_stable_time;
  int min_backup_active_time;
  int probation_time;
  int backoff[3];
  int backoff_reset_time;
  int failback_immediate;
  uint64_t phase_since_ms;
  uint64_t recovery_since_ms;
  uint64_t leader_last_seen_ms;
  uint64_t active_since_ms;
  unsigned int consecutive_probe_failures;
  unsigned int probe_total;
  unsigned int probe_success;
  int dirty;
} dtund_ha_runtime_t;

int dtund_ha_runtime_init(dtund_ha_runtime_t *runtime,
                          const dtun_config_t *config,
                          const dtun_ha_state_t *state, uint64_t now_ms);
void dtund_ha_note_heartbeat(dtund_ha_runtime_t *runtime, const char *hub_id,
                             uint64_t term, uint64_t match_index,
                             uint64_t now_ms);
void dtund_ha_note_probe(dtund_ha_runtime_t *runtime, int success,
                         uint64_t now_ms);
int dtund_ha_tick(dtund_ha_runtime_t *runtime, uint64_t now_ms);
int dtund_ha_is_active(const dtund_ha_runtime_t *runtime);
int dtund_ha_allocation_allowed(const dtund_ha_runtime_t *runtime);
const char *dtund_ha_phase_name(enum dtund_ha_phase phase);

#endif
