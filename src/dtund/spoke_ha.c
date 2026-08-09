#include "spoke_ha.h"
#include <dtun/ha_state.h>
#include <string.h>

#define SPOKE_HA_STATE_VERSION 1U

typedef struct {
  char magic[4];
  uint32_t version;
  dtund_spoke_ha_t state;
} spoke_ha_file_t;

void dtund_spoke_ha_init(dtund_spoke_ha_t *s, uint64_t now_ms) {
  memset(s, 0, sizeof(*s));
  dtun_liveness_init(&s->leader_health, DTUN_LIVENESS_CRITICAL, now_ms);
}

int dtund_spoke_ha_update(dtund_spoke_ha_t *s, const dtrg_msg_t *m,
                          uint64_t now_ms) {
  char new_active[DTRG_HUB_ID_LEN] = {0};
  if (!m || m->kind != DTRG_HUB_LIST || !m->hub_count ||
      m->hub_count > DTRG_MAX_HUBS || m->term < s->term)
    return -1;
  for (uint8_t i = 0; i < m->hub_count; i++)
    if (m->hubs[i].flags & DTRG_HUB_ACTIVE) {
      snprintf(new_active, sizeof(new_active), "%s", m->hubs[i].hub_id);
      break;
    }
  if (s->active_hub_id[0] && new_active[0] &&
      strcmp(s->active_hub_id, new_active))
    s->force_switch = 1;
  memcpy(s->hubs, m->hubs, (size_t)m->hub_count * sizeof(s->hubs[0]));
  s->hub_count = m->hub_count;
  s->mode = m->ha_mode;
  s->term = m->term;
  if (new_active[0])
    snprintf(s->active_hub_id, sizeof(s->active_hub_id), "%s", new_active);
  if (s->leader_health.state == DTUN_LIVENESS_UNKNOWN)
    dtun_liveness_note_success(&s->leader_health, s->leader_health.srtt_us,
                               now_ms);
  return 0;
}

void dtund_spoke_ha_seen(dtund_spoke_ha_t *s, uint64_t rtt_us,
                         uint64_t now_ms) {
  dtun_liveness_note_success(&s->leader_health, rtt_us, now_ms);
}

void dtund_spoke_ha_missed(dtund_spoke_ha_t *s, uint64_t now_ms) {
  dtun_liveness_note_miss(&s->leader_health, now_ms);
  (void)dtun_liveness_tick(&s->leader_health, now_ms);
}

int dtund_spoke_ha_failover(dtund_spoke_ha_t *s, struct sockaddr_in *current,
                            uint64_t now_ms) {
  dtrg_hub_t *best = NULL;
  if (!s->hub_count ||
      (!s->force_switch &&
       dtun_liveness_tick(&s->leader_health, now_ms) != DTUN_LIVENESS_OFFLINE))
    return 0;
  for (uint8_t i = 0; i < s->hub_count; i++) {
    dtrg_hub_t *h = &s->hubs[i];
    if (!h->address.s_addr || !h->control_port ||
        h->address.s_addr == current->sin_addr.s_addr)
      continue;
    if (!best ||
        ((h->flags & DTRG_HUB_ACTIVE) && !(best->flags & DTRG_HUB_ACTIVE)) ||
        (((h->flags & DTRG_HUB_ACTIVE) == (best->flags & DTRG_HUB_ACTIVE)) &&
         (h->weight > best->weight ||
          (h->weight == best->weight && strcmp(h->hub_id, best->hub_id) < 0))))
      best = h;
  }
  if (!best)
    return 0;
  current->sin_addr = best->address;
  current->sin_port = htons(best->control_port);
  s->force_switch = 0;
  dtun_liveness_init(&s->leader_health, DTUN_LIVENESS_CRITICAL, now_ms);
  return 1;
}

int dtund_spoke_ha_load(dtund_spoke_ha_t *s, const char *path,
                        uint64_t now_ms) {
  spoke_ha_file_t file;
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return -1;
  int ok = fread(&file, sizeof(file), 1, fp) == 1 && fgetc(fp) == EOF &&
           !memcmp(file.magic, "DTSH", 4) &&
           file.version == SPOKE_HA_STATE_VERSION &&
           file.state.hub_count <= DTRG_MAX_HUBS;
  fclose(fp);
  if (!ok)
    return -1;
  *s = file.state;
  dtun_liveness_init(&s->leader_health, DTUN_LIVENESS_CRITICAL, now_ms);
  /* A persisted switch request belongs to the old process.  A new process
   * always starts by trying the configured bootstrap Primary. */
  s->force_switch = 0;
  return 0;
}

int dtund_spoke_ha_save(const dtund_spoke_ha_t *s, const char *path) {
  spoke_ha_file_t file;
  memset(&file, 0, sizeof(file));
  memcpy(file.magic, "DTSH", 4);
  file.version = SPOKE_HA_STATE_VERSION;
  file.state = *s;
  return dtun_ha_atomic_write(path, &file, sizeof(file), 0640);
}
