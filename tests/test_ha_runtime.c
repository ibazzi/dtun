#include "../src/dtund/ha_runtime.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "test_ha_runtime:%d: %s\n", __LINE__, #x);               \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static void member(dtun_ha_state_t *s, int n, const char *id, int weight) {
  dtun_ha_member_t *m = &s->members[n];
  strcpy(m->hub_id, id);
  m->weight = weight;
  m->enabled = 1;
  m->role = DTUN_HA_VOTER;
}

int main(void) {
  dtun_config_t c;
  dtun_ha_state_t s;
  dtund_ha_runtime_t r;
  dtun_config_init(&c);
  memset(&s, 0, sizeof(s));
  strcpy(s.local_hub_id, "backup");
  strcpy(s.leader_id, "primary");
  s.term = 4;
  s.member_count = 3;
  member(&s, 0, "primary", 1000);
  member(&s, 1, "backup", 900);
  member(&s, 2, "backup-b", 800);
  CHECK(dtund_ha_runtime_init(&r, &c, &s, 100000) == 0 &&
        r.phase == DTUND_HA_STANDBY);
  CHECK(c.raw_transport == 1);
  dtund_ha_note_heartbeat(&r, "backup-b", 4, 10, 100800);
  CHECK(!dtund_ha_tick(&r, 100899));
  CHECK(dtund_ha_tick(&r, 100900));
  CHECK(r.phase == DTUND_HA_BACKUP_HOLDDOWN && r.persistent.term == 5 &&
        dtund_ha_is_active(&r));
  CHECK(!dtund_ha_tick(&r, 400899));
  CHECK(dtund_ha_tick(&r, 400900) && r.phase == DTUND_HA_RECOVERY_OBSERVING);
  for (int i = 0; i <= 120; i++)
    dtund_ha_note_probe(&r, 1, 401000 + (uint64_t)i * 1000);
  CHECK(dtund_ha_tick(&r, 521000) && r.phase == DTUND_HA_FAILBACK_PREPARE);

  memset(&s, 0, sizeof(s));
  strcpy(s.local_hub_id, "backup-b");
  strcpy(s.leader_id, "primary");
  s.term = 1;
  s.member_count = 3;
  member(&s, 0, "primary", 1000);
  member(&s, 1, "backup-a", 800);
  member(&s, 2, "backup-b", 900);
  CHECK(dtund_ha_runtime_init(&r, &c, &s, 1000000) == 0);
  dtund_ha_note_heartbeat(&r, "backup-a", 1, 10, 1000200);
  CHECK(dtund_ha_tick(&r, 1000900) &&
        !strcmp(r.persistent.leader_id, "backup-b"));

  memset(&s, 0, sizeof(s));
  strcpy(s.local_hub_id, "backup");
  strcpy(s.leader_id, "primary");
  s.term = 7;
  s.member_count = 2;
  member(&s, 0, "primary", 1000);
  member(&s, 1, "backup", 900);
  CHECK(dtund_ha_runtime_init(&r, &c, &s, 2000000) == 0);
  CHECK(dtund_ha_tick(&r, 2000900) && r.persistent.term == 8 &&
        !strcmp(r.persistent.leader_id, "backup"));
  dtun_config_free(&c);
  puts("HA runtime state-machine tests passed");
  return 0;
}
