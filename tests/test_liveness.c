#include "dtun_liveness.h"

#include <stdio.h>

#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "test_liveness:%d: %s\n", __LINE__, #expression);        \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  dtun_liveness_t critical, direct;

  dtun_liveness_init(&critical, DTUN_LIVENESS_CRITICAL, 1000);
  CHECK(dtun_liveness_probe_interval_ms(&critical) == 200);
  CHECK(dtun_liveness_offline_ms(&critical) == 600);
  CHECK(dtun_liveness_tick(&critical, 1499) == DTUN_LIVENESS_SUSPECT);

  dtun_liveness_note_success(&critical, 200000, 1500);
  CHECK(critical.srtt_us == 200000 && critical.rttvar_us == 100000);
  CHECK(dtun_liveness_probe_interval_ms(&critical) == 250);
  CHECK(dtun_liveness_offline_ms(&critical) == 750);
  dtun_liveness_note_miss(&critical, 1750);
  dtun_liveness_note_miss(&critical, 1850);
  CHECK(dtun_liveness_tick(&critical, 2200) == DTUN_LIVENESS_SUSPECT);
  dtun_liveness_note_miss(&critical, 2250);
  dtun_liveness_note_miss(&critical, 2250);
  CHECK(dtun_liveness_tick(&critical, 2250) == DTUN_LIVENESS_OFFLINE);
  CHECK(dtun_liveness_offline_ms(&critical) <= 900);

  dtun_liveness_note_success(&critical, 100000, 2300);
  CHECK(dtun_liveness_tick(&critical, 2300) == DTUN_LIVENESS_HEALTHY);
  CHECK(dtun_liveness_loss_ppm(&critical) > 0);

  dtun_liveness_init(&direct, DTUN_LIVENESS_DIRECT, 0);
  CHECK(dtun_liveness_probe_interval_ms(&direct) == 400);
  CHECK(dtun_liveness_offline_ms(&direct) >= 900);
  CHECK(dtun_liveness_offline_ms(&direct) <= 1800);

  puts("Adaptive liveness tests passed");
  return 0;
}
