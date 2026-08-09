#include <dtun/liveness.h>

#include <stddef.h>
#include <string.h>
#include <time.h>

#define LOSS_Q16_TWO_PERCENT 1311U

static uint64_t max_u64(uint64_t left, uint64_t right) {
  return left > right ? left : right;
}

static uint32_t clamp_u64(uint64_t value, uint32_t low, uint32_t high) {
  if (value < low)
    return low;
  if (value > high)
    return high;
  return (uint32_t)value;
}

void dtun_liveness_init(dtun_liveness_t *liveness,
                        enum dtun_liveness_profile profile, uint64_t now_ms) {
  memset(liveness, 0, sizeof(*liveness));
  liveness->profile = (uint8_t)profile;
  liveness->state = DTUN_LIVENESS_UNKNOWN;
  liveness->srtt_us = 100000;
  liveness->rttvar_us = 50000;
  liveness->last_ack_ms = now_ms;
  liveness->next_probe_ms = now_ms;
}

uint32_t dtun_liveness_probe_interval_ms(const dtun_liveness_t *liveness) {
  uint64_t estimate_us = liveness->srtt_us + 2 * liveness->rttvar_us;

  if (liveness->state == DTUN_LIVENESS_SUSPECT)
    return 100;
  if (liveness->profile == DTUN_LIVENESS_DIRECT)
    return clamp_u64((2 * estimate_us + 999) / 1000, 250, 750);
  return clamp_u64((estimate_us + 999) / 1000, 100, 250);
}

uint32_t dtun_liveness_rto_ms(const dtun_liveness_t *liveness) {
  uint64_t variation_us = max_u64(10000, 4 * liveness->rttvar_us);

  return clamp_u64((liveness->srtt_us + variation_us + 999) / 1000, 100,
                   liveness->profile == DTUN_LIVENESS_DIRECT ? 1000 : 500);
}

uint32_t dtun_liveness_miss_budget(const dtun_liveness_t *liveness) {
  return liveness->loss_q16 < LOSS_Q16_TWO_PERCENT ? 3 : 4;
}

uint32_t dtun_liveness_offline_ms(const dtun_liveness_t *liveness) {
  uint64_t interval = dtun_liveness_probe_interval_ms(liveness);
  uint64_t deadline = max_u64(dtun_liveness_rto_ms(liveness),
                              dtun_liveness_miss_budget(liveness) * interval);

  if (liveness->profile == DTUN_LIVENESS_DIRECT)
    return clamp_u64(deadline, 900, 1800);
  return clamp_u64(deadline, 600, 900);
}

void dtun_liveness_note_success(dtun_liveness_t *liveness, uint64_t rtt_us,
                                uint64_t now_ms) {
  uint64_t old_srtt = liveness->srtt_us;
  uint64_t error;

  if (!rtt_us)
    rtt_us = 1;
  if (!liveness->initialized) {
    liveness->srtt_us = rtt_us;
    liveness->rttvar_us = rtt_us / 2;
    liveness->initialized = 1;
  } else {
    error = rtt_us > old_srtt ? rtt_us - old_srtt : old_srtt - rtt_us;
    liveness->rttvar_us = (3 * liveness->rttvar_us + error) / 4;
    liveness->srtt_us = (7 * old_srtt + rtt_us) / 8;
  }
  liveness->loss_q16 = (7 * liveness->loss_q16) / 8;
  liveness->last_ack_ms = now_ms;
  liveness->failed_rounds = 0;
  liveness->state = DTUN_LIVENESS_HEALTHY;
  liveness->next_probe_ms = now_ms + dtun_liveness_probe_interval_ms(liveness);
}

void dtun_liveness_note_miss(dtun_liveness_t *liveness, uint64_t now_ms) {
  (void)now_ms;
  liveness->loss_q16 =
      (uint32_t)((7ULL * liveness->loss_q16 + 65536ULL) / 8ULL);
  if (liveness->failed_rounds != UINT32_MAX)
    liveness->failed_rounds++;
  if (liveness->state != DTUN_LIVENESS_OFFLINE)
    liveness->state = DTUN_LIVENESS_SUSPECT;
}

enum dtun_liveness_state dtun_liveness_tick(dtun_liveness_t *liveness,
                                            uint64_t now_ms) {
  uint64_t age =
      now_ms >= liveness->last_ack_ms ? now_ms - liveness->last_ack_ms : 0;

  if (age >= dtun_liveness_offline_ms(liveness) &&
      liveness->failed_rounds >= dtun_liveness_miss_budget(liveness))
    liveness->state = DTUN_LIVENESS_OFFLINE;
  else if (liveness->failed_rounds || age >= dtun_liveness_rto_ms(liveness))
    liveness->state = DTUN_LIVENESS_SUSPECT;
  else if (liveness->initialized)
    liveness->state = DTUN_LIVENESS_HEALTHY;
  return (enum dtun_liveness_state)liveness->state;
}

int dtun_liveness_probe_due(const dtun_liveness_t *liveness, uint64_t now_ms) {
  return now_ms >= liveness->next_probe_ms;
}

void dtun_liveness_probe_sent(dtun_liveness_t *liveness, uint64_t now_ms) {
  liveness->next_probe_ms = now_ms + dtun_liveness_probe_interval_ms(liveness);
}

uint32_t dtun_liveness_loss_ppm(const dtun_liveness_t *liveness) {
  return (uint32_t)((1000000ULL * liveness->loss_q16) / 65536ULL);
}

const char *dtun_liveness_state_name(enum dtun_liveness_state state) {
  static const char *const names[] = {"unknown", "healthy", "suspect",
                                      "offline"};

  return state >= DTUN_LIVENESS_UNKNOWN && state <= DTUN_LIVENESS_OFFLINE
             ? names[state]
             : "invalid";
}

uint64_t dtun_monotonic_ms(void) {
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

uint64_t dtun_monotonic_us(void) {
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_nsec / 1000;
}
