#ifndef DTUN_LIVENESS_H
#define DTUN_LIVENESS_H

#include <stdint.h>

enum dtun_liveness_state {
  DTUN_LIVENESS_UNKNOWN = 0,
  DTUN_LIVENESS_HEALTHY = 1,
  DTUN_LIVENESS_SUSPECT = 2,
  DTUN_LIVENESS_OFFLINE = 3,
};

enum dtun_liveness_profile {
  DTUN_LIVENESS_CRITICAL = 0,
  DTUN_LIVENESS_DIRECT = 1,
};

typedef struct {
  uint64_t srtt_us;
  uint64_t rttvar_us;
  uint64_t last_ack_ms;
  uint64_t next_probe_ms;
  uint32_t loss_q16;
  uint32_t failed_rounds;
  uint8_t initialized;
  uint8_t profile;
  uint8_t state;
} dtun_liveness_t;

void dtun_liveness_init(dtun_liveness_t *liveness,
                        enum dtun_liveness_profile profile, uint64_t now_ms);
void dtun_liveness_note_success(dtun_liveness_t *liveness, uint64_t rtt_us,
                                uint64_t now_ms);
void dtun_liveness_note_miss(dtun_liveness_t *liveness, uint64_t now_ms);
enum dtun_liveness_state dtun_liveness_tick(dtun_liveness_t *liveness,
                                            uint64_t now_ms);
int dtun_liveness_probe_due(const dtun_liveness_t *liveness, uint64_t now_ms);
void dtun_liveness_probe_sent(dtun_liveness_t *liveness, uint64_t now_ms);
uint32_t dtun_liveness_probe_interval_ms(const dtun_liveness_t *liveness);
uint32_t dtun_liveness_rto_ms(const dtun_liveness_t *liveness);
uint32_t dtun_liveness_offline_ms(const dtun_liveness_t *liveness);
uint32_t dtun_liveness_loss_ppm(const dtun_liveness_t *liveness);
uint32_t dtun_liveness_miss_budget(const dtun_liveness_t *liveness);
const char *dtun_liveness_state_name(enum dtun_liveness_state state);
uint64_t dtun_monotonic_ms(void);
uint64_t dtun_monotonic_us(void);

#endif
