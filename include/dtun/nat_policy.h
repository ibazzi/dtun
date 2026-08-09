/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DTUN_NAT_POLICY_H
#define DTUN_NAT_POLICY_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 dtun_nat_u32;
typedef u16 dtun_nat_u16;
typedef u64 dtun_nat_u64;
#else
#include <stdint.h>
typedef uint32_t dtun_nat_u32;
typedef uint16_t dtun_nat_u16;
typedef uint64_t dtun_nat_u64;
#endif

#define DTUN_NAT_MIN_SAFE_MS 5000U
#define DTUN_NAT_MAX_SAFE_MS 45000U
#define DTUN_NAT_RECALIBRATE_MS (30U * 60U * 1000U)

static inline dtun_nat_u32 dtun_nat_trial_ms(dtun_nat_u32 step) {
  static const dtun_nat_u32 trials[] = {5000,  8000,  12000, 18000,
                                        27000, 40000, 60000};

  return step < sizeof(trials) / sizeof(trials[0]) ? trials[step] : 0;
}

static inline dtun_nat_u32 dtun_nat_safe_ms(dtun_nat_u32 last_success_ms) {
  dtun_nat_u32 safe = (last_success_ms / 4U) * 3U;

  if (safe < DTUN_NAT_MIN_SAFE_MS)
    return DTUN_NAT_MIN_SAFE_MS;
  if (safe > DTUN_NAT_MAX_SAFE_MS)
    return DTUN_NAT_MAX_SAFE_MS;
  return safe;
}

static inline dtun_nat_u32 dtun_nat_shared_safe_ms(dtun_nat_u32 local_ms,
                                                   dtun_nat_u32 remote_ms) {
  if (!local_ms)
    return remote_ms;
  if (!remote_ms)
    return local_ms;
  return local_ms < remote_ms ? local_ms : remote_ms;
}

static inline dtun_nat_u32 dtun_nat_next_epoch(dtun_nat_u32 epoch) {
  epoch++;
  return epoch ? epoch : 1;
}

static inline int dtun_nat_epoch_matches(dtun_nat_u32 expected,
                                         dtun_nat_u32 received) {
  return expected == received;
}

static inline int dtun_nat_endpoint_changed(dtun_nat_u32 begin_addr,
                                            dtun_nat_u16 begin_port,
                                            dtun_nat_u32 check_addr,
                                            dtun_nat_u16 check_port) {
  return begin_addr != check_addr || begin_port != check_port;
}

static inline int dtun_nat_stop_growth(dtun_nat_u32 consecutive_failures,
                                       int endpoint_changed) {
  return endpoint_changed || consecutive_failures >= 2;
}

static inline int dtun_nat_local_is_owner(dtun_nat_u64 local_node_low,
                                          dtun_nat_u64 remote_node_low) {
  return local_node_low < remote_node_low;
}

static inline int dtun_nat_takeover_due(dtun_nat_u32 silence_ms,
                                        dtun_nat_u32 shared_safe_ms) {
  return shared_safe_ms && silence_ms >= 2U * shared_safe_ms;
}

#endif
