#include <dtun/nat_policy.h>

#include <stdio.h>

#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "test_nat_policy:%d: %s\n", __LINE__, #expression);      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  uint32_t last_success;

  CHECK(dtun_nat_trial_ms(0) == 5000);
  CHECK(dtun_nat_trial_ms(1) == 8000);
  CHECK(dtun_nat_trial_ms(2) == 12000);
  CHECK(dtun_nat_trial_ms(3) == 18000);
  CHECK(dtun_nat_trial_ms(4) == 27000);
  CHECK(dtun_nat_trial_ms(5) == 40000);
  CHECK(dtun_nat_trial_ms(6) == 60000);
  CHECK(dtun_nat_trial_ms(7) == 0);

  CHECK(dtun_nat_safe_ms(0) == 5000);
  CHECK(dtun_nat_safe_ms(5000) == 5000);
  CHECK(dtun_nat_safe_ms(12000) == 9000);
  CHECK(dtun_nat_safe_ms(40000) == 30000);
  CHECK(dtun_nat_safe_ms(60000) == 45000);
  CHECK(dtun_nat_shared_safe_ms(9000, 30000) == 9000);
  CHECK(dtun_nat_shared_safe_ms(0, 30000) == 30000);
  CHECK(dtun_nat_shared_safe_ms(9000, 0) == 9000);

  CHECK(dtun_nat_next_epoch(7) == 8);
  CHECK(dtun_nat_next_epoch(UINT32_MAX) == 1);
  CHECK(dtun_nat_epoch_matches(9, 9));
  CHECK(!dtun_nat_epoch_matches(9, 8));
  CHECK(!dtun_nat_endpoint_changed(0x01020304, 49000, 0x01020304, 49000));
  CHECK(dtun_nat_endpoint_changed(0x01020304, 49000, 0x01020304, 49001));
  CHECK(!dtun_nat_stop_growth(1, 0));
  CHECK(dtun_nat_stop_growth(2, 0));
  CHECK(dtun_nat_stop_growth(0, 1));
  CHECK(dtun_nat_local_is_owner(2, 3));
  CHECK(!dtun_nat_local_is_owner(3, 2));
  CHECK(!dtun_nat_takeover_due(17999, 9000));
  CHECK(dtun_nat_takeover_due(18000, 9000));

  last_success = dtun_nat_trial_ms(2);
  CHECK(dtun_nat_safe_ms(last_success) == 9000);
  CHECK(dtun_nat_stop_growth(0, 1));
  CHECK(dtun_nat_shared_safe_ms(dtun_nat_safe_ms(dtun_nat_trial_ms(2)),
                                dtun_nat_safe_ms(dtun_nat_trial_ms(5))) ==
        9000);

  last_success = 0;
  for (uint32_t step = 0; dtun_nat_trial_ms(step); step++)
    last_success = dtun_nat_trial_ms(step);
  CHECK(dtun_nat_safe_ms(last_success) == 45000);

  puts("NAT calibration policy tests passed");
  return 0;
}
