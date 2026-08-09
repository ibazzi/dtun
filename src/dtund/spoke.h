#ifndef DTUND_SPOKE_H
#define DTUND_SPOKE_H

#include <dtun/config.h>

#include <stdint.h>

int run_spoke(dtun_config_t *config, const uint8_t psk[32], int has_psk);

#endif /* DTUND_SPOKE_H */
