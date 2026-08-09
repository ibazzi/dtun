#ifndef DTUND_HUB_H
#define DTUND_HUB_H

#include <dtun/config.h>

#include <stdint.h>

int run_hub(dtun_config_t *config, const uint8_t psk[32], int has_psk);

#endif /* DTUND_HUB_H */
