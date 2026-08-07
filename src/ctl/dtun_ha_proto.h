#ifndef DTUN_HA_PROTO_H
#define DTUN_HA_PROTO_H

#include "dtun_ha_state.h"

typedef struct {
    char hub_id[DTUN_HA_ID_LEN];
    uint8_t public_key[DTUN_HA_PUBLIC_KEY_LEN];
    struct in_addr observed_address;
} dtun_ha_join_peer_t;

int dtun_ha_join_client(struct in_addr leader, uint16_t port,
                        const dtun_ha_invite_t *invite,
                        const uint8_t invite_secret[DTUN_HA_SECRET_LEN],
                        const uint8_t expected_leader_key[DTUN_HA_PUBLIC_KEY_LEN],
                        const char *identity_key_path,
                        char **configuration);
int dtun_ha_join_client_fd(int fd, const dtun_ha_invite_t *invite,
                           const uint8_t invite_secret[DTUN_HA_SECRET_LEN],
                           const uint8_t expected_leader_key[DTUN_HA_PUBLIC_KEY_LEN],
                           const char *identity_key_path,
                           char **configuration);

int dtun_ha_join_server(int fd, dtun_ha_state_t *state,
                        const char *state_path, const char *identity_key_path,
                        const char *configuration,
                        dtun_ha_join_peer_t *peer);

#endif
