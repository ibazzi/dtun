#ifndef DTUN_HA_REPLICATION_H
#define DTUN_HA_REPLICATION_H

#include <dtun/ha_state.h>

int dtun_ha_replica_server(int fd, dtun_ha_state_t *state,
                           const char *identity_key_path,
                           const char *hub_state_path,
                           uint8_t replicated_digest[32],
                           char replicated_hub_id[DTUN_HA_ID_LEN]);
int dtun_ha_replica_client(struct in_addr leader, uint16_t port,
                           dtun_ha_state_t *state,
                           const char *identity_key_path,
                           const char *ha_state_path,
                           const char *hub_state_path);
uint64_t dtun_ha_last_leader_contact_ms(void);

#endif
