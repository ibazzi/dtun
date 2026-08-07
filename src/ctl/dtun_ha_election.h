#ifndef DTUN_HA_ELECTION_H
#define DTUN_HA_ELECTION_H

#include "dtun_ha_state.h"

int dtun_ha_vote_server(int fd, dtun_ha_state_t *state, const char *state_path,
                        const char *identity_key_path);
int dtun_ha_request_vote(struct in_addr address, uint16_t port,
                         const dtun_ha_state_t *state,
                         const dtun_ha_member_t *peer, uint64_t term,
                         const char *identity_key_path);
int dtun_ha_leader_server(int fd, dtun_ha_state_t *state,
                          const char *state_path);
int dtun_ha_announce_leader(struct in_addr address, uint16_t port,
                            const dtun_ha_state_t *state,
                            const dtun_ha_member_t *peer,
                            const char *identity_key_path);

#endif
