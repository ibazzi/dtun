#ifndef DTUN_HA_STATE_H
#define DTUN_HA_STATE_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#define DTUN_HA_MAX_MEMBERS 16
#define DTUN_HA_MAX_INVITES 32
#define DTUN_HA_ID_LEN 64
#define DTUN_HA_CLUSTER_ID_LEN 16
#define DTUN_HA_PUBLIC_KEY_LEN 32
#define DTUN_HA_SECRET_LEN 32
#define DTUN_HA_STATE_VERSION 3U

enum dtun_ha_role { DTUN_HA_LEARNER = 0, DTUN_HA_VOTER = 1 };

typedef struct {
    char hub_id[DTUN_HA_ID_LEN];
    uint8_t public_key[DTUN_HA_PUBLIC_KEY_LEN];
    struct in_addr address;
    uint16_t ha_port;
    uint16_t control_port;
    uint16_t data_port;
    uint16_t weight;
    uint8_t role;
    uint8_t enabled;
    uint64_t endpoint_generation;
    uint64_t match_index;
} dtun_ha_member_t;

typedef struct {
    uint8_t id[16];
    uint8_t secret_hash[32];
    char hub_id[DTUN_HA_ID_LEN];
    uint16_t weight;
    time_t expires_at;
    uint8_t status; /* 0 unused, 1 claimed, 2 revoked */
    uint8_t claimed_key[DTUN_HA_PUBLIC_KEY_LEN];
} dtun_ha_invite_t;

typedef struct {
    uint8_t cluster_id[DTUN_HA_CLUSTER_ID_LEN];
    char local_hub_id[DTUN_HA_ID_LEN];
    char leader_id[DTUN_HA_ID_LEN];
    uint64_t term;
    uint64_t commit_index;
    uint32_t manifest_version;
    uint32_t member_count;
    uint32_t invite_count;
    uint32_t failback_level;
    uint64_t voted_term;
    char voted_for[DTUN_HA_ID_LEN];
    uint8_t failback_requested;
    uint8_t failback_force;
    dtun_ha_member_t members[DTUN_HA_MAX_MEMBERS];
    dtun_ha_invite_t invites[DTUN_HA_MAX_INVITES];
} dtun_ha_state_t;

int dtun_ha_validate_hub_id(const char *hub_id);
void dtun_ha_random_id(uint8_t *out, size_t len);
int dtun_ha_make_parent_dirs(const char *path, mode_t mode);
int dtun_ha_atomic_write(const char *path, const void *data, size_t len,
                         mode_t mode);
int dtun_ha_state_load(const char *path, dtun_ha_state_t *state);
int dtun_ha_state_save(const char *path, const dtun_ha_state_t *state);
int dtun_ha_state_lock(const char *path);
void dtun_ha_state_unlock(int lock_fd);
dtun_ha_member_t *dtun_ha_member_find(dtun_ha_state_t *state,
                                      const char *hub_id);
int dtun_ha_identity_generate(const char *private_path,
                              uint8_t public_key[DTUN_HA_PUBLIC_KEY_LEN]);
int dtun_ha_identity_public(const char *private_path,
                            uint8_t public_key[DTUN_HA_PUBLIC_KEY_LEN]);
int dtun_ha_invite_encode(const dtun_ha_state_t *state,
                          const dtun_ha_invite_t *invite,
                          const uint8_t secret[DTUN_HA_SECRET_LEN],
                          struct in_addr leader_addr, uint16_t leader_port,
                          const char *private_key_path,
                          char **encoded);
int dtun_ha_invite_decode(const char *encoded, dtun_ha_invite_t *invite,
                          uint8_t secret[DTUN_HA_SECRET_LEN],
                          uint8_t cluster_id[DTUN_HA_CLUSTER_ID_LEN],
                          struct in_addr *leader_addr, uint16_t *leader_port,
                          uint8_t leader_key[DTUN_HA_PUBLIC_KEY_LEN]);
void dtun_ha_hex(const uint8_t *data, size_t len, char *out);

#endif
