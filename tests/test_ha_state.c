#include <dtun/ha_state.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "test_ha_state:%d: %s\n", __LINE__, #x);                 \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  char dir[] = "/tmp/dtun-ha-test-XXXXXX", key[256], state_path[256];
  uint8_t public_key[32], secret[32], decoded_secret[32], cluster[16],
      leader_key[32];
  dtun_ha_state_t state, loaded;
  dtun_ha_invite_t invite, decoded;
  struct in_addr addr, decoded_addr;
  uint16_t port;
  char *token = NULL;
  CHECK(mkdtemp(dir) != NULL);
  snprintf(key, sizeof(key), "%s/identity.key", dir);
  snprintf(state_path, sizeof(state_path), "%s/state", dir);
  CHECK(dtun_ha_identity_generate(key, public_key) == 0);
  memset(&state, 0, sizeof(state));
  dtun_ha_random_id(state.cluster_id, 16);
  strcpy(state.local_hub_id, "hub-primary");
  strcpy(state.leader_id, "hub-primary");
  state.term = 1;
  state.commit_index = 1;
  state.member_count = 1;
  strcpy(state.members[0].hub_id, "hub-primary");
  memcpy(state.members[0].public_key, public_key, 32);
  state.members[0].weight = 1000;
  state.members[0].role = DTUN_HA_VOTER;
  state.members[0].enabled = 1;
  CHECK(dtun_ha_state_save(state_path, &state) == 0);
  CHECK(dtun_ha_state_load(state_path, &loaded) == 0 && loaded.term == 1 &&
        !strcmp(loaded.leader_id, "hub-primary"));
  memset(&invite, 0, sizeof(invite));
  dtun_ha_random_id(invite.id, 16);
  dtun_ha_random_id(secret, 32);
  strcpy(invite.hub_id, "hub-backup-1");
  invite.weight = 900;
  invite.expires_at = 2000000000;
  CHECK(inet_pton(AF_INET, "192.0.2.1", &addr) == 1);
  CHECK(dtun_ha_invite_encode(&state, &invite, secret, addr, 49001, key,
                              &token) == 0);
  CHECK(dtun_ha_invite_decode(token, &decoded, decoded_secret, cluster,
                              &decoded_addr, &port, leader_key) == 0);
  CHECK(!strcmp(decoded.hub_id, "hub-backup-1") && decoded.weight == 900 &&
        port == 49001 && !strncmp(token, "dtun-ha1:", 9));
  CHECK(decoded_addr.s_addr == addr.s_addr &&
        !memcmp(secret, decoded_secret, 32) &&
        !memcmp(cluster, state.cluster_id, 16));
  token[20] ^= 1;
  CHECK(dtun_ha_invite_decode(token, &decoded, decoded_secret, cluster,
                              &decoded_addr, &port, leader_key) < 0);
  free(token);
  {
    FILE *legacy = fopen(state_path, "wb");
    uint32_t version = DTUN_HA_STATE_VERSION - 1;

    CHECK(legacy != NULL);
    CHECK(fwrite("DTHS", 4, 1, legacy) == 1);
    CHECK(fwrite(&version, sizeof(version), 1, legacy) == 1);
    CHECK(fclose(legacy) == 0);
    CHECK(dtun_ha_state_load(state_path, &loaded) == -EPROTONOSUPPORT);
  }
  unlink(state_path);
  unlink(key);
  rmdir(dir);
  puts("HA state/identity/invite tests passed");
  return 0;
}
