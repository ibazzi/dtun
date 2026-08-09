#include <dtun/ha_proto.h>

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "test_ha_join:%d: %s\n", __LINE__, #x);                  \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int admin_roundtrip(dtun_ha_state_t *state, const char *state_path,
                           const char *server_key, uint8_t action,
                           const char *target) {
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t length = sizeof(address);
  dtun_ha_admin_reply_t reply;
  int listener = socket(AF_INET, SOCK_STREAM, 0), status;
  pid_t child;

  if (listener < 0 ||
      bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
      listen(listener, 1) < 0 ||
      getsockname(listener, (struct sockaddr *)&address, &length) < 0)
    return -1;
  state->members[0].address = address.sin_addr;
  state->members[0].ha_port = ntohs(address.sin_port);
  if (dtun_ha_state_save(state_path, state) < 0) {
    close(listener);
    return -1;
  }
  child = fork();
  if (child < 0) {
    close(listener);
    return -1;
  }
  if (!child) {
    dtun_ha_state_t current;
    int fd = accept(listener, NULL, NULL);
    int result =
        fd < 0 || dtun_ha_state_load(state_path, &current) < 0
            ? -1
            : dtun_ha_admin_server(fd, &current, state_path, server_key);
    if (fd >= 0)
      close(fd);
    close(listener);
    _exit(result ? 1 : 0);
  }
  close(listener);
  int result =
      dtun_ha_admin_client(address.sin_addr, ntohs(address.sin_port), state,
                           server_key, action, target, 0, &reply);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status))
    return -1;
  if (result < 0)
    return result;
  return dtun_ha_state_load(state_path, state);
}

int main(void) {
  char dir[] = "/tmp/dtun-ha-join-XXXXXX", server_key[256], client_key[256],
       state_path[256];
  dtun_ha_state_t state, loaded;
  dtun_ha_invite_t *invite;
  uint8_t server_pub[32], client_pub[32], secret[32];
  int sockets[2];
  pid_t child;
  char *configuration = NULL;
  CHECK(mkdtemp(dir));
  snprintf(server_key, sizeof(server_key), "%s/server.key", dir);
  snprintf(client_key, sizeof(client_key), "%s/client.key", dir);
  snprintf(state_path, sizeof(state_path), "%s/state", dir);
  CHECK(dtun_ha_identity_generate(server_key, server_pub) == 0);
  CHECK(dtun_ha_identity_generate(client_key, client_pub) == 0);
  memset(&state, 0, sizeof(state));
  dtun_ha_random_id(state.cluster_id, 16);
  strcpy(state.local_hub_id, "primary");
  strcpy(state.primary_hub_id, "primary");
  strcpy(state.leader_id, "primary");
  state.term = 1;
  state.member_count = 1;
  state.invite_count = 1;
  strcpy(state.members[0].hub_id, "primary");
  memcpy(state.members[0].public_key, server_pub, 32);
  state.members[0].enabled = 1;
  state.members[0].role = DTUN_HA_VOTER;
  invite = &state.invites[0];
  dtun_ha_random_id(invite->id, 16);
  dtun_ha_random_id(secret, 32);
  SHA256(secret, 32, invite->secret_hash);
  strcpy(invite->hub_id, "backup");
  invite->weight = 900;
  invite->expires_at = time(NULL) + 60;
  CHECK(dtun_ha_state_save(state_path, &state) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    close(sockets[0]);
    dtun_ha_join_peer_t peer;
    int rc = dtun_ha_join_server(sockets[1], &state, state_path, server_key,
                                 "[cluster]\npool = 10.99.0.0/24\n", &peer);
    close(sockets[1]);
    _exit(rc ? -rc : 0);
  }
  close(sockets[1]);
  int join_result = dtun_ha_join_client_fd(
      sockets[0], invite, secret, server_pub, client_key, &configuration);
  close(sockets[0]);
  int status;
  CHECK(waitpid(child, &status, 0) == child);
  if (join_result == -EPERM) {
    unlink(state_path);
    unlink(server_key);
    unlink(client_key);
    rmdir(dir);
    puts("HA online-join socket test skipped by sandbox");
    return 0;
  }
  if (join_result)
    fprintf(stderr, "join result=%d child_status=%d signal=%d\n", join_result,
            WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  CHECK(join_result == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(configuration && strstr(configuration, "10.99.0.0/24"));
  free(configuration);
  CHECK(dtun_ha_state_load(state_path, &loaded) == 0 &&
        loaded.invites[0].status == 1 &&
        !memcmp(loaded.invites[0].claimed_key, client_pub, 32));
  loaded.member_count = 2;
  strcpy(loaded.members[1].hub_id, "backup");
  memcpy(loaded.members[1].public_key, client_pub, 32);
  loaded.members[1].enabled = 1;
  loaded.members[1].role = DTUN_HA_VOTER;
  loaded.members[1].lifecycle = DTUN_HA_MEMBER_ACTIVE;
  CHECK(admin_roundtrip(&loaded, state_path, server_key, DTUN_HA_ADMIN_DISABLE,
                        "backup") == 0);
  CHECK(loaded.members[1].lifecycle == DTUN_HA_MEMBER_DISABLED &&
        !loaded.members[1].enabled);
  CHECK(admin_roundtrip(&loaded, state_path, server_key, DTUN_HA_ADMIN_ENABLE,
                        "backup") == 0);
  CHECK(loaded.members[1].lifecycle == DTUN_HA_MEMBER_ACTIVE &&
        loaded.members[1].enabled && loaded.members[1].role == DTUN_HA_LEARNER);
  CHECK(admin_roundtrip(&loaded, state_path, server_key, DTUN_HA_ADMIN_KICK,
                        "backup") == 0);
  CHECK(loaded.members[1].lifecycle == DTUN_HA_MEMBER_EVICTED &&
        !loaded.members[1].enabled);
  unlink(state_path);
  unlink(server_key);
  unlink(client_key);
  rmdir(dir);
  puts("HA encrypted online-join tests passed");
  return 0;
}
