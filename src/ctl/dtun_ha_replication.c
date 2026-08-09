#include "dtun_ha_replication.h"
#include "dtun_liveness.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define REPL_REQUEST_MAGIC "DTRP"
#define REPL_REPLY_MAGIC "DTSN"
#define REPL_MAX_HUB_STATE (4U * 1024U * 1024U)

static uint64_t last_leader_contact_ms;

uint64_t dtun_ha_last_leader_contact_ms(void) {
  return __atomic_load_n(&last_leader_contact_ms, __ATOMIC_RELAXED);
}

typedef struct __attribute__((packed)) {
  char magic[4];
  char hub_id[DTUN_HA_ID_LEN];
  uint64_t known_term;
  uint64_t known_commit_index;
  uint8_t known_hub_digest[32];
  uint8_t nonce[16];
  uint8_t signature[64];
} replica_request_t;

typedef struct __attribute__((packed)) {
  char magic[4];
  uint64_t term;
  uint64_t commit_index;
  uint32_t ha_length;
  uint32_t hub_length;
  uint8_t nonce[16];
  uint8_t signature[64];
} replica_reply_t;

static int io_all(int fd, void *data, size_t len, int output) {
  uint8_t *p = data;
  size_t done = 0;
  while (done < len) {
    ssize_t n = output ? send(fd, p + done, len - done, MSG_NOSIGNAL)
                       : recv(fd, p + done, len - done, 0);
    if (n <= 0)
      return errno ? -errno : -EPIPE;
    done += (size_t)n;
  }
  return 0;
}

static int connect_timeout(int fd, const struct sockaddr *address,
                           socklen_t length, int timeout_ms) {
  int flags = fcntl(fd, F_GETFL, 0), error = 0;
  struct pollfd wait = {.fd = fd, .events = POLLOUT};
  socklen_t error_length = sizeof(error);
  int ready;
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;
  if (connect(fd, address, length) == 0)
    ready = 1;
  else if (errno == EINPROGRESS)
    ready = poll(&wait, 1, timeout_ms);
  else
    ready = -1;
  if (ready <= 0 ||
      getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) < 0 ||
      error) {
    if (!error && ready == 0)
      errno = ETIMEDOUT;
    else if (error)
      errno = error;
    return -1;
  }
  return fcntl(fd, F_SETFL, flags);
}

static int set_io_timeout(int fd, int timeout_ms) {
  struct timeval timeout = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };

  return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
                     0 ||
                 setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                            sizeof(timeout)) < 0
             ? -1
             : 0;
}

static EVP_PKEY *load_private(const char *path) {
  FILE *fp = fopen(path, "r");
  EVP_PKEY *k = fp ? PEM_read_PrivateKey(fp, NULL, NULL, NULL) : NULL;
  if (fp)
    fclose(fp);
  return k;
}

static int sign_data(const char *path, const void *data, size_t len,
                     uint8_t signature[64]) {
  EVP_PKEY *k = load_private(path);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t n = 64;
  int ok = k && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestSign(ctx, signature, &n, data, len) == 1 && n == 64;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}

static int verify_data(const uint8_t public_key[32], const void *data,
                       size_t len, const uint8_t signature[64]) {
  EVP_PKEY *k =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = k && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestVerify(ctx, signature, 64, data, len) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}

static int read_file(const char *path, uint8_t **data, uint32_t *length) {
  struct stat st;
  FILE *fp;
  if (stat(path, &st) < 0 || st.st_size < 0 ||
      (uint64_t)st.st_size > REPL_MAX_HUB_STATE)
    return -1;
  *length = (uint32_t)st.st_size;
  *data = malloc(*length ? *length : 1);
  fp = *data ? fopen(path, "rb") : NULL;
  if (!fp) {
    free(*data);
    return -1;
  }
  if (*length && fread(*data, *length, 1, fp) != 1) {
    fclose(fp);
    free(*data);
    return -1;
  }
  fclose(fp);
  return 0;
}

static void snapshot_digest(const replica_reply_t *r, const dtun_ha_state_t *s,
                            const uint8_t *hub, uint32_t hub_len,
                            uint8_t digest[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned int n = 0;
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, r, offsetof(replica_reply_t, signature));
  if (s)
    EVP_DigestUpdate(ctx, s, sizeof(*s));
  if (hub_len)
    EVP_DigestUpdate(ctx, hub, hub_len);
  EVP_DigestFinal_ex(ctx, digest, &n);
  EVP_MD_CTX_free(ctx);
}

int dtun_ha_replica_server(int fd, dtun_ha_state_t *state, const char *identity,
                           const char *hub_path, uint8_t replicated_digest[32],
                           char replicated_hub_id[DTUN_HA_ID_LEN]) {
  replica_request_t q;
  replica_reply_t r;
  dtun_ha_member_t *m;
  uint8_t *hub = NULL, digest[32];
  uint32_t hub_len = 0;
  int metadata_only;
  if (io_all(fd, &q, sizeof(q), 0) < 0 ||
      memcmp(q.magic, REPL_REQUEST_MAGIC, 4))
    return -1;
  m = dtun_ha_member_find(state, q.hub_id);
  if (!m || !m->enabled ||
      verify_data(m->public_key, &q, offsetof(replica_request_t, signature),
                  q.signature) < 0)
    return -1;
  snprintf(replicated_hub_id, DTUN_HA_ID_LEN, "%s", q.hub_id);
  if (m->role == DTUN_HA_LEARNER) {
    m->role = DTUN_HA_VOTER;
    state->manifest_version++;
    state->commit_index++;
  }
  memset(&r, 0, sizeof(r));
  memcpy(r.magic, REPL_REPLY_MAGIC, 4);
  r.term = htobe64(state->term);
  r.commit_index = htobe64(state->commit_index);
  memcpy(r.nonce, q.nonce, 16);
  if (read_file(hub_path, &hub, &hub_len) < 0)
    return -1;
  SHA256(hub, hub_len, replicated_digest);
  metadata_only = be64toh(q.known_term) == state->term &&
                  be64toh(q.known_commit_index) == state->commit_index &&
                  !memcmp(q.known_hub_digest, replicated_digest, 32);
  if (metadata_only) {
    free(hub);
    snapshot_digest(&r, NULL, NULL, 0, digest);
    if (sign_data(identity, digest, sizeof(digest), r.signature) < 0)
      return -1;
    return io_all(fd, &r, sizeof(r), 1);
  }
  r.ha_length = htonl(sizeof(*state));
  r.hub_length = htonl(hub_len);
  snapshot_digest(&r, state, hub, hub_len, digest);
  if (sign_data(identity, digest, sizeof(digest), r.signature) < 0) {
    free(hub);
    return -1;
  }
  int result = io_all(fd, &r, sizeof(r), 1) ||
                       io_all(fd, state, sizeof(*state), 1) ||
                       (hub_len && io_all(fd, hub, hub_len, 1))
                   ? -1
                   : 0;
  free(hub);
  return result;
}

int dtun_ha_replica_client(struct in_addr leader, uint16_t port,
                           dtun_ha_state_t *state, const char *identity,
                           const char *ha_path, const char *hub_path) {
  replica_request_t q;
  replica_reply_t r;
  dtun_ha_state_t incoming;
  dtun_ha_member_t *leader_member, *incoming_target;
  uint8_t *hub = NULL, digest[32];
  uint32_t ha_len, hub_len;
  int fd = -1, result = -1;
  struct sockaddr_in dst;
  char local_id[DTUN_HA_ID_LEN], target_id[DTUN_HA_ID_LEN];
  leader_member = dtun_ha_member_find(state, state->leader_id);
  if (!leader_member)
    return -1;
  snprintf(target_id, sizeof(target_id), "%s", leader_member->hub_id);
  memset(&q, 0, sizeof(q));
  memcpy(q.magic, REPL_REQUEST_MAGIC, 4);
  snprintf(q.hub_id, sizeof(q.hub_id), "%s", state->local_hub_id);
  q.known_term = htobe64(state->term);
  q.known_commit_index = htobe64(state->commit_index);
  if (hub_path) {
    uint8_t *known_hub = NULL;
    uint32_t known_hub_len = 0;

    if (read_file(hub_path, &known_hub, &known_hub_len) == 0) {
      SHA256(known_hub, known_hub_len, q.known_hub_digest);
      free(known_hub);
    } else {
      q.known_commit_index = 0;
    }
  } else {
    memcpy(q.known_hub_digest, state->committed_hub_digest, 32);
  }
  RAND_bytes(q.nonce, 16);
  if (sign_data(identity, &q, offsetof(replica_request_t, signature),
                q.signature) < 0)
    return -1;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = leader;
  dst.sin_port = htons(port);
  if (fd < 0 ||
      connect_timeout(fd, (struct sockaddr *)&dst, sizeof(dst), 400) < 0 ||
      set_io_timeout(fd, 400) < 0 || io_all(fd, &q, sizeof(q), 1) < 0 ||
      io_all(fd, &r, sizeof(r), 0) < 0 ||
      memcmp(r.magic, REPL_REPLY_MAGIC, 4) || memcmp(r.nonce, q.nonce, 16))
    goto out;
  ha_len = ntohl(r.ha_length);
  hub_len = ntohl(r.hub_length);
  if (!ha_len && !hub_len) {
    snapshot_digest(&r, NULL, NULL, 0, digest);
    if (verify_data(leader_member->public_key, digest, sizeof(digest),
                    r.signature) < 0 ||
        be64toh(r.term) < state->term ||
        be64toh(r.commit_index) < state->commit_index)
      goto out;
    __atomic_store_n(&last_leader_contact_ms, dtun_monotonic_ms(),
                     __ATOMIC_RELAXED);
    result = 0;
    goto out;
  }
  if (ha_len != sizeof(incoming) || hub_len > REPL_MAX_HUB_STATE)
    goto out;
  hub = malloc(hub_len ? hub_len : 1);
  if (!hub || io_all(fd, &incoming, sizeof(incoming), 0) < 0 ||
      (hub_len && io_all(fd, hub, hub_len, 0) < 0))
    goto out;
  snapshot_digest(&r, &incoming, hub, hub_len, digest);
  if (verify_data(leader_member->public_key, digest, sizeof(digest),
                  r.signature) < 0 ||
      be64toh(r.term) < state->term)
    goto out;
  snprintf(local_id, sizeof(local_id), "%s", state->local_hub_id);
  incoming.term = be64toh(r.term);
  incoming.commit_index = be64toh(r.commit_index);
  if (strcmp(incoming.leader_id, target_id))
    goto out;
  snprintf(incoming.local_hub_id, sizeof(incoming.local_hub_id), "%s",
           local_id);
  /* The endpoint that carried this authenticated exchange is known to be
   * reachable from this Hub.  Preserve it instead of replacing a working
   * NAT bootstrap path with the leader's possibly private local_outer_ip. */
  incoming_target = dtun_ha_member_find(&incoming, target_id);
  if (incoming_target && incoming_target->address.s_addr != leader.s_addr) {
    incoming_target->address = leader;
    incoming_target->ha_port = port;
    incoming_target->endpoint_generation++;
  }
  if ((hub_path && dtun_ha_atomic_write(hub_path, hub, hub_len, 0640) < 0) ||
      dtun_ha_state_save(ha_path, &incoming) < 0)
    goto out;
  *state = incoming;
  __atomic_store_n(&last_leader_contact_ms, dtun_monotonic_ms(),
                   __ATOMIC_RELAXED);
  result = 0;
out:
  if (fd >= 0)
    close(fd);
  free(hub);
  return result;
}
