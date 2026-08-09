#include <dtun/ha_election.h>
#include <dtun/ha_replication.h>
#include <dtun/liveness.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VOTE_MAGIC "DTVQ"
#define VOTE_REPLY_MAGIC "DTVR"
#define LEADER_MAGIC "DTHL"
#define ELECTION_LEADER_GRACE_MS 800U
#define ELECTION_PRIORITY_GRACE_MS 1400U

typedef struct __attribute__((packed)) {
  char magic[4];
  char candidate_id[DTUN_HA_ID_LEN];
  uint64_t term;
  uint64_t commit_index;
  uint16_t weight;
  uint8_t nonce[16];
  uint8_t signature[64];
} vote_request_t;

typedef struct __attribute__((packed)) {
  char magic[4];
  char voter_id[DTUN_HA_ID_LEN];
  uint64_t term;
  uint8_t granted;
  uint8_t nonce[16];
  uint8_t signature[64];
} vote_reply_t;

typedef struct __attribute__((packed)) {
  char magic[4];
  char leader_id[DTUN_HA_ID_LEN];
  uint64_t term;
  uint64_t commit_index;
  uint8_t signature[64];
} leader_announce_t;

static int io_all(int fd, void *data, size_t len, int output) {
  uint8_t *p = data;
  size_t done = 0;
  while (done < len) {
    ssize_t n = output ? send(fd, p + done, len - done, MSG_NOSIGNAL)
                       : recv(fd, p + done, len - done, 0);
    if (n <= 0)
      return -1;
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
static EVP_PKEY *load_private(const char *p) {
  FILE *f = fopen(p, "r");
  EVP_PKEY *k = f ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
  if (f)
    fclose(f);
  return k;
}
static int sign_data(const char *p, const void *d, size_t n, uint8_t s[64]) {
  EVP_PKEY *k = load_private(p);
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  size_t z = 64;
  int ok = k && c && EVP_DigestSignInit(c, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestSign(c, s, &z, d, n) == 1 && z == 64;
  EVP_MD_CTX_free(c);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}
static int verify_data(const uint8_t p[32], const void *d, size_t n,
                       const uint8_t s[64]) {
  EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, p, 32);
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  int ok = k && c && EVP_DigestVerifyInit(c, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestVerify(c, s, 64, d, n) == 1;
  EVP_MD_CTX_free(c);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}

static int member_precedes(const dtun_ha_member_t *left,
                           const dtun_ha_member_t *right) {
  return left->weight > right->weight ||
         (left->weight == right->weight &&
          strcmp(left->hub_id, right->hub_id) < 0);
}

int dtun_ha_vote_server(int fd, dtun_ha_state_t *state, const char *state_path,
                        const char *identity) {
  vote_request_t q;
  vote_reply_t r;
  dtun_ha_member_t *candidate, *local;
  uint64_t last_contact;
  uint64_t contact_age;
  uint64_t term;
  if (io_all(fd, &q, sizeof(q), 0) < 0 || memcmp(q.magic, VOTE_MAGIC, 4))
    return -1;
  candidate = dtun_ha_member_find(state, q.candidate_id);
  local = dtun_ha_member_find(state, state->local_hub_id);
  term = be64toh(q.term);
  if (!candidate || !local || !candidate->enabled ||
      candidate->role != DTUN_HA_VOTER ||
      ntohs(q.weight) != candidate->weight ||
      verify_data(candidate->public_key, &q,
                  offsetof(vote_request_t, signature), q.signature) < 0)
    return -1;
  memset(&r, 0, sizeof(r));
  memcpy(r.magic, VOTE_REPLY_MAGIC, 4);
  snprintf(r.voter_id, sizeof(r.voter_id), "%s", state->local_hub_id);
  r.term = htobe64(state->term);
  memcpy(r.nonce, q.nonce, 16);
  last_contact = dtun_ha_last_leader_contact_ms();
  contact_age = last_contact ? dtun_monotonic_ms() - last_contact : UINT64_MAX;
  if (term >= state->term && be64toh(q.commit_index) >= state->commit_index &&
      (!strcmp(state->leader_id, q.candidate_id) || !last_contact ||
       contact_age >= ELECTION_LEADER_GRACE_MS) &&
      (!member_precedes(local, candidate) ||
       contact_age >= ELECTION_PRIORITY_GRACE_MS) &&
      (state->voted_term < term ||
       (state->voted_term == term &&
        !strcmp(state->voted_for, q.candidate_id)))) {
    state->term = term;
    state->voted_term = term;
    snprintf(state->voted_for, sizeof(state->voted_for), "%s", q.candidate_id);
    r.term = htobe64(term);
    r.granted = 1;
    if (dtun_ha_state_save(state_path, state) < 0)
      return -1;
  }
  if (sign_data(identity, &r, offsetof(vote_reply_t, signature), r.signature) <
      0)
    return -1;
  return io_all(fd, &r, sizeof(r), 1);
}

int dtun_ha_request_vote(struct in_addr address, uint16_t port,
                         const dtun_ha_state_t *state,
                         const dtun_ha_member_t *peer, uint64_t term,
                         const char *identity) {
  int fd = -1, result = 0;
  struct sockaddr_in dst;
  vote_request_t q;
  vote_reply_t r;
  memset(&q, 0, sizeof(q));
  memcpy(q.magic, VOTE_MAGIC, 4);
  snprintf(q.candidate_id, sizeof(q.candidate_id), "%s", state->local_hub_id);
  q.term = htobe64(term);
  q.commit_index = htobe64(state->commit_index);
  dtun_ha_member_t *local = NULL;
  for (uint32_t i = 0; i < state->member_count; i++)
    if (!strcmp(state->members[i].hub_id, state->local_hub_id)) {
      local = (dtun_ha_member_t *)&state->members[i];
      break;
    }
  if (!local)
    return 0;
  q.weight = htons(local->weight);
  RAND_bytes(q.nonce, 16);
  if (sign_data(identity, &q, offsetof(vote_request_t, signature),
                q.signature) < 0)
    return 0;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = address;
  dst.sin_port = htons(port);
  if (fd >= 0 &&
      connect_timeout(fd, (struct sockaddr *)&dst, sizeof(dst), 400) == 0 &&
      set_io_timeout(fd, 400) == 0 && io_all(fd, &q, sizeof(q), 1) == 0 &&
      io_all(fd, &r, sizeof(r), 0) == 0 &&
      !memcmp(r.magic, VOTE_REPLY_MAGIC, 4) && !memcmp(r.nonce, q.nonce, 16) &&
      verify_data(peer->public_key, &r, offsetof(vote_reply_t, signature),
                  r.signature) == 0 &&
      r.granted && be64toh(r.term) == term)
    result = 1;
  if (fd >= 0)
    close(fd);
  return result;
}

int dtun_ha_leader_server(int fd, dtun_ha_state_t *state,
                          const char *state_path) {
  leader_announce_t a;
  dtun_ha_member_t *leader;
  uint64_t term;
  if (io_all(fd, &a, sizeof(a), 0) < 0 || memcmp(a.magic, LEADER_MAGIC, 4))
    return -1;
  leader = dtun_ha_member_find(state, a.leader_id);
  term = be64toh(a.term);
  if (!leader || !leader->enabled || leader->role != DTUN_HA_VOTER ||
      term < state->term || be64toh(a.commit_index) < state->commit_index ||
      verify_data(leader->public_key, &a,
                  offsetof(leader_announce_t, signature), a.signature) < 0)
    return -1;
  state->term = term;
  state->commit_index = be64toh(a.commit_index);
  snprintf(state->leader_id, sizeof(state->leader_id), "%s", a.leader_id);
  return dtun_ha_state_save(state_path, state);
}

int dtun_ha_announce_leader(struct in_addr address, uint16_t port,
                            const dtun_ha_state_t *state,
                            const dtun_ha_member_t *peer,
                            const char *identity) {
  leader_announce_t a;
  struct sockaddr_in dst;
  int fd, result = -1;
  (void)peer;
  memset(&a, 0, sizeof(a));
  memcpy(a.magic, LEADER_MAGIC, 4);
  snprintf(a.leader_id, sizeof(a.leader_id), "%s", state->local_hub_id);
  a.term = htobe64(state->term);
  a.commit_index = htobe64(state->commit_index);
  if (sign_data(identity, &a, offsetof(leader_announce_t, signature),
                a.signature) < 0)
    return -1;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = address;
  dst.sin_port = htons(port);
  if (fd >= 0 &&
      connect_timeout(fd, (struct sockaddr *)&dst, sizeof(dst), 400) == 0 &&
      set_io_timeout(fd, 400) == 0 && io_all(fd, &a, sizeof(a), 1) == 0)
    result = 0;
  if (fd >= 0)
    close(fd);
  return result;
}
