#include "dtun_ha_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HA_JOIN_MAGIC "DTJ1"
#define HA_JOIN_MAX_CONFIG 8192
#define HA_ADMIN_MAGIC "DTHA"

typedef struct __attribute__((packed)) {
  char magic[4];
  uint8_t action;
  uint8_t force;
  uint8_t cluster_id[DTUN_HA_CLUSTER_ID_LEN];
  char signer[DTUN_HA_ID_LEN];
  char target[DTUN_HA_ID_LEN];
  uint8_t nonce[16];
  uint8_t signature[64];
} admin_request_t;

typedef struct __attribute__((packed)) {
  char magic[4];
  uint8_t status;
  uint64_t term;
  uint64_t commit_index;
  uint8_t nonce[16];
  uint8_t signature[64];
} admin_reply_t;

static uint8_t admin_nonces[64][16];
static uint32_t admin_nonce_cursor;

static int admin_nonce_new(const uint8_t nonce[16]) {
  for (size_t i = 0; i < sizeof(admin_nonces) / sizeof(admin_nonces[0]); i++)
    if (!memcmp(admin_nonces[i], nonce, 16))
      return 0;
  memcpy(admin_nonces[admin_nonce_cursor++ % 64], nonce, 16);
  return 1;
}

typedef struct __attribute__((packed)) {
  char magic[4];
  uint8_t invite_id[16];
  uint8_t client_x25519[32];
  uint8_t client_nonce[16];
  uint8_t client_ed25519[32];
  uint8_t proof[32];
} join_hello_t;

typedef struct __attribute__((packed)) {
  char magic[4];
  uint8_t status;
  uint8_t server_x25519[32];
  uint8_t server_nonce[16];
  uint8_t signature[64];
  uint32_t ciphertext_len;
  uint8_t iv[12];
  uint8_t tag[16];
} join_reply_t;

static int io_all(int fd, void *data, size_t len, int send_data) {
  uint8_t *p = data;
  size_t done = 0;
  while (done < len) {
    ssize_t n = send_data ? send(fd, p + done, len - done, MSG_NOSIGNAL)
                          : recv(fd, p + done, len - done, 0);
    if (n <= 0)
      return errno ? -errno : -EPIPE;
    done += (size_t)n;
  }
  return 0;
}

static EVP_PKEY *load_private(const char *path) {
  FILE *fp = fopen(path, "r");
  EVP_PKEY *k = fp ? PEM_read_PrivateKey(fp, NULL, NULL, NULL) : NULL;
  if (fp)
    fclose(fp);
  return k;
}

static EVP_PKEY *x25519_generate(uint8_t public_key[32]) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *key = NULL;
  size_t len = 32;
  if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
      EVP_PKEY_keygen(ctx, &key) != 1 ||
      EVP_PKEY_get_raw_public_key(key, public_key, &len) != 1 || len != 32) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  EVP_PKEY_CTX_free(ctx);
  return key;
}

static int derive_key(EVP_PKEY *local, const uint8_t remote_raw[32],
                      const uint8_t psk[32], const uint8_t cn[16],
                      const uint8_t sn[16], uint8_t out[32]) {
  EVP_PKEY *remote =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, remote_raw, 32);
  EVP_PKEY_CTX *dctx = NULL, *kctx = NULL;
  uint8_t shared[32], info[32];
  size_t shared_len = 32, out_len = 32;
  int ok = 0;
  if (!remote || (dctx = EVP_PKEY_CTX_new(local, NULL)) == NULL ||
      EVP_PKEY_derive_init(dctx) != 1 ||
      EVP_PKEY_derive_set_peer(dctx, remote) != 1 ||
      EVP_PKEY_derive(dctx, shared, &shared_len) != 1)
    goto out;
  memcpy(info, cn, 16);
  memcpy(info + 16, sn, 16);
  kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (!kctx || EVP_PKEY_derive_init(kctx) != 1 ||
      EVP_PKEY_CTX_hkdf_mode(kctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) !=
          1 ||
      EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_salt(kctx, psk, 32) != 1 ||
      EVP_PKEY_CTX_set1_hkdf_key(kctx, shared, shared_len) != 1 ||
      EVP_PKEY_CTX_add1_hkdf_info(kctx, info, sizeof(info)) != 1 ||
      EVP_PKEY_derive(kctx, out, &out_len) != 1 || out_len != 32)
    goto out;
  ok = 1;
out:
  OPENSSL_cleanse(shared, sizeof(shared));
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_CTX_free(dctx);
  EVP_PKEY_free(remote);
  return ok ? 0 : -1;
}

static void hello_proof(join_hello_t *h, const uint8_t psk[32]) {
  unsigned int len = 0;
  HMAC(EVP_sha256(), psk, 32, (uint8_t *)h, offsetof(join_hello_t, proof),
       h->proof, &len);
}

static int sign_reply(const char *path, const join_hello_t *h,
                      join_reply_t *r) {
  EVP_PKEY *k = load_private(path);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  uint8_t transcript[sizeof(*h) + 4 + 1 + 32 + 16];
  size_t len = 64;
  memcpy(transcript, h, sizeof(*h));
  memcpy(transcript + sizeof(*h), r, 4 + 1 + 32 + 16);
  int ok = k && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestSign(ctx, r->signature, &len, transcript,
                          sizeof(transcript)) == 1 &&
           len == 64;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}

static int verify_reply(const uint8_t key_raw[32], const join_hello_t *h,
                        const join_reply_t *r) {
  EVP_PKEY *k =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_raw, 32);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  uint8_t transcript[sizeof(*h) + 4 + 1 + 32 + 16];
  memcpy(transcript, h, sizeof(*h));
  memcpy(transcript + sizeof(*h), r, 4 + 1 + 32 + 16);
  int ok = k && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, k) == 1 &&
           EVP_DigestVerify(ctx, r->signature, 64, transcript,
                            sizeof(transcript)) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(k);
  return ok ? 0 : -1;
}

static int crypt_config(int encrypt, const uint8_t key[32],
                        const uint8_t iv[12], const uint8_t *input, size_t len,
                        uint8_t *output, uint8_t tag[16]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int n = 0, total = 0, ok = 0;
  if (!ctx)
    return -1;
  if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, encrypt) !=
          1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
      EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt) != 1)
    goto out;
  if (!encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
    goto out;
  if (EVP_CipherUpdate(ctx, output, &n, input, (int)len) != 1)
    goto out;
  total = n;
  if (EVP_CipherFinal_ex(ctx, output + total, &n) != 1)
    goto out;
  total += n;
  if (encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    goto out;
  ok = total == (int)len;
out:
  EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}

int dtun_ha_join_client_fd(int fd, const dtun_ha_invite_t *invite,
                           const uint8_t secret[32],
                           const uint8_t leader_key[32], const char *identity,
                           char **configuration) {
  int result = -1;
  join_hello_t h;
  join_reply_t r;
  EVP_PKEY *xkey = NULL;
  uint8_t psk[32], session[32], *cipher = NULL, *plain = NULL;
  uint32_t cipher_len;
  memset(&h, 0, sizeof(h));
  memcpy(h.magic, HA_JOIN_MAGIC, 4);
  memcpy(h.invite_id, invite->id, 16);
  RAND_bytes(h.client_nonce, 16);
  SHA256(secret, 32, psk);
  if (dtun_ha_identity_public(identity, h.client_ed25519) < 0 ||
      (xkey = x25519_generate(h.client_x25519)) == NULL)
    goto out;
  hello_proof(&h, psk);
  result = io_all(fd, &h, sizeof(h), 1);
  if (result < 0)
    goto out;
  result = -21;
  if (io_all(fd, &r, sizeof(r), 0) < 0)
    goto out;
  result = -3;
  if (memcmp(r.magic, HA_JOIN_MAGIC, 4) || r.status)
    goto out;
  result = -4;
  if (verify_reply(leader_key, &h, &r) < 0)
    goto out;
  result = -5;
  if (derive_key(xkey, r.server_x25519, psk, h.client_nonce, r.server_nonce,
                 session) < 0)
    goto out;
  cipher_len = ntohl(r.ciphertext_len);
  result = -6;
  if (!cipher_len || cipher_len > HA_JOIN_MAX_CONFIG)
    goto out;
  cipher = malloc(cipher_len);
  plain = calloc(1, cipher_len + 1);
  result = -7;
  if (!cipher || !plain || io_all(fd, cipher, cipher_len, 0) < 0)
    goto out;
  result = -8;
  if (crypt_config(0, session, r.iv, cipher, cipher_len, plain, r.tag) < 0)
    goto out;
  *configuration = (char *)plain;
  plain = NULL;
  result = 0;
out:
  EVP_PKEY_free(xkey);
  OPENSSL_cleanse(psk, sizeof(psk));
  OPENSSL_cleanse(session, sizeof(session));
  free(cipher);
  free(plain);
  return result;
}

int dtun_ha_join_client(struct in_addr leader, uint16_t port,
                        const dtun_ha_invite_t *invite,
                        const uint8_t secret[32], const uint8_t leader_key[32],
                        const char *identity, char **configuration) {
  int fd, result;
  struct sockaddr_in dst;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = leader;
  dst.sin_port = htons(port);
  if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    close(fd);
    return -1;
  }
  result = dtun_ha_join_client_fd(fd, invite, secret, leader_key, identity,
                                  configuration);
  close(fd);
  return result;
}

int dtun_ha_join_server(int fd, dtun_ha_state_t *state, const char *state_path,
                        const char *identity, const char *configuration,
                        dtun_ha_join_peer_t *peer) {
  join_hello_t h;
  join_reply_t r;
  dtun_ha_invite_t *invite = NULL;
  EVP_PKEY *xkey = NULL;
  uint8_t expected[32], session[32], *cipher = NULL;
  struct sockaddr_in source;
  socklen_t slen = sizeof(source);
  int result = -1;
  memset(&r, 0, sizeof(r));
  memcpy(r.magic, HA_JOIN_MAGIC, 4);
  if (io_all(fd, &h, sizeof(h), 0) < 0)
    return -9;
  if (memcmp(h.magic, HA_JOIN_MAGIC, 4))
    return -10;
  for (uint32_t i = 0; i < state->invite_count; i++)
    if (!memcmp(state->invites[i].id, h.invite_id, 16)) {
      invite = &state->invites[i];
      break;
    }
  if (!invite || invite->status == 2 ||
      (invite->status == 1 &&
       CRYPTO_memcmp(invite->claimed_key, h.client_ed25519, 32)) ||
      (invite->status == 0 && invite->expires_at < time(NULL))) {
    r.status = 1;
    io_all(fd, &r, sizeof(r), 1);
    return -11;
  }
  memcpy(expected, h.proof, 32);
  hello_proof(&h, invite->secret_hash);
  if (CRYPTO_memcmp(expected, h.proof, 32)) {
    r.status = 2;
    io_all(fd, &r, sizeof(r), 1);
    return -12;
  }
  memcpy(peer->public_key, h.client_ed25519, 32);
  snprintf(peer->hub_id, sizeof(peer->hub_id), "%s", invite->hub_id);
  if (getpeername(fd, (struct sockaddr *)&source, &slen) == 0)
    peer->observed_address = source.sin_addr;
  RAND_bytes(r.server_nonce, 16);
  RAND_bytes(r.iv, 12);
  xkey = x25519_generate(r.server_x25519);
  if (!xkey) {
    r.status = 3;
    io_all(fd, &r, sizeof(r), 1);
    result = -13;
    goto out;
  }
  if (sign_reply(identity, &h, &r) < 0) {
    r.status = 4;
    io_all(fd, &r, sizeof(r), 1);
    result = -14;
    goto out;
  }
  if (derive_key(xkey, h.client_x25519, invite->secret_hash, h.client_nonce,
                 r.server_nonce, session) < 0) {
    r.status = 5;
    io_all(fd, &r, sizeof(r), 1);
    result = -15;
    goto out;
  }
  size_t len = strlen(configuration);
  cipher = malloc(len);
  if (!cipher || crypt_config(1, session, r.iv, (const uint8_t *)configuration,
                              len, cipher, r.tag) < 0) {
    result = -16;
    goto out;
  }
  r.ciphertext_len = htonl((uint32_t)len);
  if (invite->status == 0) {
    invite->status = 1;
    memcpy(invite->claimed_key, h.client_ed25519, 32);
    state->commit_index++;
  }
  if (dtun_ha_state_save(state_path, state) < 0) {
    result = -17;
    goto out;
  }
  if (io_all(fd, &r, sizeof(r), 1) < 0 || io_all(fd, cipher, len, 1) < 0) {
    result = -18;
    goto out;
  }
  result = 0;
out:
  EVP_PKEY_free(xkey);
  OPENSSL_cleanse(session, sizeof(session));
  free(cipher);
  return result;
}

static int sign_admin(const char *path, void *message, size_t signed_length,
                      uint8_t signature[64]) {
  EVP_PKEY *key = load_private(path);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t length = 64;
  int ok =
      key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
      EVP_DigestSign(ctx, signature, &length, message, signed_length) == 1 &&
      length == 64;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : -1;
}

static int verify_admin(const uint8_t public_key[32], const void *message,
                        size_t signed_length, const uint8_t signature[64]) {
  EVP_PKEY *key =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = key && ctx &&
           EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestVerify(ctx, signature, 64, message, signed_length) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : -1;
}

static int admin_connect(struct in_addr address, uint16_t port) {
  struct sockaddr_in target = {
      .sin_family = AF_INET, .sin_addr = address, .sin_port = htons(port)};
  struct pollfd wait;
  socklen_t length;
  int fd, flags, error = 0, ready;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    goto fail;
  ready = connect(fd, (struct sockaddr *)&target, sizeof(target));
  if (ready < 0 && errno == EINPROGRESS) {
    wait.fd = fd;
    wait.events = POLLOUT;
    ready = poll(&wait, 1, 500);
  } else if (!ready)
    ready = 1;
  length = sizeof(error);
  if (ready <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 ||
      error || fcntl(fd, F_SETFL, flags) < 0)
    goto fail;
  return fd;
fail:
  close(fd);
  return -1;
}

int dtun_ha_admin_client(struct in_addr address, uint16_t port,
                         const dtun_ha_state_t *state,
                         const char *identity_key_path, uint8_t action,
                         const char *target_hub_id, int force,
                         dtun_ha_admin_reply_t *reply) {
  admin_request_t request;
  admin_reply_t response;
  dtun_ha_member_t *server;
  dtun_ha_state_t copy = *state;
  int fd, result = -1;

  dtun_ha_member_t *target = dtun_ha_member_find(&copy, target_hub_id);
  if (action == DTUN_HA_ADMIN_STATUS ||
      (target && target->address.s_addr == address.s_addr &&
       target->ha_port == port))
    server = dtun_ha_member_find(&copy, target_hub_id);
  else
    server = dtun_ha_member_find(&copy, copy.leader_id);
  if (!server)
    return -1;
  memset(&request, 0, sizeof(request));
  memcpy(request.magic, HA_ADMIN_MAGIC, 4);
  request.action = action;
  request.force = force != 0;
  memcpy(request.cluster_id, state->cluster_id, sizeof(request.cluster_id));
  snprintf(request.signer, sizeof(request.signer), "%s", state->local_hub_id);
  snprintf(request.target, sizeof(request.target), "%s", target_hub_id);
  RAND_bytes(request.nonce, sizeof(request.nonce));
  if (sign_admin(identity_key_path, &request,
                 offsetof(admin_request_t, signature), request.signature) < 0)
    return -1;
  fd = admin_connect(address, port);
  if (fd < 0)
    return -1;
  if (io_all(fd, &request, sizeof(request), 1) < 0 ||
      io_all(fd, &response, sizeof(response), 0) < 0 ||
      memcmp(response.magic, HA_ADMIN_MAGIC, 4) ||
      memcmp(response.nonce, request.nonce, sizeof(request.nonce)) ||
      verify_admin(server->public_key, &response,
                   offsetof(admin_reply_t, signature), response.signature) < 0)
    goto out;
  if (reply) {
    reply->status = response.status;
    reply->term = be64toh(response.term);
    reply->commit_index = be64toh(response.commit_index);
  }
  result = response.status ? -response.status : 0;
out:
  close(fd);
  return result;
}

int dtun_ha_admin_server(int fd, dtun_ha_state_t *state, const char *state_path,
                         const char *identity_key_path) {
  admin_request_t request;
  admin_reply_t response;
  dtun_ha_member_t *signer, *target;
  int authorized = 0, changed = 0;

  memset(&response, 0, sizeof(response));
  memcpy(response.magic, HA_ADMIN_MAGIC, 4);
  if (io_all(fd, &request, sizeof(request), 0) < 0 ||
      memcmp(request.magic, HA_ADMIN_MAGIC, 4))
    return -1;
  memcpy(response.nonce, request.nonce, sizeof(response.nonce));
  signer = dtun_ha_member_find(state, request.signer);
  target = dtun_ha_member_find(state, request.target);
  if (signer &&
      !memcmp(request.cluster_id, state->cluster_id,
              sizeof(request.cluster_id)) &&
      verify_admin(signer->public_key, &request,
                   offsetof(admin_request_t, signature),
                   request.signature) == 0 &&
      admin_nonce_new(request.nonce)) {
    if (request.action == DTUN_HA_ADMIN_STATUS)
      authorized = 1;
    else if (request.action == DTUN_HA_ADMIN_LEAVE)
      authorized = target && !strcmp(request.signer, request.target) &&
                   strcmp(request.target, state->primary_hub_id) &&
                   strcmp(request.target, state->leader_id);
    else
      authorized = !strcmp(request.signer, state->primary_hub_id) &&
                   (!strcmp(state->local_hub_id, state->leader_id) ||
                    !strcmp(request.target, state->local_hub_id));
  }
  if (!authorized || !target)
    response.status = EPERM;
  else if (request.action == DTUN_HA_ADMIN_DISABLE) {
    target->enabled = 0;
    target->lifecycle = DTUN_HA_MEMBER_DISABLED;
    changed = 1;
  } else if (request.action == DTUN_HA_ADMIN_ENABLE) {
    if (target->lifecycle == DTUN_HA_MEMBER_EVICTED)
      response.status = EPERM;
    else {
      target->enabled = 1;
      target->lifecycle = DTUN_HA_MEMBER_ACTIVE;
      target->role = DTUN_HA_LEARNER;
      changed = 1;
    }
  } else if (request.action == DTUN_HA_ADMIN_KICK ||
             request.action == DTUN_HA_ADMIN_LEAVE) {
    target->enabled = 0;
    target->lifecycle = DTUN_HA_MEMBER_EVICTED;
    changed = 1;
  }
  if (changed) {
    state->manifest_version++;
    state->commit_index++;
    if (dtun_ha_state_save(state_path, state) < 0)
      response.status = EIO;
  }
  response.term = htobe64(state->term);
  response.commit_index = htobe64(state->commit_index);
  if (sign_admin(identity_key_path, &response,
                 offsetof(admin_reply_t, signature), response.signature) < 0 ||
      io_all(fd, &response, sizeof(response), 1) < 0)
    return -1;
  return response.status ? -response.status : 0;
}
