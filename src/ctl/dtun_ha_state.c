#include "dtun_ha_state.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define HA_STATE_MAGIC "DTHS"
#define HA_INVITE_MAGIC "DTHI"

typedef struct {
  char magic[4];
  uint32_t version;
  dtun_ha_state_t state;
} ha_state_file_t;

typedef struct {
  char magic[4];
  uint8_t version;
  uint8_t cluster_id[16];
  uint8_t invite_id[16];
  uint8_t secret[32];
  uint8_t leader_key[32];
  uint32_t leader_addr;
  uint16_t leader_port;
  uint16_t weight;
  uint64_t expires_at;
  char hub_id[DTUN_HA_ID_LEN];
  uint8_t signature[64];
} ha_invite_wire_t;

int dtun_ha_validate_hub_id(const char *hub_id) {
  size_t i, len;
  if (!hub_id || !(len = strlen(hub_id)) || len >= DTUN_HA_ID_LEN)
    return -1;
  for (i = 0; i < len; i++)
    if (!((hub_id[i] >= 'a' && hub_id[i] <= 'z') ||
          (hub_id[i] >= 'A' && hub_id[i] <= 'Z') ||
          (hub_id[i] >= '0' && hub_id[i] <= '9') || hub_id[i] == '-' ||
          hub_id[i] == '_'))
      return -1;
  return 0;
}

void dtun_ha_random_id(uint8_t *out, size_t len) {
  if (!out || RAND_bytes(out, (int)len) != 1)
    abort();
}

int dtun_ha_make_parent_dirs(const char *path, mode_t mode) {
  char copy[512], *p;
  if (!path || strlen(path) >= sizeof(copy))
    return -ENAMETOOLONG;
  strcpy(copy, path);
  for (p = copy + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(copy, mode) < 0 && errno != EEXIST)
      return -errno;
    *p = '/';
  }
  return 0;
}

int dtun_ha_atomic_write(const char *path, const void *data, size_t len,
                         mode_t mode) {
  char temp[560];
  int fd, err = 0;
  ssize_t written;
  if (dtun_ha_make_parent_dirs(path, 0750) < 0)
    return -1;
  if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path) >= (int)sizeof(temp))
    return -1;
  fd = mkstemp(temp);
  if (fd < 0)
    return -errno;
  if (fchmod(fd, mode) < 0)
    err = -errno;
  written = err ? -1 : write(fd, data, len);
  if (!err && (written < 0 || (size_t)written != len))
    err = -EIO;
  if (!err && fsync(fd) < 0)
    err = -errno;
  if (close(fd) < 0 && !err)
    err = -errno;
  if (!err && rename(temp, path) < 0)
    err = -errno;
  if (err)
    unlink(temp);
  return err;
}

int dtun_ha_state_load(const char *path, dtun_ha_state_t *state) {
  ha_state_file_t file;
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return -errno;
  if (fread(file.magic, sizeof(file.magic), 1, fp) != 1 ||
      fread(&file.version, sizeof(file.version), 1, fp) != 1 ||
      memcmp(file.magic, HA_STATE_MAGIC, 4)) {
    fclose(fp);
    return -EINVAL;
  }
  if (file.version != DTUN_HA_STATE_VERSION) {
    fclose(fp);
    return -EPROTONOSUPPORT;
  }
  if (fread(&file.state, sizeof(file.state), 1, fp) != 1 || fgetc(fp) != EOF ||
      file.state.member_count > DTUN_HA_MAX_MEMBERS ||
      file.state.invite_count > DTUN_HA_MAX_INVITES) {
    fclose(fp);
    return -EINVAL;
  }
  fclose(fp);
  *state = file.state;
  return 0;
}

int dtun_ha_state_save(const char *path, const dtun_ha_state_t *state) {
  ha_state_file_t file;
  memset(&file, 0, sizeof(file));
  memcpy(file.magic, HA_STATE_MAGIC, 4);
  file.version = DTUN_HA_STATE_VERSION;
  file.state = *state;
  return dtun_ha_atomic_write(path, &file, sizeof(file), 0640);
}

int dtun_ha_state_lock(const char *path) {
  char lock_path[560];
  int fd;
  if (!path || snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >=
                   (int)sizeof(lock_path))
    return -ENAMETOOLONG;
  if (dtun_ha_make_parent_dirs(lock_path, 0750) < 0)
    return -1;
  fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0)
    return -errno;
  if (flock(fd, LOCK_EX) < 0) {
    int error = -errno;
    close(fd);
    return error;
  }
  return fd;
}

void dtun_ha_state_unlock(int lock_fd) {
  if (lock_fd < 0)
    return;
  (void)flock(lock_fd, LOCK_UN);
  close(lock_fd);
}

int dtun_ha_runtime_lock(const char *path, int nonblock) {
  char lock_path[560];
  int fd, operation = LOCK_EX;

  if (!path || snprintf(lock_path, sizeof(lock_path), "%s.runtime", path) >=
                   (int)sizeof(lock_path))
    return -ENAMETOOLONG;
  if (dtun_ha_make_parent_dirs(lock_path, 0750) < 0)
    return -1;
  fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0)
    return -errno;
  if (nonblock)
    operation |= LOCK_NB;
  if (flock(fd, operation) < 0) {
    int error = -errno;
    close(fd);
    return error;
  }
  return fd;
}

dtun_ha_member_t *dtun_ha_member_find(dtun_ha_state_t *state,
                                      const char *hub_id) {
  uint32_t i;
  for (i = 0; i < state->member_count; i++)
    if (!strcmp(state->members[i].hub_id, hub_id))
      return &state->members[i];
  return NULL;
}

static EVP_PKEY *load_key(const char *path) {
  FILE *fp = fopen(path, "r");
  EVP_PKEY *key = fp ? PEM_read_PrivateKey(fp, NULL, NULL, NULL) : NULL;
  if (fp)
    fclose(fp);
  return key;
}

int dtun_ha_identity_public(const char *private_path, uint8_t public_key[32]) {
  EVP_PKEY *key = load_key(private_path);
  size_t len = 32;
  int result = key && EVP_PKEY_get_raw_public_key(key, public_key, &len) == 1 &&
                       len == 32
                   ? 0
                   : -1;
  EVP_PKEY_free(key);
  return result;
}

int dtun_ha_identity_generate(const char *private_path,
                              uint8_t public_key[32]) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  BIO *bio = NULL;
  BUF_MEM *mem = NULL;
  int result = -1;
  if (!access(private_path, F_OK))
    return -EEXIST;
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &key) != 1)
    goto out;
  bio = BIO_new(BIO_s_mem());
  if (!bio ||
      PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1)
    goto out;
  BIO_get_mem_ptr(bio, &mem);
  if (!mem ||
      dtun_ha_atomic_write(private_path, mem->data, mem->length, 0600) < 0)
    goto out;
  result = dtun_ha_identity_public(private_path, public_key);
out:
  BIO_free(bio);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return result;
}

static int sign_wire(const char *path, ha_invite_wire_t *wire) {
  EVP_PKEY *key = load_key(path);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t len = sizeof(wire->signature);
  int ok = key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestSign(ctx, wire->signature, &len, (uint8_t *)wire,
                          offsetof(ha_invite_wire_t, signature)) == 1 &&
           len == 64;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : -1;
}

static int verify_wire(const ha_invite_wire_t *wire) {
  EVP_PKEY *key =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, wire->leader_key, 32);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = key && ctx &&
           EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestVerify(ctx, wire->signature, 64, (const uint8_t *)wire,
                            offsetof(ha_invite_wire_t, signature)) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok ? 0 : -1;
}

static void base64url(char *text) {
  for (; *text; text++) {
    if (*text == '+')
      *text = '-';
    else if (*text == '/')
      *text = '_';
  }
}

int dtun_ha_invite_encode(const dtun_ha_state_t *state,
                          const dtun_ha_invite_t *invite,
                          const uint8_t secret[32], struct in_addr leader_addr,
                          uint16_t leader_port, const char *private_key_path,
                          char **encoded) {
  ha_invite_wire_t wire;
  size_t max = 9 + 4 * ((sizeof(wire) + 2) / 3) + 1;
  char *text = calloc(1, max);
  if (!text)
    return -ENOMEM;
  memset(&wire, 0, sizeof(wire));
  memcpy(wire.magic, HA_INVITE_MAGIC, 4);
  wire.version = 1;
  memcpy(wire.cluster_id, state->cluster_id, 16);
  memcpy(wire.invite_id, invite->id, 16);
  memcpy(wire.secret, secret, 32);
  wire.leader_addr = leader_addr.s_addr;
  wire.leader_port = htons(leader_port);
  wire.weight = htons(invite->weight);
  wire.expires_at = htobe64((uint64_t)invite->expires_at);
  memcpy(wire.hub_id, invite->hub_id,
         strnlen(invite->hub_id, sizeof(wire.hub_id) - 1));
  if (dtun_ha_identity_public(private_key_path, wire.leader_key) < 0 ||
      sign_wire(private_key_path, &wire) < 0) {
    free(text);
    return -1;
  }
  strcpy(text, "dtun-ha1:");
  EVP_EncodeBlock((unsigned char *)text + 9, (const unsigned char *)&wire,
                  sizeof(wire));
  base64url(text + 9);
  while (text[strlen(text) - 1] == '=')
    text[strlen(text) - 1] = '\0';
  *encoded = text;
  return 0;
}

int dtun_ha_invite_decode(const char *encoded, dtun_ha_invite_t *invite,
                          uint8_t secret[32], uint8_t cluster_id[16],
                          struct in_addr *leader_addr, uint16_t *leader_port,
                          uint8_t leader_key[32]) {
  ha_invite_wire_t wire;
  unsigned char decoded_buffer[sizeof(ha_invite_wire_t) + 2];
  char *copy;
  size_t n, pad, decoded;
  if (!encoded || strncmp(encoded, "dtun-ha1:", 9))
    return -EINVAL;
  n = strlen(encoded + 9);
  pad = (4 - n % 4) % 4;
  copy = calloc(1, n + pad + 1);
  if (!copy)
    return -ENOMEM;
  memcpy(copy, encoded + 9, n);
  for (size_t i = 0; i < n; i++) {
    if (copy[i] == '-')
      copy[i] = '+';
    else if (copy[i] == '_')
      copy[i] = '/';
  }
  for (size_t i = 0; i < pad; i++)
    copy[n + i] = '=';
  decoded = (size_t)EVP_DecodeBlock(decoded_buffer, (unsigned char *)copy,
                                    (int)(n + pad));
  free(copy);
  if (decoded < pad || decoded - pad != sizeof(wire))
    return -EINVAL;
  memcpy(&wire, decoded_buffer, sizeof(wire));
  if (memcmp(wire.magic, HA_INVITE_MAGIC, 4) || wire.version != 1 ||
      verify_wire(&wire) < 0)
    return -EINVAL;
  memset(invite, 0, sizeof(*invite));
  memcpy(invite->id, wire.invite_id, 16);
  memcpy(invite->hub_id, wire.hub_id,
         strnlen(wire.hub_id, sizeof(invite->hub_id) - 1));
  invite->weight = ntohs(wire.weight);
  invite->expires_at = (time_t)be64toh(wire.expires_at);
  memcpy(secret, wire.secret, 32);
  memcpy(cluster_id, wire.cluster_id, 16);
  memcpy(leader_key, wire.leader_key, 32);
  leader_addr->s_addr = wire.leader_addr;
  *leader_port = ntohs(wire.leader_port);
  return 0;
}

void dtun_ha_hex(const uint8_t *data, size_t len, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 15];
  }
  out[len * 2] = '\0';
}
