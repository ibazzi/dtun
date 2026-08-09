#ifndef DTUN_PROTO_H
#define DTUN_PROTO_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define DTRG_MAGIC "DTG2"
#define DTRG_INIT 1
#define DTRG_CHALLENGE 2
#define DTRG_CONFIRM 3
#define DTRG_ACK 4
#define DTRG_SYNC 5
#define DTRG_REFRESH 6
#define DTRG_REFRESH_ACK 7
#define DTRG_HUB_LIST 8
#define DTRG_NOT_LEADER 9
#define DTRG_LEAVE 10
#define DTRG_LEAVE_ACK 11

#define DTRG_REFRESH_SNAPSHOT 0x01
#define DTRG_REFRESH_MORE 0x02
#define DTRG_REFRESH_RE_REGISTER 0x04
#define DTRG_REFRESH_HUB_SWITCH 0x08
#define DTRG_PEER_ONLINE 0x01
#define DTRG_PEER_TOMBSTONE 0x02
#define DTRG_PEER_OFFLINE 0x04

#define DTRG_TAG_LEN 16
#define DTRG_KEY_LEN 32
#define DTRG_NONCE_LEN 16
#define DTRG_COOKIE_LEN 32
#define DTRG_LEASE_TOKEN_LEN 16
#define DTRG_MAX_SYNC_PEERS 128
#define DTRG_MAX_PACKET 8192
#define DTRG_MAX_HUBS 16
#define DTRG_HUB_ID_LEN 64

#define DTRG_HA_MODE_DIRECT_PAIR 1
#define DTRG_HA_MODE_QUORUM 2
#define DTRG_HUB_ACTIVE 0x01

typedef struct {
  char hub_id[DTRG_HUB_ID_LEN];
  struct in_addr address;
  uint16_t control_port;
  uint16_t data_port;
  uint16_t weight;
  uint8_t public_key[32];
  uint8_t flags;
} dtrg_hub_t;

typedef struct {
  uint64_t node_id;
  uint32_t tunnel_id;
  uint32_t remote_tunnel_id;
  struct in_addr address;
  struct in_addr raw;
  struct in_addr udp_addr;
  uint16_t udp_port;
  uint64_t generation;
  uint8_t flags;
} dtrg_sync_peer_t;

typedef struct {
  uint8_t kind;
  uint64_t node_id;
  struct in_addr address;
  uint8_t prefix_len;
  struct in_addr raw;
  uint8_t nonce[DTRG_NONCE_LEN];
  uint8_t cookie[DTRG_COOKIE_LEN];
  uint8_t lease_token[DTRG_LEASE_TOKEN_LEN];
  uint32_t tunnel_id;
  uint32_t remote_tunnel_id;
  uint16_t data_port; /* Hub's actual data plane UDP port */
  uint64_t epoch;
  uint64_t counter;
  uint16_t offset;
  uint8_t flags;
  struct in_addr observed_addr;
  uint16_t observed_port;
  dtrg_sync_peer_t *peers; /* Allocated SYNC peer array */
  uint16_t peer_count;
  uint8_t cluster_id[16];
  uint64_t term;
  uint8_t ha_mode;
  char leader_id[DTRG_HUB_ID_LEN];
  dtrg_hub_t *hubs;
  uint8_t hub_count;
} dtrg_msg_t;

/* Compute HMAC-SHA256 truncated to 16 bytes */
void dtrg_hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
               size_t data_len, uint8_t *out_tag);

/* Pack functions return total byte length written, or < 0 on error. */
ssize_t dtrg_pack_init(const uint8_t *key, uint64_t node_id,
                       struct in_addr address, uint8_t prefix_len,
                       struct in_addr raw, const uint8_t *nonce, uint8_t *out,
                       size_t max_len);

ssize_t dtrg_pack_challenge(const uint8_t *key, uint64_t node_id,
                            struct in_addr address, uint8_t prefix_len,
                            struct in_addr raw, const uint8_t *nonce,
                            const uint8_t *cookie, uint8_t *out,
                            size_t max_len);

ssize_t dtrg_pack_confirm(const uint8_t *key, uint64_t node_id,
                          struct in_addr address, uint8_t prefix_len,
                          struct in_addr raw, const uint8_t *nonce,
                          const uint8_t *cookie, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_ack(const uint8_t *key, uint64_t node_id, uint32_t tunnel_id,
                      uint32_t remote_tunnel_id, struct in_addr address,
                      uint8_t prefix_len, uint16_t data_port,
                      const uint8_t *nonce, const uint8_t *lease_token,
                      uint64_t epoch, uint64_t term, const char *leader_id,
                      uint8_t *out, size_t max_len);

ssize_t dtrg_pack_sync(const uint8_t *key, uint64_t node_id,
                       const uint8_t *nonce, const dtrg_sync_peer_t *peers,
                       uint16_t peer_count, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_refresh(const uint8_t *key, uint64_t node_id,
                          const uint8_t *lease_token, uint64_t counter,
                          uint64_t epoch, uint16_t offset, uint8_t *out,
                          size_t max_len);

ssize_t dtrg_pack_leave(const uint8_t *key, uint8_t kind, uint64_t node_id,
                        const uint8_t *lease_token, uint64_t counter,
                        uint8_t *out, size_t max_len);

ssize_t dtrg_pack_refresh_ack(
    const uint8_t *key, uint64_t node_id, const uint8_t *lease_token,
    uint64_t counter, uint64_t epoch, struct in_addr observed_addr,
    uint16_t observed_port, uint8_t flags, uint16_t next_offset, uint64_t term,
    const char *leader_id, uint16_t data_port, const dtrg_sync_peer_t *peers,
    uint16_t peer_count, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_hub_list(const uint8_t *key, uint64_t node_id,
                           const uint8_t cluster_id[16], uint64_t term,
                           uint8_t ha_mode, const dtrg_hub_t *hubs,
                           uint8_t hub_count, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_not_leader(const uint8_t *key, uint64_t node_id,
                             uint64_t term, const char *leader_id,
                             struct in_addr leader_address,
                             uint16_t control_port, uint16_t data_port,
                             uint8_t *out, size_t max_len);

/* Parse and authenticate an incoming packet. Returns 0 on success. */
int dtrg_parse(const uint8_t *key, const uint8_t *pkt, size_t pkt_len,
               dtrg_msg_t *msg);

void dtrg_msg_free(dtrg_msg_t *msg);

#endif /* DTUN_PROTO_H */
