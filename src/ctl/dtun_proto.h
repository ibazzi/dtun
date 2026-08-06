#ifndef DTUN_PROTO_H
#define DTUN_PROTO_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define DTRG_MAGIC "DTRG"
#define DTRG_VERSION 2

#define DTRG_INIT 1
#define DTRG_CHALLENGE 2
#define DTRG_CONFIRM 3
#define DTRG_ACK 4
#define DTRG_SYNC 5

#define DTRG_TAG_LEN 16
#define DTRG_KEY_LEN 32
#define DTRG_NONCE_LEN 16
#define DTRG_COOKIE_LEN 32
#define DTRG_MAX_SYNC_PEERS 128
#define DTRG_MAX_PACKET 8192

typedef struct {
    uint64_t node_id;
    uint32_t tunnel_id;
    uint32_t remote_tunnel_id;
    struct in_addr address;
    struct in_addr raw;
    struct in_addr udp_addr;
    uint16_t udp_port;
} dtrg_sync_peer_t;

typedef struct {
    uint8_t kind;
    uint64_t node_id;
    struct in_addr address;
    uint8_t prefix_len;
    struct in_addr raw;
    uint8_t nonce[DTRG_NONCE_LEN];
    uint8_t cookie[DTRG_COOKIE_LEN];
    uint32_t tunnel_id;
    uint32_t remote_tunnel_id;
    uint16_t data_port;     /* Hub's actual data plane UDP port */
    dtrg_sync_peer_t *peers; /* Allocated SYNC peer array */
    uint16_t peer_count;
} dtrg_msg_t;

/* Compute HMAC-SHA256 truncated to 16 bytes */
void dtrg_hmac(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out_tag);

/* Pack functions return total byte length written, or < 0 on error. */
ssize_t dtrg_pack_init(const uint8_t *key, uint64_t node_id, struct in_addr address, uint8_t prefix_len,
                       struct in_addr raw, const uint8_t *nonce, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_challenge(const uint8_t *key, uint64_t node_id, struct in_addr address, uint8_t prefix_len,
                            struct in_addr raw, const uint8_t *nonce, const uint8_t *cookie, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_confirm(const uint8_t *key, uint64_t node_id, struct in_addr address, uint8_t prefix_len,
                          struct in_addr raw, const uint8_t *nonce, const uint8_t *cookie, uint8_t *out, size_t max_len);

ssize_t dtrg_pack_ack(const uint8_t *key, uint64_t node_id, uint32_t tunnel_id, uint32_t remote_tunnel_id,
                      struct in_addr address, uint8_t prefix_len, uint16_t data_port, const uint8_t *nonce,
                      uint8_t *out, size_t max_len);

ssize_t dtrg_pack_sync(const uint8_t *key, uint64_t node_id, const uint8_t *nonce,
                       const dtrg_sync_peer_t *peers, uint16_t peer_count,
                       uint8_t *out, size_t max_len);

/* Parse and authenticate an incoming packet. Returns 0 on success. */
int dtrg_parse(const uint8_t *key, const uint8_t *pkt, size_t pkt_len, dtrg_msg_t *msg);

void dtrg_msg_free(dtrg_msg_t *msg);

#endif /* DTUN_PROTO_H */
