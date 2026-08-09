#include <dtun/proto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dtrg_hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
               size_t data_len, uint8_t *out_tag) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  HMAC(EVP_sha256(), key, key_len, data, data_len, md, &md_len);
  memcpy(out_tag, md, DTRG_TAG_LEN);
}

static uint64_t hton64(uint64_t val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (((uint64_t)htonl((uint32_t)val)) << 32) |
         htonl((uint32_t)(val >> 32));
#else
  return val;
#endif
}

static uint64_t ntoh64(uint64_t val) { return hton64(val); }

ssize_t dtrg_pack_init(const uint8_t *key, uint64_t node_id,
                       struct in_addr address, uint8_t prefix_len,
                       struct in_addr raw, const uint8_t *nonce, uint8_t *out,
                       size_t max_len) {
  size_t body_len = 4 + 1 + 8 + 4 + 1 + 4 + 16;
  if (max_len < body_len + DTRG_TAG_LEN)
    return -1;

  uint8_t *p = out;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_INIT;
  uint64_t nid = hton64(node_id);
  memcpy(p, &nid, 8);
  p += 8;
  memcpy(p, &address.s_addr, 4);
  p += 4;
  *p++ = prefix_len;
  memcpy(p, &raw.s_addr, 4);
  p += 4;
  memcpy(p, nonce, 16);
  p += 16;

  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return body_len + DTRG_TAG_LEN;
}

ssize_t dtrg_pack_challenge(const uint8_t *key, uint64_t node_id,
                            struct in_addr address, uint8_t prefix_len,
                            struct in_addr raw, const uint8_t *nonce,
                            const uint8_t *cookie, uint8_t *out,
                            size_t max_len) {
  size_t body_len = 4 + 1 + 8 + 4 + 1 + 4 + 16 + 32;
  if (max_len < body_len + DTRG_TAG_LEN)
    return -1;

  uint8_t *p = out;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_CHALLENGE;
  uint64_t nid = hton64(node_id);
  memcpy(p, &nid, 8);
  p += 8;
  memcpy(p, &address.s_addr, 4);
  p += 4;
  *p++ = prefix_len;
  memcpy(p, &raw.s_addr, 4);
  p += 4;
  memcpy(p, nonce, 16);
  p += 16;
  memcpy(p, cookie, 32);
  p += 32;

  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return body_len + DTRG_TAG_LEN;
}

ssize_t dtrg_pack_confirm(const uint8_t *key, uint64_t node_id,
                          struct in_addr address, uint8_t prefix_len,
                          struct in_addr raw, const uint8_t *nonce,
                          const uint8_t *cookie, uint8_t *out, size_t max_len) {
  size_t body_len = 4 + 1 + 8 + 4 + 1 + 4 + 16 + 32;
  if (max_len < body_len + DTRG_TAG_LEN)
    return -1;

  uint8_t *p = out;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_CONFIRM;
  uint64_t nid = hton64(node_id);
  memcpy(p, &nid, 8);
  p += 8;
  memcpy(p, &address.s_addr, 4);
  p += 4;
  *p++ = prefix_len;
  memcpy(p, &raw.s_addr, 4);
  p += 4;
  memcpy(p, nonce, 16);
  p += 16;
  memcpy(p, cookie, 32);
  p += 32;

  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return body_len + DTRG_TAG_LEN;
}

ssize_t dtrg_pack_ack(const uint8_t *key, uint64_t node_id, uint32_t tunnel_id,
                      uint32_t remote_tunnel_id, struct in_addr address,
                      uint8_t prefix_len, uint16_t data_port,
                      const uint8_t *nonce, const uint8_t *lease_token,
                      uint64_t epoch, uint64_t term, const char *leader_id,
                      uint8_t *out, size_t max_len) {
  size_t body_len =
      4 + 1 + 8 + 4 + 4 + 4 + 1 + 2 + 16 + 16 + 8 + 8 + DTRG_HUB_ID_LEN;
  if (!leader_id || max_len < body_len + DTRG_TAG_LEN)
    return -1;

  uint8_t *p = out;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_ACK;
  uint64_t nid = hton64(node_id);
  memcpy(p, &nid, 8);
  p += 8;
  uint32_t tid = htonl(tunnel_id);
  memcpy(p, &tid, 4);
  p += 4;
  uint32_t rtid = htonl(remote_tunnel_id);
  memcpy(p, &rtid, 4);
  p += 4;
  memcpy(p, &address.s_addr, 4);
  p += 4;
  *p++ = prefix_len;
  uint16_t dp = htons(data_port);
  memcpy(p, &dp, 2);
  p += 2;
  memcpy(p, nonce, 16);
  p += 16;
  memcpy(p, lease_token, 16);
  p += 16;
  uint64_t epoch_be = hton64(epoch);
  memcpy(p, &epoch_be, 8);
  p += 8;
  uint64_t term_be = hton64(term);
  memcpy(p, &term_be, 8);
  p += 8;
  memset(p, 0, DTRG_HUB_ID_LEN);
  memcpy(p, leader_id, strnlen(leader_id, DTRG_HUB_ID_LEN - 1));
  p += DTRG_HUB_ID_LEN;

  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return body_len + DTRG_TAG_LEN;
}

ssize_t dtrg_pack_sync(const uint8_t *key, uint64_t node_id,
                       const uint8_t *nonce, const dtrg_sync_peer_t *peers,
                       uint16_t peer_count, uint8_t *out, size_t max_len) {
  const size_t peer_wire_len = 8 + 4 + 4 + 4 + 4 + 4 + 2 + 8 + 1;
  size_t body_len;
  uint16_t i;

  if (peer_count > DTRG_MAX_SYNC_PEERS || (peer_count && !peers))
    return -1;
  body_len = 4 + 1 + 8 + 16 + 2 + (size_t)peer_count * peer_wire_len;
  if (max_len < body_len + DTRG_TAG_LEN)
    return -1;

  uint8_t *p = out;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_SYNC;
  uint64_t nid = hton64(node_id);
  memcpy(p, &nid, 8);
  p += 8;
  memcpy(p, nonce, 16);
  p += 16;
  uint16_t count = htons(peer_count);
  memcpy(p, &count, 2);
  p += 2;
  for (i = 0; i < peer_count; i++) {
    uint64_t peer_node = hton64(peers[i].node_id);
    uint32_t tunnel_id = htonl(peers[i].tunnel_id);
    uint32_t remote_tunnel_id = htonl(peers[i].remote_tunnel_id);
    uint16_t udp_port = htons(peers[i].udp_port);
    uint64_t generation = hton64(peers[i].generation);

    memcpy(p, &peer_node, 8);
    p += 8;
    memcpy(p, &tunnel_id, 4);
    p += 4;
    memcpy(p, &remote_tunnel_id, 4);
    p += 4;
    memcpy(p, &peers[i].address.s_addr, 4);
    p += 4;
    memcpy(p, &peers[i].raw.s_addr, 4);
    p += 4;
    memcpy(p, &peers[i].udp_addr.s_addr, 4);
    p += 4;
    memcpy(p, &udp_port, 2);
    p += 2;
    memcpy(p, &generation, 8);
    p += 8;
    *p++ = peers[i].flags;
  }

  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return body_len + DTRG_TAG_LEN;
}

ssize_t dtrg_pack_refresh(const uint8_t *key, uint64_t node_id,
                          const uint8_t *lease_token, uint64_t counter,
                          uint64_t epoch, uint16_t offset, uint8_t *out,
                          size_t max_len) {
  size_t body_len = 4 + 1 + 8 + 16 + 8 + 8 + 2;
  uint8_t *p = out;
  uint64_t value;
  uint16_t offset_be;
  if (!lease_token || max_len < body_len + DTRG_TAG_LEN)
    return -1;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_REFRESH;
  value = hton64(node_id);
  memcpy(p, &value, 8);
  p += 8;
  memcpy(p, lease_token, 16);
  p += 16;
  value = hton64(counter);
  memcpy(p, &value, 8);
  p += 8;
  value = hton64(epoch);
  memcpy(p, &value, 8);
  p += 8;
  offset_be = htons(offset);
  memcpy(p, &offset_be, 2);
  p += 2;
  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return (ssize_t)(body_len + DTRG_TAG_LEN);
}

ssize_t dtrg_pack_refresh_ack(
    const uint8_t *key, uint64_t node_id, const uint8_t *lease_token,
    uint64_t counter, uint64_t epoch, struct in_addr observed_addr,
    uint16_t observed_port, uint8_t flags, uint16_t next_offset, uint64_t term,
    const char *leader_id, uint16_t data_port, const dtrg_sync_peer_t *peers,
    uint16_t peer_count, uint8_t *out, size_t max_len) {
  const size_t peer_wire_len = 8 + 4 + 4 + 4 + 4 + 4 + 2 + 8 + 1;
  size_t body_len = 4 + 1 + 8 + 16 + 8 + 8 + 4 + 2 + 1 + 2 + 8 +
                    DTRG_HUB_ID_LEN + 2 + 2 +
                    (size_t)peer_count * peer_wire_len;
  uint8_t *p = out;
  uint64_t value;
  uint16_t short_value;
  uint16_t i;
  if (!lease_token || !leader_id || peer_count > DTRG_MAX_SYNC_PEERS ||
      (peer_count && !peers) || max_len < body_len + DTRG_TAG_LEN)
    return -1;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_REFRESH_ACK;
  value = hton64(node_id);
  memcpy(p, &value, 8);
  p += 8;
  memcpy(p, lease_token, 16);
  p += 16;
  value = hton64(counter);
  memcpy(p, &value, 8);
  p += 8;
  value = hton64(epoch);
  memcpy(p, &value, 8);
  p += 8;
  memcpy(p, &observed_addr.s_addr, 4);
  p += 4;
  short_value = htons(observed_port);
  memcpy(p, &short_value, 2);
  p += 2;
  *p++ = flags;
  short_value = htons(next_offset);
  memcpy(p, &short_value, 2);
  p += 2;
  value = hton64(term);
  memcpy(p, &value, 8);
  p += 8;
  memset(p, 0, DTRG_HUB_ID_LEN);
  memcpy(p, leader_id, strnlen(leader_id, DTRG_HUB_ID_LEN - 1));
  p += DTRG_HUB_ID_LEN;
  short_value = htons(data_port);
  memcpy(p, &short_value, 2);
  p += 2;
  short_value = htons(peer_count);
  memcpy(p, &short_value, 2);
  p += 2;
  for (i = 0; i < peer_count; i++) {
    value = hton64(peers[i].node_id);
    memcpy(p, &value, 8);
    p += 8;
    uint32_t word = htonl(peers[i].tunnel_id);
    memcpy(p, &word, 4);
    p += 4;
    word = htonl(peers[i].remote_tunnel_id);
    memcpy(p, &word, 4);
    p += 4;
    memcpy(p, &peers[i].address.s_addr, 4);
    p += 4;
    memcpy(p, &peers[i].raw.s_addr, 4);
    p += 4;
    memcpy(p, &peers[i].udp_addr.s_addr, 4);
    p += 4;
    short_value = htons(peers[i].udp_port);
    memcpy(p, &short_value, 2);
    p += 2;
    value = hton64(peers[i].generation);
    memcpy(p, &value, 8);
    p += 8;
    *p++ = peers[i].flags;
  }
  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return (ssize_t)(body_len + DTRG_TAG_LEN);
}

ssize_t dtrg_pack_hub_list(const uint8_t *key, uint64_t node_id,
                           const uint8_t cluster_id[16], uint64_t term,
                           uint8_t ha_mode, const dtrg_hub_t *hubs,
                           uint8_t hub_count, uint8_t *out, size_t max_len) {
  const size_t item_len = DTRG_HUB_ID_LEN + 4 + 2 + 2 + 2 + 32 + 1;
  size_t body_len = 4 + 1 + 8 + 16 + 8 + 1 + 1 + (size_t)hub_count * item_len;
  uint8_t *p = out;
  if (!cluster_id || hub_count > DTRG_MAX_HUBS || (hub_count && !hubs) ||
      max_len < body_len + DTRG_TAG_LEN)
    return -1;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_HUB_LIST;
  uint64_t value = hton64(node_id);
  memcpy(p, &value, 8);
  p += 8;
  memcpy(p, cluster_id, 16);
  p += 16;
  value = hton64(term);
  memcpy(p, &value, 8);
  p += 8;
  *p++ = ha_mode;
  *p++ = hub_count;
  uint16_t word;
  for (uint8_t i = 0; i < hub_count; i++) {
    memset(p, 0, DTRG_HUB_ID_LEN);
    memcpy(p, hubs[i].hub_id, strnlen(hubs[i].hub_id, DTRG_HUB_ID_LEN - 1));
    p += DTRG_HUB_ID_LEN;
    memcpy(p, &hubs[i].address.s_addr, 4);
    p += 4;
    word = htons(hubs[i].control_port);
    memcpy(p, &word, 2);
    p += 2;
    word = htons(hubs[i].data_port);
    memcpy(p, &word, 2);
    p += 2;
    word = htons(hubs[i].weight);
    memcpy(p, &word, 2);
    p += 2;
    memcpy(p, hubs[i].public_key, 32);
    p += 32;
    *p++ = hubs[i].flags;
  }
  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return (ssize_t)(body_len + DTRG_TAG_LEN);
}

ssize_t dtrg_pack_not_leader(const uint8_t *key, uint64_t node_id,
                             uint64_t term, const char *leader_id,
                             struct in_addr leader_address,
                             uint16_t control_port, uint16_t data_port,
                             uint8_t *out, size_t max_len) {
  size_t body_len = 4 + 1 + 8 + 8 + DTRG_HUB_ID_LEN + 4 + 2 + 2;
  uint8_t *p = out;
  uint64_t value;
  uint16_t word;

  if (!leader_id || max_len < body_len + DTRG_TAG_LEN)
    return -1;
  memcpy(p, DTRG_MAGIC, 4);
  p += 4;
  *p++ = DTRG_NOT_LEADER;
  value = hton64(node_id);
  memcpy(p, &value, 8);
  p += 8;
  value = hton64(term);
  memcpy(p, &value, 8);
  p += 8;
  memset(p, 0, DTRG_HUB_ID_LEN);
  memcpy(p, leader_id, strnlen(leader_id, DTRG_HUB_ID_LEN - 1));
  p += DTRG_HUB_ID_LEN;
  memcpy(p, &leader_address.s_addr, 4);
  p += 4;
  word = htons(control_port);
  memcpy(p, &word, 2);
  p += 2;
  word = htons(data_port);
  memcpy(p, &word, 2);
  p += 2;
  dtrg_hmac(key, DTRG_KEY_LEN, out, body_len, p);
  return (ssize_t)(body_len + DTRG_TAG_LEN);
}

int dtrg_parse(const uint8_t *key, const uint8_t *pkt, size_t pkt_len,
               dtrg_msg_t *msg) {
  if (!msg)
    return -1;
  memset(msg, 0, sizeof(*msg));
  if (pkt_len < 4 + 1 + DTRG_TAG_LEN)
    return -1;

  size_t body_len = pkt_len - DTRG_TAG_LEN;
  const uint8_t *tag = pkt + body_len;

  uint8_t calc_tag[DTRG_TAG_LEN];
  dtrg_hmac(key, DTRG_KEY_LEN, pkt, body_len, calc_tag);
  if (CRYPTO_memcmp(tag, calc_tag, DTRG_TAG_LEN) != 0) {
    return -2; /* HMAC mismatch */
  }

  const uint8_t *p = pkt;
  if (memcmp(p, DTRG_MAGIC, 4) != 0) {
    return -3;
  }
  p += 4;
  uint8_t kind = *p++;

  msg->kind = kind;

  if (kind == DTRG_INIT) {
    if (body_len != 4 + 1 + 8 + 4 + 1 + 4 + 16)
      return -5;
    uint64_t nid;
    memcpy(&nid, p, 8);
    msg->node_id = ntoh64(nid);
    p += 8;
    memcpy(&msg->address.s_addr, p, 4);
    p += 4;
    msg->prefix_len = *p++;
    memcpy(&msg->raw.s_addr, p, 4);
    p += 4;
    memcpy(msg->nonce, p, 16);
    p += 16;
    return 0;
  }

  if (kind == DTRG_CHALLENGE || kind == DTRG_CONFIRM) {
    if (body_len != 4 + 1 + 8 + 4 + 1 + 4 + 16 + 32)
      return -5;
    uint64_t nid;
    memcpy(&nid, p, 8);
    msg->node_id = ntoh64(nid);
    p += 8;
    memcpy(&msg->address.s_addr, p, 4);
    p += 4;
    msg->prefix_len = *p++;
    memcpy(&msg->raw.s_addr, p, 4);
    p += 4;
    memcpy(msg->nonce, p, 16);
    p += 16;
    memcpy(msg->cookie, p, 32);
    p += 32;
    return 0;
  }

  if (kind == DTRG_ACK) {
    if (body_len !=
        4 + 1 + 8 + 4 + 4 + 4 + 1 + 2 + 16 + 16 + 8 + 8 + DTRG_HUB_ID_LEN)
      return -5;
    uint64_t nid;
    memcpy(&nid, p, 8);
    msg->node_id = ntoh64(nid);
    p += 8;
    uint32_t tid;
    memcpy(&tid, p, 4);
    msg->tunnel_id = ntohl(tid);
    p += 4;
    uint32_t rtid;
    memcpy(&rtid, p, 4);
    msg->remote_tunnel_id = ntohl(rtid);
    p += 4;
    memcpy(&msg->address.s_addr, p, 4);
    p += 4;
    msg->prefix_len = *p++;
    uint16_t dp;
    memcpy(&dp, p, 2);
    msg->data_port = ntohs(dp);
    p += 2;
    memcpy(msg->nonce, p, 16);
    p += 16;
    memcpy(msg->lease_token, p, 16);
    p += 16;
    uint64_t epoch;
    memcpy(&epoch, p, 8);
    msg->epoch = ntoh64(epoch);
    p += 8;
    memcpy(&epoch, p, 8);
    msg->term = ntoh64(epoch);
    p += 8;
    memcpy(msg->leader_id, p, DTRG_HUB_ID_LEN);
    msg->leader_id[DTRG_HUB_ID_LEN - 1] = '\0';
    p += DTRG_HUB_ID_LEN;
    return 0;
  }

  if (kind == DTRG_SYNC) {
    const size_t header_len = 4 + 1 + 8 + 16 + 2;
    const size_t peer_wire_len = 8 + 4 + 4 + 4 + 4 + 4 + 2 + 8 + 1;
    uint16_t count;
    uint16_t i;

    if (body_len < header_len)
      return -5;
    uint64_t nid;
    memcpy(&nid, p, 8);
    msg->node_id = ntoh64(nid);
    p += 8;
    memcpy(msg->nonce, p, 16);
    p += 16;
    memcpy(&count, p, 2);
    count = ntohs(count);
    p += 2;
    if (count > DTRG_MAX_SYNC_PEERS ||
        body_len != header_len + (size_t)count * peer_wire_len)
      return -5;
    if (count) {
      msg->peers = calloc(count, sizeof(*msg->peers));
      if (!msg->peers)
        return -7;
    }
    msg->peer_count = count;
    for (i = 0; i < count; i++) {
      uint64_t peer_node;
      uint32_t tunnel_id, remote_tunnel_id;
      uint16_t udp_port;
      uint64_t generation;

      memcpy(&peer_node, p, 8);
      p += 8;
      memcpy(&tunnel_id, p, 4);
      p += 4;
      memcpy(&remote_tunnel_id, p, 4);
      p += 4;
      memcpy(&msg->peers[i].address.s_addr, p, 4);
      p += 4;
      memcpy(&msg->peers[i].raw.s_addr, p, 4);
      p += 4;
      memcpy(&msg->peers[i].udp_addr.s_addr, p, 4);
      p += 4;
      memcpy(&udp_port, p, 2);
      p += 2;
      memcpy(&generation, p, 8);
      p += 8;
      msg->peers[i].flags = *p++;
      msg->peers[i].node_id = ntoh64(peer_node);
      msg->peers[i].tunnel_id = ntohl(tunnel_id);
      msg->peers[i].remote_tunnel_id = ntohl(remote_tunnel_id);
      msg->peers[i].udp_port = ntohs(udp_port);
      msg->peers[i].generation = ntoh64(generation);
    }
    return 0;
  }

  if (kind == DTRG_REFRESH) {
    uint64_t value;
    uint16_t offset;
    if (body_len != 4 + 1 + 8 + 16 + 8 + 8 + 2)
      return -5;
    memcpy(&value, p, 8);
    msg->node_id = ntoh64(value);
    p += 8;
    memcpy(msg->lease_token, p, 16);
    p += 16;
    memcpy(&value, p, 8);
    msg->counter = ntoh64(value);
    p += 8;
    memcpy(&value, p, 8);
    msg->epoch = ntoh64(value);
    p += 8;
    memcpy(&offset, p, 2);
    msg->offset = ntohs(offset);
    p += 2;
    return 0;
  }

  if (kind == DTRG_HUB_LIST) {
    const size_t header_len = 4 + 1 + 8 + 16 + 8 + 1 + 1;
    const size_t item_len = DTRG_HUB_ID_LEN + 4 + 2 + 2 + 2 + 32 + 1;
    uint64_t value;
    uint16_t word;
    uint8_t count;
    if (body_len < header_len)
      return -5;
    memcpy(&value, p, 8);
    msg->node_id = ntoh64(value);
    p += 8;
    memcpy(msg->cluster_id, p, 16);
    p += 16;
    memcpy(&value, p, 8);
    msg->term = ntoh64(value);
    p += 8;
    msg->ha_mode = *p++;
    count = *p++;
    if (count > DTRG_MAX_HUBS ||
        body_len != header_len + (size_t)count * item_len)
      return -5;
    if (count) {
      msg->hubs = calloc(count, sizeof(*msg->hubs));
      if (!msg->hubs)
        return -7;
    }
    msg->hub_count = count;
    for (uint8_t i = 0; i < count; i++) {
      memcpy(msg->hubs[i].hub_id, p, DTRG_HUB_ID_LEN);
      msg->hubs[i].hub_id[DTRG_HUB_ID_LEN - 1] = '\0';
      p += DTRG_HUB_ID_LEN;
      memcpy(&msg->hubs[i].address.s_addr, p, 4);
      p += 4;
      memcpy(&word, p, 2);
      msg->hubs[i].control_port = ntohs(word);
      p += 2;
      memcpy(&word, p, 2);
      msg->hubs[i].data_port = ntohs(word);
      p += 2;
      memcpy(&word, p, 2);
      msg->hubs[i].weight = ntohs(word);
      p += 2;
      memcpy(msg->hubs[i].public_key, p, 32);
      p += 32;
      msg->hubs[i].flags = *p++;
    }
    return 0;
  }

  if (kind == DTRG_REFRESH_ACK) {
    const size_t header_len =
        4 + 1 + 8 + 16 + 8 + 8 + 4 + 2 + 1 + 2 + 8 + DTRG_HUB_ID_LEN + 2 + 2;
    const size_t peer_wire_len = 8 + 4 + 4 + 4 + 4 + 4 + 2 + 8 + 1;
    uint64_t value;
    uint16_t count, short_value, i;
    if (body_len < header_len)
      return -5;
    memcpy(&value, p, 8);
    msg->node_id = ntoh64(value);
    p += 8;
    memcpy(msg->lease_token, p, 16);
    p += 16;
    memcpy(&value, p, 8);
    msg->counter = ntoh64(value);
    p += 8;
    memcpy(&value, p, 8);
    msg->epoch = ntoh64(value);
    p += 8;
    memcpy(&msg->observed_addr.s_addr, p, 4);
    p += 4;
    memcpy(&short_value, p, 2);
    msg->observed_port = ntohs(short_value);
    p += 2;
    msg->flags = *p++;
    memcpy(&short_value, p, 2);
    msg->offset = ntohs(short_value);
    p += 2;
    memcpy(&value, p, 8);
    msg->term = ntoh64(value);
    p += 8;
    memcpy(msg->leader_id, p, DTRG_HUB_ID_LEN);
    msg->leader_id[DTRG_HUB_ID_LEN - 1] = '\0';
    p += DTRG_HUB_ID_LEN;
    memcpy(&short_value, p, 2);
    msg->data_port = ntohs(short_value);
    p += 2;
    memcpy(&count, p, 2);
    count = ntohs(count);
    p += 2;
    if (count > DTRG_MAX_SYNC_PEERS ||
        body_len != header_len + (size_t)count * peer_wire_len)
      return -5;
    msg->peers = count ? calloc(count, sizeof(*msg->peers)) : NULL;
    if (count && !msg->peers)
      return -7;
    msg->peer_count = count;
    for (i = 0; i < count; i++) {
      uint32_t word;
      memcpy(&value, p, 8);
      msg->peers[i].node_id = ntoh64(value);
      p += 8;
      memcpy(&word, p, 4);
      msg->peers[i].tunnel_id = ntohl(word);
      p += 4;
      memcpy(&word, p, 4);
      msg->peers[i].remote_tunnel_id = ntohl(word);
      p += 4;
      memcpy(&msg->peers[i].address.s_addr, p, 4);
      p += 4;
      memcpy(&msg->peers[i].raw.s_addr, p, 4);
      p += 4;
      memcpy(&msg->peers[i].udp_addr.s_addr, p, 4);
      p += 4;
      memcpy(&short_value, p, 2);
      msg->peers[i].udp_port = ntohs(short_value);
      p += 2;
      memcpy(&value, p, 8);
      msg->peers[i].generation = ntoh64(value);
      p += 8;
      msg->peers[i].flags = *p++;
    }
    return 0;
  }

  if (kind == DTRG_NOT_LEADER) {
    const size_t expected = 4 + 1 + 8 + 8 + DTRG_HUB_ID_LEN + 4 + 2 + 2;
    uint64_t value;
    uint16_t word;

    if (body_len != expected)
      return -5;
    memcpy(&value, p, 8);
    msg->node_id = ntoh64(value);
    p += 8;
    memcpy(&value, p, 8);
    msg->term = ntoh64(value);
    p += 8;
    memcpy(msg->leader_id, p, DTRG_HUB_ID_LEN);
    msg->leader_id[DTRG_HUB_ID_LEN - 1] = '\0';
    p += DTRG_HUB_ID_LEN;
    memcpy(&msg->address.s_addr, p, 4);
    p += 4;
    memcpy(&word, p, 2);
    msg->observed_port = ntohs(word);
    p += 2;
    memcpy(&word, p, 2);
    msg->data_port = ntohs(word);
    return 0;
  }

  return -6; /* Unknown message type */
}

void dtrg_msg_free(dtrg_msg_t *msg) {
  if (!msg)
    return;
  free(msg->peers);
  free(msg->hubs);
  msg->peers = NULL;
  msg->hubs = NULL;
  msg->peer_count = 0;
  msg->hub_count = 0;
}
