#include <dtun/proto.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "test_proto:%d: check failed: %s\n", __LINE__,           \
              #condition);                                                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int same_nonce(const uint8_t *left, const uint8_t *right) {
  return memcmp(left, right, DTRG_NONCE_LEN) == 0;
}

int main(void) {
  uint8_t key[DTRG_KEY_LEN];
  uint8_t nonce[DTRG_NONCE_LEN];
  uint8_t cookie[DTRG_COOKIE_LEN];
  uint8_t lease_token[DTRG_LEASE_TOKEN_LEN];
  uint8_t packet[DTRG_MAX_PACKET];
  struct in_addr address, raw;
  dtrg_msg_t message;
  dtrg_sync_peer_t peers[2];
  dtrg_hub_t hubs[2];
  uint8_t cluster_id[16];
  ssize_t length;

  memset(key, 0x5a, sizeof(key));
  memset(nonce, 0xa5, sizeof(nonce));
  memset(cookie, 0x3c, sizeof(cookie));
  memset(lease_token, 0x7e, sizeof(lease_token));
  memset(cluster_id, 0x19, sizeof(cluster_id));
  CHECK(inet_pton(AF_INET, "10.99.0.2", &address) == 1);
  CHECK(inet_pton(AF_INET, "192.0.2.2", &raw) == 1);

  length =
      dtrg_pack_init(key, 2, address, 24, raw, nonce, packet, sizeof(packet));
  CHECK(length > 0);
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_INIT && message.node_id == 2);
  CHECK(message.address.s_addr == address.s_addr &&
        message.raw.s_addr == raw.s_addr && message.prefix_len == 24);
  CHECK(same_nonce(message.nonce, nonce));
  dtrg_msg_free(&message);

  memset(hubs, 0, sizeof(hubs));
  strcpy(hubs[0].hub_id, "hub-primary");
  strcpy(hubs[1].hub_id, "hub-backup-1");
  CHECK(inet_pton(AF_INET, "192.0.2.1", &hubs[0].address) == 1);
  CHECK(inet_pton(AF_INET, "192.0.2.2", &hubs[1].address) == 1);
  hubs[0].control_port = hubs[1].control_port = 49001;
  hubs[0].data_port = hubs[1].data_port = 49000;
  hubs[0].weight = 1000;
  hubs[1].weight = 900;
  hubs[0].flags = DTRG_HUB_ACTIVE;
  memset(hubs[0].public_key, 1, 32);
  memset(hubs[1].public_key, 2, 32);
  length = dtrg_pack_hub_list(key, 2, cluster_id, 7, DTRG_HA_MODE_DIRECT_PAIR,
                              hubs, 2, packet, sizeof(packet));
  CHECK(length > 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_HUB_LIST && message.term == 7 &&
        message.hub_count == 2 &&
        !strcmp(message.hubs[1].hub_id, "hub-backup-1") &&
        message.hubs[1].weight == 900);
  dtrg_msg_free(&message);

  length = dtrg_pack_challenge(key, 2, address, 24, raw, nonce, cookie, packet,
                               sizeof(packet));
  CHECK(length > 0);
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_CHALLENGE &&
        memcmp(message.cookie, cookie, sizeof(cookie)) == 0);
  dtrg_msg_free(&message);

  length = dtrg_pack_confirm(key, 2, address, 24, raw, nonce, cookie, packet,
                             sizeof(packet));
  CHECK(length > 0);
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_CONFIRM);
  dtrg_msg_free(&message);

  length =
      dtrg_pack_ack(key, 2, 100, 101, address, 24, 49000, nonce, lease_token, 9,
                    7, "hub-primary", packet, sizeof(packet));
  CHECK(length > 0);
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_ACK && message.tunnel_id == 100 &&
        message.remote_tunnel_id == 101 && message.data_port == 49000 &&
        message.epoch == 9 && message.term == 7 &&
        !strcmp(message.leader_id, "hub-primary") &&
        memcmp(message.lease_token, lease_token, sizeof(lease_token)) == 0);
  dtrg_msg_free(&message);

  memset(peers, 0, sizeof(peers));
  peers[0].node_id = 3;
  peers[0].tunnel_id = 102;
  peers[0].remote_tunnel_id = 103;
  CHECK(inet_pton(AF_INET, "10.99.0.3", &peers[0].address) == 1);
  CHECK(inet_pton(AF_INET, "198.51.100.3", &peers[0].raw) == 1);
  peers[0].udp_addr = peers[0].raw;
  peers[0].udp_port = 41003;
  peers[0].generation = 7;
  peers[0].flags = DTRG_PEER_ONLINE;
  peers[1].node_id = 4;
  peers[1].tunnel_id = 104;
  peers[1].remote_tunnel_id = 105;
  CHECK(inet_pton(AF_INET, "10.99.0.4", &peers[1].address) == 1);
  CHECK(inet_pton(AF_INET, "203.0.113.4", &peers[1].raw) == 1);
  peers[1].udp_addr = peers[1].raw;
  peers[1].udp_port = 41004;
  peers[1].generation = 8;
  peers[1].flags = DTRG_PEER_ONLINE;
  length = dtrg_pack_sync(key, 2, nonce, peers, 2, packet, sizeof(packet));
  CHECK(length > 0);
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_SYNC && message.peer_count == 2);
  CHECK(message.peers[0].node_id == 3 && message.peers[0].tunnel_id == 102 &&
        message.peers[0].remote_tunnel_id == 103 &&
        message.peers[0].udp_port == 41003 && message.peers[0].generation == 7);
  CHECK(message.peers[1].node_id == 4 &&
        message.peers[1].address.s_addr == peers[1].address.s_addr);
  dtrg_msg_free(&message);

  length =
      dtrg_pack_refresh(key, 2, lease_token, 11, 9, 0, packet, sizeof(packet));
  CHECK(length > 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_REFRESH && message.counter == 11 &&
        message.epoch == 9 && message.offset == 0);
  dtrg_msg_free(&message);

  length = dtrg_pack_refresh_ack(key, 2, lease_token, 11, 10, raw, 41002,
                                 DTRG_REFRESH_SNAPSHOT, 2, 7, "hub-primary",
                                 49000, peers, 2, packet, sizeof(packet));
  CHECK(length > 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_REFRESH_ACK && message.epoch == 10 &&
        message.observed_port == 41002 && message.peer_count == 2 &&
        message.term == 7 && message.data_port == 49000 &&
        message.peers[1].generation == 8);
  dtrg_msg_free(&message);

  length = dtrg_pack_refresh_ack(key, 2, lease_token, 11, 10, raw, 0,
                                 DTRG_REFRESH_RE_REGISTER, 0, 7, "hub-primary",
                                 49000, NULL, 0, packet, sizeof(packet));
  CHECK(length > 0 && dtrg_parse(key, packet, (size_t)length, &message) == 0);
  CHECK(message.kind == DTRG_REFRESH_ACK &&
        message.flags == DTRG_REFRESH_RE_REGISTER && message.peer_count == 0);
  dtrg_msg_free(&message);

  packet[12] ^= 1;
  CHECK(dtrg_parse(key, packet, (size_t)length, &message) < 0);
  dtrg_msg_free(&message);
  packet[12] ^= 1;
  CHECK(dtrg_parse(key, packet, (size_t)length - 1, &message) < 0);
  dtrg_msg_free(&message);
  CHECK(dtrg_pack_sync(key, 2, nonce, peers, DTRG_MAX_SYNC_PEERS + 1, packet,
                       sizeof(packet)) < 0);
  CHECK(dtrg_pack_sync(key, 2, nonce, peers, 2, packet, 32) < 0);

  puts("C registration protocol tests passed");
  return 0;
}
