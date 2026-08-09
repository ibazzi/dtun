/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DTUN_H
#define _DTUN_H

#include <crypto/hash.h>
#include <linux/atomic.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>

#define DTUN_NAME "dtun"
#define DTUN_GENL_VERSION 1
#define DTUN_IPPROTO 253
#define DTUN_VERSION 1
#define DTUN_TAG_LEN 16
#define DTUN_KEY_LEN 32
#define DTUN_PROBE_MAGIC 0x44545032U
#define DTUN_LOSS_Q16_TWO_PERCENT 1311U

enum dtun_frame_type {
  DTUN_FRAME_DATA = 1,
  DTUN_FRAME_PROBE = 2,
  DTUN_FRAME_KEEPALIVE = 3,
};

enum dtun_transport {
  DTUN_TRANSPORT_RAW = 1,
  DTUN_TRANSPORT_UDP = 2,
  DTUN_TRANSPORT_RELAY = 3,
};

enum dtun_selected_path {
  DTUN_PATH_DOWN = 0,
  DTUN_PATH_RAW = 1,
  DTUN_PATH_UDP = 2,
  DTUN_PATH_HUB = 3,
};

/* The tag authenticates all preceding header bytes plus the inner packet. */
struct dtun_hdr {
  u8 version;
  u8 type;
  __be16 flags;
  __be32 src_tunnel_id;
  __be32 dst_tunnel_id;
  __be64 seq;
  __be64 src_node;
  __be64 dst_node;
  u8 tag[DTUN_TAG_LEN];
} __packed;

struct dtun_probe_payload {
  __be32 magic;
  __be64 probe_id;
} __packed;

enum dtun_health_state {
  DTUN_HEALTH_UNKNOWN = 0,
  DTUN_HEALTH_HEALTHY = 1,
  DTUN_HEALTH_SUSPECT = 2,
  DTUN_HEALTH_OFFLINE = 3,
};

struct dtun_path_health {
  u64 srtt_us;
  u64 rttvar_us;
  u64 probe_id;
  u64 probe_sent_ns;
  unsigned long last_ack;
  unsigned long next_probe;
  unsigned long duplicate_probe;
  u32 loss_q16;
  u32 failed_rounds;
  u8 initialized;
  u8 pending;
  u8 duplicate_pending;
  u8 state;
};

struct dtun_prefix {
  struct list_head list;
  __be32 addr;
  u8 len;
};

#define DTUN_REPLAY_BITMAP_LENS 32
#define DTUN_REPLAY_WINDOW (DTUN_REPLAY_BITMAP_LENS * 64)

struct dtun_peer {
  struct list_head list;
  struct dtun_dev *tdev;
  refcount_t refs;
  /* local ID selects this peer on receive; remote ID is written on send. */
  u32 tunnel_id;
  u32 remote_tunnel_id;
  u64 node_id;
  __be32 raw_addr;
  __be32 raw_validated_addr;
  __be32 udp_addr;
  __be16 udp_port;
  __be32 direct_udp_addr;
  __be16 direct_udp_port;
  u64 candidate_generation;
  bool dynamic_raw;
  struct dtun_path_health raw_health;
  struct dtun_path_health udp_health;
  atomic64_t tx_seq;
  u64 rx_highest;
  u64 rx_window[DTUN_REPLAY_BITMAP_LENS];
  spinlock_t state_lock;
  u8 key[DTUN_KEY_LEN];
  struct crypto_shash *hmac;
  struct list_head prefixes;
};

struct dtun_dev {
  struct net_device *dev;
  __be32 local_addr;
  __be32 hub_addr;
  __be16 udp_port;
  __be16 hub_port;
  spinlock_t hub_lock;
  u64 node_id;
  bool operational;
  struct socket *udp_sock;
  u64 hub_term;
  spinlock_t peer_lock;
  struct list_head peers;
  struct delayed_work probe_work;
  struct list_head global_list;
};

enum dtun_nl_cmd {
  DTUN_CMD_UNSPEC,
  DTUN_CMD_PEER_ADD,
  DTUN_CMD_PEER_DEL,
  DTUN_CMD_PEER_SET,
  DTUN_CMD_ROUTE_ADD,
  DTUN_CMD_ROUTE_DEL,
  DTUN_CMD_PEER_GET,
  DTUN_CMD_STATS_GET,
  DTUN_CMD_PEER_LIST,
  DTUN_CMD_REBIND,
  DTUN_CMD_HUB_SET,
  DTUN_CMD_HUB_MIGRATE,
  DTUN_CMD_ROLE_SET,
  __DTUN_CMD_MAX,
};
#define DTUN_CMD_MAX (__DTUN_CMD_MAX - 1)

enum dtun_nl_attr {
  DTUN_A_UNSPEC,
  DTUN_A_IFINDEX,
  DTUN_A_TUNNEL_ID,
  DTUN_A_NODE_ID,
  DTUN_A_RAW_ADDR,
  DTUN_A_UDP_ADDR,
  DTUN_A_UDP_PORT,
  DTUN_A_KEY,
  DTUN_A_PREFIX,
  DTUN_A_PREFIX_LEN,
  DTUN_A_PATH,
  DTUN_A_RAW_UP,
  DTUN_A_UDP_UP,
  DTUN_A_REMOTE_TUNNEL_ID,
  DTUN_A_DYNAMIC_RAW,
  DTUN_A_CANDIDATE_GENERATION,
  DTUN_A_RENDEZVOUS_UDP_ADDR,
  DTUN_A_RENDEZVOUS_UDP_PORT,
  DTUN_A_DIRECT_UDP_ADDR,
  DTUN_A_DIRECT_UDP_PORT,
  DTUN_A_RAW_VALIDATED_ADDR,
  DTUN_A_SELECTED_PATH,
  DTUN_A_HUB_ADDR,
  DTUN_A_HUB_PORT,
  DTUN_A_HUB_TERM,
  DTUN_A_OPERATIONAL,
  DTUN_A_RAW_HEALTH,
  DTUN_A_UDP_HEALTH,
  DTUN_A_RAW_SRTT_US,
  DTUN_A_UDP_SRTT_US,
  DTUN_A_RAW_RTTVAR_US,
  DTUN_A_UDP_RTTVAR_US,
  DTUN_A_RAW_LOSS_PPM,
  DTUN_A_UDP_LOSS_PPM,
  DTUN_A_RAW_THRESHOLD_MS,
  DTUN_A_UDP_THRESHOLD_MS,
  DTUN_A_RAW_LAST_ACK_MS,
  DTUN_A_UDP_LAST_ACK_MS,
  __DTUN_A_MAX,
};
#define DTUN_A_MAX (__DTUN_A_MAX - 1)

enum dtun_link_attr {
  IFLA_DTUN_UNSPEC,
  IFLA_DTUN_LOCAL,
  IFLA_DTUN_UDP_PORT,
  IFLA_DTUN_NODE_ID,
  IFLA_DTUN_HUB,
  IFLA_DTUN_HUB_PORT,
  IFLA_DTUN_PROBE_INTERVAL_MS_RESERVED,
  IFLA_DTUN_PATH_TIMEOUT_MS_RESERVED,
  __IFLA_DTUN_MAX,
};
#define IFLA_DTUN_MAX (__IFLA_DTUN_MAX - 1)

extern struct genl_family dtun_genl_family;
extern struct list_head dtun_devices;

struct dtun_dev *dtun_dev_by_ifindex(struct net *net, int ifindex);
struct dtun_peer *dtun_peer_by_id(struct dtun_dev *d, u32 tunnel_id);
struct dtun_peer *dtun_peer_by_node(struct dtun_dev *d, u64 node_id);
void dtun_peer_free(struct dtun_peer *peer);
void dtun_peer_put(struct dtun_peer *peer);
int dtun_peer_set_key(struct dtun_peer *peer, const u8 *key, size_t len);
int dtun_add_prefix(struct dtun_peer *peer, __be32 addr, u8 len);
int dtun_del_prefix(struct dtun_peer *peer, __be32 addr, u8 len);
int dtun_genl_register(void);
void dtun_genl_unregister(void);
void dtun_genl_observed_peer(struct dtun_dev *d, struct dtun_peer *peer,
                             __be32 addr, __be16 port,
                             enum dtun_transport transport);
void dtun_path_health_init(struct dtun_path_health *health);
u32 dtun_path_probe_interval_ms(const struct dtun_peer *peer,
                                const struct dtun_path_health *health);
u32 dtun_path_rto_ms(const struct dtun_peer *peer,
                     const struct dtun_path_health *health);
u32 dtun_path_offline_ms(const struct dtun_peer *peer,
                         const struct dtun_path_health *health);
u32 dtun_path_loss_ppm(const struct dtun_path_health *health);
void dtun_path_note_ack(struct dtun_peer *peer, struct dtun_path_health *health,
                        u64 probe_id);
void dtun_path_tick(struct dtun_peer *peer, struct dtun_path_health *health);
bool dtun_path_available(const struct dtun_path_health *health);

#endif
