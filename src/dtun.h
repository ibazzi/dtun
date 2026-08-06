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

#define DTUN_NAME               "dtun"
#define DTUN_GENL_VERSION       1
#define DTUN_IPPROTO            253
#define DTUN_VERSION            1
#define DTUN_TAG_LEN            16
#define DTUN_KEY_LEN            32
#define DTUN_PROBE_INTERVAL     (5 * HZ)
#define DTUN_PATH_TIMEOUT       (15 * HZ)

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
	__be32 udp_addr;
	__be16 udp_port;
	unsigned long raw_seen;
	unsigned long udp_seen;
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
	u64 node_id;
	struct socket *udp_sock;
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
	__IFLA_DTUN_MAX,
};
#define IFLA_DTUN_MAX (__IFLA_DTUN_MAX - 1)

extern struct genl_family dtun_genl_family;
extern struct list_head dtun_devices;

struct dtun_dev *dtun_dev_by_ifindex(struct net *net, int ifindex);
struct dtun_peer *dtun_peer_by_id(struct dtun_dev *d, u32 tunnel_id);
void dtun_peer_free(struct dtun_peer *peer);
void dtun_peer_put(struct dtun_peer *peer);
int dtun_peer_set_key(struct dtun_peer *peer, const u8 *key, size_t len);
int dtun_add_prefix(struct dtun_peer *peer, __be32 addr, u8 len);
int dtun_del_prefix(struct dtun_peer *peer, __be32 addr, u8 len);
int dtun_genl_register(void);
void dtun_genl_unregister(void);
void dtun_genl_observed_peer(struct dtun_dev *d, struct dtun_peer *peer,
			     __be32 addr, __be16 port, enum dtun_transport transport);

#endif
