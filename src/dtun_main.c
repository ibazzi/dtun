// SPDX-License-Identifier: GPL-2.0
#include <crypto/sha2.h>
#include <linux/etherdevice.h>
#include <linux/crypto.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/sockptr.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/udp.h>

#include "dtun.h"

LIST_HEAD(dtun_devices);

static const struct nla_policy dtun_link_policy[IFLA_DTUN_MAX + 1] = {
	[IFLA_DTUN_LOCAL] = { .type = NLA_U32 },
	[IFLA_DTUN_UDP_PORT] = { .type = NLA_U16 },
	[IFLA_DTUN_NODE_ID] = { .type = NLA_U64 },
	[IFLA_DTUN_HUB] = { .type = NLA_U32 },
	[IFLA_DTUN_HUB_PORT] = { .type = NLA_U16 },
};

static int dtun_tag(struct dtun_peer *peer, const struct dtun_hdr *hdr,
		    const u8 *payload, size_t payload_len, u8 tag[DTUN_TAG_LEN]);
static int dtun_tag_skb(struct dtun_peer *peer, const struct dtun_hdr *hdr,
			struct sk_buff *skb, u8 tag[DTUN_TAG_LEN]);
static bool dtun_replay_ok(struct dtun_peer *peer, u64 seq);

/*
 * crypto_memneq() is not exported by every supported 6.6+ kernel.  Keep the
 * authentication check local and fixed-time for the protocol's fixed-size tag.
 */
static bool dtun_tag_equal(const u8 left[DTUN_TAG_LEN],
			   const u8 right[DTUN_TAG_LEN])
{
	volatile u8 different = 0;
	unsigned int i;

	for (i = 0; i < DTUN_TAG_LEN; i++)
		different |= left[i] ^ right[i];
	return different == 0;
}

static struct dtun_peer *dtun_peer_get_by_id(struct dtun_dev *d, u32 tunnel_id)
{
	struct dtun_peer *peer;

	spin_lock_bh(&d->peer_lock);
	peer = dtun_peer_by_id(d, tunnel_id);
	if (peer)
		refcount_inc(&peer->refs);
	spin_unlock_bh(&d->peer_lock);
	return peer;
}

static struct dtun_peer *dtun_peer_get_by_node(struct dtun_dev *d, u64 node_id)
{
	struct dtun_peer *peer;

	spin_lock_bh(&d->peer_lock);
	peer = dtun_peer_by_node(d, node_id);
	if (peer)
		refcount_inc(&peer->refs);
	spin_unlock_bh(&d->peer_lock);
	return peer;
}

static int dtun_ingress(struct dtun_dev *d, struct sk_buff *skb, __be32 src,
			__be16 port, enum dtun_transport transport)
{
	struct dtun_hdr *hdr;
	struct dtun_peer *peer = NULL;
	u8 tag[DTUN_TAG_LEN];
	u64 src_node, dst_node;
	int err;

	if (!pskb_may_pull(skb, sizeof(*hdr)))
		goto drop;
	hdr = (struct dtun_hdr *)skb->data;
	if (hdr->version != DTUN_VERSION || hdr->type < DTUN_FRAME_DATA ||
	    hdr->type > DTUN_FRAME_KEEPALIVE)
		goto drop;
	src_node = be64_to_cpu(hdr->src_node);
	dst_node = be64_to_cpu(hdr->dst_node);
	if (dst_node != d->node_id) {
		if (d->node_id != 1)
			goto drop;
		peer = dtun_peer_get_by_node(d, src_node);
	} else {
		peer = dtun_peer_get_by_id(d, ntohl(hdr->dst_tunnel_id));
		if (!peer || peer->node_id != src_node)
			goto drop;
	}
	if (!peer)
		goto drop;
	/*
	 * A spoke behind NAT cannot know the public source port selected by its
	 * gateway.  Do not reject a changed UDP candidate before authenticating
	 * the frame: tunnel_id selects the peer key and the HMAC below proves that
	 * the sender owns that peer.  The authenticated candidate is learned under
	 * state_lock afterwards.  Raw-IP remains pinned to its configured address.
	 */
	spin_lock_bh(&peer->state_lock);
	if (transport == DTUN_TRANSPORT_RAW && src != peer->raw_addr)
		goto drop_unlock;
	if (peer->hmac && !IS_ERR(peer->hmac)) {
		memcpy(tag, hdr->tag, sizeof(tag));
		err = dtun_tag_skb(peer, hdr, skb, hdr->tag);
		if (err || !dtun_tag_equal(tag, hdr->tag))
			goto drop_unlock;
		memcpy(hdr->tag, tag, sizeof(tag));
	}
	if (!dtun_replay_ok(peer, be64_to_cpu(hdr->seq))) {
		goto drop_unlock;
	}
	if (transport == DTUN_TRANSPORT_RAW)
		peer->raw_seen = jiffies;
	else {
		peer->udp_seen = jiffies;
		if (src != d->hub_addr || port != d->hub_port) {
			/* Learn the authenticated source port too: a NAT'd spoke's
			 * public mapping is only observable from inbound frames.  The
			 * configured Hub relay endpoint is kept stable. */
			peer->udp_port = port;
			peer->udp_addr = src;
		}
	}
	spin_unlock_bh(&peer->state_lock);
	if (transport == DTUN_TRANSPORT_UDP)
		dtun_genl_observed_peer(d, peer, src, port, transport);
	if (hdr->type != DTUN_FRAME_DATA) {
		dtun_peer_put(peer);
		kfree_skb(skb);
		return 0;
	}
	skb_pull(skb, sizeof(*hdr));
	if (!pskb_may_pull(skb, 1))
		goto drop;
	if ((skb->data[0] >> 4) != 4 && (skb->data[0] >> 4) != 6)
		goto drop;
	/* The skb came from an outer IP/UDP socket.  Make it look like a freshly
	 * received inner L3 packet before reinjecting it into the network stack. */
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->encapsulation = 0;
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_level = 0;
	skb->pkt_type = PACKET_HOST;
	skb->dev = d->dev;
	/* The outer socket's skb still carries the outer input route (usually
	 * RTN_LOCAL at the receiving node).  Without dropping it, the IP stack
	 * treats reinjected inner packets as locally destined and never
	 * forwards hub-relayed spoke-to-spoke traffic. */
	skb_dst_drop(skb);
	skb->protocol = (skb->data[0] >> 4) == 6 ? htons(ETH_P_IPV6) :
		htons(ETH_P_IP);
	d->dev->stats.rx_packets++;
	d->dev->stats.rx_bytes += skb->len;
	dtun_peer_put(peer);
	netif_rx(skb);
	return 0;

drop_unlock:
	spin_unlock_bh(&peer->state_lock);
drop:
	if (peer)
		dtun_peer_put(peer);
	d->dev->stats.rx_dropped++;
	kfree_skb(skb);
	return 0;
}

static int dtun_udp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct dtun_dev *d = READ_ONCE(sk->sk_user_data);
	struct udphdr *uh;
	__be32 src;
	__be16 port;

	if (!d) {
		kfree_skb(skb);
		return 0;
	}
	uh = udp_hdr(skb);
	src = ip_hdr(skb)->saddr;
	port = uh->source;
	/* UDP invokes encapsulation hooks before it pulls its transport header. */
	if (!pskb_may_pull(skb, sizeof(*uh))) {
		kfree_skb(skb);
		return 0;
	}
	skb_pull(skb, sizeof(*uh));
	return dtun_ingress(d, skb, src, port, DTUN_TRANSPORT_UDP);
}

static int dtun_raw_rcv(struct sk_buff *skb)
{
	struct dtun_hdr *hdr;
	struct dtun_dev *d;
	int ret = 0;

	if (!pskb_may_pull(skb, sizeof(*hdr)))
		goto drop;
	hdr = (struct dtun_hdr *)skb->data;
	rcu_read_lock();
	list_for_each_entry_rcu(d, &dtun_devices, global_list) {
		if (hdr->dst_node == cpu_to_be64(d->node_id)) {
			ret = dtun_ingress(d, skb, ip_hdr(skb)->saddr, 0,
					   DTUN_TRANSPORT_RAW);
			rcu_read_unlock();
			return ret;
		}
	}
	rcu_read_unlock();
drop:
	kfree_skb(skb);
	return 0;
}

static const struct net_protocol dtun_ip_protocol = {
	.handler = dtun_raw_rcv,
	.no_policy = 1,
};

static struct dtun_peer *dtun_route_peer(struct dtun_dev *d, struct sk_buff *skb)
{
	struct dtun_peer *peer, *best = NULL;
	__be32 dst;
	int best_len = -1;

	if (skb->protocol != htons(ETH_P_IP) || !pskb_may_pull(skb, sizeof(struct iphdr)))
		return NULL;
	dst = ip_hdr(skb)->daddr;
	spin_lock_bh(&d->peer_lock);
	list_for_each_entry(peer, &d->peers, list) {
		struct dtun_prefix *prefix;

		list_for_each_entry(prefix, &peer->prefixes, list) {
			u32 mask = prefix->len ? htonl(~0U << (32 - prefix->len)) : 0;

			if ((dst & mask) == (prefix->addr & mask) && prefix->len > best_len) {
				best = peer;
				best_len = prefix->len;
			}
		}
	}
	if (best)
		refcount_inc(&best->refs);
	spin_unlock_bh(&d->peer_lock);
	return best;
}

/*
 * Multicast has no single longest-prefix destination.  Take references to a
 * snapshot of every configured peer so the packet can be replicated without
 * holding peer_lock across route lookup and outer transmission.
 */
static int dtun_peer_snapshot(struct dtun_dev *d, struct dtun_peer ***snapshot)
{
	struct dtun_peer **peers;
	struct dtun_peer *peer;
	unsigned int count = 0, used = 0;

	*snapshot = NULL;
	spin_lock_bh(&d->peer_lock);
	list_for_each_entry(peer, &d->peers, list)
		count++;
	spin_unlock_bh(&d->peer_lock);
	if (!count)
		return 0;

	peers = kmalloc_array(count, sizeof(*peers), GFP_ATOMIC);
	if (!peers)
		return -ENOMEM;

	spin_lock_bh(&d->peer_lock);
	list_for_each_entry(peer, &d->peers, list) {
		if (used == count)
			break;
		refcount_inc(&peer->refs);
		peers[used++] = peer;
	}
	spin_unlock_bh(&d->peer_lock);
	*snapshot = peers;
	return used;
}

static enum dtun_transport dtun_choose_path(struct dtun_dev *d,
					     struct dtun_peer *peer,
					     __be32 *addr, __be16 *port)
{
	spin_lock_bh(&peer->state_lock);
	if (peer->raw_addr && time_before(jiffies, peer->raw_seen + DTUN_PATH_TIMEOUT)) {
		*addr = peer->raw_addr;
		*port = 0;
		spin_unlock_bh(&peer->state_lock);
		return DTUN_TRANSPORT_RAW;
	}
	if (peer->udp_addr && peer->udp_port &&
	    time_before(jiffies, peer->udp_seen + DTUN_PATH_TIMEOUT)) {
		*addr = peer->udp_addr;
		*port = peer->udp_port;
		spin_unlock_bh(&peer->state_lock);
		return DTUN_TRANSPORT_UDP;
	}
	spin_unlock_bh(&peer->state_lock);
	*addr = d->hub_addr;
	*port = d->hub_port;
	return DTUN_TRANSPORT_RELAY;
}

static int dtun_tag(struct dtun_peer *peer, const struct dtun_hdr *hdr,
		    const u8 *payload, size_t payload_len, u8 tag[DTUN_TAG_LEN])
{
	if (!peer->hmac || IS_ERR(peer->hmac)) {
		memset(tag, 0, DTUN_TAG_LEN);
		return 0;
	}
	SHASH_DESC_ON_STACK(desc, peer->hmac);
	u8 digest[SHA256_DIGEST_SIZE];
	int err;

	desc->tfm = peer->hmac;
	err = crypto_shash_init(desc);
	if (!err)
		err = crypto_shash_update(desc, (const u8 *)hdr,
					offsetof(struct dtun_hdr, tag));
	if (!err && payload_len)
		err = crypto_shash_update(desc, payload, payload_len);
	if (!err)
		err = crypto_shash_final(desc, digest);
	if (!err)
		memcpy(tag, digest, DTUN_TAG_LEN);
	memzero_explicit(digest, sizeof(digest));
	return err;
}

static int dtun_tag_skb(struct dtun_peer *peer, const struct dtun_hdr *hdr,
			struct sk_buff *skb, u8 tag[DTUN_TAG_LEN])
{
	if (!peer->hmac || IS_ERR(peer->hmac)) {
		memset(tag, 0, DTUN_TAG_LEN);
		return 0;
	}
	SHASH_DESC_ON_STACK(desc, peer->hmac);
	u8 digest[SHA256_DIGEST_SIZE];
	u8 block[128];
	unsigned int offset = sizeof(*hdr);
	int err;

	desc->tfm = peer->hmac;
	err = crypto_shash_init(desc);
	if (!err)
		err = crypto_shash_update(desc, (const u8 *)hdr,
					 offsetof(struct dtun_hdr, tag));
	while (!err && offset < skb->len) {
		unsigned int len = min_t(unsigned int, sizeof(block), skb->len - offset);

		err = skb_copy_bits(skb, offset, block, len);
		if (!err)
			err = crypto_shash_update(desc, block, len);
		offset += len;
	}
	if (!err)
		err = crypto_shash_final(desc, digest);
	if (!err)
		memcpy(tag, digest, DTUN_TAG_LEN);
	memzero_explicit(block, sizeof(block));
	memzero_explicit(digest, sizeof(digest));
	return err;
}

static bool dtun_replay_ok(struct dtun_peer *peer, u64 seq)
{
	u64 diff;
	u32 index, bit;

	if (unlikely(seq == 0))
		return false;

	if (seq > peer->rx_highest) {
		diff = seq - peer->rx_highest;
		if (diff < DTUN_REPLAY_WINDOW) {
			u32 old_index = (peer->rx_highest / 64) % DTUN_REPLAY_BITMAP_LENS;
			u32 new_index = (seq / 64) % DTUN_REPLAY_BITMAP_LENS;
			if (new_index != old_index) {
				u32 i = (old_index + 1) % DTUN_REPLAY_BITMAP_LENS;
				while (i != new_index) {
					peer->rx_window[i] = 0;
					i = (i + 1) % DTUN_REPLAY_BITMAP_LENS;
				}
				peer->rx_window[new_index] = 0;
			}
		} else {
			memset(peer->rx_window, 0, sizeof(peer->rx_window));
		}
		peer->rx_highest = seq;
		index = (seq / 64) % DTUN_REPLAY_BITMAP_LENS;
		bit = seq % 64;
		peer->rx_window[index] |= (1ULL << bit);
		return true;
	}

	diff = peer->rx_highest - seq;
	if (diff >= DTUN_REPLAY_WINDOW)
		return false;

	index = (seq / 64) % DTUN_REPLAY_BITMAP_LENS;
	bit = seq % 64;
	if (peer->rx_window[index] & (1ULL << bit))
		return false;

	peer->rx_window[index] |= (1ULL << bit);
	return true;
}

static void dtun_udp_ip_xmit(struct dtun_dev *d, struct rtable *rt,
			      struct sk_buff *skb, __be32 source, __be32 addr,
			      int stats_len)
{
	struct net *net = dev_net(d->dev);
	struct iphdr *ip;
	int result;

	skb_dst_set(skb, &rt->dst);
	skb->dev = rt->dst.dev;
	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
	ip = (struct iphdr *)skb_push(skb, sizeof(*ip));
	skb_reset_network_header(skb);
	ip->version = 4;
	ip->ihl = sizeof(*ip) / 4;
	ip->tos = 0;
	ip->tot_len = htons(skb->len);
	ip->frag_off = htons(IP_DF);
	ip->ttl = IPDEFTTL;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = source;
	ip->daddr = addr;
	ip->check = 0;
	ip_select_ident(net, skb, NULL);
	ip_send_check(ip);
	skb->protocol = htons(ETH_P_IP);
	result = ip_local_out(net, NULL, skb);
	iptunnel_xmit_stats(d->dev, net_xmit_eval(result) ? -1 : stats_len);
}

static int dtun_send_path(struct dtun_dev *d, struct dtun_peer *peer, u8 type,
			  const u8 *payload, size_t payload_len,
			  enum dtun_transport transport, __be32 addr, __be16 port)
{
	struct dtun_hdr *hdr;
	struct flowi4 fl4;
	struct rtable *rt;
	struct sk_buff *skb;
	__be32 source;
	size_t frame_len = sizeof(*hdr) + payload_len;
	int err;

	if (!addr)
		return -ENETUNREACH;
	if (transport != DTUN_TRANSPORT_RAW && !port)
		return -ENETUNREACH;

	/* Build an outer payload skb and hand it directly to the IPv4 tunnel
	 * helpers.  In particular, do not call kernel_sendmsg() from
	 * ndo_start_xmit: socket send may re-enable bottom halves while the inner
	 * transport socket is locked, which can deadlock bidirectional TCP. */
	skb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) +
				sizeof(struct udphdr) + frame_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, LL_MAX_HEADER + sizeof(struct iphdr) +
		    sizeof(struct udphdr));
	hdr = skb_put(skb, frame_len);
	spin_lock_bh(&peer->state_lock);
	hdr->version = DTUN_VERSION;
	hdr->type = type;
	hdr->flags = 0;
	hdr->src_tunnel_id = htonl(peer->tunnel_id);
	hdr->dst_tunnel_id = htonl(peer->remote_tunnel_id);
	hdr->seq = cpu_to_be64(atomic64_inc_return(&peer->tx_seq));
	hdr->src_node = cpu_to_be64(d->node_id);
	hdr->dst_node = cpu_to_be64(peer->node_id);
	memset(hdr->tag, 0, sizeof(hdr->tag));
	if (payload_len)
		memcpy((u8 *)hdr + sizeof(*hdr), payload, payload_len);
	err = dtun_tag(peer, hdr, (u8 *)hdr + sizeof(*hdr), payload_len,
		       hdr->tag);
	spin_unlock_bh(&peer->state_lock);
	if (err)
		goto out_free;

	skb->dev = d->dev;
	skb->protocol = htons(ETH_P_IP);
	if (payload_len)
		skb_set_inner_network_header(skb, sizeof(*hdr));
	if (transport == DTUN_TRANSPORT_RAW) {
		memset(&fl4, 0, sizeof(fl4));
		fl4.flowi4_proto = DTUN_IPPROTO;
		fl4.saddr = d->local_addr;
		fl4.daddr = addr;
		rt = ip_route_output_key(dev_net(d->dev), &fl4);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			goto out_free;
		}
		source = fl4.saddr;
		if (!source) {
			ip_rt_put(rt);
			err = -EADDRNOTAVAIL;
			goto out_free;
		}
		iptunnel_xmit(NULL, rt, skb, source, addr, DTUN_IPPROTO,
			      0, IPDEFTTL, 0, false);
	} else {
		struct udphdr *udp;

		rt = ip_route_output_ports(dev_net(d->dev), &fl4,
					   NULL, addr, d->local_addr,
					   port, d->udp_port, IPPROTO_UDP, 0, 0);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			goto out_free;
		}
		source = fl4.saddr;
		if (!source) {
			ip_rt_put(rt);
			err = -EADDRNOTAVAIL;
			goto out_free;
		}
		/* Construct UDP and IPv4 explicitly.  Socket and generic tunnel sends
		 * can carry reroute state that suppresses the ordinary LOCAL_OUT hook;
		 * this fresh skb deliberately enters ip_local_out() with a clean IPCB. */
		udp = (struct udphdr *)skb_push(skb, sizeof(*udp));
		skb_reset_transport_header(skb);
		udp->source = d->udp_port;
		udp->dest = port;
		udp->len = htons(skb->len);
		udp->check = 0;
		udp_set_csum(false, skb, source, addr, skb->len);
		dtun_udp_ip_xmit(d, rt, skb, source, addr,
				 payload_len ? (int)payload_len : (int)frame_len);
	}
	return 0;

out_free:
	kfree_skb(skb);
	return err;
}

static int dtun_send(struct dtun_dev *d, struct dtun_peer *peer, u8 type,
		     const u8 *payload, size_t payload_len)
{
	__be32 addr;
	__be16 port;
	enum dtun_transport transport;

	transport = dtun_choose_path(d, peer, &addr, &port);
	return dtun_send_path(d, peer, type, payload, payload_len, transport, addr, port);
}

static netdev_tx_t dtun_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct dtun_dev *d = netdev_priv(dev);
	struct dtun_peer **peers = NULL;
	struct dtun_peer *peer = NULL;
	unsigned int peer_count = 0, i;
	bool multicast = false;
	u8 *payload;
	int err;

	if (skb->protocol == htons(ETH_P_IP) &&
	    pskb_may_pull(skb, sizeof(struct iphdr)))
		multicast = ipv4_is_multicast(ip_hdr(skb)->daddr);

	if (multicast) {
		err = dtun_peer_snapshot(d, &peers);
		if (err > 0)
			peer_count = err;
	} else {
		peer = dtun_route_peer(d, skb);
	}
	if ((!multicast && !peer) || (multicast && !peer_count)) {
		dev->stats.tx_dropped++;
		kfree(peers);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	payload = kmalloc(skb->len, GFP_ATOMIC);
	if (!payload || skb_copy_bits(skb, 0, payload, skb->len)) {
		dev->stats.tx_dropped++;
		kfree(payload);
		if (peer)
			dtun_peer_put(peer);
		for (i = 0; i < peer_count; i++)
			dtun_peer_put(peers[i]);
		kfree(peers);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	if (multicast) {
		for (i = 0; i < peer_count; i++) {
			err = dtun_send(d, peers[i], DTUN_FRAME_DATA, payload,
					skb->len);
			if (err)
				DEV_STATS_INC(dev, tx_errors);
			dtun_peer_put(peers[i]);
		}
		kfree(peers);
	} else {
		err = dtun_send(d, peer, DTUN_FRAME_DATA, payload, skb->len);
		dtun_peer_put(peer);
		if (err)
			DEV_STATS_INC(dev, tx_errors);
	}
	kfree(payload);
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void dtun_get_stats64(struct net_device *dev,
			     struct rtnl_link_stats64 *stats)
{
	stats->rx_packets = READ_ONCE(dev->stats.rx_packets);
	stats->rx_bytes = READ_ONCE(dev->stats.rx_bytes);
	stats->rx_errors = READ_ONCE(dev->stats.rx_errors);
	stats->rx_dropped = READ_ONCE(dev->stats.rx_dropped);
	stats->tx_errors = READ_ONCE(dev->stats.tx_errors);
	stats->tx_dropped = READ_ONCE(dev->stats.tx_dropped);
	stats->tx_aborted_errors = READ_ONCE(dev->stats.tx_aborted_errors);
	dev_fetch_sw_netstats(stats, dev->tstats);
}

static const struct net_device_ops dtun_netdev_ops = {
	.ndo_start_xmit = dtun_xmit,
	.ndo_get_stats64 = dtun_get_stats64,
};

static void dtun_free_netdev(struct net_device *dev)
{
	free_percpu(dev->tstats);
	dev->tstats = NULL;
}

static void dtun_setup(struct net_device *dev)
{
	dev->netdev_ops = &dtun_netdev_ops;
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->tx_queue_len = 10000;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	/* IPv4 + UDP + dtun framing adds 76 bytes.  1200 leaves room for
	 * common NAT, PPPoE and cloud underlays without outer fragmentation. */
	dev->mtu = 1200;
	dev->needs_free_netdev = true;
	dev->priv_destructor = dtun_free_netdev;
}

static int dtun_open_sockets(struct dtun_dev *d)
{
	struct sockaddr_in sin = { .sin_family = AF_INET };
	int encap = UDP_ENCAP_L2TPINUDP;
	int err;

	err = sock_create_kern(dev_net(d->dev), AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			       &d->udp_sock);
	if (err)
		return err;

	d->udp_sock->sk->sk_sndbuf = 4 * 1024 * 1024;
	d->udp_sock->sk->sk_rcvbuf = 4 * 1024 * 1024;
	sin.sin_addr.s_addr = d->local_addr;
	sin.sin_port = d->udp_port;
	err = kernel_bind(d->udp_sock, (struct sockaddr *)&sin, sizeof(sin));
	if (err)
		goto err_udp;
	/* Enable UDP's encapsulation receive path, including its static key. */
	err = do_sock_setsockopt(d->udp_sock, false, IPPROTO_UDP, UDP_ENCAP,
			   KERNEL_SOCKPTR(&encap), sizeof(encap));
	if (err) {
		netdev_err(d->dev, "failed to enable UDP encapsulation: %d\n", err);
		goto err_udp;
	}
	udp_sk(d->udp_sock->sk)->encap_rcv = dtun_udp_rcv;
	WRITE_ONCE(d->udp_sock->sk->sk_user_data, d);
	return 0;
err_udp:
	sock_release(d->udp_sock);
	d->udp_sock = NULL;
	return err;
}

static void dtun_probe_work(struct work_struct *work)
{
	struct dtun_dev *d = container_of(to_delayed_work(work), struct dtun_dev,
					  probe_work);
	struct dtun_peer *peer;
	struct dtun_peer **peers;
	unsigned int count = 0, used = 0, i;

	spin_lock_bh(&d->peer_lock);
	list_for_each_entry(peer, &d->peers, list)
		count++;
	spin_unlock_bh(&d->peer_lock);
	peers = count ? kcalloc(count, sizeof(*peers), GFP_KERNEL) : NULL;
	if (count && !peers)
		goto reschedule;
	spin_lock_bh(&d->peer_lock);
	list_for_each_entry(peer, &d->peers, list) {
		if (used == count)
			break;
		refcount_inc(&peer->refs);
		peers[used++] = peer;
	}
	spin_unlock_bh(&d->peer_lock);
	for (i = 0; i < used; i++) {
		__be32 raw_addr, udp_addr;
		__be16 udp_port;

		peer = peers[i];
		spin_lock_bh(&peer->state_lock);
		raw_addr = peer->raw_addr;
		udp_addr = peer->udp_addr;
		udp_port = peer->udp_port;
		spin_unlock_bh(&peer->state_lock);
		if (raw_addr)
			dtun_send_path(d, peer, DTUN_FRAME_PROBE, NULL, 0,
				       DTUN_TRANSPORT_RAW, raw_addr, 0);
		if (udp_addr && udp_port)
			dtun_send_path(d, peer, DTUN_FRAME_PROBE, NULL, 0,
				       DTUN_TRANSPORT_UDP, udp_addr, udp_port);
		else if (d->hub_addr)
			dtun_send_path(d, peer, DTUN_FRAME_KEEPALIVE, NULL, 0,
				       DTUN_TRANSPORT_RELAY, d->hub_addr, d->hub_port);
		dtun_peer_put(peer);
	}
	kfree(peers);

reschedule:
	schedule_delayed_work(&d->probe_work, DTUN_PROBE_INTERVAL);
}

static int dtun_newlink(struct net *net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	struct dtun_dev *d = netdev_priv(dev);
	int err;

	if (!data || !data[IFLA_DTUN_LOCAL] || !data[IFLA_DTUN_UDP_PORT] ||
	    !data[IFLA_DTUN_NODE_ID])
		return -EINVAL;
	if (!dev->tstats)
		return -ENOMEM;
	d->dev = dev;
	d->local_addr = nla_get_be32(data[IFLA_DTUN_LOCAL]);
	d->udp_port = nla_get_be16(data[IFLA_DTUN_UDP_PORT]);
	d->node_id = nla_get_u64(data[IFLA_DTUN_NODE_ID]);
	if (data[IFLA_DTUN_HUB])
		d->hub_addr = nla_get_be32(data[IFLA_DTUN_HUB]);
	if (data[IFLA_DTUN_HUB_PORT])
		d->hub_port = nla_get_be16(data[IFLA_DTUN_HUB_PORT]);
	else
		d->hub_port = d->udp_port;
	spin_lock_init(&d->peer_lock);
	INIT_LIST_HEAD(&d->peers);
	INIT_LIST_HEAD(&d->global_list);
	INIT_DELAYED_WORK(&d->probe_work, dtun_probe_work);
	err = dtun_open_sockets(d);
	if (err)
		return err;
	err = register_netdevice(dev);
	if (err) {
		sock_release(d->udp_sock);
		d->udp_sock = NULL;
		return err;
	}
	list_add_rcu(&d->global_list, &dtun_devices);
	schedule_delayed_work(&d->probe_work, DTUN_PROBE_INTERVAL);
	return 0;
}

static void dtun_dellink(struct net_device *dev, struct list_head *head)
{
	struct dtun_dev *d = netdev_priv(dev);
	struct dtun_peer *peer, *next;

	netif_tx_disable(dev);
	cancel_delayed_work_sync(&d->probe_work);
	if (d->udp_sock)
		WRITE_ONCE(d->udp_sock->sk->sk_user_data, NULL);
	list_del_rcu(&d->global_list);
	synchronize_rcu();
	synchronize_net();
	spin_lock_bh(&d->peer_lock);
	list_for_each_entry_safe(peer, next, &d->peers, list) {
		list_del(&peer->list);
		spin_unlock_bh(&d->peer_lock);
		dtun_peer_put(peer);
		spin_lock_bh(&d->peer_lock);
	}
	spin_unlock_bh(&d->peer_lock);
	if (d->udp_sock)
		sock_release(d->udp_sock);
	unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops dtun_link_ops = {
	.kind = DTUN_NAME,
	.priv_size = sizeof(struct dtun_dev),
	.setup = dtun_setup,
	.maxtype = IFLA_DTUN_MAX,
	.policy = dtun_link_policy,
	.newlink = dtun_newlink,
	.dellink = dtun_dellink,
};

struct dtun_dev *dtun_dev_by_ifindex(struct net *net, int ifindex)
{
	struct net_device *dev = dev_get_by_index(net, ifindex);
	struct dtun_dev *d = NULL;

	if (dev && dev->rtnl_link_ops == &dtun_link_ops)
		d = netdev_priv(dev);
	if (dev)
		dev_put(dev);
	return d;
}

struct dtun_peer *dtun_peer_by_id(struct dtun_dev *d, u32 tunnel_id)
{
	struct dtun_peer *peer;

	list_for_each_entry(peer, &d->peers, list)
		if (peer->tunnel_id == tunnel_id)
			return peer;
	return NULL;
}

struct dtun_peer *dtun_peer_by_node(struct dtun_dev *d, u64 node_id)
{
	struct dtun_peer *peer;

	list_for_each_entry(peer, &d->peers, list)
		if (peer->node_id == node_id)
			return peer;
	return NULL;
}

int dtun_peer_set_key(struct dtun_peer *peer, const u8 *key, size_t len)
{
	struct crypto_shash *hmac;
	struct crypto_shash *old;
	int err;

	if (len != DTUN_KEY_LEN)
		return -EINVAL;
	hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(hmac))
		return PTR_ERR(hmac);
	err = crypto_shash_setkey(hmac, key, DTUN_KEY_LEN);
	if (err) {
		crypto_free_shash(hmac);
		return err;
	}
	spin_lock_bh(&peer->state_lock);
	old = peer->hmac;
	memcpy(peer->key, key, DTUN_KEY_LEN);
	peer->hmac = hmac;
	peer->rx_highest = 0;
	memset(peer->rx_window, 0, sizeof(peer->rx_window));
	spin_unlock_bh(&peer->state_lock);
	if (old && !IS_ERR(old))
		crypto_free_shash(old);
	return 0;
}

void dtun_peer_put(struct dtun_peer *peer)
{
	if (refcount_dec_and_test(&peer->refs))
		dtun_peer_free(peer);
}

void dtun_peer_free(struct dtun_peer *peer)
{
	struct dtun_prefix *prefix, *next;

	list_for_each_entry_safe(prefix, next, &peer->prefixes, list) {
		list_del(&prefix->list);
		kfree(prefix);
	}
	if (peer->hmac && !IS_ERR(peer->hmac))
		crypto_free_shash(peer->hmac);
	memzero_explicit(peer->key, sizeof(peer->key));
	kfree(peer);
}

int dtun_add_prefix(struct dtun_peer *peer, __be32 addr, u8 len)
{
	struct dtun_prefix *prefix;

	if (len > 32)
		return -EINVAL;
	list_for_each_entry(prefix, &peer->prefixes, list)
		if (prefix->addr == addr && prefix->len == len)
			return -EEXIST;
	prefix = kzalloc(sizeof(*prefix), GFP_KERNEL);
	if (!prefix)
		return -ENOMEM;
	prefix->addr = addr;
	prefix->len = len;
	list_add_tail(&prefix->list, &peer->prefixes);
	return 0;
}

int dtun_del_prefix(struct dtun_peer *peer, __be32 addr, u8 len)
{
	struct dtun_prefix *prefix, *next;

	list_for_each_entry_safe(prefix, next, &peer->prefixes, list) {
		if (prefix->addr == addr && prefix->len == len) {
			list_del(&prefix->list);
			kfree(prefix);
			return 0;
		}
	}
	return -ENOENT;
}

static int __init dtun_init(void)
{
	int err;

	err = rtnl_link_register(&dtun_link_ops);
	if (err)
		return err;
	err = dtun_genl_register();
	if (err) {
		rtnl_link_unregister(&dtun_link_ops);
		return err;
	}
	err = inet_add_protocol(&dtun_ip_protocol, DTUN_IPPROTO);
	if (err) {
		dtun_genl_unregister();
		rtnl_link_unregister(&dtun_link_ops);
		return err;
	}
	pr_info("dtun: loaded (IPv4 protocol %u, UDP dual transport)\n", DTUN_IPPROTO);
	return 0;
}

static void __exit dtun_exit(void)
{
	inet_del_protocol(&dtun_ip_protocol, DTUN_IPPROTO);
	dtun_genl_unregister();
	rtnl_link_unregister(&dtun_link_ops);
}

module_init(dtun_init);
module_exit(dtun_exit);
MODULE_DESCRIPTION("Dual transport authenticated L3 tunnel");
MODULE_AUTHOR("OpenAI");
MODULE_LICENSE("GPL");
