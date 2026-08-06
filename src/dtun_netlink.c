// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>

#include "dtun.h"

static const struct nla_policy dtun_nl_policy[DTUN_A_MAX + 1] = {
	[DTUN_A_IFINDEX] = { .type = NLA_U32 },
	[DTUN_A_TUNNEL_ID] = { .type = NLA_U32 },
	[DTUN_A_NODE_ID] = { .type = NLA_U64 },
	[DTUN_A_RAW_ADDR] = { .type = NLA_BINARY, .len = sizeof(__be32) },
	[DTUN_A_UDP_ADDR] = { .type = NLA_BINARY, .len = sizeof(__be32) },
	[DTUN_A_UDP_PORT] = { .type = NLA_U16 },
	[DTUN_A_KEY] = { .type = NLA_BINARY, .len = DTUN_KEY_LEN },
	[DTUN_A_PREFIX] = { .type = NLA_BINARY, .len = sizeof(__be32) },
	[DTUN_A_PREFIX_LEN] = { .type = NLA_U8 },
	[DTUN_A_REMOTE_TUNNEL_ID] = { .type = NLA_U32 },
};

static struct dtun_dev *dtun_nl_dev(struct genl_info *info)
{
	if (!info->attrs[DTUN_A_IFINDEX])
		return NULL;
	return dtun_dev_by_ifindex(genl_info_net(info),
				   nla_get_u32(info->attrs[DTUN_A_IFINDEX]));
}

static int dtun_nl_peer_add(struct sk_buff *skb, struct genl_info *info)
{
	struct dtun_dev *d;
	struct dtun_peer *peer;
	int err = 0;

	if (!info->attrs[DTUN_A_TUNNEL_ID] || !info->attrs[DTUN_A_NODE_ID])
		return -EINVAL;
	rtnl_lock();
	d = dtun_nl_dev(info);
	if (!d) {
		err = -ENODEV;
		goto out_unlock;
	}
	if (dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID]))) {
		err = -EEXIST;
		goto out_unlock;
	}
	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		err = -ENOMEM;
		goto out_unlock;
	}
	peer->tdev = d;
	refcount_set(&peer->refs, 1);
	peer->tunnel_id = nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID]);
	peer->remote_tunnel_id = info->attrs[DTUN_A_REMOTE_TUNNEL_ID] ?
		nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID]) : peer->tunnel_id;
	peer->node_id = nla_get_u64(info->attrs[DTUN_A_NODE_ID]);
	if (info->attrs[DTUN_A_RAW_ADDR])
		memcpy(&peer->raw_addr, nla_data(info->attrs[DTUN_A_RAW_ADDR]),
		       sizeof(peer->raw_addr));
	if (info->attrs[DTUN_A_UDP_ADDR])
		memcpy(&peer->udp_addr, nla_data(info->attrs[DTUN_A_UDP_ADDR]),
		       sizeof(peer->udp_addr));
	if (info->attrs[DTUN_A_UDP_PORT])
		peer->udp_port = nla_get_be16(info->attrs[DTUN_A_UDP_PORT]);
	if (info->attrs[DTUN_A_REMOTE_TUNNEL_ID])
		peer->remote_tunnel_id = nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID]);
	INIT_LIST_HEAD(&peer->prefixes);
	spin_lock_init(&peer->state_lock);
	if (info->attrs[DTUN_A_KEY]) {
		err = dtun_peer_set_key(peer, nla_data(info->attrs[DTUN_A_KEY]),
					nla_len(info->attrs[DTUN_A_KEY]));
		if (err) {
			dtun_peer_free(peer);
			goto out_unlock;
		}
	}
	spin_lock_bh(&d->peer_lock);
	list_add_tail(&peer->list, &d->peers);
	spin_unlock_bh(&d->peer_lock);
	mod_delayed_work(system_wq, &d->probe_work, 0);
	out_unlock:
	rtnl_unlock();
	return err;
}

static int dtun_nl_peer_del(struct sk_buff *skb, struct genl_info *info)
{
	struct dtun_dev *d;
	struct dtun_peer *peer;
	int err = 0;

	if (!info->attrs[DTUN_A_TUNNEL_ID])
		return -EINVAL;
	rtnl_lock();
	d = dtun_nl_dev(info);
	peer = d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
	if (!peer)
		err = -ENOENT;
	else {
		spin_lock_bh(&d->peer_lock);
		list_del(&peer->list);
		spin_unlock_bh(&d->peer_lock);
		dtun_peer_put(peer);
	}
	rtnl_unlock();
	return err;
}

static int dtun_nl_peer_set(struct sk_buff *skb, struct genl_info *info)
{
	struct dtun_dev *d;
	struct dtun_peer *peer;
	int err = 0;

	if (!info->attrs[DTUN_A_TUNNEL_ID])
		return -EINVAL;
	rtnl_lock();
	d = dtun_nl_dev(info);
	peer = d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
	if (!peer) {
		err = -ENOENT;
		goto out;
	}
	spin_lock_bh(&peer->state_lock);
	if (info->attrs[DTUN_A_REMOTE_TUNNEL_ID])
		peer->remote_tunnel_id =
			nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID]);
	if (info->attrs[DTUN_A_RAW_ADDR]) {
		__be32 raw_addr;
		memcpy(&raw_addr, nla_data(info->attrs[DTUN_A_RAW_ADDR]), 4);
		if (raw_addr != peer->raw_addr)
			peer->raw_seen = 0;
		peer->raw_addr = raw_addr;
	}
	if (info->attrs[DTUN_A_UDP_ADDR] || info->attrs[DTUN_A_UDP_PORT]) {
		__be32 udp_addr = peer->udp_addr;
		__be16 udp_port = peer->udp_port;
		if (info->attrs[DTUN_A_UDP_ADDR])
			memcpy(&udp_addr, nla_data(info->attrs[DTUN_A_UDP_ADDR]), 4);
		if (info->attrs[DTUN_A_UDP_PORT])
			udp_port = nla_get_be16(info->attrs[DTUN_A_UDP_PORT]);
		if (udp_addr != peer->udp_addr || udp_port != peer->udp_port)
			peer->udp_seen = 0;
		peer->udp_addr = udp_addr;
		peer->udp_port = udp_port;
	}
	spin_unlock_bh(&peer->state_lock);
	if (info->attrs[DTUN_A_KEY]) {
		err = dtun_peer_set_key(peer, nla_data(info->attrs[DTUN_A_KEY]),
					nla_len(info->attrs[DTUN_A_KEY]));
	}
	mod_delayed_work(system_wq, &d->probe_work, 0);
out:
	rtnl_unlock();
	return err;
}

static int dtun_nl_route(struct sk_buff *skb, struct genl_info *info, bool add)
{
	struct dtun_dev *d;
	struct dtun_peer *peer;
	__be32 prefix;
	int err;

	if (!info->attrs[DTUN_A_TUNNEL_ID] || !info->attrs[DTUN_A_PREFIX] ||
	    !info->attrs[DTUN_A_PREFIX_LEN])
		return -EINVAL;
	memcpy(&prefix, nla_data(info->attrs[DTUN_A_PREFIX]), sizeof(prefix));
	rtnl_lock();
	d = dtun_nl_dev(info);
	peer = d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
	if (!peer)
		err = -ENOENT;
	else {
		spin_lock_bh(&d->peer_lock);
		if (add)
			err = dtun_add_prefix(peer, prefix,
				      nla_get_u8(info->attrs[DTUN_A_PREFIX_LEN]));
		else
			err = dtun_del_prefix(peer, prefix,
				      nla_get_u8(info->attrs[DTUN_A_PREFIX_LEN]));
		spin_unlock_bh(&d->peer_lock);
	}
	rtnl_unlock();
	return err;
}

static int dtun_nl_route_add(struct sk_buff *skb, struct genl_info *info)
{
	return dtun_nl_route(skb, info, true);
}

static int dtun_nl_route_del(struct sk_buff *skb, struct genl_info *info)
{
	return dtun_nl_route(skb, info, false);
}

static int dtun_nl_peer_get(struct sk_buff *skb, struct genl_info *info)
{
	struct dtun_dev *d;
	struct dtun_peer *peer;
	struct sk_buff *reply;
	void *hdr;
	int err = 0;

	if (!info->attrs[DTUN_A_TUNNEL_ID])
		return -EINVAL;
	rtnl_lock();
	d = dtun_nl_dev(info);
	peer = d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
	if (!peer) {
		err = -ENOENT;
		goto out_unlock;
	}
	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply) {
		err = -ENOMEM;
		goto out_unlock;
	}
	hdr = genlmsg_put_reply(reply, info, &dtun_genl_family, 0, DTUN_CMD_PEER_GET);
	if (!hdr) {
		nlmsg_free(reply);
		err = -EMSGSIZE;
		goto out_unlock;
	}
	if (nla_put_u32(reply, DTUN_A_IFINDEX, d->dev->ifindex) ||
	    nla_put_u32(reply, DTUN_A_TUNNEL_ID, peer->tunnel_id) ||
	    nla_put_u32(reply, DTUN_A_REMOTE_TUNNEL_ID, peer->remote_tunnel_id) ||
	    nla_put_u64_64bit(reply, DTUN_A_NODE_ID, peer->node_id, DTUN_A_UNSPEC) ||
	    nla_put(reply, DTUN_A_RAW_ADDR, sizeof(peer->raw_addr), &peer->raw_addr) ||
	    nla_put(reply, DTUN_A_UDP_ADDR, sizeof(peer->udp_addr), &peer->udp_addr) ||
	    nla_put_be16(reply, DTUN_A_UDP_PORT, peer->udp_port) ||
	    nla_put_u8(reply, DTUN_A_RAW_UP,
		       peer->raw_addr &&
		       time_before(jiffies, peer->raw_seen + DTUN_PATH_TIMEOUT)) ||
	    nla_put_u8(reply, DTUN_A_UDP_UP,
		       peer->udp_addr && peer->udp_port &&
		       time_before(jiffies, peer->udp_seen + DTUN_PATH_TIMEOUT))) {
		genlmsg_cancel(reply, hdr);
		nlmsg_free(reply);
		err = -EMSGSIZE;
		goto out_unlock;
	}
	genlmsg_end(reply, hdr);
	err = genlmsg_reply(reply, info);
out_unlock:
	rtnl_unlock();
	return err;
}

static const struct genl_ops dtun_genl_ops[] = {
	{ .cmd = DTUN_CMD_PEER_ADD, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_peer_add },
	{ .cmd = DTUN_CMD_PEER_DEL, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_peer_del },
	{ .cmd = DTUN_CMD_PEER_SET, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_peer_set },
	{ .cmd = DTUN_CMD_ROUTE_ADD, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_route_add },
	{ .cmd = DTUN_CMD_ROUTE_DEL, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_route_del },
	{ .cmd = DTUN_CMD_PEER_GET, .flags = GENL_ADMIN_PERM,
	  .policy = dtun_nl_policy, .doit = dtun_nl_peer_get },
};

static const struct genl_multicast_group dtun_genl_groups[] = {
	{ .name = "events" },
};

struct genl_family dtun_genl_family = {
	.name = "DTUN",
	.version = DTUN_GENL_VERSION,
	.maxattr = DTUN_A_MAX,
	.module = THIS_MODULE,
	.netnsok = true,
	.ops = dtun_genl_ops,
	.n_ops = ARRAY_SIZE(dtun_genl_ops),
	.mcgrps = dtun_genl_groups,
	.n_mcgrps = ARRAY_SIZE(dtun_genl_groups),
};

void dtun_genl_observed_peer(struct dtun_dev *d, struct dtun_peer *peer,
			     __be32 addr, __be16 port, enum dtun_transport transport)
{
	struct sk_buff *event;
	void *hdr;

	event = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!event)
		return;
	hdr = genlmsg_put(event, 0, 0, &dtun_genl_family, 0, DTUN_CMD_PEER_GET);
	if (!hdr) {
		nlmsg_free(event);
		return;
	}
	if (nla_put_u32(event, DTUN_A_IFINDEX, d->dev->ifindex) ||
	    nla_put_u32(event, DTUN_A_TUNNEL_ID, peer->tunnel_id) ||
	    nla_put(event, DTUN_A_UDP_ADDR, sizeof(addr), &addr) ||
	    nla_put_be16(event, DTUN_A_UDP_PORT, port) ||
	    nla_put_u8(event, DTUN_A_PATH, transport)) {
		genlmsg_cancel(event, hdr);
		nlmsg_free(event);
		return;
	}
	genlmsg_end(event, hdr);
	genlmsg_multicast_netns(&dtun_genl_family, dev_net(d->dev), event, 0, 0,
				  GFP_ATOMIC);
}

int dtun_genl_register(void)
{
	return genl_register_family(&dtun_genl_family);
}

void dtun_genl_unregister(void)
{
	genl_unregister_family(&dtun_genl_family);
}
