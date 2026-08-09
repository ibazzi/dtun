// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>

#include "dtun.h"

static const struct nla_policy dtun_nl_policy[DTUN_A_MAX + 1] = {
    [DTUN_A_IFINDEX] = {.type = NLA_U32},
    [DTUN_A_TUNNEL_ID] = {.type = NLA_U32},
    [DTUN_A_NODE_ID] = {.type = NLA_U64},
    [DTUN_A_RAW_ADDR] = {.type = NLA_BINARY, .len = sizeof(__be32)},
    [DTUN_A_UDP_ADDR] = {.type = NLA_BINARY, .len = sizeof(__be32)},
    [DTUN_A_UDP_PORT] = {.type = NLA_U16},
    [DTUN_A_KEY] = {.type = NLA_BINARY, .len = DTUN_KEY_LEN},
    [DTUN_A_PREFIX] = {.type = NLA_BINARY, .len = sizeof(__be32)},
    [DTUN_A_PREFIX_LEN] = {.type = NLA_U8},
    [DTUN_A_REMOTE_TUNNEL_ID] = {.type = NLA_U32},
    [DTUN_A_DYNAMIC_RAW] = {.type = NLA_U8},
    [DTUN_A_CANDIDATE_GENERATION] = {.type = NLA_U64},
    [DTUN_A_RENDEZVOUS_UDP_ADDR] = {.type = NLA_BINARY, .len = sizeof(__be32)},
    [DTUN_A_RENDEZVOUS_UDP_PORT] = {.type = NLA_U16},
    [DTUN_A_HUB_ADDR] = {.type = NLA_BINARY, .len = sizeof(__be32)},
    [DTUN_A_HUB_PORT] = {.type = NLA_U16},
    [DTUN_A_HUB_TERM] = {.type = NLA_U64},
    [DTUN_A_OPERATIONAL] = {.type = NLA_U8},
};

struct dtun_peer_status_snapshot {
  u32 ifindex;
  u32 tunnel_id;
  u32 remote_tunnel_id;
  u64 node_id;
  u64 candidate_generation;
  __be32 raw_addr;
  __be32 raw_validated_addr;
  __be32 rendezvous_udp_addr;
  __be16 rendezvous_udp_port;
  __be32 direct_udp_addr;
  __be16 direct_udp_port;
  u8 dynamic_raw;
  u8 raw_up;
  u8 udp_up;
  u8 selected_path;
  u8 raw_health;
  u8 udp_health;
  u64 raw_srtt_us;
  u64 udp_srtt_us;
  u64 raw_rttvar_us;
  u64 udp_rttvar_us;
  u32 raw_loss_ppm;
  u32 udp_loss_ppm;
  u32 raw_threshold_ms;
  u32 udp_threshold_ms;
  u32 raw_last_ack_ms;
  u32 udp_last_ack_ms;
};

static struct dtun_dev *dtun_nl_dev(struct genl_info *info) {
  if (!info->attrs[DTUN_A_IFINDEX])
    return NULL;
  return dtun_dev_by_ifindex(genl_info_net(info),
                             nla_get_u32(info->attrs[DTUN_A_IFINDEX]));
}

static int dtun_nl_peer_add(struct sk_buff *skb, struct genl_info *info) {
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
  peer->remote_tunnel_id =
      info->attrs[DTUN_A_REMOTE_TUNNEL_ID]
          ? nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID])
          : peer->tunnel_id;
  peer->node_id = nla_get_u64(info->attrs[DTUN_A_NODE_ID]);
  if (info->attrs[DTUN_A_RAW_ADDR])
    memcpy(&peer->raw_addr, nla_data(info->attrs[DTUN_A_RAW_ADDR]),
           sizeof(peer->raw_addr));
  if (info->attrs[DTUN_A_UDP_ADDR])
    memcpy(&peer->udp_addr, nla_data(info->attrs[DTUN_A_UDP_ADDR]),
           sizeof(peer->udp_addr));
  if (info->attrs[DTUN_A_UDP_PORT])
    peer->udp_port = nla_get_be16(info->attrs[DTUN_A_UDP_PORT]);
  if (info->attrs[DTUN_A_RENDEZVOUS_UDP_ADDR])
    memcpy(&peer->udp_addr, nla_data(info->attrs[DTUN_A_RENDEZVOUS_UDP_ADDR]),
           sizeof(peer->udp_addr));
  if (info->attrs[DTUN_A_RENDEZVOUS_UDP_PORT])
    peer->udp_port = nla_get_be16(info->attrs[DTUN_A_RENDEZVOUS_UDP_PORT]);
  if (info->attrs[DTUN_A_DYNAMIC_RAW])
    peer->dynamic_raw = nla_get_u8(info->attrs[DTUN_A_DYNAMIC_RAW]);
  if (info->attrs[DTUN_A_CANDIDATE_GENERATION])
    peer->candidate_generation =
        nla_get_u64(info->attrs[DTUN_A_CANDIDATE_GENERATION]);
  if (info->attrs[DTUN_A_REMOTE_TUNNEL_ID])
    peer->remote_tunnel_id = nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID]);
  INIT_LIST_HEAD(&peer->prefixes);
  spin_lock_init(&peer->state_lock);
  dtun_path_health_init(&peer->raw_health);
  dtun_path_health_init(&peer->udp_health);
  dtun_nat_reset(peer);
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

static int dtun_nl_peer_del(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  struct dtun_peer *peer;
  int err = 0;

  if (!info->attrs[DTUN_A_TUNNEL_ID])
    return -EINVAL;
  rtnl_lock();
  d = dtun_nl_dev(info);
  peer =
      d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
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

static int dtun_nl_peer_set(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  struct dtun_peer *peer;
  bool accept_candidates = true;
  int err = 0;

  if (!info->attrs[DTUN_A_TUNNEL_ID])
    return -EINVAL;
  rtnl_lock();
  d = dtun_nl_dev(info);
  peer =
      d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
  if (!peer) {
    err = -ENOENT;
    goto out;
  }
  spin_lock_bh(&peer->state_lock);
  if (info->attrs[DTUN_A_CANDIDATE_GENERATION]) {
    u64 generation = nla_get_u64(info->attrs[DTUN_A_CANDIDATE_GENERATION]);
    if (generation < peer->candidate_generation) {
      accept_candidates = false;
    } else if (generation > peer->candidate_generation) {
      peer->candidate_generation = generation;
      peer->direct_udp_addr = 0;
      peer->direct_udp_port = 0;
      peer->raw_validated_addr = 0;
      dtun_path_health_init(&peer->udp_health);
      dtun_path_health_init(&peer->raw_health);
      dtun_nat_reset(peer);
    }
  }
  if (info->attrs[DTUN_A_REMOTE_TUNNEL_ID])
    peer->remote_tunnel_id = nla_get_u32(info->attrs[DTUN_A_REMOTE_TUNNEL_ID]);
  if (accept_candidates && info->attrs[DTUN_A_RAW_ADDR]) {
    __be32 raw_addr;
    memcpy(&raw_addr, nla_data(info->attrs[DTUN_A_RAW_ADDR]), 4);
    if (raw_addr != peer->raw_addr)
      peer->raw_validated_addr = 0;
    if (raw_addr != peer->raw_addr) {
      dtun_path_health_init(&peer->raw_health);
      dtun_nat_reset(peer);
    }
    peer->raw_addr = raw_addr;
  }
  if (accept_candidates &&
      (info->attrs[DTUN_A_UDP_ADDR] || info->attrs[DTUN_A_UDP_PORT])) {
    __be32 udp_addr = peer->udp_addr;
    __be16 udp_port = peer->udp_port;
    if (info->attrs[DTUN_A_UDP_ADDR])
      memcpy(&udp_addr, nla_data(info->attrs[DTUN_A_UDP_ADDR]), 4);
    if (info->attrs[DTUN_A_UDP_PORT])
      udp_port = nla_get_be16(info->attrs[DTUN_A_UDP_PORT]);
    if (udp_addr != peer->udp_addr || udp_port != peer->udp_port) {
      dtun_path_health_init(&peer->udp_health);
      dtun_nat_reset(peer);
    }
    peer->udp_addr = udp_addr;
    peer->udp_port = udp_port;
  }
  if (accept_candidates && (info->attrs[DTUN_A_RENDEZVOUS_UDP_ADDR] ||
                            info->attrs[DTUN_A_RENDEZVOUS_UDP_PORT])) {
    __be32 addr = peer->udp_addr;
    __be16 port = peer->udp_port;
    if (info->attrs[DTUN_A_RENDEZVOUS_UDP_ADDR])
      memcpy(&addr, nla_data(info->attrs[DTUN_A_RENDEZVOUS_UDP_ADDR]), 4);
    if (info->attrs[DTUN_A_RENDEZVOUS_UDP_PORT])
      port = nla_get_be16(info->attrs[DTUN_A_RENDEZVOUS_UDP_PORT]);
    if (addr != peer->udp_addr || port != peer->udp_port) {
      dtun_path_health_init(&peer->udp_health);
      dtun_nat_reset(peer);
    }
    peer->udp_addr = addr;
    peer->udp_port = port;
  }
  if (info->attrs[DTUN_A_DYNAMIC_RAW])
    peer->dynamic_raw = nla_get_u8(info->attrs[DTUN_A_DYNAMIC_RAW]);
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

static int dtun_nl_route(struct sk_buff *skb, struct genl_info *info,
                         bool add) {
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
  peer =
      d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
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
    if (!err) {
      spin_lock_bh(&peer->state_lock);
      dtun_nat_reset(peer);
      spin_unlock_bh(&peer->state_lock);
    }
    spin_unlock_bh(&d->peer_lock);
  }
  rtnl_unlock();
  return err;
}

static int dtun_nl_route_add(struct sk_buff *skb, struct genl_info *info) {
  return dtun_nl_route(skb, info, true);
}

static int dtun_nl_route_del(struct sk_buff *skb, struct genl_info *info) {
  return dtun_nl_route(skb, info, false);
}

static void dtun_snapshot_peer(struct dtun_dev *d, struct dtun_peer *peer,
                               struct dtun_peer_status_snapshot *status) {
  bool hub_available = false;

  memset(status, 0, sizeof(*status));
  status->ifindex = d->dev->ifindex;
  spin_lock_bh(&peer->state_lock);
  status->tunnel_id = peer->tunnel_id;
  status->remote_tunnel_id = peer->remote_tunnel_id;
  status->node_id = peer->node_id;
  status->candidate_generation = peer->candidate_generation;
  status->raw_addr = peer->raw_addr;
  status->raw_validated_addr = peer->raw_validated_addr;
  status->rendezvous_udp_addr = peer->udp_addr;
  status->rendezvous_udp_port = peer->udp_port;
  status->direct_udp_addr = peer->direct_udp_addr;
  status->direct_udp_port = peer->direct_udp_port;
  status->dynamic_raw = peer->dynamic_raw;
  dtun_path_tick(peer, &peer->raw_health);
  dtun_path_tick(peer, &peer->udp_health);
  status->raw_up =
      peer->raw_validated_addr &&
      peer->raw_health.state == DTUN_HEALTH_HEALTHY &&
      (!peer->direct_activation_after ||
       time_after_eq(peer->raw_health.last_ack, peer->direct_activation_after));
  status->udp_up =
      peer->direct_udp_addr && peer->direct_udp_port &&
      peer->udp_health.state == DTUN_HEALTH_HEALTHY &&
      (!peer->direct_activation_after ||
       time_after_eq(peer->udp_health.last_ack, peer->direct_activation_after));
  status->raw_health = peer->raw_health.state;
  status->udp_health = peer->udp_health.state;
  status->raw_srtt_us = peer->raw_health.srtt_us;
  status->udp_srtt_us = peer->udp_health.srtt_us;
  status->raw_rttvar_us = peer->raw_health.rttvar_us;
  status->udp_rttvar_us = peer->udp_health.rttvar_us;
  status->raw_loss_ppm = dtun_path_loss_ppm(&peer->raw_health);
  status->udp_loss_ppm = dtun_path_loss_ppm(&peer->udp_health);
  status->raw_threshold_ms = dtun_path_offline_ms(peer, &peer->raw_health);
  status->udp_threshold_ms = dtun_path_offline_ms(peer, &peer->udp_health);
  status->raw_last_ack_ms =
      peer->raw_health.initialized
          ? jiffies_to_msecs(jiffies - peer->raw_health.last_ack)
          : U32_MAX;
  status->udp_last_ack_ms =
      peer->udp_health.initialized
          ? jiffies_to_msecs(jiffies - peer->udp_health.last_ack)
          : U32_MAX;
  spin_unlock_bh(&peer->state_lock);

  if (status->raw_up)
    status->selected_path = DTUN_PATH_RAW;
  else if (status->udp_up)
    status->selected_path = DTUN_PATH_UDP;
  else if (status->node_id == 1 && status->rendezvous_udp_addr &&
           status->rendezvous_udp_port &&
           status->udp_health != DTUN_HEALTH_OFFLINE)
    status->selected_path = DTUN_PATH_UDP;
  else {
    struct dtun_peer *hub = dtun_peer_by_node(d, 1);
    if (hub) {
      spin_lock_bh(&hub->state_lock);
      hub_available =
          hub->raw_validated_addr ||
          ((hub->direct_udp_addr || hub->udp_addr) && hub->udp_port &&
           hub->udp_health.state != DTUN_HEALTH_OFFLINE);
      spin_unlock_bh(&hub->state_lock);
    }
    status->selected_path =
        hub_available && peer->node_id != 1 ? DTUN_PATH_HUB : DTUN_PATH_DOWN;
  }
}

static int dtun_put_peer_status(struct sk_buff *skb, u32 portid, u32 seq,
                                u8 cmd,
                                const struct dtun_peer_status_snapshot *status,
                                int flags) {
  void *hdr = genlmsg_put(skb, portid, seq, &dtun_genl_family, flags, cmd);

  if (!hdr)
    return -EMSGSIZE;
  if (nla_put_u32(skb, DTUN_A_IFINDEX, status->ifindex) ||
      nla_put_u32(skb, DTUN_A_TUNNEL_ID, status->tunnel_id) ||
      nla_put_u32(skb, DTUN_A_REMOTE_TUNNEL_ID, status->remote_tunnel_id) ||
      nla_put_u64_64bit(skb, DTUN_A_NODE_ID, status->node_id, DTUN_A_UNSPEC) ||
      nla_put_u64_64bit(skb, DTUN_A_CANDIDATE_GENERATION,
                        status->candidate_generation, DTUN_A_UNSPEC) ||
      nla_put_u8(skb, DTUN_A_DYNAMIC_RAW, status->dynamic_raw) ||
      nla_put(skb, DTUN_A_RAW_ADDR, sizeof(status->raw_addr),
              &status->raw_addr) ||
      nla_put(skb, DTUN_A_RAW_VALIDATED_ADDR,
              sizeof(status->raw_validated_addr),
              &status->raw_validated_addr) ||
      nla_put(skb, DTUN_A_RENDEZVOUS_UDP_ADDR,
              sizeof(status->rendezvous_udp_addr),
              &status->rendezvous_udp_addr) ||
      nla_put_be16(skb, DTUN_A_RENDEZVOUS_UDP_PORT,
                   status->rendezvous_udp_port) ||
      nla_put(skb, DTUN_A_DIRECT_UDP_ADDR, sizeof(status->direct_udp_addr),
              &status->direct_udp_addr) ||
      nla_put_be16(skb, DTUN_A_DIRECT_UDP_PORT, status->direct_udp_port) ||
      nla_put_u8(skb, DTUN_A_RAW_UP, status->raw_up) ||
      nla_put_u8(skb, DTUN_A_UDP_UP, status->udp_up) ||
      nla_put_u8(skb, DTUN_A_SELECTED_PATH, status->selected_path) ||
      nla_put_u8(skb, DTUN_A_RAW_HEALTH, status->raw_health) ||
      nla_put_u8(skb, DTUN_A_UDP_HEALTH, status->udp_health) ||
      nla_put_u64_64bit(skb, DTUN_A_RAW_SRTT_US, status->raw_srtt_us,
                        DTUN_A_UNSPEC) ||
      nla_put_u64_64bit(skb, DTUN_A_UDP_SRTT_US, status->udp_srtt_us,
                        DTUN_A_UNSPEC) ||
      nla_put_u64_64bit(skb, DTUN_A_RAW_RTTVAR_US, status->raw_rttvar_us,
                        DTUN_A_UNSPEC) ||
      nla_put_u64_64bit(skb, DTUN_A_UDP_RTTVAR_US, status->udp_rttvar_us,
                        DTUN_A_UNSPEC) ||
      nla_put_u32(skb, DTUN_A_RAW_LOSS_PPM, status->raw_loss_ppm) ||
      nla_put_u32(skb, DTUN_A_UDP_LOSS_PPM, status->udp_loss_ppm) ||
      nla_put_u32(skb, DTUN_A_RAW_THRESHOLD_MS, status->raw_threshold_ms) ||
      nla_put_u32(skb, DTUN_A_UDP_THRESHOLD_MS, status->udp_threshold_ms) ||
      nla_put_u32(skb, DTUN_A_RAW_LAST_ACK_MS, status->raw_last_ack_ms) ||
      nla_put_u32(skb, DTUN_A_UDP_LAST_ACK_MS, status->udp_last_ack_ms)) {
    genlmsg_cancel(skb, hdr);
    return -EMSGSIZE;
  }
  genlmsg_end(skb, hdr);
  return 0;
}

static int dtun_nl_peer_get(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  struct dtun_peer *peer;
  struct sk_buff *reply;
  struct dtun_peer_status_snapshot status;
  int err = 0;

  if (!info->attrs[DTUN_A_TUNNEL_ID])
    return -EINVAL;
  rtnl_lock();
  d = dtun_nl_dev(info);
  peer =
      d ? dtun_peer_by_id(d, nla_get_u32(info->attrs[DTUN_A_TUNNEL_ID])) : NULL;
  if (!peer) {
    err = -ENOENT;
    goto out_unlock;
  }
  reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
  if (!reply) {
    err = -ENOMEM;
    goto out_unlock;
  }
  dtun_snapshot_peer(d, peer, &status);
  err = dtun_put_peer_status(reply, info->snd_portid, info->snd_seq,
                             DTUN_CMD_PEER_GET, &status, 0);
  if (err) {
    nlmsg_free(reply);
    goto out_unlock;
  }
  err = genlmsg_reply(reply, info);
out_unlock:
  rtnl_unlock();
  return err;
}

static int dtun_nl_peer_list_start(struct netlink_callback *cb) {
  const struct genl_info *info = genl_info_dump(cb);
  struct dtun_peer_status_snapshot *items = NULL;
  struct dtun_dev *d;
  struct dtun_peer *peer;
  unsigned int count = 0, i = 0;

  if (!info->attrs[DTUN_A_IFINDEX])
    return -EINVAL;
  rtnl_lock();
  d = dtun_dev_by_ifindex(genl_info_net(info),
                          nla_get_u32(info->attrs[DTUN_A_IFINDEX]));
  if (!d) {
    rtnl_unlock();
    return -ENODEV;
  }
  spin_lock_bh(&d->peer_lock);
  list_for_each_entry(peer, &d->peers, list) count++;
  spin_unlock_bh(&d->peer_lock);
  if (count > 65536) {
    rtnl_unlock();
    return -E2BIG;
  }
  if (count) {
    items = kcalloc(count, sizeof(*items), GFP_KERNEL);
    if (!items) {
      rtnl_unlock();
      return -ENOMEM;
    }
    spin_lock_bh(&d->peer_lock);
    list_for_each_entry(peer, &d->peers, list) {
      if (i == count)
        break;
      dtun_snapshot_peer(d, peer, &items[i++]);
    }
    spin_unlock_bh(&d->peer_lock);
  }
  rtnl_unlock();
  cb->args[0] = (long)items;
  cb->args[1] = i;
  cb->args[2] = 0;
  return 0;
}

static int dtun_nl_peer_list_dump(struct sk_buff *skb,
                                  struct netlink_callback *cb) {
  struct dtun_peer_status_snapshot *items = (void *)cb->args[0];
  unsigned long count = cb->args[1];
  unsigned long i = cb->args[2];

  for (; i < count; i++) {
    if (dtun_put_peer_status(skb, NETLINK_CB(cb->skb).portid,
                             cb->nlh->nlmsg_seq, DTUN_CMD_PEER_LIST, &items[i],
                             NLM_F_MULTI))
      break;
  }
  cb->args[2] = i;
  return skb->len;
}

static int dtun_nl_peer_list_done(struct netlink_callback *cb) {
  kfree((void *)cb->args[0]);
  cb->args[0] = 0;
  return 0;
}

static int dtun_nl_rebind(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  struct dtun_peer *peer;

  (void)skb;
  rtnl_lock();
  d = dtun_nl_dev(info);
  if (!d) {
    rtnl_unlock();
    return -ENODEV;
  }
  spin_lock_bh(&d->peer_lock);
  list_for_each_entry(peer, &d->peers, list) {
    spin_lock_bh(&peer->state_lock);
    if (peer->dynamic_raw) {
      peer->raw_validated_addr = 0;
      dtun_path_health_init(&peer->raw_health);
      dtun_nat_reset(peer);
    }
    spin_unlock_bh(&peer->state_lock);
  }
  spin_unlock_bh(&d->peer_lock);
  mod_delayed_work(system_wq, &d->probe_work, 0);
  rtnl_unlock();
  return 0;
}

static int dtun_nl_hub_set(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  __be32 address;
  __be16 port;

  (void)skb;
  if (!info->attrs[DTUN_A_HUB_ADDR] || !info->attrs[DTUN_A_HUB_PORT])
    return -EINVAL;
  memcpy(&address, nla_data(info->attrs[DTUN_A_HUB_ADDR]), sizeof(address));
  port = nla_get_be16(info->attrs[DTUN_A_HUB_PORT]);
  if (!address || !port)
    return -EINVAL;
  rtnl_lock();
  d = dtun_nl_dev(info);
  if (!d) {
    rtnl_unlock();
    return -ENODEV;
  }
  spin_lock_bh(&d->hub_lock);
  d->hub_addr = address;
  d->hub_port = port;
  spin_unlock_bh(&d->hub_lock);
  mod_delayed_work(system_wq, &d->probe_work, 0);
  rtnl_unlock();
  return 0;
}

static int dtun_nl_hub_migrate(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;
  struct dtun_peer *hub;
  __be32 address;
  __be16 port;
  u64 term;

  (void)skb;
  if (!info->attrs[DTUN_A_HUB_ADDR] || !info->attrs[DTUN_A_HUB_PORT] ||
      !info->attrs[DTUN_A_HUB_TERM])
    return -EINVAL;
  memcpy(&address, nla_data(info->attrs[DTUN_A_HUB_ADDR]), sizeof(address));
  port = nla_get_be16(info->attrs[DTUN_A_HUB_PORT]);
  term = nla_get_u64(info->attrs[DTUN_A_HUB_TERM]);
  if (!address || !port || !term)
    return -EINVAL;

  rtnl_lock();
  d = dtun_nl_dev(info);
  if (!d) {
    rtnl_unlock();
    return -ENODEV;
  }
  spin_lock_bh(&d->hub_lock);
  if (term < d->hub_term) {
    spin_unlock_bh(&d->hub_lock);
    rtnl_unlock();
    return -ESTALE;
  }
  d->hub_addr = address;
  d->hub_port = port;
  d->hub_term = term;
  spin_unlock_bh(&d->hub_lock);

  hub = dtun_peer_by_node(d, 1);
  if (!hub) {
    rtnl_unlock();
    return -ENOENT;
  }
  spin_lock_bh(&hub->state_lock);
  hub->udp_addr = address;
  hub->udp_port = port;
  hub->direct_udp_addr = 0;
  hub->direct_udp_port = 0;
  hub->raw_validated_addr = 0;
  atomic64_set(&hub->tx_seq, 0);
  hub->rx_highest = 0;
  memset(hub->rx_window, 0, sizeof(hub->rx_window));
  dtun_path_health_init(&hub->raw_health);
  dtun_path_health_init(&hub->udp_health);
  spin_unlock_bh(&hub->state_lock);
  mod_delayed_work(system_wq, &d->probe_work, 0);
  rtnl_unlock();
  return 0;
}

static int dtun_nl_role_set(struct sk_buff *skb, struct genl_info *info) {
  struct dtun_dev *d;

  (void)skb;
  if (!info->attrs[DTUN_A_OPERATIONAL])
    return -EINVAL;
  rtnl_lock();
  d = dtun_nl_dev(info);
  if (!d) {
    rtnl_unlock();
    return -ENODEV;
  }
  WRITE_ONCE(d->operational, !!nla_get_u8(info->attrs[DTUN_A_OPERATIONAL]));
  if (d->operational)
    mod_delayed_work(system_wq, &d->probe_work, 0);
  rtnl_unlock();
  return 0;
}

static const struct genl_ops dtun_genl_ops[] = {
    {.cmd = DTUN_CMD_PEER_ADD,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_peer_add},
    {.cmd = DTUN_CMD_PEER_DEL,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_peer_del},
    {.cmd = DTUN_CMD_PEER_SET,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_peer_set},
    {.cmd = DTUN_CMD_ROUTE_ADD,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_route_add},
    {.cmd = DTUN_CMD_ROUTE_DEL,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_route_del},
    {.cmd = DTUN_CMD_PEER_GET,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_peer_get},
    {.cmd = DTUN_CMD_PEER_LIST,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .start = dtun_nl_peer_list_start,
     .dumpit = dtun_nl_peer_list_dump,
     .done = dtun_nl_peer_list_done},
    {.cmd = DTUN_CMD_REBIND,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_rebind},
    {.cmd = DTUN_CMD_HUB_SET,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_hub_set},
    {.cmd = DTUN_CMD_HUB_MIGRATE,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_hub_migrate},
    {.cmd = DTUN_CMD_ROLE_SET,
     .flags = GENL_ADMIN_PERM,
     .policy = dtun_nl_policy,
     .doit = dtun_nl_role_set},
};

static const struct genl_multicast_group dtun_genl_groups[] = {
    {.name = "events"},
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
                             __be32 addr, __be16 port,
                             enum dtun_transport transport) {
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

int dtun_genl_register(void) { return genl_register_family(&dtun_genl_family); }

void dtun_genl_unregister(void) { genl_unregister_family(&dtun_genl_family); }
