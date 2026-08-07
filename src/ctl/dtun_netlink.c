#include "dtun_netlink.h"
#include "dtun_log.h"
#include "dtun_uapi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>

#define NL_ALIGN(len) (((len) + 3) & ~3)

static int genl_fd = -1;
static uint16_t dtun_genl_family_id = 0;
static uint32_t genl_seq = 0;
/* Modules are system-wide while dtund instances may live in independent
 * network namespaces.  Teardown must not unload a module that this process
 * merely found already present. */
static int dtun_module_loaded_here = 0;

static int pack_dtun_attr(char *buf, size_t maxlen, int type,
                          const void *val, size_t len);

static int add_attr(struct nlmsghdr *n, size_t maxlen, int type, const void *data, int alen) {
    int len = RTA_LENGTH(alen);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) return -1;
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen > 0 && data) memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static struct rtattr *add_nested_attr(struct nlmsghdr *n, size_t maxlen, int type) {
    struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    if (add_attr(n, maxlen, type, NULL, 0) < 0) return NULL;
    return rta;
}

static void end_nested_attr(struct nlmsghdr *n, struct rtattr *rta) {
    rta->rta_len = (char *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len)) - (char *)rta;
}

static int genl_request(uint16_t family, uint8_t cmd, const void *attrs, size_t attrs_len,
                         void *reply_buf, size_t *reply_len) {
    if (genl_fd < 0) return -1;

    char buf[4096];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *genl = (struct genlmsghdr *)(buf + sizeof(struct nlmsghdr));

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + attrs_len);
    nlh->nlmsg_type = family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++genl_seq;
    nlh->nlmsg_pid = getpid();

    genl->cmd = cmd;
    genl->version = 1;

    if (attrs && attrs_len > 0) {
        memcpy(buf + sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr), attrs, attrs_len);
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(genl_fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        return -errno;
    }

    while (1) {
        char recv_buf[8192];
        ssize_t ret = recv(genl_fd, recv_buf, sizeof(recv_buf), 0);
        if (ret < 0) return -errno;

        struct nlmsghdr *r_nlh = (struct nlmsghdr *)recv_buf;
        while (NLMSG_OK(r_nlh, ret)) {
            if (r_nlh->nlmsg_seq != genl_seq) {
                r_nlh = NLMSG_NEXT(r_nlh, ret);
                continue;
            }
            if (r_nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(r_nlh);
                if (err->error < 0) return err->error;
                if (reply_len) *reply_len = 0;
                return 0;
            }
            if (reply_buf && reply_len) {
                size_t payload_len = r_nlh->nlmsg_len - NLMSG_HDRLEN;
                if (payload_len > *reply_len) payload_len = *reply_len;
                memcpy(reply_buf, NLMSG_DATA(r_nlh), payload_len);
                *reply_len = payload_len;
                return 0;
            }
            r_nlh = NLMSG_NEXT(r_nlh, ret);
        }
    }
}

static int parse_peer_status(const void *payload, size_t payload_len,
                             dtun_nl_peer_status_t *status) {
    const struct genlmsghdr *gmsg = payload;
    struct rtattr *attr;
    int len;

    if (payload_len < sizeof(*gmsg)) return -EPROTO;
    memset(status, 0, sizeof(*status));
    attr = (struct rtattr *)((char *)payload + sizeof(*gmsg));
    len = (int)(payload_len - sizeof(*gmsg));
    while (RTA_OK(attr, len)) {
        switch (attr->rta_type) {
        case DTUN_A_IFINDEX: status->ifindex = *(uint32_t *)RTA_DATA(attr); break;
        case DTUN_A_TUNNEL_ID: status->tunnel_id = *(uint32_t *)RTA_DATA(attr); break;
        case DTUN_A_REMOTE_TUNNEL_ID: status->remote_tunnel_id = *(uint32_t *)RTA_DATA(attr); break;
        case DTUN_A_NODE_ID: memcpy(&status->node_id, RTA_DATA(attr), sizeof(status->node_id)); break;
        case DTUN_A_RAW_ADDR: memcpy(&status->raw_addr.s_addr, RTA_DATA(attr), 4); break;
        case DTUN_A_RAW_VALIDATED_ADDR: memcpy(&status->raw_validated_addr.s_addr, RTA_DATA(attr), 4); break;
        case DTUN_A_UDP_ADDR:
        case DTUN_A_RENDEZVOUS_UDP_ADDR: memcpy(&status->udp_addr.s_addr, RTA_DATA(attr), 4); break;
        case DTUN_A_UDP_PORT:
        case DTUN_A_RENDEZVOUS_UDP_PORT: status->udp_port = ntohs(*(uint16_t *)RTA_DATA(attr)); break;
        case DTUN_A_DIRECT_UDP_ADDR: memcpy(&status->direct_udp_addr.s_addr, RTA_DATA(attr), 4); break;
        case DTUN_A_DIRECT_UDP_PORT: status->direct_udp_port = ntohs(*(uint16_t *)RTA_DATA(attr)); break;
        case DTUN_A_CANDIDATE_GENERATION: memcpy(&status->candidate_generation, RTA_DATA(attr), sizeof(status->candidate_generation)); break;
        case DTUN_A_DYNAMIC_RAW: status->dynamic_raw = *(uint8_t *)RTA_DATA(attr); break;
        case DTUN_A_RAW_UP: status->raw_up = *(uint8_t *)RTA_DATA(attr); break;
        case DTUN_A_UDP_UP: status->udp_up = *(uint8_t *)RTA_DATA(attr); break;
        case DTUN_A_SELECTED_PATH: status->selected_path = *(uint8_t *)RTA_DATA(attr); break;
        }
        attr = RTA_NEXT(attr, len);
    }
    return status->ifindex && status->tunnel_id ? 0 : -EPROTO;
}

static int genl_peer_dump(uint32_t ifindex, dtun_nl_peer_status_t **statuses,
                          size_t *status_count) {
    char attrs[64];
    int attrs_len = 0;
    char request[256];
    struct nlmsghdr *nlh = (struct nlmsghdr *)request;
    struct genlmsghdr *genl = (struct genlmsghdr *)(request + NLMSG_HDRLEN);
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    uint32_t seq;
    dtun_nl_peer_status_t *items = NULL;
    size_t count = 0, capacity = 0;

    if (!statuses || !status_count) return -EINVAL;
    *statuses = NULL;
    *status_count = 0;
    attrs_len += pack_dtun_attr(attrs + attrs_len, sizeof(attrs) - attrs_len,
                                DTUN_A_IFINDEX, &ifindex, sizeof(ifindex));
    memset(request, 0, sizeof(request));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*genl) + attrs_len);
    nlh->nlmsg_type = dtun_genl_family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = ++genl_seq;
    nlh->nlmsg_pid = getpid();
    genl->cmd = DTUN_CMD_PEER_LIST;
    genl->version = 1;
    memcpy(request + NLMSG_HDRLEN + sizeof(*genl), attrs, attrs_len);
    if (sendto(genl_fd, request, nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -errno;

    for (;;) {
        char buffer[16384];
        ssize_t received = recv(genl_fd, buffer, sizeof(buffer), 0);
        struct nlmsghdr *msg;
        int remaining;

        if (received < 0) {
            if (errno == EINTR) continue;
            free(items);
            return -errno;
        }
        remaining = (int)received;
        for (msg = (struct nlmsghdr *)buffer; NLMSG_OK(msg, remaining);
             msg = NLMSG_NEXT(msg, remaining)) {
            dtun_nl_peer_status_t status;
            int err;

            if (msg->nlmsg_seq != seq ||
                (msg->nlmsg_pid != 0 && msg->nlmsg_pid != (uint32_t)getpid()))
                continue;
            if (msg->nlmsg_type == NLMSG_DONE) {
                if (msg->nlmsg_flags & NLM_F_DUMP_INTR) {
                    free(items);
                    return -EINTR;
                }
                *statuses = items;
                *status_count = count;
                return 0;
            }
            if (msg->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlerr = NLMSG_DATA(msg);
                err = nlerr->error ? nlerr->error : -EPROTO;
                free(items);
                return err;
            }
            if (msg->nlmsg_type != dtun_genl_family_id) continue;
            err = parse_peer_status(NLMSG_DATA(msg),
                                    msg->nlmsg_len - NLMSG_HDRLEN, &status);
            if (err < 0) {
                free(items);
                return err;
            }
            if (count == capacity) {
                size_t next = capacity ? capacity * 2 : 16;
                dtun_nl_peer_status_t *grown;
                if (next > 65536) {
                    free(items);
                    return -E2BIG;
                }
                grown = realloc(items, next * sizeof(*items));
                if (!grown) {
                    free(items);
                    return -ENOMEM;
                }
                items = grown;
                capacity = next;
            }
            items[count++] = status;
        }
    }
}

static uint16_t genl_resolve_family(const char *name) {
    char attrs[128];
    memset(attrs, 0, sizeof(attrs));
    struct rtattr *rta = (struct rtattr *)attrs;
    rta->rta_type = CTRL_ATTR_FAMILY_NAME;
    int name_len = strlen(name) + 1;
    rta->rta_len = RTA_LENGTH(name_len);
    memcpy(RTA_DATA(rta), name, name_len);

    char reply[4096];
    size_t reply_len = sizeof(reply);
    int res = genl_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attrs, RTA_ALIGN(rta->rta_len), reply, &reply_len);
    if (res < 0) return 0;

    struct genlmsghdr *gmsg = (struct genlmsghdr *)reply;
    struct rtattr *attr = (struct rtattr *)((char *)gmsg + sizeof(struct genlmsghdr));
    int len = reply_len - sizeof(struct genlmsghdr);

    while (RTA_OK(attr, len)) {
        if (attr->rta_type == CTRL_ATTR_FAMILY_ID) {
            return *(uint16_t *)RTA_DATA(attr);
        }
        attr = RTA_NEXT(attr, len);
    }
    return 0;
}

int dtun_nl_init(void) {
    if (genl_fd >= 0) return 0;

    genl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (genl_fd < 0) return -errno;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();

    if (bind(genl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(genl_fd);
        genl_fd = -1;
        return -errno;
    }

    dtun_genl_family_id = genl_resolve_family("DTUN");
    if (!dtun_genl_family_id) {
        close(genl_fd);
        genl_fd = -1;
        return -ENOENT;
    }

    return 0;
}

void dtun_nl_close(void) {
    if (genl_fd >= 0) {
        close(genl_fd);
        genl_fd = -1;
    }
}

uint32_t dtun_link_get_ifindex(const char *ifname) {
    return if_nametoindex(ifname);
}

int dtun_link_create(const char *ifname, struct in_addr local_addr,
                     uint16_t udp_port, uint64_t node_id,
                     struct in_addr hub_addr, uint16_t hub_port,
                     uint32_t probe_interval_ms, uint32_t path_timeout_ms) {
    uint32_t existing = dtun_link_get_ifindex(ifname);
    if (existing > 0) {
        dtun_link_delete_by_name(ifname);
        usleep(100000);
    }

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -errno;

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi = (struct ifinfomsg *)(buf + sizeof(struct nlmsghdr));

    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    n->nlmsg_type = RTM_NEWLINK;
    n->nlmsg_seq = 1;
    ifi->ifi_family = AF_UNSPEC;

    add_attr(n, sizeof(buf), IFLA_IFNAME, ifname, strlen(ifname) + 1);

    struct rtattr *linkinfo = add_nested_attr(n, sizeof(buf), IFLA_LINKINFO);
    if (linkinfo) {
        add_attr(n, sizeof(buf), IFLA_INFO_KIND, "dtun", 5);
        struct rtattr *infodata = add_nested_attr(n, sizeof(buf), IFLA_INFO_DATA);
        if (infodata) {
            add_attr(n, sizeof(buf), IFLA_DTUN_LOCAL, &local_addr.s_addr, 4);
            uint16_t uport = htons(udp_port);
            add_attr(n, sizeof(buf), IFLA_DTUN_UDP_PORT, &uport, 2);
            add_attr(n, sizeof(buf), IFLA_DTUN_NODE_ID, &node_id, 8);
            add_attr(n, sizeof(buf), IFLA_DTUN_PROBE_INTERVAL_MS,
                     &probe_interval_ms, sizeof(probe_interval_ms));
            add_attr(n, sizeof(buf), IFLA_DTUN_PATH_TIMEOUT_MS,
                     &path_timeout_ms, sizeof(path_timeout_ms));
            if (hub_addr.s_addr) {
                uint16_t hport = htons(hub_port);
                add_attr(n, sizeof(buf), IFLA_DTUN_HUB, &hub_addr.s_addr, 4);
                add_attr(n, sizeof(buf), IFLA_DTUN_HUB_PORT, &hport, 2);
            }
            end_nested_attr(n, infodata);
        }
        end_nested_attr(n, linkinfo);
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(fd, buf, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -errno;
    }

    char reply[1024];
    ssize_t ret = recv(fd, reply, sizeof(reply), 0);
    close(fd);

    if (ret > 0) {
        struct nlmsghdr *r = (struct nlmsghdr *)reply;
        if (r->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(r);
            if (err->error < 0 && err->error != -EEXIST) return err->error;
        }
    }

    return (int)dtun_link_get_ifindex(ifname);
}

int dtun_link_delete_by_name(const char *ifname) {
    uint32_t ifindex = dtun_link_get_ifindex(ifname);
    if (ifindex <= 0) return 0; /* Already deleted */

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -errno;

    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi = (struct ifinfomsg *)(buf + sizeof(struct nlmsghdr));

    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_type = RTM_DELLINK;
    n->nlmsg_seq = 1;

    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;

    add_attr(n, sizeof(buf), IFLA_IFNAME, ifname, strlen(ifname) + 1);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    sendto(fd, buf, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    recv(fd, buf, sizeof(buf), 0);
    close(fd);

    return 0;
}

int dtun_link_setup(uint32_t ifindex, const char *ifname, struct in_addr addr, uint8_t prefix_len) {
    (void)ifname;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -errno;

    /* Add IPv4 address */
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)(buf + sizeof(struct nlmsghdr));

    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    n->nlmsg_type = RTM_NEWADDR;
    n->nlmsg_seq = 1;

    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix_len;
    ifa->ifa_index = ifindex;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;

    add_attr(n, sizeof(buf), IFA_LOCAL, &addr.s_addr, 4);
    add_attr(n, sizeof(buf), IFA_ADDRESS, &addr.s_addr, 4);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sendto(fd, buf, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    recv(fd, buf, sizeof(buf), 0);

    /* Set Link UP */
    memset(buf, 0, sizeof(buf));
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_type = RTM_NEWLINK;
    n->nlmsg_seq = 2;

    struct ifinfomsg *ifi = (struct ifinfomsg *)(buf + sizeof(struct nlmsghdr));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = ifindex;
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    sendto(fd, buf, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    recv(fd, buf, sizeof(buf), 0);

    close(fd);
    return 0;
}

static int pack_dtun_attr(char *buf, size_t maxlen, int type, const void *val, size_t len) {
    (void)maxlen;
    struct rtattr *rta = (struct rtattr *)buf;
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    if (len > 0 && val) memcpy(RTA_DATA(rta), val, len);
    return RTA_ALIGN(rta->rta_len);
}

int dtun_nl_peer_add(const dtun_nl_peer_info_t *peer) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[512];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &peer->ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &peer->tunnel_id, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_REMOTE_TUNNEL_ID, &peer->remote_tunnel_id, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_NODE_ID, &peer->node_id, 8);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_RAW_ADDR, &peer->raw_addr.s_addr, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_UDP_ADDR, &peer->udp_addr.s_addr, 4);
    uint16_t port = htons(peer->udp_port);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_UDP_PORT, &port, 2);

    if (peer->has_key) {
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_KEY, peer->key, 32);
    }
    uint8_t dynamic_raw = peer->dynamic_raw ? 1 : 0;
    if (peer->has_dynamic_raw)
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_DYNAMIC_RAW, &dynamic_raw, 1);
    if (peer->has_generation)
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_CANDIDATE_GENERATION,
                              &peer->candidate_generation, sizeof(peer->candidate_generation));

    return genl_request(dtun_genl_family_id, DTUN_CMD_PEER_ADD, attrs, off, NULL, NULL);
}

int dtun_nl_peer_set(const dtun_nl_peer_info_t *peer) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[512];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &peer->ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &peer->tunnel_id, 4);
    if (peer->remote_tunnel_id) {
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_REMOTE_TUNNEL_ID, &peer->remote_tunnel_id, 4);
    }
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_RAW_ADDR, &peer->raw_addr.s_addr, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_UDP_ADDR, &peer->udp_addr.s_addr, 4);
    uint16_t port = htons(peer->udp_port);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_UDP_PORT, &port, 2);

    if (peer->has_key) {
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_KEY, peer->key, 32);
    }
    uint8_t dynamic_raw = peer->dynamic_raw ? 1 : 0;
    if (peer->has_dynamic_raw)
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_DYNAMIC_RAW, &dynamic_raw, 1);
    if (peer->has_generation)
        off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_CANDIDATE_GENERATION,
                              &peer->candidate_generation, sizeof(peer->candidate_generation));

    return genl_request(dtun_genl_family_id, DTUN_CMD_PEER_SET, attrs, off, NULL, NULL);
}

int dtun_nl_peer_del(uint32_t ifindex, uint32_t tunnel_id) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[64];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &tunnel_id, 4);

    return genl_request(dtun_genl_family_id, DTUN_CMD_PEER_DEL, attrs, off, NULL, NULL);
}

int dtun_nl_peer_get(uint32_t ifindex, uint32_t tunnel_id, dtun_nl_peer_status_t *status) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[64];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &tunnel_id, 4);

    char reply[512];
    size_t reply_len = sizeof(reply);
    int res = genl_request(dtun_genl_family_id, DTUN_CMD_PEER_GET, attrs, off, reply, &reply_len);
    if (res < 0) return res;

    return parse_peer_status(reply, reply_len, status);
}

int dtun_nl_peer_list(uint32_t ifindex, dtun_nl_peer_status_t **statuses,
                      size_t *count) {
    int err = dtun_nl_init();
    if (err < 0) return err;
    return genl_peer_dump(ifindex, statuses, count);
}

int dtun_nl_rebind(uint32_t ifindex) {
    char attrs[64];
    int off = 0;
    int err = dtun_nl_init();
    if (err < 0) return err;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off,
                          DTUN_A_IFINDEX, &ifindex, sizeof(ifindex));
    return genl_request(dtun_genl_family_id, DTUN_CMD_REBIND,
                        attrs, off, NULL, NULL);
}

int dtun_nl_hub_set(uint32_t ifindex, struct in_addr hub_addr,
                    uint16_t hub_port) {
    char attrs[96];
    int off = 0;
    uint16_t port_be;
    int err = dtun_nl_init();
    if (err < 0) return err;
    if (!ifindex || !hub_addr.s_addr || !hub_port) return -EINVAL;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off,
                          DTUN_A_IFINDEX, &ifindex, sizeof(ifindex));
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off,
                          DTUN_A_HUB_ADDR, &hub_addr.s_addr,
                          sizeof(hub_addr.s_addr));
    port_be = htons(hub_port);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off,
                          DTUN_A_HUB_PORT, &port_be, sizeof(port_be));
    return genl_request(dtun_genl_family_id, DTUN_CMD_HUB_SET,
                        attrs, off, NULL, NULL);
}

int dtun_nl_route_add(uint32_t ifindex, uint32_t tunnel_id, struct in_addr prefix, uint8_t prefix_len) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[64];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &tunnel_id, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_PREFIX, &prefix.s_addr, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_PREFIX_LEN, &prefix_len, 1);

    return genl_request(dtun_genl_family_id, DTUN_CMD_ROUTE_ADD, attrs, off, NULL, NULL);
}

int dtun_nl_route_del(uint32_t ifindex, uint32_t tunnel_id, struct in_addr prefix, uint8_t prefix_len) {
    int init_error = dtun_nl_init();
    if (init_error < 0) return init_error;

    char attrs[64];
    int off = 0;
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_IFINDEX, &ifindex, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_TUNNEL_ID, &tunnel_id, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_PREFIX, &prefix.s_addr, 4);
    off += pack_dtun_attr(attrs + off, sizeof(attrs) - off, DTUN_A_PREFIX_LEN, &prefix_len, 1);

    return genl_request(dtun_genl_family_id, DTUN_CMD_ROUTE_DEL, attrs, off, NULL, NULL);
}

int dtun_module_ensure_loaded(void) {
    if (access("/sys/module/dtun", F_OK) == 0) {
        return 0;
    }

    dtun_log_info("[dtund] Kernel module 'dtun' is not loaded, attempting to load...");

    int ret = system("modprobe dtun 2>/dev/null");
    if (ret != 0 || access("/sys/module/dtun", F_OK) != 0) {
        ret = system("insmod ./build/dtun.ko 2>/dev/null || insmod ./dtun.ko 2>/dev/null"); (void)ret;
    }

    if (access("/sys/module/dtun", F_OK) == 0) {
        dtun_module_loaded_here = 1;
        dtun_log_info("[dtund] Kernel module 'dtun' loaded successfully.");
        return 0;
    }

    dtun_log_err("[dtund] Error: Failed to load kernel module 'dtun'. Please ensure dtun.ko is installed or present.");
    return -1;
}

void dtun_module_unload_if_needed(void) {
    if (!dtun_module_loaded_here || access("/sys/module/dtun", F_OK) != 0) {
        return;
    }

    dtun_log_info("[dtund] Unloading kernel module 'dtun'...");

    int ret = system("modprobe -r dtun 2>/dev/null");
    if (ret != 0) {
        ret = system("rmmod dtun 2>/dev/null"); (void)ret;
    }
    dtun_module_loaded_here = 0;
}
