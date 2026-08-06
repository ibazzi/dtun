#include "../../src/ctl/dtun_netlink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void parse_hex_key(const char *hex, uint8_t *out) {
    for (int i = 0; i < 32; i++) {
        unsigned int byte_val;
        sscanf(hex + i * 2, "%02x", &byte_val);
        out[i] = (uint8_t)byte_val;
    }
}

static void parse_udp(const char *udp_str, struct in_addr *addr, uint16_t *port) {
    char buf[128];
    strncpy(buf, udp_str, sizeof(buf) - 1);
    char *colon = strrchr(buf, ':');
    if (!colon) {
        fprintf(stderr, "Invalid UDP address format (expected IP:PORT): %s\n", udp_str);
        exit(1);
    }
    *colon = '\0';
    inet_pton(AF_INET, buf, addr);
    *port = atoi(colon + 1);
}

static void parse_prefix(const char *prefix_str, struct in_addr *addr, uint8_t *len) {
    char buf[128];
    strncpy(buf, prefix_str, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    if (!slash) {
        fprintf(stderr, "Invalid prefix format (expected IP/LEN): %s\n", prefix_str);
        exit(1);
    }
    *slash = '\0';
    inet_pton(AF_INET, buf, addr);
    *len = atoi(slash + 1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <peer-add|peer-set|peer-del|peer-get|route-add|route-del> [options]\n", argv[0]);
        return 1;
    }

    const char *action = argv[1];
    uint32_t ifindex = 0;
    uint32_t tunnel_id = 0;
    uint32_t remote_tunnel_id = 0;
    uint64_t node_id = 0;
    struct in_addr raw_addr = {0};
    struct in_addr udp_addr = {0};
    uint16_t udp_port = 0;
    uint8_t key[32] = {0};
    int has_key = 0;
    struct in_addr prefix = {0};
    uint8_t prefix_len = 32;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--ifindex") == 0 && i + 1 < argc) ifindex = atoi(argv[++i]);
        else if (strcmp(argv[i], "--tunnel-id") == 0 && i + 1 < argc) tunnel_id = atoi(argv[++i]);
        else if (strcmp(argv[i], "--remote-tunnel-id") == 0 && i + 1 < argc) remote_tunnel_id = atoi(argv[++i]);
        else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) node_id = strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--raw") == 0 && i + 1 < argc) inet_pton(AF_INET, argv[++i], &raw_addr);
        else if (strcmp(argv[i], "--udp") == 0 && i + 1 < argc) parse_udp(argv[++i], &udp_addr, &udp_port);
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) { parse_hex_key(argv[++i], key); has_key = 1; }
        else if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) parse_prefix(argv[++i], &prefix, &prefix_len);
    }

    if (!remote_tunnel_id) remote_tunnel_id = tunnel_id;

    if (strcmp(action, "peer-add") == 0) {
        dtun_nl_peer_info_t info = {
            .ifindex = ifindex, .tunnel_id = tunnel_id, .remote_tunnel_id = remote_tunnel_id,
            .node_id = node_id, .raw_addr = raw_addr, .udp_addr = udp_addr, .udp_port = udp_port,
            .has_key = has_key
        };
        memcpy(info.key, key, 32);
        int res = dtun_nl_peer_add(&info);
        if (res < 0) { perror("peer-add failed"); return 1; }
    } else if (strcmp(action, "peer-set") == 0) {
        dtun_nl_peer_info_t info = {
            .ifindex = ifindex, .tunnel_id = tunnel_id, .remote_tunnel_id = remote_tunnel_id,
            .node_id = node_id, .raw_addr = raw_addr, .udp_addr = udp_addr, .udp_port = udp_port,
            .has_key = has_key
        };
        memcpy(info.key, key, 32);
        int res = dtun_nl_peer_set(&info);
        if (res < 0) { perror("peer-set failed"); return 1; }
    } else if (strcmp(action, "peer-del") == 0) {
        int res = dtun_nl_peer_del(ifindex, tunnel_id);
        if (res < 0) { perror("peer-del failed"); return 1; }
    } else if (strcmp(action, "peer-get") == 0) {
        dtun_nl_peer_status_t status;
        int res = dtun_nl_peer_get(ifindex, tunnel_id, &status);
        if (res < 0) { perror("peer-get failed"); return 1; }
        char raw_str[INET_ADDRSTRLEN], udp_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &status.raw_addr, raw_str, sizeof(raw_str));
        inet_ntop(AF_INET, &status.udp_addr, udp_str, sizeof(udp_str));
        printf("{\"ifindex\": %u, \"tunnel_id\": %u, \"remote_tunnel_id\": %u, \"node_id\": %llu, \"raw\": \"%s\", \"udp\": \"%s:%u\", \"raw_up\": %s, \"udp_up\": %s}\n",
               status.ifindex, status.tunnel_id, status.remote_tunnel_id, (unsigned long long)status.node_id,
               raw_str, udp_str, status.udp_port, status.raw_up ? "true" : "false", status.udp_up ? "true" : "false");
    } else if (strcmp(action, "route-add") == 0) {
        int res = dtun_nl_route_add(ifindex, tunnel_id, prefix, prefix_len);
        if (res < 0) { perror("route-add failed"); return 1; }
    } else if (strcmp(action, "route-del") == 0) {
        int res = dtun_nl_route_del(ifindex, tunnel_id, prefix, prefix_len);
        if (res < 0) { perror("route-del failed"); return 1; }
    } else {
        fprintf(stderr, "Unknown action: %s\n", action);
        return 1;
    }

    return 0;
}
