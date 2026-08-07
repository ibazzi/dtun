#include "../../src/ctl/dtun_netlink.h"
#include "../../src/ctl/dtun_uapi.h"
#include "dtunctl_ha.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum output_format { FORMAT_HUMAN, FORMAT_JSON };

static const char *path_name(int path)
{
    switch (path) {
    case DTUN_PATH_RAW: return "raw";
    case DTUN_PATH_UDP: return "udp";
    case DTUN_PATH_HUB: return "hub";
    default: return "down";
    }
}

static const char *error_name(int code)
{
    switch (-code) {
    case EEXIST: return "EEXIST";
    case ENOENT: return "ENOENT";
    case ENODEV: return "ENODEV";
    case EINVAL: return "EINVAL";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOMEM: return "ENOMEM";
    default: return "ERROR";
    }
}

static void parse_hex_key(const char *hex, uint8_t *out)
{
    size_t i;
    if (strlen(hex) != 64) {
        fprintf(stderr, "key must contain exactly 64 hexadecimal characters\n");
        exit(2);
    }
    for (i = 0; i < 32; i++) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%02x", &value) != 1) {
            fprintf(stderr, "invalid hexadecimal key\n");
            exit(2);
        }
        out[i] = (uint8_t)value;
    }
}

static void parse_udp(const char *text, struct in_addr *addr, uint16_t *port)
{
    char buf[128];
    char *colon;
    long value;
    char *end;
    if (strlen(text) >= sizeof(buf)) goto invalid;
    memcpy(buf, text, strlen(text) + 1);
    colon = strrchr(buf, ':');
    if (!colon) goto invalid;
    *colon++ = '\0';
    value = strtol(colon, &end, 10);
    if (inet_pton(AF_INET, buf, addr) != 1 || !*colon || *end ||
        value < 0 || value > 65535) goto invalid;
    *port = (uint16_t)value;
    return;
invalid:
    fprintf(stderr, "invalid UDP endpoint (expected IPv4:PORT): %s\n", text);
    exit(2);
}

static void parse_prefix(const char *text, struct in_addr *addr, uint8_t *len)
{
    char buf[128];
    char *slash, *end;
    long value;
    if (strlen(text) >= sizeof(buf)) goto invalid;
    memcpy(buf, text, strlen(text) + 1);
    slash = strchr(buf, '/');
    if (!slash) goto invalid;
    *slash++ = '\0';
    value = strtol(slash, &end, 10);
    if (inet_pton(AF_INET, buf, addr) != 1 || !*slash || *end ||
        value < 0 || value > 32) goto invalid;
    *len = (uint8_t)value;
    return;
invalid:
    fprintf(stderr, "invalid prefix (expected IPv4/LEN): %s\n", text);
    exit(2);
}

static const char *address_text(struct in_addr addr, char buf[INET_ADDRSTRLEN])
{
    return addr.s_addr && inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN) ?
        buf : NULL;
}

static void endpoint_text(struct in_addr addr, uint16_t port, char *buf,
                          size_t size)
{
    char ip[INET_ADDRSTRLEN];
    if (!address_text(addr, ip) || !port) snprintf(buf, size, "-");
    else snprintf(buf, size, "%s:%u", ip, port);
}

static void print_json_string_or_null(const char *value)
{
    if (value) printf("\"%s\"", value);
    else printf("null");
}

static void print_peer_json(const dtun_nl_peer_status_t *s)
{
    char raw_candidate[INET_ADDRSTRLEN], raw_validated[INET_ADDRSTRLEN];
    char rendezvous[64], direct[64];
    const char *raw = address_text(s->raw_addr, raw_candidate);
    const char *validated = address_text(s->raw_validated_addr, raw_validated);
    endpoint_text(s->udp_addr, s->udp_port, rendezvous, sizeof(rendezvous));
    endpoint_text(s->direct_udp_addr, s->direct_udp_port, direct, sizeof(direct));
    printf("{\"ifindex\":%u,\"tunnel_id\":%u,\"remote_tunnel_id\":%u,"
           "\"node_id\":%llu,\"candidate_generation\":%llu,"
           "\"dynamic_raw\":%s,\"raw_candidate\":",
           s->ifindex, s->tunnel_id, s->remote_tunnel_id,
           (unsigned long long)s->node_id,
           (unsigned long long)s->candidate_generation,
           s->dynamic_raw ? "true" : "false");
    print_json_string_or_null(raw);
    printf(",\"raw_validated\":");
    print_json_string_or_null(validated);
    printf(",\"raw_up\":%s,\"rendezvous_udp\":",
           s->raw_up ? "true" : "false");
    print_json_string_or_null(strcmp(rendezvous, "-") ? rendezvous : NULL);
    printf(",\"direct_udp\":");
    print_json_string_or_null(strcmp(direct, "-") ? direct : NULL);
    printf(",\"udp_up\":%s,\"selected_path\":\"%s\"}",
           s->udp_up ? "true" : "false", path_name(s->selected_path));
}

static void print_peer_human(const dtun_nl_peer_status_t *s)
{
    char raw[INET_ADDRSTRLEN], validated[INET_ADDRSTRLEN];
    char rendezvous[64], direct[64];
    endpoint_text(s->udp_addr, s->udp_port, rendezvous, sizeof(rendezvous));
    endpoint_text(s->direct_udp_addr, s->direct_udp_port, direct, sizeof(direct));
    printf("Interface:             %u\n", s->ifindex);
    printf("Tunnel ID:            %u\n", s->tunnel_id);
    printf("Remote tunnel ID:     %u\n", s->remote_tunnel_id);
    printf("Node ID:              %llu\n", (unsigned long long)s->node_id);
    printf("Selected path:        %s\n", path_name(s->selected_path));
    printf("Candidate generation: %llu\n", (unsigned long long)s->candidate_generation);
    printf("Dynamic Raw:          %s\n", s->dynamic_raw ? "yes" : "no");
    printf("Raw candidate:        %s\n", address_text(s->raw_addr, raw) ?: "-");
    printf("Raw validated:        %s\n", address_text(s->raw_validated_addr, validated) ?: "-");
    printf("Raw state:            %s\n", s->raw_up ? "up" : "down");
    printf("Direct UDP:           %s\n", direct);
    printf("Rendezvous UDP:       %s\n", rendezvous);
    printf("UDP state:            %s\n", s->udp_up ? "up" : "down");
}

static int compare_peer(const void *left, const void *right)
{
    const dtun_nl_peer_status_t *a = left, *b = right;
    return a->tunnel_id < b->tunnel_id ? -1 : a->tunnel_id > b->tunnel_id;
}

static void print_peer_list_human(dtun_nl_peer_status_t *items, size_t count)
{
    size_t i;
    printf("%-8s %-8s %-8s %-6s %-15s %-25s %-25s %s\n",
           "TUNNEL", "REMOTE", "NODE", "PATH", "RAW", "DIRECT-UDP",
           "RENDEZVOUS-UDP", "GEN");
    if (!count) {
        printf("No peers.\n");
        return;
    }
    for (i = 0; i < count; i++) {
        char raw[INET_ADDRSTRLEN], direct[64], rendezvous[64];
        endpoint_text(items[i].direct_udp_addr, items[i].direct_udp_port,
                      direct, sizeof(direct));
        endpoint_text(items[i].udp_addr, items[i].udp_port,
                      rendezvous, sizeof(rendezvous));
        printf("%-8u %-8u %-8llu %-6s %-15s %-25s %-25s %llu\n",
               items[i].tunnel_id, items[i].remote_tunnel_id,
               (unsigned long long)items[i].node_id,
               path_name(items[i].selected_path),
               address_text(items[i].raw_addr, raw) ?: "-", direct,
               rendezvous, (unsigned long long)items[i].candidate_generation);
    }
}

static int command_result(const char *action, enum output_format format,
                          uint32_t ifindex, uint32_t tunnel_id, int result)
{
    if (format == FORMAT_JSON) {
        if (!result)
            printf("{\"action\":\"%s\",\"success\":true,\"ifindex\":%u,\"tunnel_id\":%u}\n",
                   action, ifindex, tunnel_id);
        else
            printf("{\"action\":\"%s\",\"success\":false,\"ifindex\":%u,\"tunnel_id\":%u,"
                   "\"error\":{\"code\":%d,\"name\":\"%s\",\"message\":\"%s\"}}\n",
                   action, ifindex, tunnel_id, result, error_name(result),
                   strerror(result < 0 ? -result : result));
    } else if (!result) {
        printf("%s succeeded: ifindex=%u tunnel_id=%u\n",
               action, ifindex, tunnel_id);
    } else {
        fprintf(stderr, "%s failed: %s\n", action,
                strerror(result < 0 ? -result : result));
    }
    return result ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *action;
    enum output_format format = FORMAT_HUMAN;
    uint32_t ifindex = 0, tunnel_id = 0, remote_tunnel_id = 0;
    uint64_t node_id = 0, generation = 0;
    struct in_addr raw_addr = {0}, udp_addr = {0}, prefix = {0};
    uint16_t udp_port = 0;
    uint8_t key[32] = {0}, prefix_len = 32;
    int has_key = 0, dynamic_raw = 0, dynamic_raw_seen = 0;
    int format_seen = 0, generation_seen = 0;
    int i, result;

    if (argc >= 2 && !strcmp(argv[1], "ha"))
        return dtunctl_ha_main(argc - 1, argv + 1);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <peer-add|peer-set|peer-del|peer-get|peer-list|rebind|hub-set|route-add|route-del> [options]\n", argv[0]);
        return 2;
    }
    action = argv[1];
    for (i = 2; i < argc; i++) {
        const char *value = NULL;
        if (!strcmp(argv[i], "--format") && i + 1 < argc) {
            value = argv[++i]; format_seen = 1;
        } else if (!strncmp(argv[i], "--format=", 9)) {
            value = argv[i] + 9; format_seen = 1;
        }
        if (value) {
            if (!strcmp(value, "human")) format = FORMAT_HUMAN;
            else if (!strcmp(value, "json")) format = FORMAT_JSON;
            else { fprintf(stderr, "invalid format: %s\n", value); return 2; }
        } else if (!strcmp(argv[i], "--ifindex") && i + 1 < argc) ifindex = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--tunnel-id") && i + 1 < argc) tunnel_id = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--remote-tunnel-id") && i + 1 < argc) remote_tunnel_id = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--node-id") && i + 1 < argc) node_id = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--generation") && i + 1 < argc) { generation = strtoull(argv[++i], NULL, 10); generation_seen = 1; }
        else if (!strcmp(argv[i], "--dynamic-raw")) { dynamic_raw = 1; dynamic_raw_seen = 1; }
        else if (!strcmp(argv[i], "--raw") && i + 1 < argc && inet_pton(AF_INET, argv[++i], &raw_addr) == 1) {}
        else if ((!strcmp(argv[i], "--udp") || !strcmp(argv[i], "--hub")) &&
                 i + 1 < argc) parse_udp(argv[++i], &udp_addr, &udp_port);
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) { parse_hex_key(argv[++i], key); has_key = 1; }
        else if (!strcmp(argv[i], "--prefix") && i + 1 < argc) parse_prefix(argv[++i], &prefix, &prefix_len);
        else { fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]); return 2; }
    }

    if ((!strncmp(action, "route-", 6) || !strcmp(action, "rebind") ||
         !strcmp(action, "hub-set")) && format_seen) {
        fprintf(stderr, "--format is supported only by peer commands\n");
        return 2;
    }
    if (!ifindex || (strcmp(action, "peer-list") && strcmp(action, "rebind") &&
                     strcmp(action, "hub-set") &&
                     !tunnel_id)) {
        fprintf(stderr, "--ifindex and, for this command, --tunnel-id are required\n");
        return 2;
    }
    if (!remote_tunnel_id) remote_tunnel_id = tunnel_id;

    if (!strcmp(action, "peer-add") || !strcmp(action, "peer-set")) {
        dtun_nl_peer_info_t info = {
            .ifindex = ifindex, .tunnel_id = tunnel_id,
            .remote_tunnel_id = remote_tunnel_id, .node_id = node_id,
            .raw_addr = raw_addr, .udp_addr = udp_addr, .udp_port = udp_port,
            .candidate_generation = generation, .dynamic_raw = dynamic_raw,
            .has_generation = generation_seen,
            .has_dynamic_raw = dynamic_raw_seen,
            .has_key = has_key
        };
        memcpy(info.key, key, sizeof(info.key));
        result = !strcmp(action, "peer-add") ? dtun_nl_peer_add(&info) :
                                                dtun_nl_peer_set(&info);
        return command_result(action, format, ifindex, tunnel_id, result);
    }
    if (!strcmp(action, "peer-del"))
        return command_result(action, format, ifindex, tunnel_id,
                              dtun_nl_peer_del(ifindex, tunnel_id));
    if (!strcmp(action, "peer-get")) {
        dtun_nl_peer_status_t status;
        result = dtun_nl_peer_get(ifindex, tunnel_id, &status);
        if (result) return command_result(action, format, ifindex, tunnel_id, result);
        if (format == FORMAT_JSON) { print_peer_json(&status); putchar('\n'); }
        else print_peer_human(&status);
        return 0;
    }
    if (!strcmp(action, "peer-list")) {
        dtun_nl_peer_status_t *items = NULL;
        size_t count = 0, n;
        result = dtun_nl_peer_list(ifindex, &items, &count);
        if (result) return command_result(action, format, ifindex, 0, result);
        qsort(items, count, sizeof(*items), compare_peer);
        if (format == FORMAT_JSON) {
            putchar('[');
            for (n = 0; n < count; n++) {
                if (n) putchar(',');
                print_peer_json(&items[n]);
            }
            printf("]\n");
        } else print_peer_list_human(items, count);
        free(items);
        return 0;
    }
    if (!strcmp(action, "rebind")) {
        result = dtun_nl_rebind(ifindex);
        if (!result) printf("rebind triggered: ifindex=%u\n", ifindex);
        else fprintf(stderr, "rebind failed: %s\n", strerror(-result));
        return result ? 1 : 0;
    }
    if (!strcmp(action, "hub-set")) {
        if (!udp_addr.s_addr || !udp_port) {
            fprintf(stderr, "hub-set requires --hub IPv4:PORT\n");
            return 2;
        }
        result = dtun_nl_hub_set(ifindex, udp_addr, udp_port);
        if (!result) printf("hub endpoint updated: ifindex=%u\n", ifindex);
        else fprintf(stderr, "hub-set failed: %s\n", strerror(-result));
        return result ? 1 : 0;
    }
    if (!strcmp(action, "route-add")) result = dtun_nl_route_add(ifindex, tunnel_id, prefix, prefix_len);
    else if (!strcmp(action, "route-del")) result = dtun_nl_route_del(ifindex, tunnel_id, prefix, prefix_len);
    else { fprintf(stderr, "unknown action: %s\n", action); return 2; }
    if (result) fprintf(stderr, "%s failed: %s\n", action, strerror(-result));
    return result ? 1 : 0;
}
