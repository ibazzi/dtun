#include "../../src/ctl/dtun_netlink.h"
#include "../../src/ctl/dtun_proto.h"
#include "../../src/ctl/ini_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_PEERS DTRG_MAX_SYNC_PEERS
#define MAX_SESSIONS ((MAX_PEERS * (MAX_PEERS - 1)) / 2)
#define HUB_STATE_VERSION 2U
#define HUB_STATE_MAGIC "DTS2"

static volatile sig_atomic_t g_running = 1;

typedef struct {
    uint64_t node_id;
    uint32_t tunnel_id;
    uint32_t hub_tunnel_id;
    struct in_addr address;
    uint8_t prefix_len;
    struct in_addr raw;
    struct in_addr udp_addr;
    uint16_t udp_port;
    time_t last_seen;
} hub_node_record_t;

typedef struct {
    uint64_t first_node;
    uint64_t second_node;
    uint32_t first_tunnel_id;
    uint32_t second_tunnel_id;
} hub_session_record_t;

/* Layout used by the original unversioned C daemon. */
typedef struct {
    uint8_t cookie_key[32];
    uint32_t next_tunnel_id;
    uint64_t next_node_id;
    hub_node_record_t nodes[MAX_PEERS];
    int node_count;
} legacy_hub_state_t;

typedef struct {
    char magic[4];
    uint32_t version;
    uint8_t cookie_key[32];
    uint32_t next_tunnel_id;
    uint64_t next_node_id;
    uint32_t node_count;
    uint32_t session_count;
    hub_node_record_t nodes[MAX_PEERS];
    hub_session_record_t sessions[MAX_SESSIONS];
} hub_state_t;

typedef struct {
    uint64_t node_id;
    uint32_t tunnel_id;
    struct in_addr address;
    int seen;
} applied_peer_t;

static hub_state_t g_hub_state;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static int parse_psk(const char *hex, uint8_t out[32])
{
    size_t i;

    memset(out, 0, 32);
    if (!hex || !*hex) {
        printf("[dtund] PSK not specified: Zero-HMAC development mode enabled.\n");
        return 0;
    }
    if (strlen(hex) != 64) {
        fprintf(stderr, "Error: psk must be 64 hexadecimal characters\n");
        return -1;
    }
    for (i = 0; i < 32; i++) {
        unsigned int value;
        char byte[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char *end = NULL;

        errno = 0;
        value = (unsigned int)strtoul(byte, &end, 16);
        if (errno || !end || *end || value > 255) {
            fprintf(stderr, "Error: psk contains non-hexadecimal characters\n");
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 1;
}

static int parse_cidr(const char *cidr, struct in_addr *addr, uint8_t *prefix_len)
{
    char buf[64];
    char *slash;
    char *end = NULL;
    long prefix = 32;

    if (!cidr || strlen(cidr) >= sizeof(buf)) return -1;
    memcpy(buf, cidr, strlen(cidr) + 1);
    slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        errno = 0;
        prefix = strtol(slash, &end, 10);
        if (errno || !end || *end || prefix < 0 || prefix > 32) return -1;
    }
    if (inet_pton(AF_INET, buf, addr) != 1) return -1;
    *prefix_len = (uint8_t)prefix;
    return 0;
}

static uint32_t prefix_mask(uint8_t prefix_len)
{
    return prefix_len ? (UINT32_MAX << (32 - prefix_len)) : 0;
}

static struct in_addr network_prefix(struct in_addr addr, uint8_t prefix_len)
{
    struct in_addr network;
    network.s_addr = htonl(ntohl(addr.s_addr) & prefix_mask(prefix_len));
    return network;
}

static int same_endpoint(const struct sockaddr_in *left,
                         const struct sockaddr_in *right)
{
    return left->sin_family == right->sin_family &&
           left->sin_addr.s_addr == right->sin_addr.s_addr &&
           left->sin_port == right->sin_port;
}

static void trigger_tunnel_warmup(struct in_addr address)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst;
    char dummy = 0;

    if (sock < 0) return;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);
    dst.sin_addr = address;
    (void)sendto(sock, &dummy, 1, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(sock);
}

static void generate_cookie(const uint8_t cookie_key[32],
                            const struct sockaddr_in *source, uint64_t node_id,
                            struct in_addr address, uint8_t prefix_len,
                            struct in_addr raw, const uint8_t nonce[16],
                            uint64_t bucket, uint8_t cookie[32])
{
    uint8_t body[64];
    uint8_t *p = body;
    uint64_t node_be;
    uint64_t bucket_be;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    node_be = ((uint64_t)htonl((uint32_t)node_id) << 32) |
              htonl((uint32_t)(node_id >> 32));
    bucket_be = ((uint64_t)htonl((uint32_t)bucket) << 32) |
                htonl((uint32_t)(bucket >> 32));
#else
    node_be = node_id;
    bucket_be = bucket;
#endif
    memcpy(p, &source->sin_addr.s_addr, 4); p += 4;
    memcpy(p, &source->sin_port, 2); p += 2;
    memcpy(p, &node_be, 8); p += 8;
    memcpy(p, &address.s_addr, 4); p += 4;
    *p++ = prefix_len;
    memcpy(p, &raw.s_addr, 4); p += 4;
    memcpy(p, nonce, 16); p += 16;
    memcpy(p, &bucket_be, 8); p += 8;
    dtrg_hmac(cookie_key, 32, body, (size_t)(p - body), cookie);
    dtrg_hmac(cookie_key, 32, cookie, 16, cookie + 16);
}

static int validate_cookie(const dtun_config_t *config,
                           const struct sockaddr_in *source,
                           const dtrg_msg_t *message)
{
    uint64_t seconds = config->cookie_seconds > 0 ?
                       (uint64_t)config->cookie_seconds : 30;
    uint64_t bucket = (uint64_t)time(NULL) / seconds;
    uint8_t expected[32];

    generate_cookie(g_hub_state.cookie_key, source, message->node_id,
                    message->address, message->prefix_len, message->raw,
                    message->nonce, bucket, expected);
    if (CRYPTO_memcmp(message->cookie, expected, sizeof(expected)) == 0)
        return 1;
    if (!bucket) return 0;
    generate_cookie(g_hub_state.cookie_key, source, message->node_id,
                    message->address, message->prefix_len, message->raw,
                    message->nonce, bucket - 1, expected);
    return CRYPTO_memcmp(message->cookie, expected, sizeof(expected)) == 0;
}

static int make_parent_dirs(const char *path)
{
    char copy[PATH_MAX];
    char *p;

    if (!path || strlen(path) >= sizeof(copy)) return -1;
    memcpy(copy, path, strlen(path) + 1);
    for (p = copy + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(copy, 0750) < 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return 0;
}

static void hub_state_init(void)
{
    memset(&g_hub_state, 0, sizeof(g_hub_state));
    memcpy(g_hub_state.magic, HUB_STATE_MAGIC, 4);
    g_hub_state.version = HUB_STATE_VERSION;
    g_hub_state.next_tunnel_id = 100;
    g_hub_state.next_node_id = 2;
    if (RAND_bytes(g_hub_state.cookie_key, sizeof(g_hub_state.cookie_key)) != 1) {
        fprintf(stderr, "Failed to generate Hub cookie key\n");
        exit(1);
    }
}

static int hub_load_state(const char *path)
{
    struct stat st;
    FILE *file;

    if (stat(path, &st) < 0) {
        if (errno == ENOENT) {
            hub_state_init();
            return 0;
        }
        perror("Hub state stat failed");
        return -1;
    }
    file = fopen(path, "rb");
    if (!file) {
        perror("Hub state open failed");
        return -1;
    }
    if ((size_t)st.st_size == sizeof(g_hub_state)) {
        if (fread(&g_hub_state, sizeof(g_hub_state), 1, file) != 1 ||
            memcmp(g_hub_state.magic, HUB_STATE_MAGIC, 4) != 0 ||
            g_hub_state.version != HUB_STATE_VERSION) {
            fclose(file);
            fprintf(stderr, "Invalid or unsupported Hub state header\n");
            return -1;
        }
    } else if ((size_t)st.st_size == sizeof(legacy_hub_state_t)) {
        legacy_hub_state_t legacy;
        uint32_t count;

        if (fread(&legacy, sizeof(legacy), 1, file) != 1) {
            fclose(file);
            fprintf(stderr, "Truncated legacy Hub state\n");
            return -1;
        }
        hub_state_init();
        if (legacy.node_count < 0 || legacy.node_count > MAX_PEERS) {
            fclose(file);
            fprintf(stderr, "Invalid legacy Hub node count\n");
            return -1;
        }
        count = (uint32_t)legacy.node_count;
        memcpy(g_hub_state.cookie_key, legacy.cookie_key, 32);
        g_hub_state.next_tunnel_id = legacy.next_tunnel_id;
        g_hub_state.next_node_id = legacy.next_node_id;
        g_hub_state.node_count = count;
        memcpy(g_hub_state.nodes, legacy.nodes,
               (size_t)count * sizeof(g_hub_state.nodes[0]));
        printf("[dtund Hub] Imported legacy state with %u nodes\n", count);
    } else {
        fclose(file);
        fprintf(stderr, "Unsupported Hub state size: %lld bytes\n",
                (long long)st.st_size);
        return -1;
    }
    fclose(file);
    if (g_hub_state.node_count > MAX_PEERS ||
        g_hub_state.session_count > MAX_SESSIONS ||
        !g_hub_state.next_tunnel_id || g_hub_state.next_node_id < 2) {
        fprintf(stderr, "Hub state contains invalid counters\n");
        return -1;
    }
    return 0;
}

static int hub_save_state(const char *path)
{
    char temporary[PATH_MAX];
    FILE *file;
    int fd;
    int failed = 0;

    if (make_parent_dirs(path) < 0 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp", path) >=
        (int)sizeof(temporary)) {
        fprintf(stderr, "Invalid Hub state path\n");
        return -1;
    }
    file = fopen(temporary, "wb");
    if (!file) {
        perror("Hub state temporary open failed");
        return -1;
    }
    fd = fileno(file);
    if (fwrite(&g_hub_state, sizeof(g_hub_state), 1, file) != 1)
        failed = 1;
    if (fflush(file) != 0 || fsync(fd) != 0)
        failed = 1;
    if (fclose(file) != 0)
        failed = 1;
    if (failed) {
        perror("Hub state write failed");
        unlink(temporary);
        return -1;
    }
    if (rename(temporary, path) < 0) {
        perror("Hub state rename failed");
        unlink(temporary);
        return -1;
    }
    return 0;
}

static int address_is_usable(struct in_addr address, uint8_t prefix_len,
                             struct in_addr pool, struct in_addr hub_address)
{
    uint32_t mask = prefix_mask(prefix_len);
    uint32_t base = ntohl(pool.s_addr) & mask;
    uint32_t broadcast = base | ~mask;
    uint32_t host = ntohl(address.s_addr);

    if (prefix_len > 30 || host <= base + 1 || host >= broadcast)
        return 0;
    if ((host & mask) != base || address.s_addr == hub_address.s_addr)
        return 0;
    return 1;
}

static int hub_validate_state(const dtun_config_t *config,
                              struct in_addr hub_address)
{
    struct in_addr pool;
    uint8_t pool_prefix;
    uint32_t i, j;
    uint32_t ids[MAX_PEERS * 2 + MAX_SESSIONS * 2];
    size_t id_count = 0;
    uint32_t max_tunnel_id = 0;
    uint64_t max_node_id = 1;

    if (parse_cidr(config->pool, &pool, &pool_prefix) < 0) {
        fprintf(stderr, "Invalid Hub pool: %s\n", config->pool);
        return -1;
    }
    pool = network_prefix(pool, pool_prefix);
    if (pool_prefix > 30 ||
        (ntohl(hub_address.s_addr) & prefix_mask(pool_prefix)) !=
            ntohl(pool.s_addr) ||
        ntohl(hub_address.s_addr) == ntohl(pool.s_addr) ||
        ntohl(hub_address.s_addr) ==
            (ntohl(pool.s_addr) | ~prefix_mask(pool_prefix))) {
        fprintf(stderr, "Hub inner address is not usable in the configured pool\n");
        return -1;
    }
    for (i = 0; i < g_hub_state.node_count; i++) {
        const hub_node_record_t *record = &g_hub_state.nodes[i];
        if (record->node_id <= 1 || !record->tunnel_id ||
            !record->hub_tunnel_id ||
            record->tunnel_id == record->hub_tunnel_id ||
            record->prefix_len != pool_prefix ||
            !address_is_usable(record->address, pool_prefix, pool, hub_address)) {
            fprintf(stderr, "Invalid persisted Hub node record at index %u\n", i);
            return -1;
        }
        for (j = 0; j < i; j++) {
            const hub_node_record_t *other = &g_hub_state.nodes[j];
            if (record->node_id == other->node_id ||
                record->address.s_addr == other->address.s_addr ||
                record->tunnel_id == other->tunnel_id ||
                record->hub_tunnel_id == other->hub_tunnel_id) {
                fprintf(stderr, "Duplicate persisted Hub node record at index %u\n", i);
                return -1;
            }
        }
        for (j = 0; j < id_count; j++)
            if (ids[j] == record->tunnel_id ||
                ids[j] == record->hub_tunnel_id) {
                fprintf(stderr, "Duplicate persisted tunnel ID at node index %u\n", i);
                return -1;
            }
        ids[id_count++] = record->tunnel_id;
        ids[id_count++] = record->hub_tunnel_id;
        if (record->tunnel_id > max_tunnel_id) max_tunnel_id = record->tunnel_id;
        if (record->hub_tunnel_id > max_tunnel_id) max_tunnel_id = record->hub_tunnel_id;
        if (record->node_id > max_node_id) max_node_id = record->node_id;
    }
    for (i = 0; i < g_hub_state.session_count; i++) {
        const hub_session_record_t *session = &g_hub_state.sessions[i];
        int first_found = 0, second_found = 0;
        if (session->first_node >= session->second_node ||
            session->first_node <= 1 || !session->first_tunnel_id ||
            !session->second_tunnel_id ||
            session->first_tunnel_id == session->second_tunnel_id) {
            fprintf(stderr, "Invalid persisted Hub session at index %u\n", i);
            return -1;
        }
        for (j = 0; j < g_hub_state.node_count; j++) {
            if (g_hub_state.nodes[j].node_id == session->first_node)
                first_found = 1;
            if (g_hub_state.nodes[j].node_id == session->second_node)
                second_found = 1;
        }
        if (!first_found || !second_found) {
            fprintf(stderr, "Persisted session references an unknown node\n");
            return -1;
        }
        for (j = 0; j < i; j++)
            if (g_hub_state.sessions[j].first_node == session->first_node &&
                g_hub_state.sessions[j].second_node == session->second_node) {
                fprintf(stderr, "Duplicate persisted Hub session pair\n");
                return -1;
            }
        for (j = 0; j < id_count; j++)
            if (ids[j] == session->first_tunnel_id ||
                ids[j] == session->second_tunnel_id) {
                fprintf(stderr, "Duplicate persisted session tunnel ID\n");
                return -1;
            }
        ids[id_count++] = session->first_tunnel_id;
        ids[id_count++] = session->second_tunnel_id;
        if (session->first_tunnel_id > max_tunnel_id)
            max_tunnel_id = session->first_tunnel_id;
        if (session->second_tunnel_id > max_tunnel_id)
            max_tunnel_id = session->second_tunnel_id;
    }
    if (max_tunnel_id == UINT32_MAX || max_node_id == UINT64_MAX) {
        fprintf(stderr, "Persisted Hub identifier space is exhausted\n");
        return -1;
    }
    if (g_hub_state.next_tunnel_id <= max_tunnel_id)
        g_hub_state.next_tunnel_id = max_tunnel_id + 1;
    if (g_hub_state.next_node_id <= max_node_id)
        g_hub_state.next_node_id = max_node_id + 1;
    return 0;
}

static int address_in_use(struct in_addr address)
{
    uint32_t i;
    for (i = 0; i < g_hub_state.node_count; i++)
        if (g_hub_state.nodes[i].address.s_addr == address.s_addr) return 1;
    return 0;
}

static hub_node_record_t *node_by_id(uint64_t node_id)
{
    uint32_t i;
    for (i = 0; i < g_hub_state.node_count; i++)
        if (g_hub_state.nodes[i].node_id == node_id) return &g_hub_state.nodes[i];
    return NULL;
}

static uint32_t allocate_tunnel_id(void)
{
    uint32_t value = g_hub_state.next_tunnel_id++;
    if (!value) value = g_hub_state.next_tunnel_id++;
    return value;
}

static hub_node_record_t *hub_allocate_node(const dtun_config_t *config,
                                            struct in_addr hub_address,
                                            uint64_t requested_node,
                                            struct in_addr requested_address,
                                            uint8_t requested_prefix,
                                            char *error, size_t error_len)
{
    struct in_addr pool;
    struct in_addr final_address = requested_address;
    hub_node_record_t *existing;
    uint8_t pool_prefix;
    uint32_t i;

    if (parse_cidr(config->pool, &pool, &pool_prefix) < 0) {
        snprintf(error, error_len, "invalid configured pool");
        return NULL;
    }
    pool = network_prefix(pool, pool_prefix);
    if (requested_node == 1) {
        snprintf(error, error_len, "node ID 1 is reserved for the Hub");
        return NULL;
    }
    existing = requested_node ? node_by_id(requested_node) : NULL;
    if (existing) {
        if ((requested_address.s_addr &&
             requested_address.s_addr != existing->address.s_addr) ||
            (requested_address.s_addr && requested_prefix != existing->prefix_len)) {
            snprintf(error, error_len,
                     "node ID is already registered with another address");
            return NULL;
        }
        return existing;
    }
    if (requested_address.s_addr) {
        if (requested_prefix != pool_prefix ||
            !address_is_usable(requested_address, pool_prefix, pool, hub_address)) {
            snprintf(error, error_len,
                     "requested address is outside the usable pool");
            return NULL;
        }
        if (address_in_use(requested_address)) {
            snprintf(error, error_len, "requested address is already assigned");
            return NULL;
        }
    } else {
        uint32_t base = ntohl(pool.s_addr);
        uint32_t broadcast = base | ~prefix_mask(pool_prefix);
        uint64_t candidate;

        for (candidate = (uint64_t)base + 2; candidate < broadcast; candidate++) {
            struct in_addr item = {.s_addr = htonl((uint32_t)candidate)};
            if (item.s_addr != hub_address.s_addr && !address_in_use(item)) {
                final_address = item;
                break;
            }
        }
        if (!final_address.s_addr) {
            snprintf(error, error_len, "address pool is exhausted");
            return NULL;
        }
    }
    if (g_hub_state.node_count >= MAX_PEERS) {
        snprintf(error, error_len, "peer limit reached");
        return NULL;
    }
    if (!requested_node) {
        do {
            requested_node = g_hub_state.next_node_id++;
        } while (requested_node <= 1 || node_by_id(requested_node));
    }
    for (i = 0; i < g_hub_state.node_count; i++) {
        if (g_hub_state.nodes[i].node_id == requested_node) {
            snprintf(error, error_len, "node ID is already assigned");
            return NULL;
        }
    }
    existing = &g_hub_state.nodes[g_hub_state.node_count++];
    memset(existing, 0, sizeof(*existing));
    existing->node_id = requested_node;
    existing->tunnel_id = allocate_tunnel_id();
    existing->hub_tunnel_id = allocate_tunnel_id();
    existing->address = final_address;
    existing->prefix_len = pool_prefix;
    return existing;
}

static hub_session_record_t *hub_session(uint64_t node_id, uint64_t other_id)
{
    uint64_t first = node_id < other_id ? node_id : other_id;
    uint64_t second = node_id < other_id ? other_id : node_id;
    uint32_t i;
    hub_session_record_t *session;

    for (i = 0; i < g_hub_state.session_count; i++) {
        session = &g_hub_state.sessions[i];
        if (session->first_node == first && session->second_node == second)
            return session;
    }
    if (g_hub_state.session_count >= MAX_SESSIONS) return NULL;
    session = &g_hub_state.sessions[g_hub_state.session_count++];
    memset(session, 0, sizeof(*session));
    session->first_node = first;
    session->second_node = second;
    session->first_tunnel_id = allocate_tunnel_id();
    session->second_tunnel_id = allocate_tunnel_id();
    return session;
}

static int program_peer(const dtun_nl_peer_info_t *peer)
{
    dtun_nl_peer_info_t update;
    if (dtun_nl_peer_add(peer) == 0) return 0;
    update = *peer;
    update.has_key = 0;
    return dtun_nl_peer_set(&update);
}

static int program_route(uint32_t ifindex, uint32_t tunnel_id,
                         struct in_addr prefix, uint8_t prefix_len)
{
    int result = dtun_nl_route_add(ifindex, tunnel_id, prefix, prefix_len);
    return result == -EEXIST ? 0 : result;
}

static uint16_t build_peer_sync(uint32_t ifindex, uint64_t node_id,
                                dtrg_sync_peer_t peers[MAX_PEERS])
{
    uint16_t count = 0;
    uint32_t i;

    for (i = 0; i < g_hub_state.node_count && count < MAX_PEERS; i++) {
        hub_node_record_t *other = &g_hub_state.nodes[i];
        hub_session_record_t *session;
        dtun_nl_peer_status_t status;

        if (other->node_id == node_id) continue;
        if (dtun_nl_peer_get(ifindex, other->hub_tunnel_id, &status) < 0 ||
            !status.udp_up || !status.udp_addr.s_addr || !status.udp_port)
            continue;
        other->udp_addr = status.udp_addr;
        other->udp_port = status.udp_port;
        other->raw = status.udp_addr;
        session = hub_session(node_id, other->node_id);
        if (!session) break;
        peers[count].node_id = other->node_id;
        peers[count].address = other->address;
        peers[count].raw = other->raw;
        peers[count].udp_addr = other->udp_addr;
        peers[count].udp_port = other->udp_port;
        if (node_id == session->first_node) {
            peers[count].tunnel_id = session->first_tunnel_id;
            peers[count].remote_tunnel_id = session->second_tunnel_id;
        } else {
            peers[count].tunnel_id = session->second_tunnel_id;
            peers[count].remote_tunnel_id = session->first_tunnel_id;
        }
        count++;
    }
    return count;
}

static int run_hub(dtun_config_t *config, const uint8_t psk[32], int has_psk)
{
    struct in_addr outer_address, inner_address, no_hub = {0};
    uint8_t prefix_len;
    uint16_t data_port = config->data_port ? (uint16_t)config->data_port : 49000;
    uint32_t ifindex;
    int created_ifindex;
    int sock;
    struct sockaddr_in bind_address;
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    uint8_t rx[DTRG_MAX_PACKET], tx[DTRG_MAX_PACKET];

    if (inet_pton(AF_INET, config->local_outer_ip, &outer_address) != 1 ||
        parse_cidr(config->address, &inner_address, &prefix_len) < 0) {
        fprintf(stderr, "Invalid Hub outer or inner address\n");
        return 1;
    }
    if (hub_load_state(config->state_file) < 0 ||
        hub_validate_state(config, inner_address) < 0)
        return 1;
    created_ifindex = dtun_link_create(config->interface, outer_address,
                                       data_port,
                                       config->node_id ? config->node_id : 1,
                                       no_hub, 0);
    if (created_ifindex <= 0) {
        fprintf(stderr, "Failed to create Hub interface %s: %s\n",
                config->interface, strerror(-created_ifindex));
        return 1;
    }
    ifindex = (uint32_t)created_ifindex;
    if (dtun_link_setup(ifindex, config->interface,
                                    inner_address, prefix_len) < 0) {
        fprintf(stderr, "Failed to create Hub interface %s\n", config->interface);
        return 1;
    }
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) goto fail_link;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons((uint16_t)config->bind_port);
    if (inet_pton(AF_INET, config->bind_address, &bind_address.sin_addr) != 1 ||
        bind(sock, (struct sockaddr *)&bind_address, sizeof(bind_address)) < 0) {
        perror("Hub control socket bind failed");
        close(sock);
        goto fail_link;
    }
    printf("[dtund] Hub listening on %s:%d (DTRG v%d)\n",
           config->bind_address, config->bind_port, DTRG_VERSION);
    fflush(stdout);
    while (g_running) {
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        ssize_t length = recvfrom(sock, rx, sizeof(rx), 0,
                                  (struct sockaddr *)&source, &source_len);
        dtrg_msg_t message;

        if (length <= 0) continue;
        if (dtrg_parse(psk, rx, (size_t)length, &message) < 0) continue;
        if (message.kind == DTRG_INIT) {
            uint64_t seconds = config->cookie_seconds > 0 ?
                               (uint64_t)config->cookie_seconds : 30;
            uint8_t cookie[32];
            ssize_t packed;

            generate_cookie(g_hub_state.cookie_key, &source, message.node_id,
                            message.address, message.prefix_len, message.raw,
                            message.nonce, (uint64_t)time(NULL) / seconds,
                            cookie);
            packed = dtrg_pack_challenge(psk, message.node_id,
                                         message.address, message.prefix_len,
                                         message.raw, message.nonce, cookie,
                                         tx, sizeof(tx));
            if (packed > 0)
                (void)sendto(sock, tx, (size_t)packed, 0,
                             (struct sockaddr *)&source, source_len);
        } else if (message.kind == DTRG_CONFIRM &&
                   validate_cookie(config, &source, &message)) {
            char allocation_error[160];
            hub_node_record_t *record = hub_allocate_node(
                config, inner_address, message.node_id, message.address,
                message.prefix_len, allocation_error, sizeof(allocation_error));

            if (!record) {
                fprintf(stderr, "[dtund Hub] Rejected registration: %s\n",
                        allocation_error);
            } else {
                dtun_nl_peer_info_t peer;
                dtrg_sync_peer_t sync_peers[MAX_PEERS];
                uint16_t sync_count;
                ssize_t packed;

                record->raw = source.sin_addr;
                record->udp_addr = source.sin_addr;
                record->udp_port = data_port;
                record->last_seen = time(NULL);
                memset(&peer, 0, sizeof(peer));
                peer.ifindex = ifindex;
                peer.tunnel_id = record->hub_tunnel_id;
                peer.remote_tunnel_id = record->tunnel_id;
                peer.node_id = record->node_id;
                peer.raw_addr = record->raw;
                peer.udp_addr = record->udp_addr;
                peer.udp_port = record->udp_port;
                peer.has_key = has_psk;
                if (has_psk) memcpy(peer.key, psk, sizeof(peer.key));
                if (program_peer(&peer) < 0 ||
                    program_route(ifindex, record->hub_tunnel_id,
                                  record->address, 32) < 0) {
                    fprintf(stderr, "[dtund Hub] Failed to program registered peer\n");
                    dtrg_msg_free(&message);
                    continue;
                }
                memset(sync_peers, 0, sizeof(sync_peers));
                sync_count = build_peer_sync(ifindex, record->node_id,
                                             sync_peers);
                if (hub_save_state(config->state_file) < 0) {
                    dtrg_msg_free(&message);
                    continue;
                }
                packed = dtrg_pack_ack(psk, record->node_id,
                                       record->tunnel_id,
                                       record->hub_tunnel_id,
                                       record->address, record->prefix_len,
                                       data_port, message.nonce,
                                       tx, sizeof(tx));
                if (packed > 0)
                    (void)sendto(sock, tx, (size_t)packed, 0,
                                 (struct sockaddr *)&source, source_len);
                packed = dtrg_pack_sync(psk, record->node_id,
                                        message.nonce, sync_peers, sync_count,
                                        tx, sizeof(tx));
                if (packed > 0)
                    (void)sendto(sock, tx, (size_t)packed, 0,
                                 (struct sockaddr *)&source, source_len);
                {
                    char text[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &record->address, text, sizeof(text));
                    printf("[dtund Hub] Registered/Refreshed Spoke NodeID=%llu InnerIP=%s DirectPeers=%u\n",
                           (unsigned long long)record->node_id, text,
                           sync_count);
                    fflush(stdout);
                }
            }
        }
        dtrg_msg_free(&message);
    }
    close(sock);
    dtun_link_delete_by_name(config->interface);
    return 0;

fail_link:
    dtun_link_delete_by_name(config->interface);
    return 1;
}

static void remove_applied_peer(uint32_t ifindex, applied_peer_t *peer)
{
    (void)dtun_nl_route_del(ifindex, peer->tunnel_id, peer->address, 32);
    (void)dtun_nl_peer_del(ifindex, peer->tunnel_id);
    memset(peer, 0, sizeof(*peer));
}

static int apply_sync(uint32_t ifindex, const dtrg_msg_t *sync,
                      const uint8_t psk[32], int has_psk,
                      applied_peer_t applied[MAX_PEERS], uint16_t *applied_count)
{
    uint16_t i, j;

    for (i = 0; i < *applied_count; i++) applied[i].seen = 0;
    for (i = 0; i < sync->peer_count; i++) {
        const dtrg_sync_peer_t *item = &sync->peers[i];
        dtun_nl_peer_info_t peer;
        applied_peer_t *slot = NULL;

        if (!item->node_id || !item->tunnel_id || !item->remote_tunnel_id ||
            !item->address.s_addr || !item->udp_addr.s_addr || !item->udp_port)
            continue;
        for (j = 0; j < *applied_count; j++) {
            if (applied[j].node_id == item->node_id) {
                slot = &applied[j];
                break;
            }
        }
        if (slot && (slot->tunnel_id != item->tunnel_id ||
                     slot->address.s_addr != item->address.s_addr)) {
            remove_applied_peer(ifindex, slot);
            slot = NULL;
        }
        if (!slot) {
            if (*applied_count >= MAX_PEERS) return -1;
            slot = &applied[(*applied_count)++];
            memset(slot, 0, sizeof(*slot));
            slot->node_id = item->node_id;
            slot->tunnel_id = item->tunnel_id;
            slot->address = item->address;
        }
        memset(&peer, 0, sizeof(peer));
        peer.ifindex = ifindex;
        peer.tunnel_id = item->tunnel_id;
        peer.remote_tunnel_id = item->remote_tunnel_id;
        peer.node_id = item->node_id;
        peer.raw_addr = item->raw;
        peer.udp_addr = item->udp_addr;
        peer.udp_port = item->udp_port;
        peer.has_key = has_psk;
        if (has_psk) memcpy(peer.key, psk, sizeof(peer.key));
        if (program_peer(&peer) < 0 ||
            program_route(ifindex, item->tunnel_id,
                          item->address, 32) < 0)
            return -1;
        slot->seen = 1;
    }
    for (i = 0; i < *applied_count;) {
        if (applied[i].seen) {
            i++;
            continue;
        }
        remove_applied_peer(ifindex, &applied[i]);
        if (i + 1 < *applied_count)
            memmove(&applied[i], &applied[i + 1],
                    (size_t)(*applied_count - i - 1) * sizeof(applied[0]));
        (*applied_count)--;
    }
    return 0;
}

static int run_spoke(dtun_config_t *config, const uint8_t psk[32], int has_psk)
{
    int sock = -1;
    struct sockaddr_in local_address, hub_control;
    struct timeval timeout;
    struct in_addr requested_address = {0}, raw_claim = {0};
    uint8_t requested_prefix = 24;
    uint16_t local_data_port = config->data_port ?
                               (uint16_t)config->data_port : 49000;
    uint8_t tx[DTRG_MAX_PACKET], rx[DTRG_MAX_PACKET];
    uint32_t ifindex = 0, hub_tunnel_id = 0;
    uint16_t hub_data_port = 0;
    struct in_addr assigned_address = {0};
    uint8_t assigned_prefix = 0;
    uint64_t assigned_node = 0;
    applied_peer_t applied[MAX_PEERS];
    uint16_t applied_count = 0;
    int registered_once = 0;
    int result = 1;

    memset(applied, 0, sizeof(applied));
    if (!config->hub_address ||
        inet_pton(AF_INET, config->hub_address, &hub_control.sin_addr) != 1 ||
        parse_cidr(config->address, &requested_address,
                   &requested_prefix) < 0) {
        fprintf(stderr, "Invalid Spoke Hub or inner address\n");
        return 1;
    }
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons((uint16_t)config->local_port);
    local_address.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&local_address, sizeof(local_address)) < 0) {
        perror("Spoke control socket bind failed");
        goto out;
    }
    hub_control.sin_family = AF_INET;
    hub_control.sin_port = htons((uint16_t)config->hub_port);
    timeout.tv_sec = config->timeout > 0 ? config->timeout : 5;
    timeout.tv_usec = 0;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    printf("[dtund] Spoke registering with %s:%d every %ds (DTRG v%d)\n",
           config->hub_address, config->hub_port, config->interval,
           DTRG_VERSION);
    fflush(stdout);

    while (g_running) {
        uint8_t nonce[16];
        dtrg_msg_t challenge, ack, sync;
        struct sockaddr_in source;
        socklen_t source_len;
        ssize_t length, packed;
        int success = 0;

        memset(&challenge, 0, sizeof(challenge));
        memset(&ack, 0, sizeof(ack));
        memset(&sync, 0, sizeof(sync));
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) break;
        packed = dtrg_pack_init(psk, config->node_id, requested_address,
                                requested_prefix, raw_claim, nonce,
                                tx, sizeof(tx));
        if (packed < 0 || sendto(sock, tx, (size_t)packed, 0,
                                (struct sockaddr *)&hub_control,
                                sizeof(hub_control)) < 0)
            goto attempt_done;
        source_len = sizeof(source);
        length = recvfrom(sock, rx, sizeof(rx), 0,
                          (struct sockaddr *)&source, &source_len);
        if (length <= 0 || !same_endpoint(&source, &hub_control) ||
            dtrg_parse(psk, rx, (size_t)length, &challenge) < 0 ||
            challenge.kind != DTRG_CHALLENGE ||
            challenge.node_id != config->node_id ||
            challenge.address.s_addr != requested_address.s_addr ||
            challenge.prefix_len != requested_prefix ||
            challenge.raw.s_addr != raw_claim.s_addr ||
            CRYPTO_memcmp(challenge.nonce, nonce, sizeof(nonce)) != 0)
            goto attempt_done;
        packed = dtrg_pack_confirm(psk, challenge.node_id,
                                   challenge.address, challenge.prefix_len,
                                   challenge.raw, nonce, challenge.cookie,
                                   tx, sizeof(tx));
        if (packed < 0 || sendto(sock, tx, (size_t)packed, 0,
                                (struct sockaddr *)&hub_control,
                                sizeof(hub_control)) < 0)
            goto attempt_done;
        source_len = sizeof(source);
        length = recvfrom(sock, rx, sizeof(rx), 0,
                          (struct sockaddr *)&source, &source_len);
        if (length <= 0 || !same_endpoint(&source, &hub_control) ||
            dtrg_parse(psk, rx, (size_t)length, &ack) < 0 ||
            ack.kind != DTRG_ACK || !ack.node_id || !ack.tunnel_id ||
            !ack.remote_tunnel_id || !ack.address.s_addr ||
            !ack.data_port ||
            CRYPTO_memcmp(ack.nonce, nonce, sizeof(nonce)) != 0 ||
            (requested_address.s_addr &&
             (ack.address.s_addr != requested_address.s_addr ||
              ack.prefix_len != requested_prefix)))
            goto attempt_done;
        if (!ifindex || assigned_node != ack.node_id ||
            assigned_address.s_addr != ack.address.s_addr ||
            assigned_prefix != ack.prefix_len ||
            hub_data_port != ack.data_port) {
            struct in_addr local_outer;
            if (inet_pton(AF_INET, config->local_outer_ip, &local_outer) != 1)
                goto attempt_done;
            if (ifindex) dtun_link_delete_by_name(config->interface);
            int created_ifindex = dtun_link_create(
                config->interface, local_outer, local_data_port, ack.node_id,
                hub_control.sin_addr, ack.data_port);
            if (created_ifindex <= 0) {
                fprintf(stderr, "Failed to create Spoke interface: %s\n",
                        strerror(-created_ifindex));
                ifindex = 0;
                goto attempt_done;
            }
            ifindex = (uint32_t)created_ifindex;
            if (dtun_link_setup(ifindex, config->interface,
                                            ack.address,
                                            ack.prefix_len) < 0) {
                ifindex = 0;
                goto attempt_done;
            }
            memset(applied, 0, sizeof(applied));
            applied_count = 0;
            hub_tunnel_id = 0;
            assigned_node = ack.node_id;
            assigned_address = ack.address;
            assigned_prefix = ack.prefix_len;
            hub_data_port = ack.data_port;
        }
        if (hub_tunnel_id && hub_tunnel_id != ack.tunnel_id) {
            struct in_addr old_network = network_prefix(assigned_address,
                                                        assigned_prefix);
            (void)dtun_nl_route_del(ifindex, hub_tunnel_id, old_network,
                                    assigned_prefix);
            (void)dtun_nl_peer_del(ifindex, hub_tunnel_id);
            hub_tunnel_id = 0;
        }
        {
            dtun_nl_peer_info_t peer;
            struct in_addr route = network_prefix(ack.address,
                                                   ack.prefix_len);
            memset(&peer, 0, sizeof(peer));
            peer.ifindex = ifindex;
            peer.tunnel_id = ack.tunnel_id;
            peer.remote_tunnel_id = ack.remote_tunnel_id;
            peer.node_id = 1;
            peer.raw_addr = hub_control.sin_addr;
            peer.udp_addr = hub_control.sin_addr;
            peer.udp_port = ack.data_port;
            peer.has_key = has_psk;
            if (has_psk) memcpy(peer.key, psk, sizeof(peer.key));
            if (program_peer(&peer) < 0 ||
                program_route(ifindex, ack.tunnel_id, route,
                              ack.prefix_len) < 0)
                goto attempt_done;
            hub_tunnel_id = ack.tunnel_id;
            trigger_tunnel_warmup((struct in_addr){
                .s_addr = htonl(ntohl(route.s_addr) + 1)});
        }
        source_len = sizeof(source);
        length = recvfrom(sock, rx, sizeof(rx), 0,
                          (struct sockaddr *)&source, &source_len);
        if (length > 0 && same_endpoint(&source, &hub_control) &&
            dtrg_parse(psk, rx, (size_t)length, &sync) == 0 &&
            sync.kind == DTRG_SYNC && sync.node_id == ack.node_id &&
            CRYPTO_memcmp(sync.nonce, nonce, sizeof(nonce)) == 0) {
            if (apply_sync(ifindex, &sync, psk, has_psk, applied,
                           &applied_count) < 0)
                goto attempt_done;
        }
        requested_address = ack.address;
        requested_prefix = ack.prefix_len;
        config->node_id = ack.node_id;
        success = 1;
        registered_once = 1;
        result = 0;
        {
            char text[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ack.address, text, sizeof(text));
            printf("[dtund Spoke] Registration successful! NodeID=%llu InnerIP=%s DataPort=%u DirectPeers=%u\n",
                   (unsigned long long)ack.node_id, text, ack.data_port,
                   applied_count);
            fflush(stdout);
        }

attempt_done:
        dtrg_msg_free(&challenge);
        dtrg_msg_free(&ack);
        dtrg_msg_free(&sync);
        if (config->once) break;
        if (!success)
            fprintf(stderr, "[dtund Spoke] Registration failed; retaining existing link and retrying\n");
        for (int i = 0; i < (config->interval > 0 ? config->interval : 1) &&
                        g_running; i++)
            sleep(1);
    }

out:
    if (sock >= 0) close(sock);
    if (ifindex && !(config->once && registered_once))
        dtun_link_delete_by_name(config->interface);
    return result;
}

int main(int argc, char **argv)
{
    const char *config_file = NULL;
    const char *override_mode = NULL;
    dtun_config_t config;
    uint8_t psk[32];
    int has_psk;
    int result;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_signal);
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) &&
            i + 1 < argc)
            config_file = argv[++i];
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc)
            override_mode = argv[++i];
    }
    if (!config_file) {
        fprintf(stderr, "Usage: %s -c /path/to/dtun.conf [--mode hub|spoke]\n",
                argv[0]);
        return 1;
    }
    if (dtun_config_load(&config, config_file) < 0) return 1;
    if (override_mode) {
        free(config.mode);
        config.mode = strdup(override_mode);
    }
    if (!config.mode) {
        fprintf(stderr, "Error: mode must be hub or spoke\n");
        dtun_config_free(&config);
        return 1;
    }
    has_psk = parse_psk(config.psk_hex, psk);
    if (has_psk < 0) {
        dtun_config_free(&config);
        return 1;
    }
    if (!strcmp(config.mode, "hub"))
        result = run_hub(&config, psk, has_psk);
    else if (!strcmp(config.mode, "spoke"))
        result = run_spoke(&config, psk, has_psk);
    else {
        fprintf(stderr, "Unknown mode: %s\n", config.mode);
        result = 1;
    }
    OPENSSL_cleanse(psk, sizeof(psk));
    dtun_nl_close();
    dtun_config_free(&config);
    return result;
}
