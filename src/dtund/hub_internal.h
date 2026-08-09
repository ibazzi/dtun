#ifndef DTUND_HUB_INTERNAL_H
#define DTUND_HUB_INTERNAL_H

#include "hub_state.h"

#include <dtun/liveness.h>

#define MAX_PEERS DTRG_MAX_SYNC_PEERS
#define MAX_SESSIONS ((MAX_PEERS * (MAX_PEERS - 1)) / 2)
#define HUB_STATE_FORMAT 1U
#define HUB_STATE_MAGIC "DTSF"
#define HUB_CHANGE_LOG_SIZE 512
#define REFRESH_PEERS_PER_PAGE 20

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
  uint64_t generation;
  uint8_t lease_token[DTRG_LEASE_TOKEN_LEN];
  uint64_t refresh_counter;
  time_t offline_since;
  uint8_t online;
} hub_node_record_t;

typedef struct {
  uint64_t first_node;
  uint64_t second_node;
  uint32_t first_tunnel_id;
  uint32_t second_tunnel_id;
} hub_session_record_t;

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
} hub_node_record_v2_t;

typedef struct {
  uint8_t cookie_key[32];
  uint32_t next_tunnel_id;
  uint64_t next_node_id;
  hub_node_record_v2_t nodes[MAX_PEERS];
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
  uint64_t candidate_epoch;
  hub_node_record_t nodes[MAX_PEERS];
  hub_session_record_t sessions[MAX_SESSIONS];
} hub_state_t;

typedef struct {
  dtun_liveness_t liveness;
  uint64_t last_arrival_ms;
} hub_node_health_t;

typedef struct {
  uint64_t epoch;
  uint64_t node_id;
} hub_change_t;

extern hub_state_t g_hub_state;
extern hub_node_health_t g_hub_node_health[MAX_PEERS];
extern hub_change_t g_hub_changes[HUB_CHANGE_LOG_SIZE];
extern size_t g_hub_change_head;
extern size_t g_hub_change_count;

void hub_note_change(uint64_t node_id);
void hub_state_init(void);
int hub_load_state(const char *path);
int hub_save_state(const char *path);
int hub_validate_state(const dtun_config_t *config, struct in_addr hub_address);
hub_node_record_t *
hub_allocate_node(const dtun_config_t *config, struct in_addr hub_address,
                  uint64_t requested_node, struct in_addr requested_address,
                  uint8_t requested_prefix, char *error, size_t error_len);
hub_node_record_t *node_by_address(struct in_addr address);
hub_node_record_t *node_by_id(uint64_t node_id);
hub_session_record_t *hub_session(uint64_t node_id, uint64_t other_id);
void hub_remove_node_at(uint32_t index);

#endif /* DTUND_HUB_INTERNAL_H */
