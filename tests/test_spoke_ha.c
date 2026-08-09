#include "../src/dtund/spoke_ha.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "test_spoke_ha:%d: %s\n", __LINE__, #x);                 \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  dtund_spoke_ha_t state, loaded;
  dtrg_msg_t message;
  dtrg_hub_t hubs[3];
  struct sockaddr_in current;
  char path[] = "/tmp/dtun-spoke-ha-XXXXXX";
  int fd = mkstemp(path);
  CHECK(fd >= 0);
  close(fd);
  unlink(path);
  dtund_spoke_ha_init(&state, 100000);
  memset(&message, 0, sizeof(message));
  memset(hubs, 0, sizeof(hubs));
  message.kind = DTRG_HUB_LIST;
  message.term = 2;
  message.ha_mode = DTRG_HA_MODE_QUORUM;
  message.hub_count = 3;
  message.hubs = hubs;
  strcpy(hubs[0].hub_id, "primary");
  strcpy(hubs[1].hub_id, "backup-a");
  strcpy(hubs[2].hub_id, "backup-b");
  inet_pton(AF_INET, "192.0.2.1", &hubs[0].address);
  inet_pton(AF_INET, "192.0.2.2", &hubs[1].address);
  inet_pton(AF_INET, "192.0.2.3", &hubs[2].address);
  hubs[0].control_port = hubs[1].control_port = hubs[2].control_port = 49001;
  hubs[0].weight = 1000;
  hubs[1].weight = 800;
  hubs[2].weight = 900;
  CHECK(dtund_spoke_ha_update(&state, &message, 100000) == 0);
  memset(&current, 0, sizeof(current));
  current.sin_family = AF_INET;
  current.sin_addr = hubs[0].address;
  current.sin_port = htons(49001);
  for (int i = 0; i < 4; i++)
    dtund_spoke_ha_missed(&state, 100200 + (uint64_t)i * 100);
  CHECK(!dtund_spoke_ha_failover(&state, &current, 100599));
  CHECK(dtund_spoke_ha_failover(&state, &current, 100600));
  CHECK(current.sin_addr.s_addr == hubs[2].address.s_addr);
  for (int i = 0; i < 4; i++)
    dtund_spoke_ha_missed(&state, 100800 + (uint64_t)i * 100);
  CHECK(dtund_spoke_ha_failover(&state, &current, 101500));
  CHECK(current.sin_addr.s_addr == hubs[0].address.s_addr);
  state.force_switch = 1;
  CHECK(dtund_spoke_ha_save(&state, path) == 0);
  CHECK(dtund_spoke_ha_load(&loaded, path, 200000) == 0 && loaded.term == 2 &&
        loaded.hub_count == 3 && !loaded.force_switch);
  unlink(path);
  puts("Spoke HA selection/persistence tests passed");
  return 0;
}
