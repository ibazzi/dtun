#ifndef DTUND_HUB_SYNC_H
#define DTUND_HUB_SYNC_H

#include <dtun/proto.h>

#include <stdint.h>

uint16_t build_peer_sync(uint32_t ifindex, uint64_t node_id,
                         dtrg_sync_peer_t peers[DTRG_MAX_SYNC_PEERS]);
int refresh_hub_candidates(uint32_t ifindex);
uint16_t build_refresh_page(uint64_t requester, uint64_t requested_epoch,
                            uint16_t offset, dtrg_sync_peer_t *peers,
                            uint8_t *flags, uint16_t *next_offset);

#endif /* DTUND_HUB_SYNC_H */
