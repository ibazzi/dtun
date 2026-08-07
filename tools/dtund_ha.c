#include "dtund_ha.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int parse_backoff(const char *text, int out[3])
{
    char copy[96], *save = NULL, *item; int count = 0;
    if (!text || strlen(text) >= sizeof(copy)) return -1;
    strcpy(copy, text);
    for (item = strtok_r(copy, ",", &save); item && count < 3;
         item = strtok_r(NULL, ",", &save)) {
        char *end; long value = strtol(item, &end, 10);
        if (*end || value < 1 || value > 86400 || (count && value <= out[count-1])) return -1;
        out[count++] = (int)value;
    }
    return count == 3 && !item ? 0 : -1;
}

static dtund_ha_peer_health_t *health_by_id(dtund_ha_runtime_t *r,
                                             const char *hub_id)
{
    for (uint32_t i=0;i<r->health_count;i++)
        if (!strcmp(r->health[i].hub_id,hub_id)) return &r->health[i];
    if (r->health_count >= DTUN_HA_MAX_MEMBERS) return NULL;
    dtund_ha_peer_health_t *h=&r->health[r->health_count++];memset(h,0,sizeof(*h));
    snprintf(h->hub_id,sizeof(h->hub_id),"%s",hub_id);return h;
}

static int member_index(const dtund_ha_runtime_t *r,const char *id)
{
    for(uint32_t i=0;i<r->persistent.member_count;i++)if(!strcmp(r->persistent.members[i].hub_id,id))return(int)i;
    return -1;
}

static int member_healthy(const dtund_ha_runtime_t *r,uint32_t index,time_t now)
{
    const dtun_ha_member_t*m=&r->persistent.members[index];
    if(!m->enabled||m->role!=DTUN_HA_VOTER)return 0;
    if(!strcmp(m->hub_id,r->persistent.local_hub_id))return 1;
    for(uint32_t i=0;i<r->health_count;i++)if(!strcmp(r->health[i].hub_id,m->hub_id))
        return r->health[i].reachable&&now-r->health[i].last_heartbeat<=r->failover_timeout;
    return 0;
}

static int local_is_best_candidate(const dtund_ha_runtime_t *r,time_t now)
{
    int local=member_index(r,r->persistent.local_hub_id);if(local<0)return 0;
    const dtun_ha_member_t*best=&r->persistent.members[local];
    for(uint32_t i=0;i<r->persistent.member_count;i++){
        const dtun_ha_member_t*m=&r->persistent.members[i];
        if(!member_healthy(r,i,now))continue;
        if(m->weight>best->weight||(m->weight==best->weight&&strcmp(m->hub_id,best->hub_id)<0))best=m;
    }
    return !strcmp(best->hub_id,r->persistent.local_hub_id);
}

static int has_quorum(const dtund_ha_runtime_t *r,time_t now)
{
    uint32_t voters=0,healthy=0;
    for(uint32_t i=0;i<r->persistent.member_count;i++)if(r->persistent.members[i].enabled&&r->persistent.members[i].role==DTUN_HA_VOTER){voters++;healthy+=member_healthy(r,i,now);}
    return voters<3?healthy==voters:healthy>voters/2;
}

int dtund_ha_runtime_init(dtund_ha_runtime_t *r,const dtun_config_t*c,
                          const dtun_ha_state_t*s,time_t now)
{
    memset(r,0,sizeof(*r));r->persistent=*s;r->failover_timeout=c->failover_timeout;
    r->recovery_stable_time=c->recovery_stable_time;r->min_backup_active_time=c->min_backup_active_time;
    r->probation_time=c->failback_probation_time;r->backoff_reset_time=c->failback_backoff_reset_time;
    r->failback_immediate=c->failback&&!strcmp(c->failback,"immediate");
    if(r->failover_timeout<1||r->recovery_stable_time<1||r->min_backup_active_time<0||
       parse_backoff(c->failback_backoff,r->backoff)<0)return -1;
    r->phase=!strcmp(s->leader_id,s->local_hub_id)?DTUND_HA_PRIMARY_ACTIVE:DTUND_HA_STANDBY;
    r->phase_since=r->active_since=now;r->leader_last_seen=now;return 0;
}

void dtund_ha_note_heartbeat(dtund_ha_runtime_t*r,const char*id,uint64_t term,uint64_t match,time_t now)
{
    dtund_ha_peer_health_t*h=health_by_id(r,id);if(!h)return;h->last_heartbeat=now;h->term=term;h->match_index=match;h->reachable=1;
    if(!strcmp(id,r->persistent.leader_id))r->leader_last_seen=now;
    if(term>r->persistent.term){r->persistent.term=term;snprintf(r->persistent.leader_id,sizeof(r->persistent.leader_id),"%s",id);r->phase=DTUND_HA_STANDBY;r->phase_since=now;r->dirty=1;}
}

void dtund_ha_note_probe(dtund_ha_runtime_t*r,int success,time_t now)
{
    r->probe_total++;if(success){r->probe_success++;r->consecutive_probe_failures=0;if(!r->recovery_since)r->recovery_since=now;}
    else{r->consecutive_probe_failures++;if(r->consecutive_probe_failures>=3)r->recovery_since=0;}
}

static void promote(dtund_ha_runtime_t*r,time_t now)
{
    r->persistent.term++;r->persistent.commit_index++;
    snprintf(r->persistent.leader_id,sizeof(r->persistent.leader_id),"%s",r->persistent.local_hub_id);
    r->phase=DTUND_HA_BACKUP_HOLDDOWN;r->phase_since=r->active_since=now;r->dirty=1;
}

int dtund_ha_tick(dtund_ha_runtime_t*r,time_t now)
{
    enum dtund_ha_phase before=r->phase;
    if(r->phase==DTUND_HA_STANDBY&&now-r->leader_last_seen>=r->failover_timeout){
        if(r->persistent.member_count==2)promote(r,now);
        else if(r->persistent.member_count>=3&&has_quorum(r,now)&&local_is_best_candidate(r,now))promote(r,now);
    }else if((r->phase==DTUND_HA_PRIMARY_ACTIVE||r->phase==DTUND_HA_PRIMARY_PROBATION)&&r->persistent.member_count>=3&&!has_quorum(r,now)){
        r->phase=DTUND_HA_STANDBY;r->phase_since=now;
    }else if(r->phase==DTUND_HA_BACKUP_HOLDDOWN&&now-r->phase_since>=r->min_backup_active_time){
        r->phase=DTUND_HA_RECOVERY_OBSERVING;r->phase_since=now;r->recovery_since=0;r->probe_total=r->probe_success=0;
    }else if(r->phase==DTUND_HA_RECOVERY_OBSERVING&&r->failback_immediate&&r->recovery_since){
        int required=r->persistent.failback_level?r->backoff[(r->persistent.failback_level-1)>2?2:r->persistent.failback_level-1]:r->recovery_stable_time;
        int ratio_ok=!r->probe_total||r->probe_success*100>=r->probe_total*99;
        if(ratio_ok&&r->consecutive_probe_failures<3&&now-r->recovery_since>=required){r->phase=DTUND_HA_FAILBACK_PREPARE;r->phase_since=now;}
    }else if(r->phase==DTUND_HA_PRIMARY_PROBATION&&now-r->phase_since>=r->probation_time){
        r->phase=DTUND_HA_PRIMARY_ACTIVE;r->phase_since=now;
    }
    return before!=r->phase;
}

int dtund_ha_is_active(const dtund_ha_runtime_t*r)
{return r->phase==DTUND_HA_PRIMARY_ACTIVE||r->phase==DTUND_HA_BACKUP_HOLDDOWN||r->phase==DTUND_HA_RECOVERY_OBSERVING||r->phase==DTUND_HA_FAILBACK_PREPARE||r->phase==DTUND_HA_PRIMARY_PROBATION;}

int dtund_ha_allocation_allowed(const dtund_ha_runtime_t*r)
{return dtund_ha_is_active(r)&&has_quorum(r,time(NULL));}

const char *dtund_ha_phase_name(enum dtund_ha_phase p)
{
    static const char*n[]={"disabled","primary-active","standby","backup-holddown","recovery-observing","failback-prepare","primary-probation"};
    return p>=0&&p<(int)(sizeof(n)/sizeof(n[0]))?n[p]:"unknown";
}
