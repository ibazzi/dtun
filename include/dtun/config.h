#ifndef DTUN_CONFIG_H
#define DTUN_CONFIG_H

#include <stddef.h>

typedef struct {
  char *mode;           /* "hub" or "spoke" */
  char *interface;      /* e.g., "dtun0" */
  char *local_outer_ip; /* default "0.0.0.0" */
  int data_port;        /* default 49000 */
  int raw_transport;    /* default true; false forces UDP/Hub paths */
  unsigned long
      node_id;   /* 0 means auto-allocate for spoke, 1 for hub default */
  char *address; /* inner IPv4 CIDR, e.g., "10.99.0.2/24" or "0.0.0.0/24" */
  char *psk_hex; /* 64 hex characters (32 bytes) */

  /* Logging settings */
  int syslog_enabled;    /* 1 when syslog output is enabled */
  char *syslog_ident;    /* syslog identity, default "dtund" */
  char *syslog_facility; /* syslog facility, default "daemon" */

  /* Hub-specific settings */
  char *bind_address;     /* default "0.0.0.0" */
  int bind_port;          /* default 49001 */
  char *pool;             /* derived from address when omitted */
  int pool_configured;    /* 1 when pool was explicitly configured */
  char *state_file;       /* default "/var/lib/dtun/hub.state" */
  int cookie_seconds;     /* default 30 */
  int identity_retention; /* stable allocation retention, default 86400 */

  /* Spoke-specific settings */
  char *hub_address;      /* Hub IP address */
  int hub_port;           /* Hub control UDP port, default 49001 */
  int local_port;         /* Local UDP source port, 0 for random */
  int timeout;            /* Registration timeout in seconds, default 5 */
  int once;               /* 1 if run once and exit */
  char *spoke_state_file; /* learned HA Hub list */

  /* HA settings.  ha_config is a generated overlay loaded after this file. */
  char *ha_config;
  int ha_enabled;
  int ha_format_version;
  char *ha_cluster_id;
  char *ha_hub_id;
  char *ha_role; /* primary or backup */
  char *ha_identity_key;
  char *ha_state_file;
  char *ha_bootstrap_address;
  int ha_port;
  int ha_weight;
  char *failback; /* immediate or sticky */
  int recovery_stable_time;
  int min_backup_active_time;
  int failback_probation_time;
  char *failback_backoff;
  int failback_backoff_reset_time;
  char obsolete_key[64];
} dtun_config_t;

void dtun_config_init(dtun_config_t *config);
void dtun_config_free(dtun_config_t *config);
int dtun_config_load(dtun_config_t *config, const char *filepath);
int dtun_config_load_base(dtun_config_t *config, const char *filepath);

#endif /* DTUN_CONFIG_H */
