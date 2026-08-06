#ifndef INI_PARSER_H
#define INI_PARSER_H

#include <stddef.h>

typedef struct {
    char *mode;             /* "hub" or "spoke" */
    char *interface;        /* e.g., "dtun0" */
    char *local_outer_ip;   /* default "0.0.0.0" */
    int data_port;          /* default 49000 */
    unsigned long node_id;  /* 0 means auto-allocate for spoke, 1 for hub default */
    char *address;          /* inner IPv4 CIDR, e.g., "10.99.0.2/24" or "0.0.0.0/24" */
    char *psk_hex;          /* 64 hex characters (32 bytes) */

    /* Hub-specific settings */
    char *bind_address;     /* default "0.0.0.0" */
    int bind_port;          /* default 49001 */
    char *pool;             /* e.g., "10.99.0.0/24" */
    char *state_file;       /* default "/var/lib/dtun/hub.state" */
    int cookie_seconds;     /* default 30 */

    /* Spoke-specific settings */
    char *hub_address;      /* Hub IP address */
    int hub_port;           /* Hub control UDP port, default 49001 */
    int local_port;         /* Local UDP source port, 0 for random */
    int interval;           /* Re-registration interval in seconds, default 20 */
    int timeout;            /* Registration timeout in seconds, default 5 */
    int once;               /* 1 if run once and exit */
} dtun_config_t;

void dtun_config_init(dtun_config_t *config);
void dtun_config_free(dtun_config_t *config);
int dtun_config_load(dtun_config_t *config, const char *filepath);

#endif /* INI_PARSER_H */
