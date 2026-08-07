#include "ini_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static char *strdup_safe(const char *s) {
    if (!s) return NULL;
    return strdup(s);
}

void dtun_config_init(dtun_config_t *config) {
    memset(config, 0, sizeof(*config));
    config->mode = NULL;
    config->interface = strdup_safe("dtun0");
    config->local_outer_ip = strdup_safe("0.0.0.0");
    config->data_port = 49000;
    config->probe_interval_ms = 1000;
    config->path_timeout_ms = 3000;
    config->refresh_interval_ms = 1000;
    config->fast_recovery = 1;
    config->node_id = 0;
    config->address = strdup_safe("0.0.0.0/24");
    config->psk_hex = NULL;

    config->bind_address = strdup_safe("0.0.0.0");
    config->bind_port = 49001;
    config->pool = strdup_safe("10.99.0.0/24");
    config->state_file = strdup_safe("/var/lib/dtun/hub.state");
    config->cookie_seconds = 30;
    config->peer_timeout = 60;
    config->identity_retention = 86400;

    config->hub_address = NULL;
    config->hub_port = 49001;
    config->local_port = 0;
    config->interval = 20;
    config->timeout = 5;
    config->once = 0;
}

void dtun_config_free(dtun_config_t *config) {
    if (!config) return;
    free(config->mode);
    free(config->interface);
    free(config->local_outer_ip);
    free(config->address);
    free(config->psk_hex);
    free(config->bind_address);
    free(config->pool);
    free(config->state_file);
    free(config->hub_address);
    memset(config, 0, sizeof(*config));
}

int dtun_config_load(dtun_config_t *config, const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        perror("dtun_config_load: failed to open config file");
        return -1;
    }

    dtun_config_init(config);

    char line[512];
    char section[64] = "";

    while (fgets(line, sizeof(line), fp)) {
        /* Remove comments */
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        comment = strchr(line, ';');
        if (comment) *comment = '\0';

        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '\0') continue;

        /* Section header */
        if (trimmed[0] == '[' && trimmed[strlen(trimmed) - 1] == ']') {
            trimmed[strlen(trimmed) - 1] = '\0';
            strncpy(section, trimmed + 1, sizeof(section) - 1);
            section[sizeof(section) - 1] = '\0';
            continue;
        }

        /* Key-Value pair */
        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim_whitespace(trimmed);
        char *val = trim_whitespace(eq + 1);

        if (strcmp(key, "mode") == 0) {
            free(config->mode);
            config->mode = strdup_safe(val);
        } else if (strcmp(key, "interface") == 0) {
            free(config->interface);
            config->interface = strdup_safe(val);
        } else if (strcmp(key, "local_outer_ip") == 0) {
            free(config->local_outer_ip);
            config->local_outer_ip = strdup_safe(val);
        } else if (strcmp(key, "data_port") == 0) {
            config->data_port = atoi(val);
        } else if (strcmp(key, "probe_interval_ms") == 0) {
            config->probe_interval_ms = atoi(val);
        } else if (strcmp(key, "path_timeout_ms") == 0) {
            config->path_timeout_ms = atoi(val);
        } else if (strcmp(key, "refresh_interval_ms") == 0) {
            config->refresh_interval_ms = atoi(val);
        } else if (strcmp(key, "fast_recovery") == 0) {
            config->fast_recovery = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        } else if (strcmp(key, "node_id") == 0) {
            config->node_id = strtoul(val, NULL, 10);
        } else if (strcmp(key, "address") == 0) {
            free(config->address);
            config->address = strdup_safe(val);
        } else if (strcmp(key, "psk") == 0) {
            free(config->psk_hex);
            config->psk_hex = strdup_safe(val);
        } else if (strcmp(key, "bind_address") == 0) {
            free(config->bind_address);
            config->bind_address = strdup_safe(val);
        } else if (strcmp(key, "bind_port") == 0) {
            config->bind_port = atoi(val);
        } else if (strcmp(key, "pool") == 0) {
            free(config->pool);
            config->pool = strdup_safe(val);
        } else if (strcmp(key, "state_file") == 0) {
            free(config->state_file);
            config->state_file = strdup_safe(val);
        } else if (strcmp(key, "cookie_seconds") == 0) {
            config->cookie_seconds = atoi(val);
        } else if (strcmp(key, "peer_timeout") == 0) {
            config->peer_timeout = atoi(val);
        } else if (strcmp(key, "identity_retention") == 0) {
            config->identity_retention = atoi(val);
        } else if (strcmp(key, "hub_address") == 0) {
            free(config->hub_address);
            config->hub_address = strdup_safe(val);
        } else if (strcmp(key, "hub_port") == 0) {
            config->hub_port = atoi(val);
        } else if (strcmp(key, "local_port") == 0) {
            config->local_port = atoi(val);
        } else if (strcmp(key, "interval") == 0) {
            config->interval = atoi(val);
        } else if (strcmp(key, "timeout") == 0) {
            config->timeout = atoi(val);
        } else if (strcmp(key, "once") == 0) {
            config->once = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
    }

    fclose(fp);
    return 0;
}
