#include <arpa/inet.h>
#include <ctype.h>
#include <dtun/config.h>
#include <dtun/ha_defaults.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim_whitespace(char *str) {
  char *end;
  while (isspace((unsigned char)*str))
    str++;
  if (*str == 0)
    return str;
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;
  end[1] = '\0';
  return str;
}

static char *strdup_safe(const char *s) {
  if (!s)
    return NULL;
  return strdup(s);
}

void dtun_config_init(dtun_config_t *config) {
  memset(config, 0, sizeof(*config));
  config->mode = NULL;
  config->interface = strdup_safe("dtun0");
  config->local_outer_ip = strdup_safe("0.0.0.0");
  config->data_port = 49000;
  config->raw_transport = 1;
  config->node_id = 0;
  config->address = strdup_safe("0.0.0.0/24");
  config->psk_hex = NULL;

  config->syslog_enabled = 0;
  config->syslog_ident = strdup_safe("dtund");
  config->syslog_facility = strdup_safe("daemon");

  config->bind_address = strdup_safe("0.0.0.0");
  config->bind_port = 49001;
  config->pool = strdup_safe("10.99.0.0/24");
  config->pool_configured = 0;
  config->state_file = strdup_safe("/var/lib/dtun/hub.state");
  config->cookie_seconds = 30;
  config->identity_retention = 86400;

  config->hub_address = NULL;
  config->hub_port = 49001;
  config->local_port = 0;
  config->timeout = 5;
  config->once = 0;
  config->spoke_state_file = strdup_safe("/var/lib/dtun/spoke-ha.state");

  config->ha_config = NULL;
  config->ha_enabled = 0;
  config->ha_format_version = 0;
  config->ha_cluster_id = NULL;
  config->ha_hub_id = NULL;
  config->ha_role = NULL;
  config->ha_identity_key = NULL;
  config->ha_state_file = strdup_safe(DTUN_HA_STATE_PATH);
  config->ha_bootstrap_address = NULL;
  config->ha_port = DTUN_HA_PORT;
  config->ha_weight = 1000;
  config->failback = strdup_safe("immediate");
  config->recovery_stable_time = 120;
  config->min_backup_active_time = 300;
  config->failback_probation_time = 120;
  config->failback_backoff = strdup_safe("300,900,1800");
  config->failback_backoff_reset_time = 1800;
}

void dtun_config_free(dtun_config_t *config) {
  if (!config)
    return;
  free(config->mode);
  free(config->interface);
  free(config->local_outer_ip);
  free(config->address);
  free(config->psk_hex);
  free(config->syslog_ident);
  free(config->syslog_facility);
  free(config->bind_address);
  free(config->pool);
  free(config->state_file);
  free(config->hub_address);
  free(config->spoke_state_file);
  free(config->ha_config);
  free(config->ha_cluster_id);
  free(config->ha_hub_id);
  free(config->ha_role);
  free(config->ha_identity_key);
  free(config->ha_state_file);
  free(config->ha_bootstrap_address);
  free(config->failback);
  free(config->failback_backoff);
  memset(config, 0, sizeof(*config));
}

static void replace_string(char **target, const char *value) {
  free(*target);
  *target = strdup_safe(value);
}

static void apply_value(dtun_config_t *c, const char *section, const char *key,
                        const char *val) {
#define STRING_VALUE(name, field)                                              \
  if (!strcmp(key, name)) {                                                    \
    replace_string(&c->field, val);                                            \
    return;                                                                    \
  }
#define INT_VALUE(name, field)                                                 \
  if (!strcmp(key, name)) {                                                    \
    c->field = atoi(val);                                                      \
    return;                                                                    \
  }
  static const char *const obsolete[] = {
      "probe_interval_ms", "path_timeout_ms", "refresh_interval_ms",
      "interval",          "peer_timeout",    "failover_timeout",
      "fast_recovery"};

  for (size_t i = 0; i < sizeof(obsolete) / sizeof(obsolete[0]); i++)
    if (!strcmp(key, obsolete[i])) {
      snprintf(c->obsolete_key, sizeof(c->obsolete_key), "%s", key);
      return;
    }
  STRING_VALUE("mode", mode)
  STRING_VALUE("interface", interface)
  STRING_VALUE("local_outer_ip", local_outer_ip)
  INT_VALUE("data_port", data_port)
  if (!strcmp(key, "raw_transport")) {
    c->raw_transport = strcmp(val, "false") && strcmp(val, "0");
    return;
  }
  if (!strcmp(key, "node_id")) {
    c->node_id = strtoul(val, NULL, 10);
    return;
  }
  STRING_VALUE("address", address)
  STRING_VALUE("psk", psk_hex)
  if (!strcmp(key, "syslog") || !strcmp(key, "use_syslog") ||
      !strcmp(key, "log_syslog") || !strcmp(key, "syslog_enabled")) {
    c->syslog_enabled = !strcmp(val, "true") || !strcmp(val, "1");
    return;
  }
  STRING_VALUE("syslog_ident", syslog_ident)
  STRING_VALUE("syslog_facility", syslog_facility)
  STRING_VALUE("bind_address", bind_address)
  INT_VALUE("bind_port", bind_port)
  if (!strcmp(key, "pool")) {
    replace_string(&c->pool, val);
    c->pool_configured = 1;
    return;
  }
  STRING_VALUE("state_file", state_file)
  INT_VALUE("cookie_seconds", cookie_seconds)
  INT_VALUE("identity_retention", identity_retention)
  STRING_VALUE("hub_address", hub_address)
  STRING_VALUE("spoke_state_file", spoke_state_file)
  INT_VALUE("hub_port", hub_port)
  INT_VALUE("local_port", local_port)
  INT_VALUE("timeout", timeout)
  if (!strcmp(key, "once")) {
    c->once = !strcmp(val, "true") || !strcmp(val, "1");
    return;
  }
  STRING_VALUE("ha_config", ha_config)
  if ((!strcmp(key, "enabled") && !strcmp(section, "ha")) ||
      !strcmp(key, "ha_enabled")) {
    c->ha_enabled = !strcmp(val, "true") || !strcmp(val, "1");
    return;
  }
  if (!strcmp(key, "format_version") && !strcmp(section, "ha")) {
    c->ha_format_version = atoi(val);
    return;
  }
  STRING_VALUE("cluster_id", ha_cluster_id)
  STRING_VALUE("hub_id", ha_hub_id)
  if (!strcmp(key, "role") || !strcmp(key, "ha_role")) {
    replace_string(&c->ha_role, val);
    return;
  }
  STRING_VALUE("identity_private_key", ha_identity_key)
  STRING_VALUE("ha_state_file", ha_state_file)
  STRING_VALUE("bootstrap_address", ha_bootstrap_address)
  INT_VALUE("ha_port", ha_port)
  INT_VALUE("weight", ha_weight)
  STRING_VALUE("failback", failback)
  INT_VALUE("recovery_stable_time", recovery_stable_time)
  INT_VALUE("min_backup_active_time", min_backup_active_time)
  INT_VALUE("failback_probation_time", failback_probation_time)
  STRING_VALUE("failback_backoff", failback_backoff)
  INT_VALUE("failback_backoff_reset_time", failback_backoff_reset_time)
#undef STRING_VALUE
#undef INT_VALUE
}

static int parse_file(dtun_config_t *config, const char *filepath) {
  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    perror("dtun_config_load: failed to open config file");
    return -1;
  }
  char line[512];
  char section[64] = "";

  while (fgets(line, sizeof(line), fp)) {
    /* Remove comments */
    char *comment = strchr(line, '#');
    if (comment)
      *comment = '\0';
    comment = strchr(line, ';');
    if (comment)
      *comment = '\0';

    char *trimmed = trim_whitespace(line);
    if (trimmed[0] == '\0')
      continue;

    /* Section header */
    if (trimmed[0] == '[' && trimmed[strlen(trimmed) - 1] == ']') {
      trimmed[strlen(trimmed) - 1] = '\0';
      strncpy(section, trimmed + 1, sizeof(section) - 1);
      section[sizeof(section) - 1] = '\0';
      continue;
    }

    /* Key-Value pair */
    char *eq = strchr(trimmed, '=');
    if (!eq)
      continue;

    *eq = '\0';
    char *key = trim_whitespace(trimmed);
    char *val = trim_whitespace(eq + 1);

    apply_value(config, section, key, val);
    if (config->obsolete_key[0]) {
      fprintf(stderr,
              "%s: configuration key '%s' was removed; adaptive liveness is "
              "always enabled\n",
              filepath, config->obsolete_key);
      config->obsolete_key[0] = '\0';
    }
  }
  fclose(fp);
  return 0;
}

static void derive_pool_from_address(dtun_config_t *config) {
  char address[64];
  char *slash;
  char *end = NULL;
  char pool[INET_ADDRSTRLEN + 4];
  struct in_addr inner;
  size_t pool_length;
  unsigned long prefix;
  uint32_t mask;
  uint32_t network;

  if (config->pool_configured || !config->address ||
      strlen(config->address) >= sizeof(address))
    return;
  strcpy(address, config->address);
  slash = strchr(address, '/');
  if (!slash || slash == address)
    return;
  *slash++ = '\0';
  errno = 0;
  prefix = strtoul(slash, &end, 10);
  if (errno || !*slash || !end || *end || prefix > 32 ||
      inet_pton(AF_INET, address, &inner) != 1)
    return;

  mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
  network = ntohl(inner.s_addr) & mask;
  inner.s_addr = htonl(network);
  if (!inet_ntop(AF_INET, &inner, pool, INET_ADDRSTRLEN))
    return;
  pool_length = strlen(pool);
  if (snprintf(pool + pool_length, sizeof(pool) - pool_length, "/%lu",
               prefix) >= (int)(sizeof(pool) - pool_length))
    return;
  replace_string(&config->pool, pool);
}

int dtun_config_load(dtun_config_t *config, const char *filepath) {
  char *overlay = NULL;
  dtun_config_init(config);
  if (parse_file(config, filepath) < 0)
    return -1;
  if (config->ha_config && strcmp(filepath, config->ha_config)) {
    overlay = strdup_safe(config->ha_config);
    if (!overlay || parse_file(config, overlay) < 0) {
      free(overlay);
      return -1;
    }
  } else if (!config->ha_config && strcmp(filepath, DTUN_HA_CONFIG_PATH) &&
             (!config->mode || strcmp(config->mode, "spoke"))) {
    FILE *probe = fopen(DTUN_HA_CONFIG_PATH, "r");
    if (probe) {
      fclose(probe);
      if (parse_file(config, DTUN_HA_CONFIG_PATH) < 0)
        return -1;
    } else if (errno != ENOENT) {
      perror("dtun_config_load: failed to inspect default HA config");
      return -1;
    }
  }
  free(overlay);
  derive_pool_from_address(config);
  return 0;
}

int dtun_config_load_base(dtun_config_t *config, const char *filepath) {
  dtun_config_init(config);
  if (parse_file(config, filepath) < 0)
    return -1;
  derive_pool_from_address(config);
  return 0;
}
