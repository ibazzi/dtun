#include "cli_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *dtunctl_option_value(int argc, char **argv, const char *name) {
  size_t length = strlen(name);
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], name))
      return i + 1 < argc ? argv[i + 1] : NULL;
    if (!strncmp(argv[i], name, length) && argv[i][length] == '=')
      return argv[i] + length + 1;
  }
  return NULL;
}

int dtunctl_has_option(int argc, char **argv, const char *name) {
  for (int i = 1; i < argc; i++)
    if (!strcmp(argv[i], name))
      return 1;
  return 0;
}

long dtunctl_duration_seconds(const char *text) {
  char *end;
  long value = strtol(text, &end, 10), multiplier = 1;
  if (value <= 0)
    return -1;
  if (!*end)
    return value;
  if (!strcmp(end, "s"))
    multiplier = 1;
  else if (!strcmp(end, "m"))
    multiplier = 60;
  else if (!strcmp(end, "h"))
    multiplier = 3600;
  else
    return -1;
  return value > 86400 / multiplier ? -1 : value * multiplier;
}

int dtunctl_path_join(char *out, size_t size, const char *dir,
                      const char *name) {
  return snprintf(out, size, "%s/%s", dir, name) < (int)size ? 0 : -1;
}

enum ha_output_format dtunctl_output_format(int argc, char **argv,
                                            int allow_plain) {
  const char *value = dtunctl_option_value(argc, argv, "--format");

  if (!value || !strcmp(value, "human"))
    return HA_FORMAT_HUMAN;
  if (!strcmp(value, "json"))
    return HA_FORMAT_JSON;
  if (allow_plain && !strcmp(value, "plain"))
    return HA_FORMAT_PLAIN;
  return -1;
}

int dtunctl_ha_error(int argc, char **argv, const char *action, int code,
                     const char *message) {
  if (dtunctl_output_format(argc, argv, 0) == HA_FORMAT_JSON)
    printf("{\"action\":\"%s\",\"success\":false,\"error\":{\"code\":%d,"
           "\"name\":\"%s\",\"message\":\"%s\"}}\n",
           action, code, code == 2 ? "EINVAL" : "ERROR", message);
  else
    fprintf(stderr, "%s\n", message);
  return code;
}
