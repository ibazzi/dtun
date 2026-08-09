#ifndef DTUNCTL_CLI_COMMON_H
#define DTUNCTL_CLI_COMMON_H

#include <stddef.h>

enum ha_output_format { HA_FORMAT_HUMAN, HA_FORMAT_JSON, HA_FORMAT_PLAIN };

const char *dtunctl_option_value(int argc, char **argv, const char *name);
int dtunctl_has_option(int argc, char **argv, const char *name);
long dtunctl_duration_seconds(const char *text);
int dtunctl_path_join(char *out, size_t size, const char *dir,
                      const char *name);
enum ha_output_format dtunctl_output_format(int argc, char **argv,
                                            int allow_plain);
int dtunctl_ha_error(int argc, char **argv, const char *action, int code,
                     const char *message);

#endif /* DTUNCTL_CLI_COMMON_H */
