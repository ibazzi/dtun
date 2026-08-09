#include "ha_commands.h"
#include "peer_commands.h"

#include <stdio.h>
#include <string.h>

static void print_usage(const char *program) {
  fprintf(stderr,
          "Usage: %s peer <add|set|del|get|list> [options]\n"
          "       %s ha <command> [options]\n"
          "       %s <route-add|route-del|rebind|hub-set> [options]\n",
          program, program, program);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 2;
  }
  if (!strcmp(argv[1], "peer"))
    return dtunctl_peer_main(argc - 1, argv + 1);
  if (!strcmp(argv[1], "ha"))
    return dtunctl_ha_main(argc - 1, argv + 1);
  if (!strncmp(argv[1], "peer-", 5)) {
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
  }
  return dtunctl_peer_main(argc, argv);
}
