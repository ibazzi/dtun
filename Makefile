.PHONY: all build modules ctools clean check test p2mp-test deb

KDIR ?= /lib/modules/$(shell uname -r)/build
IP ?= $(CURDIR)/bin/ip
KDIRS ?= $(KDIR)
SUDO ?= sudo
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
override CFLAGS += -Isrc/ctl
LDFLAGS ?=
override LDFLAGS += -lcrypto

BUILD_DIR = build
CTL_OBJS = $(BUILD_DIR)/ctl/ini_parser.o $(BUILD_DIR)/ctl/dtun_proto.o $(BUILD_DIR)/ctl/dtun_netlink.o $(BUILD_DIR)/ctl/dtun_ha_state.o $(BUILD_DIR)/ctl/dtun_ha_proto.o $(BUILD_DIR)/ctl/dtun_ha_replication.o $(BUILD_DIR)/ctl/dtun_ha_election.o
CTL_HEADERS = $(wildcard src/ctl/*.h)
HA_TOOL_HEADERS = $(wildcard tools/dtund_ha*.h tools/dtund_spoke_ha.h tools/dtunctl_ha.h)

all: modules ctools

modules:
	@mkdir -p $(BUILD_DIR)/src
	@cp -f Kbuild $(BUILD_DIR)/Kbuild
	@ln -snf $(CURDIR)/src/dtun_main.c $(BUILD_DIR)/src/dtun_main.c
	@ln -snf $(CURDIR)/src/dtun_netlink.c $(BUILD_DIR)/src/dtun_netlink.c
	@ln -snf $(CURDIR)/src/dtun.h $(BUILD_DIR)/src/dtun.h
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(BUILD_DIR) modules

ctools: $(BUILD_DIR)/dtund $(BUILD_DIR)/dtunctl

$(BUILD_DIR)/ctl/%.o: src/ctl/%.c $(CTL_HEADERS)
	@mkdir -p $(BUILD_DIR)/ctl
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/dtund: tools/dtund.c tools/dtund_ha_service.c tools/dtund_spoke_ha.c $(HA_TOOL_HEADERS) $(CTL_HEADERS) $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) tools/dtund.c tools/dtund_ha_service.c tools/dtund_spoke_ha.c $(CTL_OBJS) $(LDFLAGS) -pthread -o $@

$(BUILD_DIR)/dtunctl: tools/dtunctl.c tools/dtunctl_ha.c $(HA_TOOL_HEADERS) $(CTL_HEADERS) $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) tools/dtunctl.c tools/dtunctl_ha.c $(CTL_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/test_proto: tests/test_proto.c $(BUILD_DIR)/ctl/dtun_proto.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(BUILD_DIR)/ctl/dtun_proto.o $(LDFLAGS) -o $@

$(BUILD_DIR)/test_daemon_state: tests/test_daemon_state.c tools/dtund.c tools/dtund_ha_service.c tools/dtund_spoke_ha.c $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< tools/dtund_ha_service.c tools/dtund_spoke_ha.c $(CTL_OBJS) $(LDFLAGS) -pthread -o $@

$(BUILD_DIR)/test_ha_state: tests/test_ha_state.c $(BUILD_DIR)/ctl/dtun_ha_state.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(BUILD_DIR)/ctl/dtun_ha_state.o $(LDFLAGS) -o $@

$(BUILD_DIR)/test_ha_runtime: tests/test_ha_runtime.c tools/dtund_ha.c $(BUILD_DIR)/ctl/ini_parser.o $(BUILD_DIR)/ctl/dtun_ha_state.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_ha_runtime.c tools/dtund_ha.c $(BUILD_DIR)/ctl/ini_parser.o $(BUILD_DIR)/ctl/dtun_ha_state.o $(LDFLAGS) -o $@

$(BUILD_DIR)/test_ha_join: tests/test_ha_join.c $(BUILD_DIR)/ctl/dtun_ha_state.o $(BUILD_DIR)/ctl/dtun_ha_proto.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(BUILD_DIR)/ctl/dtun_ha_state.o $(BUILD_DIR)/ctl/dtun_ha_proto.o $(LDFLAGS) -o $@

$(BUILD_DIR)/test_spoke_ha: tests/test_spoke_ha.c tools/dtund_spoke_ha.c $(BUILD_DIR)/ctl/dtun_proto.o $(BUILD_DIR)/ctl/dtun_ha_state.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< tools/dtund_spoke_ha.c $(BUILD_DIR)/ctl/dtun_proto.o $(BUILD_DIR)/ctl/dtun_ha_state.o $(LDFLAGS) -o $@

clean:
	@if [ -d "$(BUILD_DIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(CURDIR)/$(BUILD_DIR) clean 2>/dev/null || true; \
	fi
	rm -rf $(BUILD_DIR)

check: ctools $(BUILD_DIR)/test_proto $(BUILD_DIR)/test_daemon_state $(BUILD_DIR)/test_ha_state $(BUILD_DIR)/test_ha_runtime $(BUILD_DIR)/test_ha_join $(BUILD_DIR)/test_spoke_ha
	./$(BUILD_DIR)/test_proto
	./$(BUILD_DIR)/test_daemon_state
	./$(BUILD_DIR)/test_ha_state
	./$(BUILD_DIR)/test_ha_runtime
	./$(BUILD_DIR)/test_ha_join
	./$(BUILD_DIR)/test_spoke_ha
	CTL=./$(BUILD_DIR)/dtunctl sh tests/test_cli.sh
	CTL=./$(BUILD_DIR)/dtunctl sh tests/test_ha_cli.sh
	sh -n tests/netns-smoke.sh tests/p2mp-netns.sh tests/cdaemon/lib.sh
	bash -n tests/cdaemon/01-control-plane.sh tests/cdaemon/02-data-plane.sh \
		tests/cdaemon/03-stability.sh tests/cdaemon/04-perf.sh \
		tests/cdaemon/05-real-internet.sh tests/cdaemon/run-all.sh \
		tests/ha-real/run.sh tests/ha-real/cleanup.sh \
		tests/ha-real/node-netns.sh

deb: all
	./debian/rules binary

compat-build:
	@set -eu; for kdir in $(KDIRS); do \
		test -d "$$kdir" || { echo "missing kernel build tree: $$kdir" >&2; exit 2; }; \
		$(MAKE) KDIR="$$kdir" all; \
	done

test: check
	$(SUDO) env IP="$(IP)" DEBUG="$(DEBUG)" sh ./tests/netns-smoke.sh

p2mp-test: check
	$(SUDO) env IP="$(IP)" sh ./tests/p2mp-netns.sh
