obj-m += dtun.o
dtun-y := src/dtun_main.o src/dtun_netlink.o

KDIR ?= /lib/modules/$(shell uname -r)/build
IP ?= $(CURDIR)/bin/ip
KDIRS ?= $(KDIR)
SUDO ?= sudo
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Isrc/ctl
LDFLAGS ?= -lcrypto

BUILD_DIR = build
CTL_OBJS = $(BUILD_DIR)/ctl/ini_parser.o $(BUILD_DIR)/ctl/dtun_proto.o $(BUILD_DIR)/ctl/dtun_netlink.o

all: modules ctools

modules:
	@mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
	cp -f dtun.ko $(BUILD_DIR)/dtun.ko

ctools: $(BUILD_DIR)/dtund $(BUILD_DIR)/dtunctl

$(BUILD_DIR)/ctl/%.o: src/ctl/%.c
	@mkdir -p $(BUILD_DIR)/ctl
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/dtund: tools/dtund.c $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/dtunctl: tools/dtunctl.c $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/test_proto: tests/test_proto.c $(BUILD_DIR)/ctl/dtun_proto.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(BUILD_DIR)/ctl/dtun_proto.o $(LDFLAGS) -o $@

$(BUILD_DIR)/test_daemon_state: tests/test_daemon_state.c tools/dtund.c $(CTL_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -rf $(BUILD_DIR)

check: ctools $(BUILD_DIR)/test_proto $(BUILD_DIR)/test_daemon_state
	./$(BUILD_DIR)/test_proto
	./$(BUILD_DIR)/test_daemon_state
	sh -n tests/netns-smoke.sh tests/p2mp-netns.sh tests/cdaemon/lib.sh
	bash -n tests/cdaemon/01-control-plane.sh tests/cdaemon/02-data-plane.sh \
		tests/cdaemon/03-stability.sh tests/cdaemon/04-perf.sh \
		tests/cdaemon/05-real-internet.sh tests/cdaemon/run-all.sh

deb: all
	@sh package/build-deb.sh

compat-build:
	@set -eu; for kdir in $(KDIRS); do \
		test -d "$$kdir" || { echo "missing kernel build tree: $$kdir" >&2; exit 2; }; \
		$(MAKE) KDIR="$$kdir" all; \
	done

test: check
	$(SUDO) env IP="$(IP)" DEBUG="$(DEBUG)" sh ./tests/netns-smoke.sh

p2mp-test: check
	$(SUDO) env IP="$(IP)" sh ./tests/p2mp-netns.sh
