obj-m += dtun.o
dtun-y := src/dtun_main.o src/dtun_netlink.o

KDIR ?= /lib/modules/$(shell uname -r)/build
IP ?= $(CURDIR)/bin/ip
KDIRS ?= $(KDIR)
SUDO ?= sudo
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Isrc/ctl
LDFLAGS ?= -lcrypto

CTL_OBJS = src/ctl/ini_parser.o src/ctl/dtun_proto.o src/ctl/dtun_netlink.o

all: modules ctools

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

ctools: bin/dtund bin/dtunctl

src/ctl/%.o: src/ctl/%.c
	$(CC) $(CFLAGS) -c $< -o $@

bin/dtund: tools/dtund.c $(CTL_OBJS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

bin/dtunctl: tools/dtunctl.c $(CTL_OBJS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

tests/test_proto: tests/test_proto.c src/ctl/dtun_proto.o
	$(CC) $(CFLAGS) $< src/ctl/dtun_proto.o $(LDFLAGS) -o $@

tests/test_daemon_state: tests/test_daemon_state.c tools/dtund.c $(CTL_OBJS)
	$(CC) $(CFLAGS) $< $(CTL_OBJS) $(LDFLAGS) -o $@

deb: all
	@sh package/build-deb.sh

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -rf src/ctl/*.o bin/dtund bin/dtunctl tests/test_proto tests/test_daemon_state build/pkg

check: ctools tests/test_proto tests/test_daemon_state
	./tests/test_proto
	./tests/test_daemon_state
	sh -n tests/netns-smoke.sh tests/p2mp-netns.sh tests/cdaemon/lib.sh
	bash -n tests/cdaemon/01-control-plane.sh tests/cdaemon/02-data-plane.sh \
		tests/cdaemon/03-stability.sh tests/cdaemon/04-perf.sh \
		tests/cdaemon/05-real-internet.sh tests/cdaemon/run-all.sh

compat-build:
	@set -eu; for kdir in $(KDIRS); do \
		test -d "$$kdir" || { echo "missing kernel build tree: $$kdir" >&2; exit 2; }; \
		$(MAKE) KDIR="$$kdir" all; \
	done

test: check
	$(SUDO) env IP="$(IP)" DEBUG="$(DEBUG)" sh ./tests/netns-smoke.sh

p2mp-test: check
	$(SUDO) env IP="$(IP)" sh ./tests/p2mp-netns.sh
