.PHONY: all build module ctools test-binaries clean check test p2mp-test deb \
	format check-format compat-build

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRC_DIR := $(ROOT_DIR)/src
MODULE_DIR := $(ROOT_DIR)/module
BUILD_DIR ?= $(ROOT_DIR)/build
BUILD_DIR := $(abspath $(BUILD_DIR))

CLANG_FORMAT ?= $(shell command -v clang-format || command -v clang-format-18 || echo true)
KDIR ?= /lib/modules/$(shell uname -r)/build
IP ?= $(ROOT_DIR)/bin/ip
KDIRS ?= $(KDIR)
SUDO ?= sudo
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=

# Artifacts from the pre-module/Makefile root-level Kbuild layout.
LEGACY_KERNEL_ARTIFACTS := \
	.dtun.ko.cmd .dtun.mod.cmd .dtun.mod.o.cmd .dtun.o.cmd \
	.Module.symvers.cmd .modules.order.cmd .module-common.o \
	..module-common.o.cmd \
	dtun.ko dtun.mod dtun.mod.c dtun.mod.o dtun.o Module.symvers \
	modules.order module-common.o

SRC_FILES = $(shell find include src module tests iproute2 -type f \( -name "*.c" -o -name "*.h" \))

all: module ctools

build: all

ctools:
	$(MAKE) -C $(SRC_DIR) BUILD_DIR=$(BUILD_DIR) CC="$(CC)" \
		CPPFLAGS="$(CPPFLAGS)" CFLAGS="$(CFLAGS)" \
		LDFLAGS="$(LDFLAGS)" all

test-binaries:
	$(MAKE) -C $(SRC_DIR) BUILD_DIR=$(BUILD_DIR) CC="$(CC)" \
		CPPFLAGS="$(CPPFLAGS)" CFLAGS="$(CFLAGS)" \
		LDFLAGS="$(LDFLAGS)" test-binaries

format:
	@if [ "$(CLANG_FORMAT)" != "true" ]; then \
		$(CLANG_FORMAT) -i $(SRC_FILES); \
	fi

check-format:
	@if [ "$(CLANG_FORMAT)" != "true" ]; then \
		$(CLANG_FORMAT) --dry-run --Werror $(SRC_FILES); \
	fi

module:
	$(MAKE) -C $(MODULE_DIR) BUILD_DIR=$(BUILD_DIR) KDIR="$(KDIR)" module

clean:
	$(MAKE) -C $(MODULE_DIR) BUILD_DIR=$(BUILD_DIR) KDIR="$(KDIR)" clean
	$(MAKE) -C $(SRC_DIR) BUILD_DIR=$(BUILD_DIR) clean
	rm -f $(LEGACY_KERNEL_ARTIFACTS)
	rm -rf $(BUILD_DIR)

check: check-format ctools test-binaries
	$(BUILD_DIR)/test_proto
	$(BUILD_DIR)/test_daemon_state
	$(BUILD_DIR)/test_ha_state
	$(BUILD_DIR)/test_ha_runtime
	$(BUILD_DIR)/test_ha_join
	$(BUILD_DIR)/test_spoke_ha
	$(BUILD_DIR)/test_liveness
	CTL=$(BUILD_DIR)/dtunctl sh tests/test_cli.sh
	CTL=$(BUILD_DIR)/dtunctl sh tests/test_ha_cli.sh
	sh -n tests/netns-smoke.sh tests/p2mp-netns.sh tests/cdaemon/lib.sh
	bash -n tests/cdaemon/01-control-plane.sh tests/cdaemon/02-data-plane.sh \
		tests/cdaemon/03-stability.sh tests/cdaemon/04-perf.sh \
		tests/cdaemon/05-real-internet.sh tests/cdaemon/run-all.sh \
		tests/ha-real/run.sh tests/ha-real/cleanup.sh \
		tests/ha-real/node-netns.sh tests/ha-real/run-direct-pair.sh

deb: ctools
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
