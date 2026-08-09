ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MODULE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

BUILD_DIR ?= $(ROOT_DIR)/build
BUILD_DIR := $(abspath $(BUILD_DIR))
MODULE_BUILD_DIR ?= $(BUILD_DIR)/module
MODULE_BUILD_DIR := $(abspath $(MODULE_BUILD_DIR))
KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all module prepare clean

all: module

module: prepare
	$(MAKE) -C $(KDIR) M=$(MODULE_BUILD_DIR) modules
	@cp -f $(MODULE_BUILD_DIR)/dtun.ko $(BUILD_DIR)/dtun.ko

prepare:
	@mkdir -p $(MODULE_BUILD_DIR) $(BUILD_DIR)/include/dtun
	@cp -f $(MODULE_DIR)/Kbuild $(MODULE_BUILD_DIR)/Kbuild
	@ln -snf $(MODULE_DIR)/dtun.h $(MODULE_BUILD_DIR)/dtun.h
	@ln -snf $(MODULE_DIR)/dtun_main.c $(MODULE_BUILD_DIR)/dtun_main.c
	@ln -snf $(MODULE_DIR)/dtun_netlink.c $(MODULE_BUILD_DIR)/dtun_netlink.c
	@cp -f $(ROOT_DIR)/include/dtun/uapi.h $(BUILD_DIR)/include/dtun/uapi.h

clean:
	@if [ -d "$(MODULE_BUILD_DIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(MODULE_BUILD_DIR) clean 2>/dev/null || true; \
	fi
	rm -rf $(MODULE_BUILD_DIR) $(BUILD_DIR)/include/dtun $(BUILD_DIR)/dtun.ko
