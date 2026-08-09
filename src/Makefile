ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SRC_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
INCLUDE_DIR := $(ROOT_DIR)/include

BUILD_DIR ?= $(ROOT_DIR)/build
BUILD_DIR := $(abspath $(BUILD_DIR))
OBJ_DIR := $(BUILD_DIR)/obj
LIB_DIR := $(BUILD_DIR)/lib

CC ?= gcc
AR ?= ar
ARFLAGS ?= rcs
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS ?=
override CPPFLAGS += -I$(INCLUDE_DIR) -I$(SRC_DIR)/dtund -I$(SRC_DIR)/dtunctl
LDFLAGS ?=
LDLIBS ?= -lcrypto

PUBLIC_HEADERS := $(wildcard $(INCLUDE_DIR)/dtun/*.h)

CORE_SOURCES := \
	$(SRC_DIR)/lib/core/config.c \
	$(SRC_DIR)/lib/core/log.c \
	$(SRC_DIR)/lib/core/liveness.c
PROTO_SOURCES := \
	$(SRC_DIR)/lib/protocol/dtrg.c \
	$(SRC_DIR)/lib/protocol/ha.c
HA_SOURCES := \
	$(SRC_DIR)/lib/ha/state.c \
	$(SRC_DIR)/lib/ha/election.c \
	$(SRC_DIR)/lib/ha/replication.c
NETLINK_SOURCES := $(SRC_DIR)/lib/netlink/client.c
DTUND_SOURCES := \
	$(SRC_DIR)/dtund/daemon_util.c \
	$(SRC_DIR)/dtund/hub_state.c \
	$(SRC_DIR)/dtund/hub.c \
	$(SRC_DIR)/dtund/hub_sync.c \
	$(SRC_DIR)/dtund/spoke.c \
	$(SRC_DIR)/dtund/ha_runtime.c \
	$(SRC_DIR)/dtund/ha_service.c \
	$(SRC_DIR)/dtund/spoke_ha.c
DTUNCTL_SOURCES := \
	$(SRC_DIR)/dtunctl/cli_common.c \
	$(SRC_DIR)/dtunctl/peer_commands.c \
	$(SRC_DIR)/dtunctl/ha_commands.c

CORE_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(CORE_SOURCES))
PROTO_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PROTO_SOURCES))
HA_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(HA_SOURCES))
NETLINK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(NETLINK_SOURCES))
DTUND_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(DTUND_SOURCES))
DTUNCTL_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(DTUNCTL_SOURCES))

LIBS := $(LIB_DIR)/libdtun_core.a $(LIB_DIR)/libdtun_proto.a \
	$(LIB_DIR)/libdtun_ha.a $(LIB_DIR)/libdtun_netlink.a \
	$(LIB_DIR)/libdtund.a
LIB_GROUP := -Wl,--start-group $(LIBS) -Wl,--end-group

TEST_BINS := \
	$(BUILD_DIR)/test_proto \
	$(BUILD_DIR)/test_daemon_state \
	$(BUILD_DIR)/test_ha_state \
	$(BUILD_DIR)/test_ha_runtime \
	$(BUILD_DIR)/test_ha_join \
	$(BUILD_DIR)/test_spoke_ha \
	$(BUILD_DIR)/test_liveness

ALL_OBJS := $(CORE_OBJS) $(PROTO_OBJS) $(HA_OBJS) $(NETLINK_OBJS) \
	$(DTUND_OBJS) $(DTUNCTL_OBJS)
DEPS := $(ALL_OBJS:.o=.d)

.PHONY: all ctools test-binaries clean

all: ctools

ctools: $(BUILD_DIR)/dtund $(BUILD_DIR)/dtunctl

test-binaries: $(TEST_BINS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(PUBLIC_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(LIB_DIR)/libdtun_core.a: $(CORE_OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $^

$(LIB_DIR)/libdtun_proto.a: $(PROTO_OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $^

$(LIB_DIR)/libdtun_ha.a: $(HA_OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $^

$(LIB_DIR)/libdtun_netlink.a: $(NETLINK_OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $^

$(LIB_DIR)/libdtund.a: $(DTUND_OBJS)
	@mkdir -p $(dir $@)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/dtund: $(OBJ_DIR)/dtund/main.o $(LIBS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) -pthread -o $@

$(BUILD_DIR)/dtunctl: $(OBJ_DIR)/dtunctl/main.o $(DTUNCTL_OBJS) \
		$(LIB_DIR)/libdtun_core.a $(LIB_DIR)/libdtun_proto.a \
		$(LIB_DIR)/libdtun_ha.a $(LIB_DIR)/libdtun_netlink.a
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(DTUNCTL_OBJS) \
		-Wl,--start-group $(LIB_DIR)/libdtun_core.a \
		$(LIB_DIR)/libdtun_proto.a $(LIB_DIR)/libdtun_ha.a \
		$(LIB_DIR)/libdtun_netlink.a -Wl,--end-group \
		$(LDFLAGS) $(LDLIBS) -o $@

$(OBJ_DIR)/dtunctl/main.o: $(SRC_DIR)/dtunctl/main.c \
		$(SRC_DIR)/dtunctl/peer_commands.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/test_proto: $(ROOT_DIR)/tests/test_proto.c \
		$(LIB_DIR)/libdtun_proto.a $(LIB_DIR)/libdtun_core.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_daemon_state: $(ROOT_DIR)/tests/test_daemon_state.c \
		$(LIBS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) \
		-pthread -o $@

$(BUILD_DIR)/test_ha_state: $(ROOT_DIR)/tests/test_ha_state.c \
		$(LIB_DIR)/libdtun_ha.a $(LIB_DIR)/libdtun_core.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_ha_runtime: $(ROOT_DIR)/tests/test_ha_runtime.c \
		$(LIBS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) \
		-pthread -o $@

$(BUILD_DIR)/test_ha_join: $(ROOT_DIR)/tests/test_ha_join.c \
		$(LIBS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_spoke_ha: $(ROOT_DIR)/tests/test_spoke_ha.c \
		$(LIBS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_GROUP) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_liveness: $(ROOT_DIR)/tests/test_liveness.c \
		$(LIB_DIR)/libdtun_core.a
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB_DIR)/libdtun_core.a -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BUILD_DIR)/ctl
	rm -f $(BUILD_DIR)/dtund $(BUILD_DIR)/dtunctl $(TEST_BINS)

-include $(DEPS)
