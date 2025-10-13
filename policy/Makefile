# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR := $(PROJ_ROOT)/build/$(MODULE)
BPF_SRC = $(shell ls *.bpf.c)
TARGETs = $(BPF_SRC:%.bpf.c=$(BUILD_DIR)/%.bpf.o)
BPF_TARGET_ARCH := $(shell uname -m)
ifeq ($(BPF_TARGET_ARCH), loongarch64)
	BPF_TARGET_ARCH := loongarch
endif
CLANG_FLAGS = -g -MMD -Wall -O2 \
			-I$(PROJ_ROOT)/include \
			-I$(PROJ_ROOT)/export/ \
			-I$(PROJ_ROOT)/build/include \
			-I/usr/include/$(shell uname -m)-linux-gnu/ \
			-I/lib/modules/$(shell uname -r)/build/include

.PHONY: all clean
# 注明不要删除的中间文件
.SECONDARY:
.SUFFIXES:

all: $(TARGETs)

# Ensure object directory exists
$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/%.bpf.o: %.bpf.c $(PROJ_ROOT)/build/include/vmlinux.h $(PROJ_ROOT)/build/include/kconfig.h | $(BUILD_DIR)
	clang -D__$(BPF_TARGET_ARCH)__ $(CLANG_FLAGS) -target bpf -c $< -o $@

$(PROJ_ROOT)/build/include/vmlinux.h:
	make -C $(PROJ_ROOT)/include/ $@

$(PROJ_ROOT)/build/include/kconfig.h:
	make -C $(PROJ_ROOT)/include/ $@

built-in.a:
	clang -r $(BUILD_DIR)/*.bpf.o -o $@

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d $(TARGETs)

distclean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)
	
