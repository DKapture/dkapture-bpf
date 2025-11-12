# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

PROJ_ROOT ?= ..
MODULE := $(notdir $(CURDIR))
BUILD_DIR = $(PROJ_ROOT)/build/$(MODULE)
VMLINUX ?= /sys/kernel/btf/vmlinux
KCONFIG_GZ ?= /proc/config.gz

.PHONY: all clean distclean
.SECONDARY:
.SUFFIXES:

all: $(BUILD_DIR)/vmlinux.h $(BUILD_DIR)/kconfig.h

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/vmlinux.h: $(VMLINUX) | $(BUILD_DIR)
	bpftool btf dump file $< format c > $@

$(BUILD_DIR)/kconfig.h: $(KCONFIG_GZ) | $(BUILD_DIR)
	python3 $(PROJ_ROOT)/scripts/gen_kconfig.py $@ $<

clean:

distclean: clean
	rm -f $(BUILD_DIR)/vmlinux.h $(BUILD_DIR)/kconfig.h

.PHONY: all clean distclean