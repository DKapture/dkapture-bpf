# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

BUILD_DIR = build
TARGETs = include tools observe filter policy
SUBTARGETs = $(foreach i,$(TARGETs),$(i)/%)
KHEADERS_DIR ?= /lib/modules/$(shell uname -r)/build/include
PWD = $(shell pwd)

BPF_TARGET_ARCH := $(shell uname -m)
ifeq ($(BPF_TARGET_ARCH), loongarch64)
	BPF_TARGET_ARCH := loongarch
endif

BPF_PREPROCESS ?= $(PWD)/build/tools/extern-prep

MAKE_FLAGS += "PROJ_ROOT=$(PWD)"
MAKE_FLAGS += "BPF_TARGET_ARCH=$(BPF_TARGET_ARCH)"
MAKE_FLAGS += "BPF_PREPROCESS=$(BPF_PREPROCESS)"
MAKE_FLAGS += "KHEADERS_DIR=$(KHEADERS_DIR)"
MAKE += $(MAKE_FLAGS)

.PHONY: all clean distclean pseudo $(TARGETs)
.SUFFIXES:

all: $(TARGETs)

observe filter policy: include tools

$(TARGETs):
	$(MAKE) -C $@

$(SUBTARGETs): pseudo | $(BPF_PREPROCESS)
	$(MAKE) $* -C $(shell dirname $@)

$(BPF_PREPROCESS): 
	$(MAKE) -C $(PWD)/tools $@

pseudo:

clean:
	@for i in $(TARGETs); do $(MAKE) -C $$i clean; done

distclean:
	rm -rf $(BUILD_DIR)

help:
	# 编译完整项目:
	# 	make 或者 make all
	#
	# 清理完整项目：
	#	make clean
	#
	# 编译指定子模块：
	#	make dir
	#	例如 make observe
	# 
	# 编译模块的指定目标:
	# 	make dir/target 
	#	例如 make observe/bio-stat
	#		make observe/clean
	#
	# 清理指定子模块：
	# 	make dir/clean
	#	或 
	#	make clean -C dir
	#	例如 make observe/clean
