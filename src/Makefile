# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

WIREGUARD_VERSION = 1.0.0
OMIT_ENDPOINTS ?=

KERNELRELEASE ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/amneziawg-$(WIREGUARD_VERSION)
DEPMOD ?= depmod
DEPMODBASEDIR ?= /

PWD := $(shell pwd)

all: apply-patches module
debug: apply-patches module-debug

rwildcard=$(foreach d,$(if $3,$(filter-out $3,$(wildcard $1*)),$(wildcard $1*)),$(call rwildcard,$d/,$2,$3) $(filter $(subst *,%,$2),$d))

KERNEL_SOURCE_DIR := $(PWD)/kernel
WG_SOURCE_DIR := $(KERNEL_SOURCE_DIR)/drivers/net/wireguard

define MODERN_KERNEL_CHECK_COMMAND
echo $(KERNELRELEASE) | awk 'BEGIN{ FS="."};
			   { if ($$1 < 5) { print "N"; }
				 else if ($$1 == 5) {
					 if ($$2 <= 5) { print "N"; }
					 else { print "Y"; }
				 }
				 else { print "Y"; }
			   }'
endef
export MODERN_KERNEL_CHECK_COMMAND

ifeq ($(shell $(MODERN_KERNEL_CHECK_COMMAND)),Y)
define KERNEL_SRC_ABSENT_ERR

You're running a modern Linux Kernel (version $(KERNELRELEASE)).

In order to build AmneziaWG kernel module for this kernel you must obtain sources of your kernel
by yourself and make a symlink to them into this directory:

    ln -s <path to kernel sources> kernel

After that please run make script again
endef
export KERNEL_SRC_ABSENT_ERR

GENERATED_SOURCES_DIR := $(PWD)/generated
TARGET_BUILD_DIR := $(GENERATED_SOURCES_DIR)

FILE_LIST := $(if $(strip $(realpath $(WG_SOURCE_DIR))),$(call rwildcard,$(WG_SOURCE_DIR)/,*.c *.h *.S *.pl *.include,))
SOURCE_FILES := $(filter-out Makefile main.c wireguard.mod.c tests/%,$(foreach f,$(FILE_LIST),$(subst $(WG_SOURCE_DIR)/,,$(f))))
NEEDED_SOURCES := $(addprefix $(GENERATED_SOURCES_DIR)/,main.c uapi/wireguard.h Kbuild Kconfig $(SOURCE_FILES))

apply-patches: $(NEEDED_SOURCES) $(GENERATED_SOURCES_DIR)/.patches.stamp

$(GENERATED_SOURCES_DIR)/.patches.stamp: $(sort $(wildcard $(PWD)/patches/*.patch))
	CWD=$$(pwd); \
	cd $(GENERATED_SOURCES_DIR); \
	for patch in $^; do \
		patch -F3 -t -p0 -i $$patch; \
	done; \
	cd $$CWD; \
	date > $(GENERATED_SOURCES_DIR)/.patches.stamp

$(GENERATED_SOURCES_DIR)/K%: $(PWD)/K%
	@install -d $(@D) && install -m 0644 $^ $@

$(GENERATED_SOURCES_DIR)/uapi/wireguard.h: $(KERNEL_SOURCE_DIR)/include/uapi/linux/wireguard.h
	@install -d $(@D) && install -m 0644 $^ $@

$(GENERATED_SOURCES_DIR)/%: $(WG_SOURCE_DIR)/%
	@install -d $(@D) && install -m 0644 $^ $@

$(KERNEL_SOURCE_DIR)/%:
	$(error $(KERNEL_SRC_ABSENT_ERR))
else
TARGET_BUILD_DIR := $(PWD)

apply-patches:
	@:
endif

ifneq ($(V),1)
MAKEFLAGS += --no-print-directory
endif

module:
	@$(MAKE) -C $(KERNELDIR) M=$(TARGET_BUILD_DIR) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules
	[ "$(TARGET_BUILD_DIR)" != "$(PWD)" ] && cp $(TARGET_BUILD_DIR)/amneziawg.ko $(PWD)/amneziawg.ko || true

module-debug:
	@$(MAKE) -C $(KERNELDIR) M=$(TARGET_BUILD_DIR) V=1 CONFIG_AMNEZIAWG_DEBUG=y WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules
	[ "$(TARGET_BUILD_DIR)" != "$(PWD)" ] && cp $(TARGET_BUILD_DIR)/amneziawg.ko $(PWD)/amneziawg.ko || true

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	[ "$(TARGET_BUILD_DIR)" != "$(PWD)" ] && rm -rf $(TARGET_BUILD_DIR) || true

module-install:
	@$(MAKE) -C $(KERNELDIR) M=$(TARGET_BUILD_DIR) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules_install
	$(DEPMOD) -b "$(DEPMODBASEDIR)" -a $(KERNELRELEASE)

install: module-install

DKMS_SOURCES := Makefile Kbuild Kconfig dkms.conf $(call rwildcard,,*.c *.h *.S *.pl *.include *.patch,amneziawg.mod.c kernel/% tests/%)
dkms-install: $(DKMS_SOURCES)
	@$(foreach f,$(DKMS_SOURCES),install -v -m0644 -D $(f) $(DESTDIR)$(DKMSDIR)/$(f);)
	@install -v -m 0755 ../kernel-tree-scripts/prepare-sources.sh "$(DESTDIR)$(DKMSDIR)/prepare-sources.sh"
	@install -v -m 0755 ../kernel-tree-scripts/cleanup-sources.sh "$(DESTDIR)$(DKMSDIR)/cleanup-sources.sh"
	[ "$(realpath $(WG_SOURCE_DIR))" != "" ] && ln -s "$(KERNEL_SOURCE_DIR)" "$(DESTDIR)$(DKMSDIR)/kernel" || true

style:
	$(KERNELDIR)/scripts/checkpatch.pl -f --max-line-length=4000 --codespell --color=always $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h) $(wildcard selftest/*.c)

check: clean
	scan-build --html-title=wireguard-linux-compat -maxloop 100 --view --keep-going $(MAKE) module CONFIG_WIREGUARD_DEBUG=y C=2 CF="-D__CHECK_ENDIAN__"

coccicheck: clean
	@$(MAKE) -C $(KERNELDIR) M=$(TARGET_BUILD_DIR) CONFIG_WIREGUARD_DEBUG=y coccicheck MODE=report

cloc:
	@cloc --skip-uniqueness --by-file --extract-with="$$(readlink -f ../kernel-tree-scripts/filter-compat-defines.sh) >FILE< > \$$(basename >FILE<)" $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

-include tests/debug.mk

.PHONY: all module module-debug apply-patches module-install install dkms-install clean cloc check style
