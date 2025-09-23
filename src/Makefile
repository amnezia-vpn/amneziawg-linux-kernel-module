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

all: module
debug: module-debug

ifneq ($(V),1)
MAKEFLAGS += --no-print-directory
endif

module:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules

module-debug:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=1 CONFIG_AMNEZIAWG_DEBUG=y WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

module-install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) WIREGUARD_VERSION="$(WIREGUARD_VERSION)" OMIT_ENDPOINTS="$(OMIT_ENDPOINTS)" modules_install
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
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_WIREGUARD_DEBUG=y coccicheck MODE=report

cloc:
	@cloc --skip-uniqueness --by-file --extract-with="$$(readlink -f ../kernel-tree-scripts/filter-compat-defines.sh) >FILE< > \$$(basename >FILE<)" $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

-include tests/debug.mk

.PHONY: all module module-debug apply-patches module-install install dkms-install clean cloc check style
