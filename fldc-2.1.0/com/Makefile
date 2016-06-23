## KSRC=/lib/modules/$(shell uname -r)/build
KSRC=/lib/modules/$(shell uname -r)/build
KOBJ=/lib/modules/$(shell uname -r)/build
KLIB_BUILD=$(KSRC)
PWD := $(shell pwd)

autoconf_h=$(shell /bin/ls -1 $(KOBJ)/include/*/autoconf.h 2> /dev/null | head -1)
kconfig_h=$(shell /bin/ls -1 $(KOBJ)/include/*/kconfig.h 2> /dev/null | head -1)

ifneq ($(kconfig_h),)
KCONFIG_H = -include $(kconfig_h)
endif

#
# Use this if you're building on a OFED system.  Make sure you
# configure the ofa_kernel-1.3 tree with the options from 
# /etc/infiniband/info
#
OFA=/usr/src/ofa_kernel/default
OFA_SRC=/usr/src/ofa_kernel-2.0

#
# Use this if you're building against a kernel.org kernel with
# rdma support enabled.
# 
#OFA=$(KSRC)
#OFA=$(KOBJ)

# Only build the common poart if we are not building the IB transport
obj-m := fldc_com.o

# The code is split into common, IB transport and TCP (sockets) transport
fldc_com-y := rna_com_module.o rna_com_core.o rna_duplicated_code.o rna_proc_ep.o rna_com_core_wrappers.o
fldc_transport_ib-y := rna_com_ib.o rna_com_shared_ib.o
fldc_transport_tcp-y := rna_com_tcp.o rna_com_shared_tcp.o
ccflags-y := -I$(src)/../common

KBUILD_EXTRA_SYMBOLS := $(OFA)/Module.symvers

CPU := $(shell uname -m)

EXTRA_CFLAGS += -Werror
EXTRA_CFLAGS += -Wno-unused
EXTRA_CFLAGS += -DX86_DIV64
EXTRA_CFLAGS += -DRNA_READ_PAGES
EXTRA_CFLAGS += -DDBG_STATS
EXTRA_CFLAGS += -DRDMA_READ_OVERRIDE
EXTRA_CFLAGS += -DPREFIX_NODE_GUID_TO_PATH
#EXTRA_CFLAGS += -DENABLE_PROC_EP

ifeq "$(DISABLE_IB)" "TRUE"
EXTRA_CFLAGS += -D _DISABLE_IB_
endif

# Find directory of sources
ifeq ($(SOURCE_DIRECTORY),)
ifneq ($(BLKSRC),)
SOURCE_DIRECTORY = $(BLKSRC)
else ifneq ($(KBUILD_EXTMOD),)
SOURCE_DIRECTORY = $(KBUILD_EXTMOD)
else ifneq ($(SUBDIRS),)
SOURCE_DIRECTORY = $(SUBDIRS)
else	# punt
SOURCE_DIRECTORY = $(PWD)
endif	# ifneq ($(BLKSRC),)
endif	# ifeq ($(SOURCE_DIRECTORY),)

EXTRA_CFLAGS += -I$(SOURCE_DIRECTORY)/../../common

#export KBUILD_VERBOSE = 1

#NOTE: BUG 95. ZCOPY causes data corruption on 32 bit systems. It should be disabled on all 32 bit systems.
ifneq "$(CPU)" "i686"
EXTRA_CFLAGS += -DRNA_Z_COPY
EXTRA_CFLAGS += -DRNA_Z_COPY_WRITE
endif

ifndef BUILD
BUILD := $(shell svn info | grep Revision | cut -b 11-)
endif

ifndef KVER
KVER := $(shell uname -r)
endif

# We can disable either transport, and they won't be compiled.
# fldc_com.ko is always built.
ifneq "$(DISABLE_IB)" "TRUE"
obj-m += fldc_transport_ib.o
OFED_VER := $(shell ofed_info | grep "^MLNX_OFED_LINUX")
ifeq "$OFED_VER" ""
OFED_VER := $(shell ofed_info | grep "^OFED")
MLNX_OFED_VER_NUM = "0"
else
MLNX_OFED_VER_NUM = $(shell ofed_info | grep "^MLNX_OFED_LINUX" | awk -F' ' '{ print $$2 }' | sed -e 's/[:/\\ ]//g' | sed -e 's/(//g' | sed -e 's/)//g' )

#
# This should be a better test (e.g. check OFED version) but I'm tired
# of trying to sort out why I'm having trouble parsing the version string :-(
#
EXTRA_CFLAGS += -DMLNX_OFED_USED
endif
EXTRA_CFLAGS += -DOFED_1_2_5
endif

ifneq "$(DISABLE_TCP)" "TRUE"
obj-m += fldc_transport_tcp.o
endif

INSTALL_DIR := /lib/modules/$(KVER)/extra/fldc
VERSION_FILE := ../../VERSION
RELEASE_FILE := ../../RELEASE

ifeq "$(SLES_10_2_BUILD)" "TRUE"
EXTRA_CFLAGS += -DSLES_10_2_BUILD
endif

ifneq "$(rna_debug)" "0"
# uncomment this flag to enable verbose logging
# not for production
EXTRA_CFLAGS += -DVERBOSE_LOGS

# uncomment this flag to enable state lock checking
# not for production
EXTRA_CFLAGS += -DCHECK_STATE_LOCKS

# enables a few extra fields in /proc/rna/stats that we wouldn't normally enable for customers
# EXTRA_CFLAGS += -DEXTRA_VERBOSE_STATS
#EXTRA_CFLAGS += -DSPIN_ON_SEND_AVAIL
EXTRA_CFLAGS += -DINLINE_DATA_READY_RECV
EXTRA_CFLAGS += -DBLOCK_FOR_RDMA_BUF

# uncomment to turn off inline functions, handy for reading dump stacks
# EXTRA_CFLAGS += -fno-inline
endif

# We use the presence of the ofa_kernel directory to determine
# if OFED is installed. This check is weak, since its possible
# the directory is stale.
ifneq "$(DISABLE_IB)" "TRUE"
CHECK_OFED := $(shell stat --format="TRUE" $(OFA) 2> /dev/null)
else
CHECK_OFED = "FALSE"
endif

INSTALL_DEPS =
ifeq "$(CHECK_OFED)" "TRUE"
ifeq "$(MLNX_OFED_VER_NUM)" "OFED-2.0-0.2.6"
# This version of MLNX_OFED required compat.mk.
# Later versions don't provide this, and fortunately don't need it
INSTALL_DEPS += $(OFA)
SAVE_CFLAGS := $(CFLAGS)
include $(OFA_SRC)/ofed_scripts/compat.mk
COMPAT_CFLAGS := $(CFLAGS)
CFLAGS := $(SAVE_CFLAGS)
endif  # MLNX_OFED_VER_NUM
EXTRA_CFLAGS += -DRNA_OFED_BUILD -I$(OFA)/include
endif
EXTRA_CFLAGS += $(COMPAT_CFLAGS)

all: default

install:
	echo ******* INSTALL_DIR=$(INSTALL_DIR) 
	-if [ ! -d $(INSTALL_DIR) ]; then mkdir $(INSTALL_DIR); fi
	install -m 644 -c fldc_com.ko $(INSTALL_DIR)
ifneq "$(DISABLE_IB)" "TRUE"
	install -m 644 -c fldc_transport_ib.ko $(INSTALL_DIR)
endif

ifneq "$(DISABLE_TCP)" "TRUE"
	install -m 644 -c fldc_transport_tcp.ko $(INSTALL_DIR)
endif
	depmod -a

# We don't use build.h as the target because we want it updated
# with the latest SVN id (potentially) every time make is run
version_header: build.h
# If $BUILD is defined, always rewrite build.h
ifneq "$(BUILD)" ""
	echo "==== Updating build.h to build $(BUILD) ===="
	echo "#define BUILD $(BUILD)" > build.h
	echo "#define REVISION \"$(VERSION).$(RELEASE)\"" >> build.h
endif

ifeq "$(CHECK_OFED)" "TRUE"
	echo "==== [$(CHECK_OFED)] Using OFED ($(OFED_VER)) kernel IB libraries ===="
else
	echo "==== [$(CHECK_OFED)] Using stock kernel IB libraries ===="
endif

build.h:
	if [ ! svn info >/dev/null 2>&1 -a ! -f build.h ]; then echo "no build version number available";  exit 1; fi
	echo "#define BUILD $(BUILD)" > build.h
	echo "#define REVISION \"$(VERSION).$(RELEASE)\"" >> build.h


default:
# The IB transport is built separately due to having to play games with the
# LINUXINCLUDE make variable to pick up the OFED kernel override headers
ifneq "$(DISABLE_IB)" "TRUE"
ifeq "$(CHECK_OFED)" "TRUE"
	echo "==== [MLNX_OFED_VER_NUM: $(MLNX_OFED_VER_NUM)] ===="
	make -j8 -C $(KSRC) M=$(PWD) V=1 \
		LINUXINCLUDE=' \
		$(CFLAGS) \
		-I$(OFA)/include \
		-include $(autoconf_h) \
		$(KCONFIG_H) \
		-include $(OFA)/include/linux/compat-2.6.h \
		$$(if $$(CONFIG_XEN),-D__XEN_INTERFACE_VERSION__=$$(CONFIG_XEN_INTERFACE_VERSION)) \
		$$(if $$(CONFIG_XEN),-I$$(srctree)/arch/x86/include/mach-xen) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		-Iarch/$$(SRCARCH)/include/generated \
		-Iinclude \
		-I$$(srctree)/arch/$$(SRCARCH)/include/uapi \
		-Iarch/$$(SRCARCH)/include/generated/uapi \
		-I$$(srctree)/include/uapi \
		-Iinclude/generated/uapi \
		$$(if $$(KBUILD_SRC),-Iinclude2 -I$$(srctree)/include) \
		-I$$(srctree)/arch/$$(SRCARCH)/include \
		-Iarch/$$(SRCARCH)/include/generated \
		' \
		rna_debug=$(rna_debug) modules
else
	$(MAKE) -j8 -C $(KSRC) M=$(PWD) rna_debug=$(rna_debug) modules
endif  # CHECK_OFED
else
	$(MAKE) -j8 -C $(KSRC) M=$(PWD) rna_debug=$(rna_debug) modules
endif  # DISABLE_IB

$(SOURCE_DIRECTORY)/rna_com_shared_ib.c: $(SOURCE_DIRECTORY)/rna_com_shared.c
	ln -s $(notdir $<) $(SOURCE_DIRECTORY)/rna_com_shared_ib.c
$(SOURCE_DIRECTORY)/rna_com_shared_tcp.c: $(SOURCE_DIRECTORY)/rna_com_shared.c
	ln -s $(notdir $<) $(SOURCE_DIRECTORY)/rna_com_shared_tcp.c


clean:
	-rm -f Module.symvers
	-rm -f Module.markers
	-rm -f Module.symvers*
	-rm -f *.o
	-rm -f *.ko
	-rm -f *.ko.unsigned
	-rm -f *.mod.[co]
	-rm -f .*.cmd
	-rm -f *~
	-rm -f .client-rpm-type
	-rm -rf .tmp_versions
	-rm -f modules.order
	-rm -f build.h
	-rm -f rna_com_shared_*

