#ident "$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/linux-kernel/rna_service/Makefile $ $Id: Makefile 28025 2013-12-17 18:34:24Z glagasse $"

obj-m := fldc_service.o
ccflags-y := -I$(src)/com
ccflags-y += -I$(src)/../common
fldc_service-objs := rna_service.o

KBUILD_EXTRA_SYMBOLS := $(src)/../md5/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(src)/../com/Module.symvers

CPU := $(shell uname -m)

KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD := $(shell pwd)
COMMON := $(PWD)/../../common
VPATH := $(COMMON)
EXTRA_CFLAGS += -I/usr/include/
EXTRA_CFLAGS += -Werror

# Find directory of sources
ifeq ($(SOURCE_DIRECTORY),)
ifneq ($(BLKSRC),)
SOURCE_DIRECTORY = $(BLKSRC)
else ifneq ($(KBUILD_EXTMOD),)
SOURCE_DIRECTORY = $(KBUILD_EXTMOD)
else ifneq ($(SUBDIRS),)
SOURCE_DIRECTORY = $(SUBDIRS)
else	# punt
SOURCE_DIRECTORY = .
endif	# ifneq ($(BLKSRC),)
endif	# ifeq ($(SOURCE_DIRECTORY),)

COMMON := $(SOURCE_DIRECTORY)/../../common
EXTRA_CFLAGS += -I$(COMMON)

ARCH := $(shell uname -m)

ifndef BUILD
BUILD := $(shell svn info | grep Revision | cut -b 11-)
endif

INSTALL_DIR := /lib/modules/$(KVER)/extra/fldc
VERSION_FILE := ../../VERSION
RELEASE_FILE := ../../RELEASE

ifeq "$(SLES_10_2_BUILD)" "TRUE"
EXTRA_CFLAGS += -DSLES_10_2_BUILD
endif

# uncomment to turn off inline functions, handy for reading dump stacks
#EXTRA_CFLAGS += -fno-inline

# uncomment this flag to enable verbose logging
# not for production
# EXTRA_CFLAGS += -DVERBOSE_LOGS

# uncomment this flag to enable state lock checking
# not for production
# EXTRA_CFLAGS += -DCHECK_STATE_LOCKS


all: default

install:
	echo ******* INSTALL_DIR=$(INSTALL_DIR)
	-if [ ! -d $(INSTALL_DIR) ]; then mkdir $(INSTALL_DIR); fi
	install -m 644 -c fldc_service.ko $(INSTALL_DIR)
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

build.h:
	if [ ! svn info >/dev/null 2>&1 -a ! -f build.h ]; then echo "no build version number available";  exit 1; fi
	echo "#define BUILD $(BUILD)" > build.h
	echo "#define REVISION \"$(VERSION).$(RELEASE)\"" >> build.h

default: $(INSTALL_DEPS) version_header
	#if [ ! -f rna_byteswap.h ]; then ln -s ../../fcache/rna_byteswap.h .; fi
	if [ ! -f ../md5/Module.symvers ]; then echo "../md5/Module.symvers not available.  Please run \"make\" in the md5 directory first."; exit 1; fi
	cp ../md5/Module.symvers .
	if [ ! -f ../com/Module.symvers ]; then echo "../com/Module.symvers not available.  Please run \"make\" in the com directory first."; exit 1; fi
	cat ../com/Module.symvers >> ./Module.symvers
	# <KLUDGE> Trying to build rna_service.o from $(COMMON)/rna_service.c, but it doesn't work
	if [ ! -f rna_service.c ]; then ln -s $(COMMON)/rna_service.c .; fi
	# </KLUDGE>
	$(MAKE) -j8 -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	#<KLUDGE>
	-rm -rf rna_service.c
	#</KLUDGE>
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
