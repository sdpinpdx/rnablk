obj-m := fldc_md5.o
fldc_md5-objs := md5.o
ccflags-y := -I$(src)/../common

CPU := $(shell uname -m)

KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD := $(shell pwd)
EXTRA_CFLAGS += -I/usr/include/

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
EXTRA_CFLAGS += -Werror

all: default

install:
	echo ******* INSTALL_DIR=$(INSTALL_DIR)
	-if [ ! -d $(INSTALL_DIR) ]; then mkdir $(INSTALL_DIR); fi
	install -m 644 -c fldc_md5.ko $(INSTALL_DIR)
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

default: version_header
	# <KLUDGE> Trying to build md5.o from $(COMMON)/md5.c, but it doesn't work
	if [ ! -f md5.c ]; then ln -s $(COMMON)/md5.c .; fi
	# </KLUDGE>
	$(MAKE) -j8 -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	#<KLUDGE>
	-rm -rf md5.c
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

