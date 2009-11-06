ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_IP_NF_TARGET_SYSLOG) := ipt_SYSLOG.o

else

KERNEL_SRC ?= $(firstword $(wildcard /lib/modules/$(shell uname -r)/build /usr/src/linux))
ifeq ($(KERNEL_SRC),)
$(error You need to define KERNEL_SRC)
endif

ifneq ($wildcard $(KERNEL_SRC)/include/linux/modversions.h),)
MODVERSIONS = -DMODVERSIONS
endif

_KVER = $(strip $(shell cat $(KERNEL_SRC)/Makefile | grep -e '^VERSION' | cut -d"=" -f2))
_KPL = $(strip $(shell cat $(KERNEL_SRC)/Makefile | grep -e '^PATCHLEVEL' | cut -d"=" -f2))
_KSUB = $(strip $(shell cat $(KERNEL_SRC)/Makefile | grep -e '^SUBLEVEL' | cut -d"=" -f2))
KERNEL_SERIES=$(_KVER).$(_KPL)

ifeq ($(KERNEL_SERIES), 2.6)
	TARGET=ipt_SYSLOG.ko
else
	TARGET=ipt_SYSLOG.o
endif

SED = sed
IPTABLES_BIN = iptables

ifndef $(IPTABLES_SRC)
IPTVER = \
	$(shell $(IPTABLES_BIN) --version | $(SED) -e 's/^iptables v//')
IPTABLES_SRC = $(wildcard /usr/src/iptables-$(IPTVER))
endif

ifeq ($(IPTABLES_SRC),)
$(warning You need to install iptables sources and maybe set IPTABLES_SRC)
endif

IPTABLES_INCLUDE = -I$(IPTABLES_SRC)/include

ifneq ($(IPTVER),)
	IPTABLES_VERSION = $(IPTVER)
else
	IPTABLES_VERSION = $(shell cat $(IPTABLES_SRC)/Makefile | grep -e '^IPTABLES_VERSION:=' | cut -d"=" -f2)
endif

IPTABLES_OPTION = -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\"
export CONFIG_IP_NF_TARGET_SYSLOG = m

CC = gcc
CFLAGS = -O3 -Wall



all: modules libipt_SYSLOG.so

modules: $(TARGET)

ipt_SYSLOG.o: ipt_SYSLOG.c
	$(CC) $(CFLAGS) -I$(KERNEL_SRC)/include -c ipt_SYSLOG.c -D__KERNEL__ -DMODULE $(MODVERSIONS)

ipt_SYSLOG.ko: ipt_SYSLOG.c
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(PWD) modules


libipt_SYSLOG.so: libipt_SYSLOG.c
	$(CC) $(CFLAGS) $(IPTABLES_OPTION) $(IPTABLES_INCLUDE) -fPIC -c libipt_SYSLOG.c
	$(CC) -shared -o libipt_SYSLOG.so libipt_SYSLOG.o

clean:
	-rm -f *.o *.so *.ko .*.cmd *.mod.c
endif
