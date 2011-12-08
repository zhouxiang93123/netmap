CONFIG_NETMAP=m
KVERSION=linux-source-2.6.38

EXTRA_CFLAGS += -I$(PWD)/../../include

obj-$(CONFIG_NETMAP) += netmap.o

netmap-objs := netmap_core.o netmap_linux.o

all:
	make -C /usr/src/$(KVERSION) M=$(PWD) modules
clean:
	make -C /usr/src/$(KVERSION) M=$(PWD) clean
