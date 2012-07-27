# To build external modules, you must have a prebuilt kernel available
# that contains the configuration and header files used in the build.
# go in the kernel directory and do a
#       make oldconfig; make scripts; make prepare
#
# The list of targets is derived from obj-m
# and then the corresponding foo-objs

CONFIG_NETMAP=m

netmap_lin-objs := netmap.o
obj-$(CONFIG_NETMAP) += netmap_lin.o

# The following commands are needed to build the modules as out-of-tree, in
# fact the kernel sources path must be specified.

# Additional compile flags (e.g. header location)
EXTRA_CFLAGS += -I$(M) -I$(M)/../sys -I$(M)/../sys/dev/netmap

#EXTRA_CFLAGS += -DCONFIG_NETMAP=m
# The following variable is normally set inside the kernel configuration file
# and is visible to all specific module Makefiles. If you want to build your
# module without modifying the kernel configuration, than you must simulate it
# with a local variable.
#

KSRC ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KSRC) M=$(PWD) modules # EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	make -C $(KSRC) M=$(PWD) clean

# the source is not here so we need to specify a dependency
#$(obj)/netmap.o: $(M)/../sys/dev/netmap/netmap.c
	@# $(call cmd,cc_o_c)
	@# $(call cmd,modversions)
#	$(call quiet_cmd,cc_o_c)

# we could also instead the source with $(call cmd,shipped)
