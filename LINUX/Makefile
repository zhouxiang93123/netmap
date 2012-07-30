# To build external modules, you must have a prebuilt kernel available
# that contains the configuration and header files used in the build.
# go in the kernel directory and do a
#       make oldconfig; make scripts; make prepare
#
# The list of targets is derived from obj-m
# and then the corresponding foo-objs

CONFIG_NETMAP=m
CONFIG_R8169:=m
CONFIG_FORCEDETH:=m
CONFIG_E1000:=m
CONFIG_E1000E:=m
CONFIG_IXGBE:=m
CONFIG_IGB:=m

netmap_lin-objs := netmap.o
obj-$(CONFIG_NETMAP) += netmap_lin.o

obj-$(CONFIG_R8169) += r8169.o
obj-$(CONFIG_FORCEDETH) += forcedeth.o
obj-$(CONFIG_E1000) += e1000/
obj-$(CONFIG_E1000E) += e1000e/
obj-$(CONFIG_IXGBE) += ixgbe/
obj-$(CONFIG_IGB) += igb/

# names of the driver sources. In old linuxes are under
# KSRC/drivers/net, but depending on where you build they
# can be in $(KSRC)/source/drivers/net/ethernet/$(manufacturer)
DRIVER_SRCS = r8169.c forcedeth.c e1000/ e1000e/ ixgbe/ igb/
DRIVER_SUBDIRS= nvidia realtek intel
PATCHFILES = net-e1000.diff net-e1000e.diff net-forcedeth.diff \
		net-igb.diff net-ixgbe.diff net-r8169.diff

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

LIN_VER = $(shell echo $(KSRC) | sed -r 's/\./-/g;s/[^0-9\-]//g;s/(^-+)|(--.*)//g;')

all:	get-drivers
	make -C $(KSRC) M=$(PWD) CONFIG_E1000=m CONFIG_E1000E=m \
		CONFIG_IXGBE=m CONFIG_IGB=m modules

test:
	echo "version $(LIN_VER)"

clean:
	-@ make -C $(KSRC) M=$(PWD) clean
	-@ (rm -rf $(DRIVER_SRCS))

# the source is not here so we need to specify a dependency
$(obj)/netmap.o: $(M)/../sys/dev/netmap/netmap.c
	$(call cmd,cc_o_c)
	$(call cmd,modversions)
#	$(call quiet_cmd,cc_o_c)

#-- copy and patch initial files
# The location changes depending on the OS version, so ...
get-drivers:
	-@( cd $(KSRC); [ -d source ] && cd source;			\
	    cd drivers/net; s=. ;					\
	    [ -d ethernet ] && cd ethernet && s="$(DRIVER_SUBDIRS)" ;	\
	    for i in $$s; do (cd $$i ;					\
	    	cp -Rp $(DRIVER_SRCS) $(PWD) 2>/dev/null ); done )
	for i in $(PATCHFILES) ; do patch -p0 < $$i; done

# copy and patch files from the source tree
#$(obj)/r8169.c: $(srctree)/drivers/net/r8169.c 
#	# net-r8169.diff
#	$(call cmd,shipped)
#	(cd $(obj); patch < net-r8169.diff )
#

apps:
