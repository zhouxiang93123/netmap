obj-m := netmap_mod.o

netmap_mod-y := netmap_cdev.o netmap.o

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

EXTRA_CFLAGS += -I$(PWD)

HERE=$(PWD)

# _BSD_SOURCE enables __FAVOR_BSD (udp/tcp bsd structs instead of posix)
EXTRA_CFLAGS += -D_BSD_SOURCE
EXTRA_CFLAGS += -DKERNEL_MODULE  # build linux kernel module
# the two header trees for empty and override files
EXTRA_CFLAGS += -I $(M)/include_e
#EXTRA_CFLAGS += -I $(M)/include
#EXTRA_CFLAGS += -I /usr/include
EXTRA_CFLAGS += -I $(M)/../../sys # headers
# EXTRA_CFLAGS += -include $(M)/../glue.h  # headers
EXTRA_CFLAGS += -include $(M)/missing.h  # headers
EXTRA_CFLAGS += -include $(M)/glue.h  # more stuff


all: include_e Makefile netmap_cdev.c netmap.c
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

$(obj-m): $(netmap_mod-y)
	$(LD) $(LDFLAGS) -m elf_i386 -r -o $@ $^

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#
	rm -rf include_e

# M is the current directory, used in recursive builds
# so we allow it to be overridden
M ?= $(shell pwd)

# support to create empty dirs and files in include_e/
# EDIRS is the list of directories, EFILES is the list of files.

EDIRS  += altq arpa machine net netinet netinet6 sys

EFILES += opt_inet6.h opt_ipfw.h opt_ipsec.h opt_mpath.h
EFILES += opt_mbuf_stress_test.h opt_param.h

EFILES += altq/if_altq.h
EFILES += arpa/inet.h
EFILES += machine/in_cksum.h
EFILES += net/ethernet.h net/netisr.h net/pf_mtag.h
EFILES += net/bpf.h net/if_types.h
EFILES += net/vnet.h

EFILES += netinet/ether.h netinet/icmp6.h netinet/if_ether.h
EFILES += netinet/in.h netinet/in_pcb.h netinet/in_var.h
EFILES += netinet/in_systm.h
EFILES += netinet/ip_carp.h netinet/ip_var.h netinet/pim.h
EFILES += netinet/sctp.h netinet/tcp_timer.h netinet/tcpip.h
EFILES += netinet/udp_var.h

EFILES += netinet6/ip6_var.h

EFILES += sys/_lock.h sys/_rwlock.h sys/rmlock.h sys/_mutex.h sys/jail.h
EFILES += sys/condvar.h sys/eventhandler.h sys/domain.h
EFILES += sys/limits.h sys/lock.h sys/mutex.h sys/priv.h
EFILES += sys/proc.h sys/rwlock.h sys/socket.h sys/socketvar.h
EFILES += sys/sysctl.h sys/time.h sys/ucred.h

XDIRS += sys vm machine net

XFILES += opt_netmap.h

XFILES += machine/bus.h

XFILES += net/bpf.h
XFILES += net/if.h

XFILES += sys/cdefs.h
XFILES += sys/conf.h
XFILES += sys/errno.h
XFILES += sys/kernel.h
XFILES += sys/malloc.h
XFILES += sys/mman.h
XFILES += sys/module.h
XFILES += sys/param.h
XFILES += sys/poll.h
XFILES += sys/selinfo.h
XFILES += sys/socket.h
XFILES += sys/socketvar.h
XFILES += sys/sockio.h
XFILES += sys/sysctl.h
XFILES += sys/types.h
XFILES += sys/uio.h

XFILES += vm/pmap.h
XFILES += vm/vm.h

include_e:
	echo "running in $M"
	-@rm -rf $(M)/include_e opt_*
	-@mkdir -p $(M)/include_e
	-@(cd $(M)/include_e; mkdir -p $(XDIRS); touch $(XFILES) )


