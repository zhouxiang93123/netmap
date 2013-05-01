# $FreeBSD$
#
# Compile netmap as a module, useful if you want a netmap bridge
# or loadable drivers.

.PATH: ${.CURDIR}/../../dev/netmap
.PATH.h: ${.CURDIR}/../../net
KMOD	= netmap
SRCS	= device_if.h bus_if.h opt_netmap.h
SRCS	+= netmap.c netmap.h netmap_kern.h
SRCS	+= netmap_mem2.c netmap_mem2.h

.include <bsd.kmod.mk>
