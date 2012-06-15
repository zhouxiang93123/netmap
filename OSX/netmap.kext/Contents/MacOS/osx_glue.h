/*
 * glue to compile netmap under FreeBSD
 */
#ifndef OSX_GLUE_H
#define OSX_GLUE_H
#define __FBSDID(x)
#include <sys/types.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#define TUNABLE_INT(name, ptr)

#include <net/if.h>
#include <net/bpf.h>            /* BIOCIMMEDIATE */
//#include <net/vnet.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <machine/bus.h>        /* bus_dmamap_* */

#endif /* OSX_GLUE_H */
