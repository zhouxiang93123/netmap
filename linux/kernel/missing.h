/*
 * $Id$
 *
 * Support for linking under linux
 */
#ifndef _MISSING_H
#define _MISSING_H
#warning loading missing.h
#define __FBSDID(x) static char * _fbsdid = x ;
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>	/* struct timeval */

#define __FreeBSD_version	800000
typedef uint64_t vm_offset_t;
/* from if.h */
struct ifnet;
#define IFNAMSIZ 128
#define TAILQ_ENTRY(x)	struct x *
#define TAILQ_HEAD(x, y)	struct  x { struct y *h; };
struct mbuf;

typedef int	bus_dma_tag_t;
typedef uint64_t	bus_dmamap_t;
typedef uint64_t	bus_size_t;
typedef uint64_t	vm_paddr_t;
typedef	int (*d_mmap_t)(void);
typedef	int (*d_ioctl_t)(void);
typedef	int (*d_poll_t)(void);

struct malloc_type {
};

#define MALLOC_DEFINE(type, shortdesc, longdesc)        \
        struct malloc_type type[1]; void *md_dummy_ ## type = type

MALLOC_DEFINE(M_DEVBUF, "aa" , "aa aa");

#define	M_WAITOK	0x0000
#define	M_NOWAIT	0x0001
#define	M_ZERO		0x0100

#define	UID_ROOT	0
#define	GID_WHEEL	0

/*
 * Kernel locking support.
 * In linux we use spinlock_bh to implement mtx
 */

#define mtx_assert(a, b)
#define mtx_destroy(m)
#define mtx_init(m, a,b,c)      spin_lock_init(m)
#define mtx_lock(_l)            spin_lock_bh(_l)
#define mtx_unlock(_l)          spin_unlock_bh(_l)

struct ifnet {
};

struct mtx {
};

struct thread; // XXX kernel thread
struct selinfo {
};
#include <linux/mutex.h>

#define	PI_NET		100
#define	D_VERSION	1
struct cdevsw {
        int d_version;
        char *d_name;
        d_mmap_t d_mmap;
        d_ioctl_t d_ioctl;
        d_poll_t d_poll;
#ifdef NETMAP_KEVENT
        void *d_kqfilter;
#endif
};

struct sysctl_oid;
struct sysctl_req;

#if defined (__linux__) && !defined (EMULATE_SYSCTL)
#define SYSCTL_DECL(_1)
#define SYSCTL_OID(_1, _2, _3, _4, _5, _6, _7, _8)
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define _SYSCTL_BASE(_name, _var, _ty, _perm)           \
        module_param_named(_name, *(_var), _ty,         \
                ( (_perm) == CTLFLAG_RD) ? 0444: 0644 )
#define SYSCTL_PROC(_base, _oid, _name, _mode, _var, _val, _desc, _a, _b)

#define SYSCTL_INT(_base, _oid, _name, _mode, _var, _val, _desc)        \
        _SYSCTL_BASE(_name, _var, int, _mode)

#define SYSCTL_LONG(_base, _oid, _name, _mode, _var, _val, _desc)       \
        _SYSCTL_BASE(_name, _var, long, _mode)

#define SYSCTL_ULONG(_base, _oid, _name, _mode, _var, _val, _desc)      \
        _SYSCTL_BASE(_name, _var, ulong, _mode)

#define SYSCTL_UINT(_base, _oid, _name, _mode, _var, _val, _desc)       \
         _SYSCTL_BASE(_name, _var, uint, _mode)

#define TUNABLE_INT(_name, _ptr)

#define SYSCTL_VNET_PROC                SYSCTL_PROC
#define SYSCTL_VNET_INT                 SYSCTL_INT

#endif

#define SYSCTL_HANDLER_ARGS             \
        struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);
 
void microtime(struct timeval *tv);

#endif

