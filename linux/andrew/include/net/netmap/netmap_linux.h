
#ifndef netmap_linux_h
#define netmap_linux_h

#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>

#define ND(format, ...)
#define D(format, ...)					\
	do {						\
		struct timeval __xxts;			\
		do_gettimeofday(&__xxts);                               \
		printk(KERN_DEBUG "%03d.%06d %s [%d] " format "\n",     \
		(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec,		\
		__FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

typedef struct net_device interface_t;
#define IFC_NAME(dev) ((dev)->name)
#define IFC_UNREF(dev)  dev_put((dev))

/*
 * return a pointer to the struct netmap adapter from the ifp
 */
#define	NA(_dev)	((struct netmap_adapter *)(_dev)->ml_priv)	// XXX was netmap_ptr


/*
 * The combination of "enable" (ifp->if_capabilities &IFCAP_NETMAP)
 * and refcount gives the status of the interface, namely:
 *
 *	enable	refcount	Status
 *
 *	FALSE	0		normal operation
 *	FALSE	!= 0		-- (impossible)
 *	TRUE	1		netmap mode
 *	TRUE	0		being deleted.
 */

#define NETMAP_DELETING(_na)  \
    (  ((_na)->refcount == 0) && ( (_na)->nm_isactive((_na)->ifp)) )


extern char* NMB(struct netmap_slot *slot);

extern void NMA_LOCK(void);
extern void NMA_UNLOCK(void);


#endif /* netmap_linux_h */
