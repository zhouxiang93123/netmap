/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * 
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the
 *      distribution.
 * 
 *   3. Neither the name of the authors nor the names of their contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY MATTEO LANDI AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MATTEO LANDI OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * $Id: netmap.c 8972 2011-07-04 09:39:32Z luigi $
 *
 * This module supports memory mapped access to network devices,
 * see netmap(4).
 *
 * The module uses a large, memory pool allocated by the kernel
 * and accessible as mmapped memory by multiple userspace threads/processes.
 * The memory pool contains packet buffers and "netmap rings",
 * i.e. user-accessible copies of the interface's queues.
 *
 * Access to the network card works like this:
 * 1. a process/thread issues one or more open() on /dev/netmap, to create
 *    select()able file descriptor on which events are reported.
 * 2. on each descriptor, the process issues an ioctl() to identify
 *    the interface that should report events to the file descriptor.
 * 3. on each descriptor, the process issues an mmap() request to
 *    map the shared memory region within the process' address space.
 *    The list of interesting queues is indicated by a location in
 *    the shared memory region.
 * 4. using the functions in the netmap(4) userspace API, a process
 *    can look up the occupation state of a queue, access memory buffers,
 *    and retrieve received packets or enqueue packets to transmit.
 * 5. using some ioctl()s the process can synchronize the userspace view
 *    of the queue with the actual status in the kernel. This includes both
 *    receiving the notification of new packets, and transmitting new
 *    packets on the output interface.
 * 6. select() or poll() can be used to wait for events on individual
 *    transmit or receive queues (or all queues for a given interface).
 */

#include <sys/cdefs.h> /* prerequisite */
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct */
#include <sys/uio.h>	/* uio struct */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/mman.h>	/* PROT_EXEC */
#include <sys/poll.h>
#include <vm/vm.h>	/* vtophys */
#include <vm/pmap.h>	/* vtophys */
#include <sys/socket.h> /* sockaddrs */
#include <machine/bus.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <machine/bus.h>	/* bus_dmamap_* */

MALLOC_DEFINE(M_NETMAP, "netmap", "Network memory map");

/* Descriptor of the memory objects handled by our memory allocator. */
struct netmap_mem_obj {
	TAILQ_ENTRY(netmap_mem_obj) nmo_next; /* next object in the
						 chain. */
	int nmo_used; /* flag set on used memory objects. */
	size_t nmo_size; /* size of the memory area reserved for the
			    object. */
	void *nmo_data; /* pointer to the memory area. */
};

/* Wrap our memory objects to make them ``chainable``. */
TAILQ_HEAD(netmap_mem_obj_h, netmap_mem_obj);


/* Descriptor of our custom memory allocator. */
struct netmap_mem_d {
	struct mtx nm_mtx; /* lock used to handle the chain of memory
			      objects. */
	struct netmap_mem_obj_h nm_molist; /* list of memory objects */
	size_t nm_size; /* total amount of memory used for rings etc. */
	size_t nm_totalsize; /* total amount of allocated memory
		(the difference is used for buffers) */
	size_t nm_buf_start; /* offset of packet buffers.
			This is page-aligned. */
	size_t nm_buf_len; /* total memory for buffers */
	void *nm_buffer; /* pointer to the whole pre-allocated memory
			    area. */
};

static struct netmap_mem_d *netmap_mem_d; /* Our memory allocator. */

/*
 * Default amount of memory pre-allocated by the module.
 * We start with a large size and then shrink our demand
 * according to what is avalable when the module is loaded.
 * At the moment the block is contiguous, but we can easily
 * restrict our demand to smaller units (16..64k)
 */
#define NETMAP_MEMORY_SIZE (64 * 1024 * PAGE_SIZE)

static int skip_poll; /* debug poll */


SYSCTL_NODE(_dev, OID_AUTO, netmap, CTLFLAG_RW, 0, "Netmap args");
SYSCTL_INT(_dev_netmap, OID_AUTO, verbose,
    CTLFLAG_RW, &netmap_verbose, 0, "Verbose mode");
SYSCTL_INT(_dev_netmap, OID_AUTO, new_poll,
    CTLFLAG_RW, &new_poll, 0, "new_poll");
SYSCTL_INT(_dev_netmap, OID_AUTO, no_timestamp,
    CTLFLAG_RW, &no_timestamp, 0, "no_timestamp");
SYSCTL_INT(_dev_netmap, OID_AUTO, skip_poll,
    CTLFLAG_RW, &skip_poll, 0, "skip_poll");
SYSCTL_INT(_dev_netmap, OID_AUTO, total_buffers,
    CTLFLAG_RD, &nm_buf_pool.total_buffers, 0, "total_buffers");
SYSCTL_INT(_dev_netmap, OID_AUTO, free_buffers,
    CTLFLAG_RD, &nm_buf_pool.free, 0, "free_buffers");


char* nm_buffer_base;

static void
ns_dmamap_cb(__unused void *arg, __unused bus_dma_segment_t * segs,
	__unused int nseg, __unused int error)
{
}

/* unload a bus_dmamap and create a new one. Used when the
 * buffer in the slot is changed.
 * XXX buflen is probably not needed, buffers have constant size.
 */
void
netmap_reload_map(bus_dma_tag_t tag, bus_dmamap_t map,
	void *buf, bus_size_t buflen)
{
	bus_addr_t paddr;
	bus_dmamap_unload(tag, map);
	bus_dmamap_load(tag, map, buf, buflen, ns_dmamap_cb, &paddr,
				BUS_DMA_NOWAIT);
}

void
netmap_load_map(bus_dma_tag_t tag, bus_dmamap_t map,
	void *buf, bus_size_t buflen)
{
	bus_addr_t paddr;
	bus_dmamap_load(tag, map, buf, buflen, ns_dmamap_cb, &paddr,
				BUS_DMA_NOWAIT);
}

static void
netmap_dtor(void *data)
{
    netmap_cleanup((struct netmap_priv_d*) data);
}

/*
 * Initialize the memory allocator.
 *
 * Create the descriptor for the memory , allocate the pool of memory
 * and initialize the list of memory objects with a single chunk
 * containing the whole pre-allocated memory marked as free.
 *
 * Return 0 on success, errno otherwise.
 */
static int
netmap_memory_init(void)
{
	struct netmap_mem_obj *mem_obj;
	void *buf = NULL;
	int n, sz = NETMAP_MEMORY_SIZE;

	for (; !buf && sz >= 1<<20; sz >>=1) {
	        buf = contigmalloc(sz,
			     M_NETMAP,
			     M_WAITOK | M_ZERO,
			     0, /* low address */
			     -1UL, /* high address */
			     PAGE_SIZE, /* alignment */
			     0 /* boundary */
			    );
	} 
	if (buf == NULL)
		return (ENOMEM);
	netmap_mem_d = malloc(sizeof(struct netmap_mem_d), M_NETMAP,
			      M_WAITOK | M_ZERO);
	mtx_init(&netmap_mem_d->nm_mtx, "netmap memory allocator lock", NULL,
		 MTX_DEF);
	TAILQ_INIT(&netmap_mem_d->nm_molist);
	netmap_mem_d->nm_buffer = buf;
	netmap_mem_d->nm_totalsize = sz;

	/*
	 * A buffer takes 2k, a slot takes 8 bytes + ring overhead,
	 * so the ratio is 200:1. In other words, we can use 1/200 of
	 * the memory for the rings, and the rest for the buffers,
	 * and be sure we never run out.
	 */
	netmap_mem_d->nm_size = sz/200;
	netmap_mem_d->nm_buf_start =
		(netmap_mem_d->nm_size + PAGE_SIZE - 1) & ~(PAGE_SIZE-1);
	netmap_mem_d->nm_buf_len = sz - netmap_mem_d->nm_buf_start;

        nm_bufer_base = netmap_mem_d->nm_buffer + netmap_mem_d->nm_buf_start;
	D("netmap_buffer_base %p (offset %d)",
          nm_buffer_base, netmap_mem_d->nm_buf_start);

        n = (nm_buf_pool.total_buffers + 31) / 32;
        netmap_init_bufmap(1<<11, netmap_mem_d->nm_buf_len >> 11,
                           malloc(sizeof(uint32_t) * n,
                                  M_NETMAP, M_WAITOK | M_ZERO));
        D("Have %d MB, use %dKB for rings, %d buffers at %p",
          (sz >> 20), (netmap_mem_d->nm_size >> 10),
          nm_buf_pool.total_buffers, nm_buf_pool.base);

	mem_obj = malloc(sizeof(struct netmap_mem_obj), M_NETMAP,
			 M_WAITOK | M_ZERO);
	TAILQ_INSERT_HEAD(&netmap_mem_d->nm_molist, mem_obj, nmo_next);
	mem_obj->nmo_used = 0;
	mem_obj->nmo_size = netmap_mem_d->nm_size;
	mem_obj->nmo_data = netmap_mem_d->nm_buffer;

	return (0);
}


/*
 * Finalize the memory allocator.
 *
 * Free all the memory objects contained inside the list, and deallocate
 * the pool of memory; finally free the memory allocator descriptor.
 */
static void
netmap_memory_fini(void)
{
	struct netmap_mem_obj *mem_obj;

	while (!TAILQ_EMPTY(&netmap_mem_d->nm_molist)) {
		mem_obj = TAILQ_FIRST(&netmap_mem_d->nm_molist);
		TAILQ_REMOVE(&netmap_mem_d->nm_molist, mem_obj, nmo_next);
		if (mem_obj->nmo_used == 1) {
			printf("netmap: leaked %d bytes at %p\n",
			       mem_obj->nmo_size,
			       mem_obj->nmo_data);
		}
		free(mem_obj, M_NETMAP);
	}
	contigfree(netmap_mem_d->nm_buffer, netmap_mem_d->nm_totalsize, M_NETMAP);
	free(netmap_mem_d, M_NETMAP);
}

/*------ netmap memory allocator -------*/
/*
 * Request for a chunk of memory.
 *
 * Memory objects are arranged into a list, hence we need to walk this
 * list until we find an object with the needed amount of data free. 
 * This sounds like a completely inefficient implementation, but given
 * the fact that data allocation is done once, we can handle it
 * flawlessly.
 *
 * Return NULL on failure.
 */
static void *
netmap_malloc(size_t size, __unused const char *msg)
{
	struct netmap_mem_obj *mem_obj, *new_mem_obj;
	void *ret = NULL;

	NMA_LOCK();
	TAILQ_FOREACH(mem_obj, &netmap_mem_d->nm_molist, nmo_next) {
		if (mem_obj->nmo_used != 0 || mem_obj->nmo_size < size)
			continue;

		new_mem_obj = malloc(sizeof(struct netmap_mem_obj), M_NETMAP,
				     M_WAITOK | M_ZERO);
		TAILQ_INSERT_BEFORE(mem_obj, new_mem_obj, nmo_next);

		new_mem_obj->nmo_used = 1;
		new_mem_obj->nmo_size = size;
		new_mem_obj->nmo_data = mem_obj->nmo_data;
		memset(new_mem_obj->nmo_data, 0, new_mem_obj->nmo_size);

		mem_obj->nmo_size -= size;
		mem_obj->nmo_data = (char *) mem_obj->nmo_data + size;
		if (mem_obj->nmo_size == 0) {
			TAILQ_REMOVE(&netmap_mem_d->nm_molist, mem_obj,
				     nmo_next);
			free(mem_obj, M_NETMAP);
		}

		ret = new_mem_obj->nmo_data;

		break;
	}
	NMA_UNLOCK();
	ND("%s: %d bytes at %p", msg, size, ret);

	return (ret);
}

/*
 * Return the memory to the allocator.
 *
 * While freeing a memory object, we try to merge adjacent chunks in
 * order to reduce memory fragmentation.
 */
static void
netmap_free(void *addr, const char *msg)
{
	size_t size;
	struct netmap_mem_obj *cur, *prev, *next;

	if (addr == NULL) {
		D("NULL addr for %s", msg);
		return;
	}

	NMA_LOCK();
	TAILQ_FOREACH(cur, &netmap_mem_d->nm_molist, nmo_next) {
		if (cur->nmo_data == addr && cur->nmo_used)
			break;
	}
	if (cur == NULL) {
		NMA_UNLOCK();
		D("invalid addr %s %p", msg, addr);
		return;
	}

	size = cur->nmo_size;
	cur->nmo_used = 0;

	/* merge current chunk of memory with the previous one,
	   if present. */
	prev = TAILQ_PREV(cur, netmap_mem_obj_h, nmo_next);
	if (prev && prev->nmo_used == 0) {
		TAILQ_REMOVE(&netmap_mem_d->nm_molist, cur, nmo_next);
		prev->nmo_size += cur->nmo_size;
		free(cur, M_NETMAP);
		cur = prev;
	}

	/* merge with the next one */
	next = TAILQ_NEXT(cur, nmo_next);
	if (next && next->nmo_used == 0) {
		TAILQ_REMOVE(&netmap_mem_d->nm_molist, next, nmo_next);
		cur->nmo_size += next->nmo_size;
		free(next, M_NETMAP);
	}
	NMA_UNLOCK();
	ND("freed %s %d bytes at %p", msg, size, addr);
}

/*
 * mmap(2) support for the "netmap" device.
 *
 * Expose all the memory previously allocated by our custom memory
 * allocator: this way the user has only to issue a single mmap(2), and
 * can work on all the data structures flawlessly.
 *
 * Return 0 on success, -1 otherwise.
 */
static int
#if __FreeBSD_version < 900000
netmap_mmap(__unused struct cdev *dev, vm_offset_t offset, vm_paddr_t *paddr,
	    int nprot)
#else
netmap_mmap(__unused struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr,
	    int nprot, __unused vm_memattr_t *memattr)
#endif
{
	if (nprot & PROT_EXEC)
		return (-1);	// XXX -1 or EINVAL ?
	ND("request for offset 0x%x", (uint32_t)offset);
	*paddr = vtophys(netmap_mem_d->nm_buffer) + offset;

	return (0);
}

/*
 * get a refcounted reference to an interface.
 * Return ENXIO if the interface does not exist, EINVAL if netmap
 * is not supported by the interface.
 * If successful, hold a reference.
 */
static int
get_ifp(const char *name, struct ifnet **ifp)
{
	*ifp = ifunit_ref(name);
	if (*ifp == NULL)
		return (ENXIO);
	/* can do this if the capability exists and if_pspare[0]
	 * points to the netmap descriptor.
	 */
	if ((*ifp)->if_capabilities & IFCAP_NETMAP && NA(*ifp))
		return 0;	/* valid pointer, we hold the refcount */
	if_rele(*ifp);
	return EINVAL;	// not NETMAP capable
}

/*
 * ioctl(2) support for the "netmap" device.
 *
 * Following a list of accepted commands:
 * - NIOCGINFO
 * - SIOCGIFADDR	just for convenience
 * - NIOCREGIF
 * - NIOCUNREGIF
 * - NIOCTXSYNC
 * - NIOCRXSYNC
 *
 * Return 0 on success, errno otherwise.
 */
static int
netmap_ioctl(__unused struct cdev *dev, u_long cmd, caddr_t data,
	__unused int fflag, __unused struct thread *td)
{
	struct netmap_priv_d *priv = NULL;
	struct ifnet *ifp;
	struct nmreq *nmr = (struct nmreq *) data;
	struct netmap_adapter *na;
	void *adapter;
	int error;
	u_int i;
	struct netmap_if *nifp;

	error = devfs_get_cdevpriv((void **)&priv);
	if (error != ENOENT && error != 0)
		return (error);

	error = 0;	/* Could be ENOENT */
	switch (cmd) {
	case NIOCGINFO:		/* return capabilities etc */
		/* memsize is always valid */
		nmr->nr_memsize = netmap_mem_d->nm_totalsize;
		nmr->nr_offset = 0;
		nmr->nr_numrings = 0;
		nmr->nr_numslots = 0;
		if (nmr->nr_name[0] == '\0')	/* just get memory info */
			break;
		error = get_ifp(nmr->nr_name, &ifp); /* get a refcount */
		if (error)
			break;
		na = NA(ifp); /* retrieve netmap_adapter */
		nmr->nr_numrings = na->num_queues;
		nmr->nr_numslots = na->num_tx_desc;
		if_rele(ifp);	/* return the refcount */
		break;

	case NIOCREGIF:
		if (priv != NULL)	/* thread already registered */
			return netmap_set_ringid(priv, nmr->nr_ringid);
		/* find the interface and a reference */
		error = get_ifp(nmr->nr_name, &ifp); /* keep reference */
		if (error)
			break;
		na = NA(ifp); /* retrieve netmap adapter */
		adapter = na->ifp->if_softc;	/* shorthand */
		/*
		 * Allocate the private per-thread structure.
		 * XXX perhaps we can use a blocking malloc ?
		 */
		priv = malloc(sizeof(struct netmap_priv_d), M_DEVBUF,
			      M_NOWAIT | M_ZERO);
		if (priv == NULL) {
			error = ENOMEM;
			if_rele(ifp);   /* return the refcount */
			break;
		}


		for (i = 10; i > 0; i--) {
			na->nm_lock(adapter, NETMAP_CORE_LOCK, 0);
			if (!NETMAP_DELETING(na))
				break;
			na->nm_lock(adapter, NETMAP_CORE_UNLOCK, 0);
			tsleep(na, 0, "NIOCREGIF", hz/10);
		}
		if (i == 0) {
			D("too many NIOCREGIF attempts, give up");
			error = EINVAL;
			free(priv, M_DEVBUF);
			if_rele(ifp);	/* return the refcount */
			break;
		}

		priv->np_ifp = ifp;	/* store the reference */
		error = netmap_set_ringid(priv, nmr->nr_ringid);
		if (error)
			goto error;
		priv->np_nifp = nifp = netmap_if_new(nmr->nr_name, na);
		if (nifp == NULL) { /* allocation failed */
			error = ENOMEM;
		} else if (ifp->if_capenable & IFCAP_NETMAP) {
			/* was already set */
		} else {
			/* Otherwise set the card in netmap mode
			 * and make it use the shared buffers.
			 */
			error = na->nm_register(ifp, 1); /* mode on */
			if (error) {
				/*
				 * do something similar to netmap_dtor().
				 */
				netmap_free(na->tx_rings[0].ring, "rings, reg.failed");
				free(na->tx_rings, M_DEVBUF);
				na->tx_rings = na->rx_rings = NULL;
				na->refcount--;
				netmap_free(nifp, "nifp, rings failed");
				nifp = NULL;
			}
		}
		na->nm_lock(adapter, NETMAP_CORE_UNLOCK, 0);

		if (error) {	/* reg. failed, release priv and ref */
error:
			free(priv, M_DEVBUF);
			if_rele(ifp);	/* return the refcount */
			break;
		}

		error = devfs_set_cdevpriv(priv, netmap_dtor);

		if (error != 0) {
			/* could not assign the private storage for the
			 * thread, call the destructor explicitly.
			 */
			netmap_dtor(priv);
			break;
		}

		/* return the offset of the netmap_if object */
		nmr->nr_numrings = na->num_queues;
		nmr->nr_numslots = na->num_tx_desc;
		nmr->nr_memsize = netmap_mem_d->nm_totalsize;
		nmr->nr_offset =
			((char *) nifp - (char *) netmap_mem_d->nm_buffer);
		break;

	case NIOCUNREGIF:
		if (priv == NULL)
			return (ENXIO);

		/* the interface is unregistered inside the
		   destructor of the private data. */
		devfs_clear_cdevpriv();
		break;

	case NIOCTXSYNC:
        case NIOCRXSYNC:
		if (priv == NULL)
			return (ENXIO);
		ifp = priv->np_ifp;	/* we have a reference */
		na = NA(ifp); /* retrieve netmap adapter */
		adapter = ifp->if_softc;	/* shorthand */

		if (na->flags & NR_REINIT)
			netmap_clean_reinit(na);

		if (priv->np_qfirst == na->num_queues) {
			/* queues to/from host */
			if (cmd == NIOCTXSYNC)
				netmap_sync_to_host(na);
			else
				netmap_sync_from_host(na, NULL);
			return error;
		}

		for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
		    if (cmd == NIOCTXSYNC) {
			struct netmap_kring *kring = &na->tx_rings[i];
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("sync tx ring %d cur %d hwcur %d",
					i, kring->ring->cur,
					kring->nr_hwcur);
                        na->nm_txsync(adapter, i, 1 /* do lock */);
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("after sync tx ring %d cur %d hwcur %d",
					i, kring->ring->cur,
					kring->nr_hwcur);
		    } else {
			na->nm_rxsync(adapter, i, 1 /* do lock */);
			microtime(&na->rx_rings[i].ring->ts);
		    }
		}

                break;

	case BIOCIMMEDIATE:
	case BIOCGHDRCMPLT:
	case BIOCSHDRCMPLT:
	case BIOCSSEESENT:
		D("ignore BIOCIMMEDIATE/BIOCSHDRCMPLT/BIOCSHDRCMPLT/BIOCSSEESENT");
		break;

	default:
	    {
		/*
		 * allow device calls
		 */
		struct socket so;
		bzero(&so, sizeof(so));
		error = get_ifp(nmr->nr_name, &ifp); /* keep reference */
		if (error)
			break;
		so.so_vnet = ifp->if_vnet;
		// so->so_proto not null.
		error = ifioctl(&so, cmd, data, td);
		if_rele(ifp);
	    }
	}

	return (error);
}


/*
 * select(2) and poll(2) handlers for the "netmap" device.
 *
 * Can be called for one or more queues.
 * Return true the event mask corresponding to ready events.
 * If there are no ready events, do a selrecord on either individual
 * selfd or on the global one.
 * Device-dependent parts (locking and sync of tx/rx rings)
 * are done through callbacks.
 */
static int
netmap_poll(__unused struct cdev *dev, int events, struct thread *td)
{
	struct netmap_priv_d *priv = NULL;
	struct netmap_adapter *na;
	struct ifnet *ifp;
	struct netmap_kring *kring;
	u_int i, check_all, want_tx, want_rx, revents = 0;
	void *adapter;

	// XXX debugging -- just measure the cost of poll()
	if (skip_poll)
		return events;

	if (devfs_get_cdevpriv((void **)&priv) != 0 || priv == NULL)
		return POLLERR;

	ifp = priv->np_ifp;
	// XXX check for deleting() ?
	if ( (ifp->if_capenable & IFCAP_NETMAP) == 0)
		return POLLERR;

	if (netmap_verbose & 0x8000)
		D("device %s events 0x%x", ifp->if_xname, events);
	want_tx = events & (POLLOUT | POLLWRNORM);
	want_rx = events & (POLLIN | POLLRDNORM);

	adapter = ifp->if_softc;
	na = NA(ifp); /* retrieve netmap adapter */

	/* pending reinit, report up as a poll error. Pending
	 * reads and writes are lost.
	 */
	if (na->flags & NR_REINIT) {
		netmap_clean_reinit(na);
		revents |= POLLERR;
	}
	/* how many queues we are scanning */
	i = priv->np_qfirst;
	if (i == na->num_queues) { /* from/to host */
		if (priv->np_txpoll || want_tx) {
			/* push any packets up, then we are always ready */
			kring = &na->tx_rings[i];
			netmap_sync_to_host(na);
			revents |= want_tx;
		}
		if (want_rx) {
			kring = &na->rx_rings[i];
			if (kring->ring->avail == 0) {
                                if (netmap_sync_from_host(na))
                                        selrecord(td, &kring->si);
                        }
			if (kring->ring->avail > 0) {
				revents |= want_rx;
			}
		}
		return (revents);
	}

	/*
	 * check_all is set if the card has more than one queue and
	 * the client is polling all of them. If true, we sleep on
	 * the "global" selfd, otherwise we sleep on individual selfd
	 * (we can only sleep on one of them per direction).
	 * The interrupt routine in the driver should always wake on
	 * the individual selfd, and also on the global one if the card
	 * has more than one ring.
	 *
	 * If the card has only one lock, we just use that.
	 * If the card has separate ring locks, we just use those
	 * unless we are doing check_all, in which case the whole
	 * loop is wrapped by the global lock.
	 * We acquire locks only when necessary: if poll is called
	 * when buffers are available, we can just return without locks.
	 *
	 * rxsync() is only called if we run out of buffers on a POLLIN.
	 * txsync() is called if we run out of buffers on POLLOUT, or
	 * there are pending packets to send. The latter can be disabled
	 * passing NETMAP_NO_TX_POLL in the NIOCREG call.
	 */
	check_all = (i + 1 != priv->np_qlast);

	/*
	 * core_lock indicates what to do with the core lock.
	 * The core lock is used when either the card has no individual
	 * locks, or it has individual locks but we are cheking all
	 * rings so we need the core lock to avoid missing wakeup events.
	 *
	 * It has three possible states:
	 * NO_CL	we don't need to use the core lock, e.g.
	 *		because we are protected by individual locks.
	 * NEED_CL	we need the core lock. In this case, when we
	 *		call the lock routine, move to LOCKED_CL
	 *		to remember to release the lock once done.
	 * LOCKED_CL	core lock is set, so we need to release it.
	 */
	enum {NO_CL, NEED_CL, LOCKED_CL };
	int core_lock = (check_all || !na->separate_locks) ?
			NEED_CL:NO_CL;
	/*
	 * We start with a lock free round which is good if we have
	 * data available. If this fails, then lock and call the sync
	 * routines.
	 */
	for (i = priv->np_qfirst; want_rx && i < priv->np_qlast; i++) {
		kring = &na->rx_rings[i];
		if (kring->ring->avail > 0) {
			revents |= want_rx;
			want_rx = 0;	/* also breaks the loop */
		}
	}
	for (i = priv->np_qfirst; want_tx && i < priv->np_qlast; i++) {
		kring = &na->tx_rings[i];
		if (kring->ring->avail > 0) {
			revents |= want_tx;
			want_tx = 0;	/* also breaks the loop */
		}
	}

	/*
	 * If we to push packets out (priv->np_txpoll) or want_tx is
	 * still set, we do need to run the txsync calls (on all rings,
	 * to avoid that the tx rings stall).
	 */
	if (priv->np_txpoll || want_tx) {
		for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
			kring = &na->tx_rings[i];
			if (!want_tx && kring->ring->cur == kring->nr_hwcur)
				continue;
			if (core_lock == NEED_CL) {
				na->nm_lock(adapter, NETMAP_CORE_LOCK, 0);
				core_lock = LOCKED_CL;
			}
			if (na->separate_locks)
				na->nm_lock(adapter, NETMAP_TX_LOCK, i);
			if (netmap_verbose & NM_VERB_TXSYNC)
				D("send %d on %s %d",
					kring->ring->cur,
					ifp->if_xname, i);
			if (na->nm_txsync(adapter, i, 0 /* no lock */))
				revents |= POLLERR;

			if (want_tx) {
				if (kring->ring->avail > 0) {
					/* stop at the first ring. We don't risk
					 * starvation.
					 */
					revents |= want_tx;
					want_tx = 0;
				} else if (!check_all)
					selrecord(td, &kring->si);
			}
			if (na->separate_locks)
				na->nm_lock(adapter, NETMAP_TX_UNLOCK, i);
		}
	}

	/*
	 * now if want_rx is still set we need to lock and rxsync.
	 * Do it on all rings because otherwise we starve.
	 */
	if (want_rx) {
		for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
			kring = &na->rx_rings[i];
			if (core_lock == NEED_CL) {
				na->nm_lock(adapter, NETMAP_CORE_LOCK, 0);
				core_lock = LOCKED_CL;
			}
			if (na->separate_locks)
				na->nm_lock(adapter, NETMAP_RX_LOCK, i);

			if (na->nm_rxsync(adapter, i, 0 /* no lock */))
				revents |= POLLERR;
			if (no_timestamp == 0 ||
					kring->ring->flags & NR_TIMESTAMP)
				microtime(&kring->ring->ts);

			if (kring->ring->avail > 0)
				revents |= want_rx;
			else if (!check_all)
				selrecord(td, &kring->si);
			if (na->separate_locks)
				na->nm_lock(adapter, NETMAP_RX_UNLOCK, i);
		}
	}
	if (check_all && revents == 0) {
		i = na->num_queues + 1; /* the global queue */
		if (want_tx)
			selrecord(td, &na->tx_rings[i].si);
		if (want_rx)
			selrecord(td, &na->rx_rings[i].si);
	}
	if (core_lock == LOCKED_CL)
		na->nm_lock(adapter, NETMAP_CORE_UNLOCK, 0);

	return (revents);
}



/*
 * Module loader.
 *
 * Create the /dev/netmap device and initialize all global
 * variables.
 *
 * Return 0 on success, errno on failure.
 */
static int
netmap_init(void)
{
	int error;


	error = netmap_memory_init();
	if (error != 0) {
		printf("netmap: unable to initialize the memory allocator.");
		return (error);
	}
	printf("netmap: loaded module with %d Mbytes\n",
		netmap_mem_d->nm_totalsize >> 20);

	netmap_dev = make_dev(&netmap_cdevsw, 0, UID_ROOT, GID_WHEEL, 0660,
			      "netmap");

	return (0);
}


/*
 * Module unloader.
 *
 * Free all the memory, and destroy the ``/dev/netmap`` device.
 */
static void
netmap_fini(void)
{
	destroy_dev(netmap_dev);

	netmap_memory_fini();

	printf("netmap: unloaded module.\n");
}


/*
 * Kernel entry point.
 *
 * Initialize/finalize the module and return.
 *
 * Return 0 on success, errno on failure.
 */
static int
netmap_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = netmap_init();
		break;

	case MOD_UNLOAD:
		netmap_fini();
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}


DEV_MODULE(netmap, netmap_loader, NULL);
