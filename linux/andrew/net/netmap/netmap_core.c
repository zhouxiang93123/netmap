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

#if defined(FreeBSD)

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

#elif defined(linux)

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/if.h>
#include <net/netmap.h>
#include <net/netmap/netmap_kern.h>

#define bzero(a, len) memset(a, 0, len)

#endif

/* user-controlled variables */
/*int netmap_verbose;*/
int netmap_verbose = NM_VERB_HOST;

//static int no_timestamp; /* don't timestamp on rxsync */

/*
 * Allocator for a pool of packet buffers.  For each buffer we have
 * one entry in the bitmap to signal the state. Allocation scans
 * the bitmap, but since this is done only on attach, we are not
 * too worried about performance.
 * Note this is just a bitmap of which buffers are in used -- the
 * actual buffer memory is managed separately (since it is done
 * differently for different platforms)
 */
struct netmap_buf_map {
    u_int total_buffers;	/* total buffers. */
    u_int free;
    u_int bufsize;
    uint32_t *bitmap;	/* one bit per buffer, 1 means free */
};

static struct netmap_buf_map nm_buf_map;

void
netmap_init_bufmap(u_int bufsize, u_int total_buffers, uint32_t* bitmap)
{
    int i, n;
    
    /* number of buffers, they all start as free */
    nm_buf_map.bufsize = bufsize;
    nm_buf_map.total_buffers = total_buffers;
    nm_buf_map.bitmap = bitmap;

    /* initialize the bitmap. Entry 0 is considered
     * always busy (used as default when there are no buffers left).
     */
    nm_buf_map.bitmap[0] = ~3; /* slot 0 and 1 always busy */
    n = (total_buffers + 31) / 32;
    for (i = 1; i < n; i++)
        nm_buf_map.bitmap[i] = ~0;
    nm_buf_map.free = nm_buf_map.total_buffers - 2;
}

/*
 * Allocate n buffers from the ring, and fill the slot.
 * Buffer 0 is the 'junk' buffer.
 */
void
netmap_new_bufs(struct netmap_slot *slot, u_int n)
{
	uint32_t bi = 0;		/* index in the bitmap */
	uint32_t mask, j, i = 0;	/* slot counter */

	if (n > nm_buf_map.free) {
		D("only %d out of %d buffers available", i, n);
		return;
	}
	/* termination is guaranteed by p->free */
	while (i < n && nm_buf_map.free > 0) {
		uint32_t cur = nm_buf_map.bitmap[bi];
		if (cur == 0) { /* bitmask is fully used */
			bi++;
			continue;
		}
		/* locate a slot */
		for (j = 0, mask = 1; (cur & mask) == 0; j++, mask <<= 1) ;
		nm_buf_map.bitmap[bi] &= ~mask;	/* slot in use */
		nm_buf_map.free--;
		slot[i].buf_idx = bi*32+j;
		slot[i].len = nm_buf_map.bufsize;
		slot[i].flags = NS_BUF_CHANGED;
		i++;
	}
	ND("allocated %d buffers, %d available", n, nm_buf_map.free);
}


void
netmap_free_buf(uint32_t i)
{
	uint32_t pos, mask;
	if (i >= nm_buf_map.total_buffers) {
		D("invalid free index %d", i);
		return;
	}
	pos = i / 32;
	mask = 1 << (i % 32);
	if (nm_buf_map.bitmap[pos] & mask) {
		D("slot %d already free", i);
		return;
	}
	nm_buf_map.bitmap[pos] |= mask;
	nm_buf_map.free++;
}

/*
 * File descriptor's private data destructor.
 *
 * Call nm_register(ifp,0) to stop netmap mode on the interface and
 * revert to normal operation. We expect that np_ifp has not gone.
 */
void
netmap_cleanup(struct netmap_priv_d* priv)
{
    interface_t* ifp;
    struct netmap_adapter* na;
    struct netmap_if* nifp;
    
    if (priv == 0) { return; }
    ifp = priv->np_ifp;
    if (ifp == 0) { return; }

    na = NA(ifp);
    nifp = priv->np_nifp;

    D("cleaning up %p ifp %p", priv, priv ? priv->np_ifp : NULL);

    na->nm_lock(ifp, NETMAP_CORE_LOCK, 0); 

    na->refcount--;
    if (na->refcount <= 0) {	/* last instance */
        u_int i;

        D("deleting last netmap instance for %s", IFC_NAME(ifp));

        /*
         * there is a race here with *_netmap_task() and
         * netmap_poll(), which don't run under NETMAP_CORE_LOCK.
         * na->refcount == 0 && na->ifp->if_capenable & IFCAP_NETMAP
         * (aka NETMAP_DELETING(na)) are a unique marker that the
         * device is dying.
         * Before destroying stuff we sleep a bit, and then complete
         * the job. NIOCREG should realize the condition and
         * loop until they can continue; the other routines
         * should check the condition at entry and quit if
         * they cannot run.
         */
        na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);

#if defined(FreeBSD)
        tsleep(na, 0, "NIOCUNREG", 4);
#else
        /*XXX*/
#endif

        na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
        D("calling nm_(un)register");
        na->nm_register(ifp, 0); /* off, clear IFCAP_NETMAP */
        D("nm_(un)register finished");

        /* Wake up any sleeping threads. netmap_poll will
         * then return POLLERR
         */
        for (i = 0; i < na->num_queues + 2; i++) {
#if defined(FreeBSD)
            selwakeuppri(&na->tx_rings[i].si, PI_NET);
            selwakeuppri(&na->rx_rings[i].si, PI_NET);
#elif defined(linux)
            wake_up(&na->tx_rings[i].waitq);
            wake_up(&na->rx_rings[i].waitq);
#endif
        }

        /* release all buffers */
        NMA_LOCK();
        for (i = 0; i < na->num_queues + 1; i++) {
            int j, lim;
            struct netmap_ring *ring;

            ND("tx queue %d", i);
            ring = na->tx_rings[i].ring;
            lim = na->tx_rings[i].nkr_num_slots;
            for (j = 0; j < lim; j++)
                netmap_free_buf(ring->slot[j].buf_idx);

            ND("rx queue %d", i);
            ring = na->rx_rings[i].ring;
            lim = na->rx_rings[i].nkr_num_slots;
            for (j = 0; j < lim; j++)
                netmap_free_buf(ring->slot[j].buf_idx);
        }
        NMA_UNLOCK();
        netmap_free(na->tx_rings[0].ring, "shadow rings");

#if defined(FreeBSD)
        wakeup(na);
#else
        /*XXX*/
#endif
    }

    netmap_free(nifp, "nifp");

    na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0); 

    IFC_UNREF(ifp);

    bzero(priv, sizeof(*priv));	/* XXX for safety */
#if defined(FreeBSD)
    free(priv, M_DEVBUF);
#elif defined(linux)
    kfree(priv);
#endif
}

/*
 * Create and return a new ``netmap_if`` object, and possibly also
 * rings and packet buffors.
 *
 * Return NULL on failure.
 */
void *
netmap_if_new(const char *ifname, struct netmap_adapter *na)
{
	struct netmap_if *nifp;
	struct netmap_ring *ring;
	char *buff;
	u_int i, len, ofs;
	u_int n = na->num_queues + 1; /* shorthand, include stack queue */

	/*
	 * the descriptor is followed inline by an array of offsets
	 * to the tx and rx rings in the shared memory region.
	 */
	len = sizeof(struct netmap_if) + 2 * n * sizeof(ssize_t);
	nifp = netmap_malloc(len, "nifp");
	if (nifp == NULL)
		return (NULL);

	/* initialize base fields */
	*(int *)(uintptr_t)&nifp->ni_num_queues = na->num_queues;
	strncpy(nifp->ni_name, ifname, IFNAMSIZ);

	(na->refcount)++;	/* XXX atomic ? we are under lock */
	if (na->refcount > 1)
		goto final;

        D("initializing rings etc for %s, n=%d", ifname, n);
	/*
	 * If this is the first instance, allocate the shadow rings and
	 * buffers for this card (one for each hw queue, one for the host).
	 * The rings are contiguous, but have variable size.
	 * The entire block is reachable at
	 *	na->tx_rings[0].ring
	 */

	len = n * (2 * sizeof(struct netmap_ring) +
		  (na->num_tx_desc + na->num_rx_desc) *
		   sizeof(struct netmap_slot) );
	buff = netmap_malloc(len, "shadow rings");
	if (buff == NULL) {
		D("failed to allocate %d bytes for %s shadow ring",
			len, ifname);
error:
		(na->refcount)--;
		netmap_free(nifp, "nifp, rings failed");
		return (NULL);
	}
	/* do we have the bufers ? */
	len = n * 2 * (na->num_tx_desc + na->num_rx_desc);
	NMA_LOCK();
	if (nm_buf_map.free < len) {
		NMA_UNLOCK();
		netmap_free(buff, "not enough bufs");
		goto error;
	}
	/*
	 * in the kring, store the pointers to the shared rings
	 * and initialize the rings. We are under NMA_LOCK().
	 */
	ofs = 0;
	for (i = 0; i < n; i++) {
		struct netmap_kring *kring;
		int numdesc;

		/* Transmit rings */
		kring = &na->tx_rings[i];
		numdesc = na->num_tx_desc;
		bzero(kring, sizeof(*kring));
		kring->na = na;

		ring = kring->ring = (struct netmap_ring *)(buff + ofs);
		*(ssize_t *)(uintptr_t)&ring->buf_ofs =
                    netmap_ptr_to_buffer_offset((char*)ring);
		ND("txring[%d] at %p ofs %d", i, ring, ring->buf_ofs);
		*(int *)(int *)(uintptr_t)&ring->num_slots =
			kring->nkr_num_slots = numdesc;

		/*
		 * IMPORTANT:
		 * Always keep one slot empty, so we can detect new
		 * transmissions comparing cur and nr_hwcur (they are
		 * the same only if there are no new transmissions).
		 */
		ring->avail = kring->nr_hwavail = numdesc - 1;
		ring->cur = kring->nr_hwcur = 0;
		netmap_new_bufs(ring->slot, numdesc);

		ofs += sizeof(struct netmap_ring) +
			numdesc * sizeof(struct netmap_slot);
                
		/* Receive rings */
		kring = &na->rx_rings[i];
		numdesc = na->num_rx_desc;
		bzero(kring, sizeof(*kring));
		kring->na = na;

		ring = kring->ring = (struct netmap_ring *)(buff + ofs);
		*(ssize_t *)(uintptr_t)&ring->buf_ofs =
                    netmap_ptr_to_buffer_offset((char*)ring);
		ND("rxring[%d] at %p offset %d", i, ring, ring->buf_ofs);
		*(int *)(int *)(uintptr_t)&ring->num_slots =
			kring->nkr_num_slots = numdesc;
		ring->cur = kring->nr_hwcur = 0;
		ring->avail = kring->nr_hwavail = 0; /* empty */
		netmap_new_bufs(ring->slot, numdesc);
		ofs += sizeof(struct netmap_ring) +
			numdesc * sizeof(struct netmap_slot);
	}
	NMA_UNLOCK();
	for (i = 0; i < n+1; i++) {
#ifdef linux
            init_waitqueue_head(&na->tx_rings[i].waitq);
            init_waitqueue_head(&na->rx_rings[i].waitq);
#endif
	}
final:
	/*
	 * fill the slots for the rx and tx queues. They contain the offset
	 * between the ring and nifp, so the information is usable in
	 * userspace to reach the ring from the nifp.
	 */
	for (i = 0; i < n; i++) {
		char *base = (char *)nifp;
		*(ssize_t *)(uintptr_t)&nifp->ring_ofs[i] =
			(char *)na->tx_rings[i].ring - base;
		*(ssize_t *)(uintptr_t)&nifp->ring_ofs[i+n] =
			(char *)na->rx_rings[i].ring - base;
	}
	return (nifp);
}


/*
 * handler for synchronization of the queues from/to the host
 */
void
netmap_sync_to_host(struct netmap_adapter *na)
{
    (void) na;
#ifdef notyet    
	struct netmap_kring *kring = &na->tx_rings[na->num_queues];
	struct netmap_ring *ring = kring->ring;
	struct mbuf *head = NULL, *tail = NULL, *m;
	u_int n, lim = kring->nkr_num_slots - 1;

	na->nm_lock(na->ifp->if_softc, NETMAP_CORE_LOCK, 0);

	/* Take packets from hwcur to cur and pass them up.
	 * In case of no buffers we give up. At the end of the loop,
	 * the queue is drained in all cases.
	 */
	for (n = kring->nr_hwcur; n != ring->cur;) {
		struct netmap_slot *slot = &ring->slot[n];

		n = (n == lim) ? 0 : n + 1;
		if (slot->len < 14 || slot->len > NETMAP_BUF_SIZE) {
			D("bad pkt at %d len %d", n, slot->len);
			continue;
		}
		m = m_devget(NMB(slot), slot->len, 0, na->ifp, NULL);

		if (m == NULL)
			break;
		if (tail)
			tail->m_nextpkt = m;
		else
			head = m;
		tail = m;
		m->m_nextpkt = NULL;
	}
	kring->nr_hwcur = ring->cur;
	kring->nr_hwavail = ring->avail = lim;
	na->nm_lock(na->ifp->if_softc, NETMAP_CORE_UNLOCK, 0);

	/* send packets up, outside the lock */
	while ((m = head) != NULL) {
		head = head->m_nextpkt;
		m->m_nextpkt = NULL;
		m->m_pkthdr.rcvif = na->ifp;
		if (netmap_verbose & NM_VERB_HOST)
			D("sending up pkt %p size %d", m, m->m_pkthdr.len);
		(na->ifp->if_input)(na->ifp, m);
	}
#endif
}

/*
 * Returns non-zero if nothing is synced so caller can sleep
 * if necessary (ie if called from poll handler)
 */
int
netmap_sync_from_host(struct netmap_adapter *na)
{
	struct netmap_kring *kring = &na->rx_rings[na->num_queues];
	struct netmap_ring *ring = kring->ring;
	int delta, ret;

	na->nm_lock(na->ifp, NETMAP_CORE_LOCK, 0);

	/* skip past packets processed by userspace,
	 * and then sync cur/avail with hwcur/hwavail
	 */
	delta = ring->cur - kring->nr_hwcur;
	if (delta < 0)
		delta += kring->nkr_num_slots;
	kring->nr_hwavail -= delta;
	kring->nr_hwcur = ring->cur;
	ring->avail = kring->nr_hwavail;
        ret = (ring->avail == 0);
	if (ring->avail && (netmap_verbose & NM_VERB_HOST))
		D("%d pkts from stack", ring->avail);
	na->nm_lock(na->ifp, NETMAP_CORE_UNLOCK, 0);

        return (ret);
}


/*
 * Error routine called when txsync/rxsync detects an error.
 * Can't do much more than resetting cur = hwcur, avail = hwavail.
 * Return 1 on reinit.
 */
int
netmap_ring_reinit(struct netmap_kring *kring)
{
	struct netmap_ring *ring = kring->ring;
	u_int i, lim = kring->nkr_num_slots - 1;
	int errors = 0;

	D("called for %s", IFC_NAME(kring->na->ifp));
	if (ring->cur > lim)
		errors++;
	for (i = 0; i <= lim; i++) {
		u_int idx = ring->slot[i].buf_idx;
		u_int len = ring->slot[i].len;
                if (idx < 2 || idx >= nm_buf_map.total_buffers) {
			if (!errors++)
				D("bad buffer at slot %d idx %d len %d ", i, idx, len);
			ring->slot[i].buf_idx = 0;
			ring->slot[i].len = 0;
		} else if (len > NETMAP_BUF_SIZE) {
			ring->slot[i].len = 0;
			if (!errors++)
				D("bad len %d at slot %d idx %d",
					len, i, idx);
		}
	}
	if (errors) {
		int pos, n;
		D("total %d errors", errors);
		pos = kring - kring->na->tx_rings;
		n = kring->na->num_queues + 2;

		errors++;
		D("%s %s[%d] reinit, cur %d -> %d avail %d -> %d",
			IFC_NAME(kring->na->ifp),
			pos < n ?  "TX" : "RX", pos < n ? pos : pos - n, 
			ring->cur, kring->nr_hwcur,
			ring->avail, kring->nr_hwavail);
		ring->cur = kring->nr_hwcur;
		ring->avail = kring->nr_hwavail;
		ring->flags |= NR_REINIT;
		kring->na->flags |= NR_REINIT;
	}
	return (errors ? 1 : 0);
}

/*
 * Clean the reinit flag for our rings.
 * XXX at the moment, clear for all rings
 */
void
netmap_clean_reinit(struct netmap_adapter *na)
{
	//struct netmap_kring *kring;
	u_int i;

	na->flags &= ~NR_REINIT;
	D("--- NR_REINIT reset on %s", IFC_NAME(na->ifp));
	for (i = 0; i < na->num_queues + 1; i++) {
		na->tx_rings[i].ring->flags &= ~NR_REINIT;
		na->rx_rings[i].ring->flags &= ~NR_REINIT;
	}
}

#if defined(linux)
EXPORT_SYMBOL(netmap_clean_reinit);
#endif

/*
 * Set the ring ID. For devices with a single queue, a request
 * for all rings is the same as a single ring.
 */
int
netmap_set_ringid(struct netmap_priv_d *priv, u_int ringid)
{
        interface_t* ifp = priv->np_ifp;
	struct netmap_adapter *na = NA(ifp);
	u_int i = ringid & NETMAP_RING_MASK;
	/* first time we don't lock */
	int need_lock = (priv->np_qfirst != priv->np_qlast);

	if ( (ringid & NETMAP_HW_RING) && i >= na->num_queues) {
		D("invalid ring id %d", i);
		return (EINVAL);
	}
	if (need_lock)
		na->nm_lock(ifp, NETMAP_CORE_LOCK, 0);
	priv->np_ringid = ringid;
	if (ringid & NETMAP_SW_RING) {
		priv->np_qfirst = na->num_queues;
		priv->np_qlast = na->num_queues + 1;
	} else if (ringid & NETMAP_HW_RING) {
		priv->np_qfirst = i;
		priv->np_qlast = i + 1;
	} else {
		priv->np_qfirst = 0;
		priv->np_qlast = na->num_queues;
	}
	priv->np_txpoll = (ringid & NETMAP_NO_TX_POLL) ? 0 : 1;
	if (need_lock)
		na->nm_lock(ifp, NETMAP_CORE_UNLOCK, 0);
	if (ringid & NETMAP_SW_RING)
		D("ringid %s set to SW RING", IFC_NAME(ifp));
	else if (ringid & NETMAP_HW_RING)
		D("ringid %s set to HW RING %d", IFC_NAME(ifp),
			priv->np_qfirst);
	else
		D("ringid %s set to all %d HW RINGS", IFC_NAME(ifp),
			priv->np_qlast);
	return 0;
}

/*------- driver support routines ------*/


/*
 * Initialize a ``netmap_adapter`` object created by driver on attach.
 * We allocate a block of memory with room for a struct netmap_adapter
 * plus two sets of N+2 struct netmap_kring (where N is the number
 * of hardware rings):
 * krings	0..N-1	are for the hardware queues.
 * kring	N	is for the host stack queue
 * kring	N+1	is only used for the selinfo for all queues.
 * Return 0 on success, ENOMEM otherwise.
 */
int
netmap_attach(struct netmap_adapter *na, int num_queues)
{
	int n = num_queues + 2;
	int size = sizeof(*na) + 2 * n * sizeof(struct netmap_kring);
	void *buf;
        interface_t* ifp = na->ifp;

	if (ifp == NULL) {
		D("ifp not set, giving up");
		return EINVAL;
	}
	na->refcount = 0;
	na->num_queues = num_queues;

#ifdef FreeBSD
	buf = malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
#else
        buf = kmalloc(size, GFP_KERNEL);
#endif

	if (buf) {
#ifdef FreeBSD
		ifp->if_pspare[0] = buf;
#else
                ifp->ml_priv = buf;
#endif
		na->tx_rings = (void *)((char *)buf + sizeof(*na));
		na->rx_rings = na->tx_rings + n;
#ifdef FreeBSD
		bcopy(na, buf, sizeof(*na));
		ifp->if_capabilities |= IFCAP_NETMAP;
#else
                memcpy(buf, na, sizeof *na);
                ifp->flags |= IFCAP_NETMAP;
#endif
	}
	D("%s for %s", buf ? "ok" : "failed", IFC_NAME(ifp));

	return (buf ? 0 : ENOMEM);
}

#if defined(linux)
EXPORT_SYMBOL(netmap_attach);
#endif


#ifdef notyet
/*
 * Free the allocated memory linked to the given ``netmap_adapter``
 * object.
 */
void
netmap_detach(struct ifnet *ifp)
{
	u_int i;
	struct netmap_adapter *na = NA(ifp);

	if (!na)
		return;

	for (i = 0; i < na->num_queues + 2; i++) {
		knlist_destroy(&na->tx_rings[i].si.si_note);
		knlist_destroy(&na->rx_rings[i].si.si_note);
	}
	bzero(na, sizeof(*na));
	ifp->if_pspare[0] = NULL;
	free(na, M_DEVBUF);
}


/*
 * intercept packets coming from the network stack and present
 * them to netmap as incoming packets on a separate ring.
 * We are not locked when called.
 */
int
netmap_start(struct ifnet *ifp, struct mbuf *m)
{
	struct netmap_adapter *na = NA(ifp);
	u_int i, len, n = na->num_queues;
	int error = EBUSY;
	struct netmap_kring *kring = &na->rx_rings[n];
	struct netmap_slot *slot;

	len = m->m_pkthdr.len;
	if (netmap_verbose & NM_VERB_HOST)
		D("%s packet %d len %d from the stack", ifp->if_xname,
			kring->nr_hwcur + kring->nr_hwavail, len);
	na->nm_lock(ifp->if_softc, NETMAP_CORE_LOCK, 0);
	if (kring->nr_hwavail >= (int)kring->nkr_num_slots - 1) {
		D("stack ring %s full\n", ifp->if_xname);
		goto done;	/* no space */
	}
	if (len > na->buff_size) {
		D("drop packet size %d > %d", len, na->buff_size);
		goto done;	/* too long for us */
	}

	/* compute the insert position */
	i = kring->nr_hwcur + kring->nr_hwavail;
	if (i >= kring->nkr_num_slots)
		i -= kring->nkr_num_slots;
	slot = &kring->ring->slot[i];
	m_copydata(m, 0, len, NMB(slot));
	slot->len = len;
	kring->nr_hwavail++;
	if (netmap_verbose  & NM_VERB_HOST)
		D("wake up host ring %s %d", na->ifp->if_xname, na->num_queues);
	selwakeuppri(&kring->si, PI_NET);
	error = 0;
done:
	na->nm_lock(ifp->if_softc, NETMAP_CORE_UNLOCK, 0);

	/* release the mbuf in either cases of success or failure. As an
	 * alternative, put the mbuf in a free list and free the list
	 * only when really necessary.
	 */
	m_freem(m);

	return (error);
}

/*
 * netmap_reset() is called by the driver routines when reinitializing
 * a ring. The driver is in charge of locking to protect the kring.
 * If netmap mode is not set just return NULL.
 * Otherwise set NR_REINIT (in the ring and in na) to signal
 * that a ring has been reinitialized,
 * set cur = hwcur = 0 and avail = hwavail = num_slots - 1 .
 * IT IS IMPORTANT to leave one slot free even in the tx ring because
 * we rely on cur=hwcur only for empty rings.
 * These are good defaults but can be overridden later in the device
 * specific code if, after a reinit, the ring does not start from 0
 * (e.g. if_em.c does this).
 *
 * XXX we shouldn't be touching the ring, but there is a
 * race anyways and this is our best option.
 *
 * XXX setting na->flags makes the syscall code faster, as there is
 * only one place to check. On the other hand, we will need a better
 * way to notify multiple threads that rings have been reset.
 * One way is to increment na->rst_count at each ring reset.
 * Each thread in its own priv structure will keep a matching counter,
 * and on a reset will acknowledge and clean its own rings.
 */
struct netmap_slot *
netmap_reset(struct netmap_adapter *na, enum txrx tx, int n,
	u_int new_cur)
{
	struct netmap_kring *kring;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	u_int i;

	if (na == NULL)
		return NULL;	/* no netmap support here */
	if (!(na->ifp->if_capenable & IFCAP_NETMAP))
		return NULL;	/* nothing to reinitialize */
	kring = tx == NR_TX ?  na->tx_rings + n : na->rx_rings + n;
	ring = kring->ring;
    if (tx == NR_TX) {
	/*
	 * The last argument is the new value of next_to_clean.
	 *
	 * In the TX ring, we have P pending transmissions (from
	 * next_to_clean to nr_hwcur) followed by nr_hwavail free slots.
	 * Generally we can use all the slots in the ring so
	 * P = ring_size - nr_hwavail hence (modulo ring_size):
	 *	next_to_clean == nr_hwcur + nr_hwavail
	 * 
	 * If, upon a reset, nr_hwavail == ring_size and next_to_clean
	 * does not change we have nothing to report. Otherwise some
	 * pending packets may be lost, or newly injected packets will.
	 */
	/* if hwcur does not change, nothing to report.
	 * otherwise remember the change so perhaps we can
	 * shift the block at the next reinit
	 */
	if (new_cur == kring->nr_hwcur &&
		    kring->nr_hwavail == kring->nkr_num_slots - 1) {
		/* all ok */
		D("+++ NR_REINIT ok on %s TX[%d]", na->ifp->if_xname, n);
	} else {
		D("+++ NR_REINIT set on %s TX[%d]", na->ifp->if_xname, n);
	}
		ring->flags |= NR_REINIT;
		na->flags |= NR_REINIT;
		ring->avail = kring->nr_hwavail = kring->nkr_num_slots - 1;
		ring->cur = kring->nr_hwcur = new_cur;
    } else {
	/*
	 * The last argument is the next free slot.
	 * In the RX ring we have nr_hwavail full buffers starting
	 * from nr_hwcur.
	 * If nr_hwavail == 0 and nr_hwcur does not change we are ok
	 * otherwise we might be in trouble as the buffers are
	 * changing.
	 */
	if (new_cur == kring->nr_hwcur && kring->nr_hwavail == 0) {
		/* all ok */
		D("+++ NR_REINIT ok on %s RX[%d]", na->ifp->if_xname, n);
	} else {
		D("+++ NR_REINIT set on %s RX[%d]", na->ifp->if_xname, n);
	}
	ring->flags |= NR_REINIT;
	na->flags |= NR_REINIT;
	ring->avail = kring->nr_hwavail = 0; /* no data */
	ring->cur = kring->nr_hwcur = new_cur;
    }

	slot = ring->slot;
	/*
	 * Check that buffer indexes are correct. If we find a
	 * bogus value we are a bit in trouble because we cannot
	 * recover easily. Best we can do is (probably) persistently
	 * reset the ring.
	 */
	for (i = 0; i < kring->nkr_num_slots; i++) {
		if (slot[i].buf_idx >= netmap_total_buffers) {
			D("invalid buf_idx %d at slot %d", slot[i].buf_idx, i);
			slot[i].buf_idx = 0; /* XXX reset */
		}
		/* XXX we don't really need to set the length */
		slot[i].len = 0;
	}
	/* wakeup possible waiters, both on the ring and on the global
	 * selfd. Perhaps a bit early now but the device specific
	 * routine is locked so hopefully we won't have a race.
	 */
	selwakeuppri(&kring->si, PI_NET);
	selwakeuppri(&kring[na->num_queues + 1 - n].si, PI_NET);
	return kring->ring->slot;
}
#endif /* notyet */
