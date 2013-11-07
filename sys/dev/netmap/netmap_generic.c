/*
 * Copyright (C) 2013 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This module implemnts netmap support on top of standard,
 * unmodified device drivers.
 *
 * A NIOCREGIF request is handled here if the device does not
 * have native support. TX and RX rings are emulated as follows:
 *
 * NIOCREGIF
 *	We preallocate a block of TX mbufs (roughly as many as
 *	tx descriptors; the number is not critical) to speed up
 *	operation during transmissions. The refcount on most of
 *	these buffers is artificially bumped up so we can recycle
 *	them more easily. Also, the destructor is intercepted
 *	so we use it as an interrupt notification to wake up
 *	processes blocked on a poll().
 *
 *	For each receive rings, we allocate one "struct mbq"
 *	(an mbuf tailq plus a spinlock). We intercept packets
 *	(through if_input)
 *	on the receive path and put them in the mbq from which
 *	netmap receive routines can grab them.
 *
 * TX:
 *	in the generic_txsync() routine, netmap buffers are copied
 *	(or linked, in a future) to the preallocated mbufs
 *	and pushed to the transmit queue. A few of these mbufs
 *	(those with NS_REPORT, or otherwise every half ring)
 *	have the refcount=1, others have refcount=2.
 *	When the destructor is invoked, we take that as
 *	a notification that all mbufs up to that one in
 *	the specific ring have been completed.
 *
 * RX:
 *
 */
#ifdef __FreeBSD__

#include <sys/cdefs.h> /* prerequisite */
__FBSDID("$FreeBSD: head/sys/dev/netmap/netmap.c 257666 2013-11-05 01:06:22Z luigi $");

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/lock.h>   /* PROT_EXEC */ // XXX also lock.h
#include <sys/rwlock.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>        /* bus_dmamap_* in netmap_kern.h */

typedef int rx_handler_result_t;	// XXX
#define rtnl_lock() D("rtnl_lock called");
#define rtnl_unlock() D("rtnl_lock called");

static struct mbuf *
netmap_get_mbuf(int len)
{
	struct mbuf *m;

	if (len < 0 || len > MCLBYTES) {
		D("invalid size %d", len);
		return NULL;
	}
	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);

	if (m == NULL)
		return m;
	m->m_len = m->m_pkthdr.len = len;
	return m;
}

/*
 * mbuf wrappers
 */
#define GET_MBUF_REFCNT(m)	(*(m)->m_ext.ref_cnt)

/* mbuf destructor, also need to change the type to EXT_EXTREF
 * and then chain into uma_zfree(zone_clust, m->m_ext.ext_buf)
 * (or reinstall the buffer ?)
 */

#define	destructor		m_ext.ext_free

/* we get a cluster, no matter what */
#define netmap_get_mbuf(size)	m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR)

#else /* linux */
#include "bsd_glue.h"

#include <linux/rtnetlink.h>    /* rtnl_[un]lock() */
#include <linux/ethtool.h>      /* struct ethtool_ops, get_ringparam */
#include <linux/hrtimer.h>

#define RATE  /* Enables communication statistics. */

#define GET_MBUF_REFCNT(m)	NM_ATOMIC_READ(&((m)->users))

#define netmap_get_mbuf(size)	alloc_skb(size, GFP_ATOMIC)

//#define REG_RESET

#endif /* linux */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>


/* ================== STUFF DEFINED in netmap.c =================== */
extern int netmap_generic_mit;


/* ======================== usage stats =========================== */

#ifdef RATE
#define IFRATE(x) x
struct rate_stats {
    unsigned long txpkt;
    unsigned long txsync;
    unsigned long txirq;
    unsigned long rxpkt;
    unsigned long rxirq;
    unsigned long rxsync;
};

struct rate_context {
    unsigned refcount;
    struct timer_list timer;
    struct rate_stats new;
    struct rate_stats old;
};

#define RATE_PRINTK(_NAME_) \
    printk( #_NAME_ " = %lu Hz\n", (cur._NAME_ - ctx->old._NAME_)/RATE_PERIOD);
#define RATE_PERIOD  2
static void rate_callback(unsigned long arg)
{
    struct rate_context * ctx = (struct rate_context *)arg;
    struct rate_stats cur = ctx->new;
    int r;

    RATE_PRINTK(txpkt);
    RATE_PRINTK(txsync);
    RATE_PRINTK(txirq);
    RATE_PRINTK(rxpkt);
    RATE_PRINTK(rxsync);
    RATE_PRINTK(rxirq);
    printk("\n");

    ctx->old = cur;
    r = mod_timer(&ctx->timer, jiffies +
                                msecs_to_jiffies(RATE_PERIOD * 1000));
    if (unlikely(r))
        D("[v1000] Error: mod_timer()\n");
}

static struct rate_context rate_ctx;

#else /* !RATE */
#define IFRATE(x)
#endif /* !RATE */


/* =============== GENERIC NETMAP ADAPTER SUPPORT ================= */
#define GENERIC_BUF_SIZE        netmap_buf_size    /* Size of the mbufs in the Tx pool. */

#ifdef linux

/*
 * XXX Can't we just use netmap_rx_irq ?
 * Wrapper used by the generic adapter layer to notify
 * the poller threads.
 */
static int
netmap_generic_irq(struct ifnet *ifp, u_int q, u_int *work_done)
{
	if (unlikely(!(ifp->if_capenable & IFCAP_NETMAP)))
		return 0;

        return netmap_common_irq(ifp, q, work_done);
}

rx_handler_result_t generic_netmap_rx_handler(struct mbuf **pm);

static enum hrtimer_restart
generic_timer_handler(struct hrtimer *t)
{
    struct netmap_adapter *na = container_of(t, struct netmap_adapter, mit_timer);
    uint work_done;

    if (na->mit_pending) {
        /* Some work arrived while the timer was counting down:
	 * Reset the pending work flag, restart the timer and issue
	 * a notification.
	 */
        na->mit_pending = 0;
        netmap_generic_irq(na->ifp, 0, &work_done);
        IFRATE(rate_ctx.new.rxirq++);
        hrtimer_forward_now(&na->mit_timer, ktime_set(0, netmap_generic_mit));

        return HRTIMER_RESTART;
    }

    /* No pending work? Don't restart the timer. */
    return HRTIMER_NORESTART;
}

static u16 generic_ndo_select_queue(struct ifnet *ifp, struct mbuf *m)
{
    return skb_get_queue_mapping(m);
}
#endif /* linux */

/* Enable/disable netmap mode for a generic network interface. */
int generic_netmap_register(struct ifnet *ifp, int enable)
{
#ifdef __FreeBSD__
    if (enable) {
	return EINVAL;
    } else {
        return 0;
    }
#else /* linux */

    struct netmap_adapter *na = NA(ifp);
    struct mbuf *m;
    int error;
    int i, r;

    if (!na)
        return EINVAL;

#ifdef REG_RESET
    error = ifp->netdev_ops->ndo_stop(ifp);
    if (error) {
        return error;
    }
#endif /* REG_RESET */

    if (enable) { /* Enable netmap mode. */
        /* Initialize the rx queue, as generic_netmap_rx_handler() can
	 * be called as soon as netdev_rx_handler_register() returns.
	 */
        for (r=0; r<na->num_rx_rings; r++) {
            mbq_safe_init(&na->rx_rings[r].rx_queue);
            na->rx_rings[r].nr_ntc = 0;
        }
        hrtimer_init(&na->mit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        na->mit_timer.function = &generic_timer_handler;
        na->mit_pending = 0;

        for (r=0; r<na->num_tx_rings; r++) {
            na->tx_rings[r].nr_ntc = 0;
            na->tx_rings[r].tx_pool = malloc(na->num_tx_desc * sizeof(struct mbuf *),
                                                M_DEVBUF, GFP_ATOMIC);
            if (!na->tx_rings[r].tx_pool) {
                D("tx_pool allocation failed");
                error = ENOMEM;
                goto alloc_tx_pool;
            }
            for (i=0; i<na->num_tx_desc; i++) {
                m = netmap_get_mbuf(GENERIC_BUF_SIZE);
                if (!m) {
                    D("tx_pool[%d] allocation failed", i);
                    error = ENOMEM;
                    goto alloc_mbufs;
                }
                na->tx_rings[r].tx_pool[i] = m;
            }
        }
        rtnl_lock();
        error = netdev_rx_handler_register(ifp, &generic_netmap_rx_handler, na);
        if (error) {
            D("netdev_rx_handler_register() failed");
            goto register_handler;
        }
        ifp->if_capenable |= IFCAP_NETMAP;
#ifdef linux
	/*
	 * save the old pointer to the netdev_op
	 * create an updated netdev ops replacing the
	 * ndo_select_queue function with our custom one,
	 * and make the driver use it.
	 */
        na->if_transmit = (void *)ifp->netdev_ops;
        *na->generic_ndo_p = *ifp->netdev_ops;  /* Copy */
        na->generic_ndo_p->ndo_select_queue = &generic_ndo_select_queue;
        ifp->netdev_ops = na->generic_ndo_p;
#else
	XXX do the same for FreeBSD
#endif /* __FreeBSD__ */

#ifdef RATE
        if (rate_ctx.refcount == 0) {
            D("setup_timer()");
            memset(&rate_ctx, 0, sizeof(rate_ctx));
            setup_timer(&rate_ctx.timer, &rate_callback, (unsigned long)&rate_ctx);
            if (mod_timer(&rate_ctx.timer, jiffies + msecs_to_jiffies(1500))) {
                D("[v1000] Error: mod_timer()");
            }
        }
        rate_ctx.refcount++;
#endif /* RATE */

    } else { /* Disable netmap mode. */
        rtnl_lock();
        ifp->if_capenable &= ~IFCAP_NETMAP;
	/* restore the netdev_ops */
        ifp->netdev_ops = (void *)na->if_transmit;

	/* do not intercept packets on the rx path */
        netdev_rx_handler_unregister(ifp);

	/* XXX maybe we should try and put this outside
	 * the lock
	 */
	/* Free the mbufs going to the netmap rings */
        for (r=0; r<na->num_rx_rings; r++) {
            mbq_safe_purge(&na->rx_rings[r].rx_queue);
            mbq_safe_destroy(&na->rx_rings[r].rx_queue);
        }

        hrtimer_cancel(&na->mit_timer);

        for (r=0; r<na->num_tx_rings; r++) {
            for (i=0; i<na->num_tx_desc; i++) {
                m_freem(na->tx_rings[r].tx_pool[i]);
            }
            free(na->tx_rings[r].tx_pool, M_DEVBUF);
        }

#ifdef RATE
        if (--rate_ctx.refcount == 0) {
            D("del_timer()");
            del_timer(&rate_ctx.timer);
        }
#endif
    }

    rtnl_unlock();

#ifdef REG_RESET
    error = ifp->netdev_ops->ndo_open(ifp);
    if (error) {
        goto alloc_tx_pool;
    }
#endif

    return 0;

register_handler:
    rtnl_unlock();
alloc_tx_pool:
    r--;
    i = na->num_tx_desc;  /* Useless, but just to stay safe. */
alloc_mbufs:
    i--;
    for (; r>=0; r--) {
        for (; i>=0; i--) {
            m_freem(na->tx_rings[r].tx_pool[i]);
        }
        free(na->tx_rings[r].tx_pool, M_DEVBUF);
        i = na->num_tx_desc - 1;
    }

    return error;
#endif /* linux */
}

#ifdef linux
/*
 * Callback invoked when the device driver frees an mbuf used
 * by netmap to transmit a packet. This usually happens when
 * the NIC notifies the driver that transmission is completed.
 */
static void
generic_mbuf_destructor(struct mbuf *m)
{
    ND("Tx irq (%p)", arg);
    netmap_generic_irq(m->dev, skb_get_queue_mapping(m), NULL);
    IFRATE(rate_ctx.new.txirq++);
}

/* Record completed transmissions and update hwavail/avail.
 *
 * XXX document what nr_ntc is about
 */
static int
generic_netmap_tx_clean(struct netmap_kring *kring)
{
    u_int num_slots = kring->nkr_num_slots;
    u_int ntc = kring->nr_ntc;
    u_int hwcur = kring->nr_hwcur;
    u_int n = 0;
    struct mbuf **tx_pool = kring->tx_pool;

    /*
     * XXX check the termination logic.
     */
    while (ntc != hwcur) {
	struct mbuf *m = tx_pool[ntc];

        if (unlikely(m == NULL)) {
	    /* try to replenish the entry */
            tx_pool[ntc] = m = netmap_get_mbuf(GENERIC_BUF_SIZE);
            if (unlikely(m == NULL)) {
                D("mbuf allocation failed, XXX error");
		// XXX how do we proceed ? break ?
                return -ENOMEM;
            }
	} else if (GET_MBUF_REFCNT(m) == 1) {
	    /* XXX maybe unnecessary ? we can deal with that
	     * in the sending routine
	     */
            skb_trim(m, 0);
        } else {
	    break; /* still busy */
	}
        if (unlikely(++ntc == num_slots)) {
            ntc = 0;
        }
        n++;
    }
    kring->nr_ntc = ntc;
    kring->nr_hwavail += n;
    kring->ring->avail += n;
    ND("tx completed [%d] -> hwavail %d", n, kring->nr_hwavail);

    return n;
}


/*
 * return a position which is XXX between the current and the
 * last slot to be sent ?
 */
static inline u_int
generic_tx_event_middle(struct netmap_kring *kring, u_int j)
{
    u_int n = kring->nkr_num_slots;
    u_int e = (kring->nr_ntc + ((((n + j) - kring->nr_ntc) % (n)) / 2)) % (n);

    if (unlikely(e >= n)) {
        D("This cannot happen");
        e = 0;
    }

    return e;
}

static int
generic_set_tx_event(struct netmap_kring *kring, u_int e)
{
    struct mbuf *m;

    ND("Event at %d", e);
    m = kring->tx_pool[e];
    if (unlikely(!m)) {
        D("ERROR: This should never happen");
        return -EINVAL;
    }
    kring->tx_pool[e] = NULL;
    //skb_shinfo(m)->destructor_arg = NULL + e;
    m->destructor = &generic_mbuf_destructor;
    // XXX wmb() ?
    /* Decrement the refcount an free it if we have the last one. */
    m_freem(m);
    smp_mb();

    /* Double check here is redundant, because the txsync callback is called twice.
    return generic_netmap_tx_clean(kring); */
    return 0;
}
#endif /* linux */

/*
 * generic_netmap_txsync() transforms netmap buffers into mbufs
 * and passes them to the standard device driver
 * (ndo_start_xmit() or ifp->if_transmit() ).
 * On linux this is not done directly, but using dev_queue_xmit(),
 * since it implements the TX flow control (and takes some locks).
 */
static int
generic_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int flags)
{
#ifdef __FreeBSD__
    return EINVAL;
#else /* linux */
    struct netmap_adapter *na = NA(ifp);
    struct netmap_kring *kring = &na->tx_rings[ring_nr];
    struct netmap_ring *ring = kring->ring;
    u_int j, k, n = 0, lim = kring->nkr_num_slots - 1;

    IFRATE(rate_ctx.new.txsync++);

    generic_netmap_tx_clean(kring);

    /* Take a copy of ring->cur now, and never read it again. */
    k = ring->cur;
    if (unlikely(k > lim)) {
            return netmap_ring_reinit(kring);
    }

    rmb();
    j = kring->nr_hwcur;
    if (j != k) {
        /* Process new packets to send: j is the current index in the netmap ring. */
        while (j != k) {
            struct netmap_slot *slot = &ring->slot[j]; /* Current slot in the netmap ring */
            void *addr = NMB(slot);
            u_int len = slot->len;
            struct mbuf *m;
            int tx_ret;

            if (unlikely(addr == netmap_buffer_base || len > NETMAP_BUF_SIZE)) {
                    return netmap_ring_reinit(kring);
            }
            /* Tale a mbuf from the tx pool and copy in the user packet. */
            m = kring->tx_pool[j];
            if (unlikely(!m)) {
                D("This should never happen");
                return netmap_ring_reinit(kring);
            }
	    /* XXX we should ask notifications when NS_REPORT is set,
	     * or roughly every half frame. We can optimize this
	     * by lazily requesting notifications only when a
	     * transmission fails. Probably the best way is to
	     * break on failures and set notifications when
	     * ring->avail == 0 || j != k
	     */
            tx_ret = generic_xmit_frame(ifp, m, addr, len, ring_nr);
            if (unlikely(tx_ret)) {
                ND("start_xmit failed: err %d [%d,%d,%d]", tx_ret, j, k, kring->nr_hwavail);
		/*
		 * XXX this may need some simplifications.
		 * I do not understand the logic.
		 *
                 * If the frame has been dropped, just set a
		 * notification event on a netmap slot that will
		 * be cleaned in the future (and possibly continue
		 * the TX processing if the doublecheck reports
		 * new available slots).
                 */
                if (unlikely(generic_set_tx_event(kring,
                                    generic_tx_event_middle(kring, j)) > 0)) {
                    continue;
                }
                break;
            }
            slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
            if (unlikely(j++ == lim))
                j = 0;
            n++;
        }

        kring->nr_hwcur = j;
        kring->nr_hwavail -= n;
        IFRATE(rate_ctx.new.txpkt += n);
        if (!ring->avail) {
            /* No more available slots? Set a notification event
	     * on a netmap slot that will be cleaned in the future.
	     * No doublecheck is performed, since txsync() will be
	     * called twice by netmap_poll().
	     */
            generic_set_tx_event(kring, generic_tx_event_middle(kring, j));
        }
        ND("tx #%d, hwavail = %d", n, kring->nr_hwavail);
    }

    return 0;
#endif /* linux */
}

#ifdef linux

/* This handler is registered within the attached net_device in the Linux RX subsystem,
   so that every mbuf passed up by the driver can be stolen to the network stack.
   Stolen packets are put in a queue where the generic_netmap_rxsync() callback can
   extract them. */
rx_handler_result_t generic_netmap_rx_handler(struct mbuf **pm)
{
    struct netmap_adapter *na = NA((*pm)->dev);
    uint work_done;
    uint rr = 0;

    if (unlikely(mbq_len(&na->rx_rings[rr].rx_queue) > 1024)) {
        m_freem(*pm);
    } else {
        mbq_safe_enqueue(&na->rx_rings[rr].rx_queue, *pm);
    }

    if (netmap_generic_mit < 32768) {
        /* When rx mitigation is not used, never filter the notification. */
        netmap_generic_irq(na->ifp, rr, &work_done);
        IFRATE(rate_ctx.new.rxirq++);
    } else {
        /* Filter the notification when there is a pending timer, otherwise
           start the timer and don't filter. */
        if (likely(hrtimer_active(&na->mit_timer))) {
            /* Record that there is some pending work. */
            na->mit_pending = 1;
        } else {
            netmap_generic_irq(na->ifp, rr, &work_done);
            IFRATE(rate_ctx.new.rxirq++);
            hrtimer_start(&na->mit_timer, ktime_set(0, netmap_generic_mit), HRTIMER_MODE_REL);
        }
    }

    return RX_HANDLER_CONSUMED;
}
#endif /* linux */

/*
 * generic_netmap_rxsync() extracts mbufs from the queue filled by
 * generic_netmap_rx_handler() and puts their content in the netmap
 * receive ring.
 * Access must be protected because the rx handler is asynchronous,
 */
static int
generic_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int flags)
{
    struct netmap_adapter *na = NA(ifp);
    struct netmap_kring *kring = &na->rx_rings[ring_nr];
    struct netmap_ring *ring = kring->ring;
    u_int j, n, lim = kring->nkr_num_slots - 1;
    int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
    u_int k, resvd = ring->reserved;

    if (ring->cur > lim)
        return netmap_ring_reinit(kring);

    /* Import newly received packets into the netmap ring. */
    if (netmap_no_pendintr || force_update) {
        uint16_t slot_flags = kring->nkr_slot_flags;
        struct mbuf *m;

        n = 0;
        j = kring->nr_ntc;
        /* The k index in the netmap ring prevents ntc from bumping into hwcur. */
        k = (kring->nr_hwcur) ? kring->nr_hwcur-1 : lim;
        while (j != k) {
            void *addr = NMB(&ring->slot[j]);

            if (addr == netmap_buffer_base) { /* Bad buffer */
                return netmap_ring_reinit(kring);
            }
            m = mbq_safe_dequeue(&kring->rx_queue);
            if (!m)
                break;
            m_copydata(m, 0, m->len, addr);
            ring->slot[j].len = m->len;
            ring->slot[j].flags = slot_flags;
            m_freem(m);
            if (unlikely(j++ == lim))
                j = 0;
            n++;
        }
        if (n) {
            kring->nr_ntc = j;
            kring->nr_hwavail += n;
            IFRATE(rate_ctx.new.rxpkt += n);
        }
        kring->nr_kflags &= ~NKR_PENDINTR;
    }

    /* Skip past packets that userspace has released */
    j = kring->nr_hwcur;
    k = ring->cur;
    if (resvd > 0) {
        if (resvd + ring->avail >= lim + 1) {
            D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
            ring->reserved = resvd = 0; // XXX panic...
        }
        k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
    }
    if (j != k) {
        /* Userspace has released some packets. */
        for (n = 0; j != k; n++) {
            struct netmap_slot *slot = &ring->slot[j];

            slot->flags &= ~NS_BUF_CHANGED;
            if (unlikely(j++ == lim))
                j = 0;
        }
        kring->nr_hwavail -= n;
        kring->nr_hwcur = k;
    }
    /* Tell userspace that there are new packets. */
    ring->avail = kring->nr_hwavail - resvd;
    IFRATE(rate_ctx.new.rxsync++);

    return 0;
}


/*
 * generic_netmap_attach() makes it possible to use netmap on
 * a device without native netmap support.
 * This is less performant than native support but potentially
 * faster than raw sockets or similar schemes.
 *
 * In this "emulated" mode, netmap rings do not necessarily
 * have the same size as those in the NIC. We use a default
 * value and possibly override it if the OS has ways to fetch the
 * actual configuration.
 */
int
generic_netmap_attach(struct ifnet *ifp)
{
    struct netmap_adapter na;
    int retval;
    uint num_tx_desc, num_rx_desc;

    num_tx_desc = num_rx_desc = 256; /* starting point */

    generic_find_num_desc(ifp, &num_tx_desc, &num_rx_desc);
    D("Netmap ring size: TX = %d, RX = %d\n", num_tx_desc, num_rx_desc);

    bzero(&na, sizeof(na));
    na.ifp = ifp;
    na.num_tx_desc = num_tx_desc;
    na.num_rx_desc = num_rx_desc;
    na.nm_register = &generic_netmap_register;
    na.nm_txsync = &generic_netmap_txsync;
    na.nm_rxsync = &generic_netmap_rxsync;
    na.na_flags = NAF_SKIP_INTR;

    ND("[GNA] num_tx_queues(%d), real_num_tx_queues(%d), len(%lu)",
		ifp->num_tx_queues, ifp->real_num_tx_queues,
		ifp->tx_queue_len);
    ND("[GNA] num_rx_queues(%d), real_num_rx_queues(%d)",
		ifp->num_rx_queues, ifp->real_num_rx_queues);

    generic_find_num_queues(ifp, &na.num_tx_rings, &na.num_rx_rings);

    retval = netmap_attach(&na, na.num_rx_rings);
    return retval;
}
