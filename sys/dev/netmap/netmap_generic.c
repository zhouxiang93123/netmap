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

/*
 * mbuf wrappers
 */
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
	/* XXX not sure we should set the len now */
	m->m_len = m->m_pkthdr.len = len;
	return m;
}

#define GET_MBUF_REFCNT(m)	(*(m)->m_ext.ref_cnt)

/* mbuf destructor, also need to change the type to EXT_EXTREF
 * and then chain into uma_zfree(zone_clust, m->m_ext.ext_buf)
 * (or reinstall the buffer ?)
 */

#define	destructor		m_ext.ext_free

#else /* linux */

#include "bsd_glue.h"

#include <linux/rtnetlink.h>    /* rtnl_[un]lock() */
#include <linux/ethtool.h>      /* struct ethtool_ops, get_ringparam */
#include <linux/hrtimer.h>

#define RATE  /* Enables communication statistics. */

//#define REG_RESET

#endif /* linux */


/* Common headers. */
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
 * We cannot use netmap_rx_irq because the generic adapter has
 * NAF_SKIP_INTR set. We might call directly netmap_common_irq()
 * (but need to check this XXX)
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

/*
 * second argument is non-zero to intercept, 0 to restore
 */
static int
netmap_catch_rx(struct netmap_adapter *na, int intercept)
{
	struct ifnet *ifp = na->ifp;

#ifdef __FreeBSD__
	if (intercept) {
		if (na->save_if_input) {
			D("cannot intercept again");
			return EINVAL; /* already set */
		}
		na->save_if_input = ifp->if_input;
		ifp->if_input = generic_netmap_rx_handler;
	} else {
		if (!na->save_if_input){
			D("cannot restore");
			return EINVAL;  /* not saved */
		}
		ifp->if_input = na->save_if_input;
		na->save_if_input = NULL;
	}
#else /* linux */
	if (intercept) {
		return netdev_rx_handler_register(na->ifp,
			&generic_netmap_rx_handler, na);
	} else {
		netdev_rx_handler_unregister(ifp);
		return 0;
	}
#endif /* linux */
}

/*
 * The generic driver calls netmap once per packet.
 * This is inefficient so we implement a mitigation mechanism,
 * as follows:
 * - the first packet on an idle receiver triggers a notification
 *   and starts a timer;
 * - subsequent incoming packets do not cause a notification
 *   until the timer expires;
 * - when the timer expires and there are pending packets,
 *   a notification is sent up and the timer is restarted.
 */
enum hrtimer_restart
generic_timer_handler(struct hrtimer *t)
{
    struct netmap_adapter *na = container_of(t, struct netmap_adapter, mit_timer);
    uint work_done;

    if (!na->mit_pending) {
        return HRTIMER_NORESTART;
    }

    /* Some work arrived while the timer was counting down:
     * Reset the pending work flag, restart the timer and send
     * a notification.
     */
    na->mit_pending = 0;
    netmap_generic_irq(na->ifp, 0, &work_done);
    IFRATE(rate_ctx.new.rxirq++);
    netmap_mitigation_restart(na);

    return HRTIMER_RESTART;
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

        /* Init the mitigation timer. */
        netmap_mitigation_init(na);

	/*
	 * Preallocate packet buffers for the tx rings.
	 */
        for (r=0; r<na->num_tx_rings; r++) {
            na->tx_rings[r].nr_ntc = 0;
            na->tx_rings[r].tx_pool = malloc(na->num_tx_desc * sizeof(struct mbuf *),
				    M_DEVBUF, M_NOWAIT | M_ZERO);
            if (!na->tx_rings[r].tx_pool) {
                D("tx_pool allocation failed");
                error = ENOMEM;
                goto free_tx_pool;
            }
            for (i=0; i<na->num_tx_desc; i++) {
                m = netmap_get_mbuf(GENERIC_BUF_SIZE);
                if (!m) {
                    D("tx_pool[%d] allocation failed", i);
                    error = ENOMEM;
                    goto free_mbufs;
                }
                na->tx_rings[r].tx_pool[i] = m;
            }
        }
        rtnl_lock();
	/* Prepare to intercept incoming traffic. */
        error = netmap_catch_rx(na, 1);
        if (error) {
            D("netdev_rx_handler_register() failed");
            goto register_handler;
        }
        ifp->if_capenable |= IFCAP_NETMAP;
#ifdef linux
	/*
	 * Save the old pointer to the netdev_op
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
        rtnl_unlock();

#ifdef RATE
        if (rate_ctx.refcount == 0) {
            D("setup_timer()");
            memset(&rate_ctx, 0, sizeof(rate_ctx));
            setup_timer(&rate_ctx.timer, &rate_callback, (unsigned long)&rate_ctx);
            if (mod_timer(&rate_ctx.timer, jiffies + msecs_to_jiffies(1500))) {
                D("Error: mod_timer()");
            }
        }
        rate_ctx.refcount++;
#endif /* RATE */

    } else { /* Disable netmap mode. */
        rtnl_lock();

        ifp->if_capenable &= ~IFCAP_NETMAP;
	/* Restore the netdev_ops. */
        ifp->netdev_ops = (void *)na->if_transmit;

	/* Do not intercept packets on the rx path. */
        netmap_catch_rx(na, 0);

        rtnl_unlock();

	/* Free the mbufs going to the netmap rings */
        for (r=0; r<na->num_rx_rings; r++) {
            mbq_safe_purge(&na->rx_rings[r].rx_queue);
            mbq_safe_destroy(&na->rx_rings[r].rx_queue);
        }

        netmap_mitigation_cleanup(na);

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

#ifdef REG_RESET
    error = ifp->netdev_ops->ndo_open(ifp);
    if (error) {
        goto alloc_tx_pool;
    }
#endif

    return 0;

register_handler:
    rtnl_unlock();
free_tx_pool:
    r--;
    i = na->num_tx_desc;  /* Useless, but just to stay safe. */
free_mbufs:
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
 * nr_ntc is the oldest tx buffer not yet completed
 * (same as nr_hwavail + nr_hwcur + 1),
 * nr_hwcur is the first unsent buffer.
 * When cleaning, we try to recover buffers between nr_ntc and nr_hwcur.
 */
static int
generic_netmap_tx_clean(struct netmap_kring *kring)
{
    u_int num_slots = kring->nkr_num_slots;
    u_int ntc = kring->nr_ntc;
    u_int hwcur = kring->nr_hwcur;
    u_int n = 0;
    struct mbuf **tx_pool = kring->tx_pool;

    while (ntc != hwcur) { /* buffers not completed */
	struct mbuf *m = tx_pool[ntc];

        if (unlikely(m == NULL)) {
	    /* try to replenish the entry */
            tx_pool[ntc] = m = netmap_get_mbuf(GENERIC_BUF_SIZE);
            if (unlikely(m == NULL)) {
                D("mbuf allocation failed, XXX error");
		// XXX how do we proceed ? break ?
                return -ENOMEM;
            }
	} else if (GET_MBUF_REFCNT(m) != 1) {
	    break; /* This mbuf is still busy: its refcnt is 2. */
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
 * We have pending packets in the driver between nr_ntc and j.
 * Compute a position in the middle, to be used to generate
 * a notification.
 */
static inline u_int
generic_tx_event_middle(struct netmap_kring *kring, u_int j)
{
    u_int n = kring->nkr_num_slots;
    u_int e = (kring->nr_ntc + ((((n + j) - kring->nr_ntc) % (n)) / 2)) % (n);
#if 0
    if (j >= ntc)
	return (j+ntc)/2
    else {
	x = (j + ntc +n)/2;
	if (x >= n) x -= n;
	return x;
    }
#endif

    if (unlikely(e >= n)) {
        D("This cannot happen");
        e = 0;
    }

    return e;
}

/*
 * We have pending packets in the driver between nr_ntc and j.
 * Schedule a notification approximately in the middle of the two.
 * There is a race but this is only called within txsync which does
 * a double check.
 */
static void
generic_set_tx_event(struct netmap_kring *kring, u_int j)
{
    struct mbuf *m;
    u_int e = generic_tx_event_middle(kring, j);

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
    struct netmap_adapter *na = NA(ifp);
    struct netmap_kring *kring = &na->tx_rings[ring_nr];
    struct netmap_ring *ring = kring->ring;
    u_int j, k, n = 0, lim = kring->nkr_num_slots - 1;

    IFRATE(rate_ctx.new.txsync++);

    // TODO: handle the case of mbuf allocation failure
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
                 * No room in the device driver. Request a notification,
                 * then call generic_netmap_tx_clean(kring) to do the
                 * double check and see if we can free more buffers.
                 * If there is space continue, else break;
                 * XXX the double check is necessary if the problem
                 * occurs in the txsync call after selrecord().
                 * Also, we need some way to tell the caller that not
                 * all buffers were queued onto the device (this was
                 * not a problem with native netmap driver where space
                 * is preallocated). The bridge has a similar problem
                 * and we solve it there by dropping the excess packets.
                 */
                generic_set_tx_event(kring, j);
                if (generic_netmap_tx_clean(kring)) { /* space now available */
                    continue;
                } else {
                    break;
                }
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
            generic_set_tx_event(kring, j);
        }
        ND("tx #%d, hwavail = %d", n, kring->nr_hwavail);
    }

    return 0;
}

#ifdef linux

/*
 * This handler is registered within the attached net_device
 * in the Linux RX subsystem, so that every mbuf passed up by
 * the driver can be stolen to the network stack.
 * Stolen packets are put in a queue where the
 * generic_netmap_rxsync() callback can extract them.
 *
 * The FreeBSD equivalent is ether_input(m->m_pkthdr.rcvif, m)
 */
rx_handler_result_t generic_netmap_rx_handler(struct mbuf **pm)
{
    struct netmap_adapter *na = NA((*pm)->dev);
    uint work_done;
    uint rr = 0;

    /* limit the size of the queue */
    if (unlikely(mbq_len(&na->rx_rings[rr].rx_queue) > 1024)) {
        m_freem(*pm);
    } else {
        mbq_safe_enqueue(&na->rx_rings[rr].rx_queue, *pm);
    }

    if (netmap_generic_mit < 32768) {
        /* no rx mitigation, pass notification up */
        netmap_generic_irq(na->ifp, rr, &work_done);
        IFRATE(rate_ctx.new.rxirq++);
    } else {
	/* same as send combining, filter notification if there is a
	 * pending timer, otherwise pass it up and start a timer.
         */
        if (likely(netmap_mitigation_active(na))) {
            /* Record that there is some pending work. */
            na->mit_pending = 1;
        } else {
            netmap_generic_irq(na->ifp, rr, &work_done);
            IFRATE(rate_ctx.new.rxirq++);
            netmap_mitigation_start(na);
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
    /* when using generic, IFCAP_NETMAP is set so we force
     * NAF_SKIP_INTR to use the regular interrupt handler
     */
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
