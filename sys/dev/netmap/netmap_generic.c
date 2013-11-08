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

#else /* linux */
#include "bsd_glue.h"
#endif /* linux */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

#ifdef linux
#include <linux/rtnetlink.h>    /* rtnl_[un]lock() */
#include <linux/ethtool.h>      /* struct ethtool_ops, get_ringparam */
#include <linux/hrtimer.h>
#endif /* linux */

/* ====================== STUFF DEFINED in netmap.c ===================== */
int netmap_get_memory(struct netmap_priv_d* p);
void netmap_dtor(void *data);
int netmap_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td);
int netmap_poll(struct cdev *dev, int events, struct thread *td);
int netmap_init(void);
void netmap_fini(void);
extern int netmap_generic_mit;
extern void netmap_adapter_put(struct netmap_adapter *);


/* ===================== GENERIC NETMAP ADAPTER SUPPORT ================== */

#ifdef linux
#define RATE  /* Enables communication statistics. */
#endif

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


#define GENERIC_BUF_SIZE        netmap_buf_size    /* Size of the mbufs in the Tx pool. */

#ifdef linux
rx_handler_result_t generic_netmap_rx_handler(struct mbuf **pm);
enum hrtimer_restart generic_timer_handler(struct hrtimer *t);

static u16 generic_ndo_select_queue(struct ifnet *ifp, struct mbuf *m)
{
    return skb_get_queue_mapping(m);
}
#endif /* linux */

//#define REG_RESET

/* Enable/disable netmap mode for a generic network interface. */
int generic_netmap_register(struct ifnet *ifp, int enable)
{
#ifdef __FreeBSD__
    if (enable) {
	return EINVAL;
    } else {
    }
#else /* linux */

    struct netmap_adapter *na = NA(ifp);
    struct netmap_generic_adapter *gna = (struct netmap_generic_adapter*)na;
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
        /* Initialize the queue structure, since the generic_netmap_rx_handler() callback can
           be called as soon after netdev_rx_handler_register() returns. */
        for (r=0; r<na->num_rx_rings; r++) {
            skb_queue_head_init(&na->rx_rings[r].rx_queue);
            na->rx_rings[r].nr_ntc = 0;
        }
        hrtimer_init(&gna->mit_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        gna->mit_timer.function = &generic_timer_handler;
        gna->mit_pending = 0;
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
                m = alloc_skb(GENERIC_BUF_SIZE, GFP_ATOMIC);
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
        na->if_transmit = (void *)ifp->netdev_ops;
        gna->generic_ndo = *(ifp->netdev_ops);  /* Copy */
        gna->generic_ndo.ndo_select_queue = &generic_ndo_select_queue;  /* Replace a field. */
        ifp->netdev_ops = &gna->generic_ndo;  /* Switch the pointers. */
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
#endif
    } else { /* Disable netmap mode. */
        rtnl_lock();
        ifp->if_capenable &= ~IFCAP_NETMAP;
        ifp->netdev_ops = (void *)na->if_transmit;
        netdev_rx_handler_unregister(ifp);
        for (r=0; r<na->num_rx_rings; r++) {
            skb_queue_purge(&na->rx_rings[r].rx_queue);
        }
        hrtimer_cancel(&gna->mit_timer);
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
/* Invoked when the driver of the attached interface frees a socket buffer used by netmap for
   transmitting a packet. This usually happens when the NIC notifies the driver that the
   transmission is completed. */
static void
generic_mbuf_destructor(struct mbuf *m)
{
    ND("Tx irq (%p)", arg);
    netmap_irq_generic(m->dev, skb_get_queue_mapping(m), NULL, 1);
    IFRATE(rate_ctx.new.txirq++);
}

/* Record completed transmissions and update hwavail/avail. */
static int
generic_netmap_tx_clean(struct netmap_kring *kring)
{
    u_int num_slots = kring->nkr_num_slots;
    u_int ntc = kring->nr_ntc;
    u_int hwcur = kring->nr_hwcur;
    u_int n = 0;

    while (ntc != hwcur && (kring->tx_pool[ntc] == NULL
                || NM_ATOMIC_READ(&kring->tx_pool[ntc]->users) == 1)) {
        if (unlikely(kring->tx_pool[ntc] == NULL)) {
            kring->tx_pool[ntc] = alloc_skb(GENERIC_BUF_SIZE, GFP_ATOMIC);
            if (unlikely(!kring->tx_pool[ntc])) {
                D("mbuf allocation failed");
                return -ENOMEM;
            }
        } else {
            skb_trim(kring->tx_pool[ntc], 0);
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

static inline u_int generic_tx_event_middle(struct netmap_kring *kring, u_int j)
{
    u_int n = kring->nkr_num_slots;
    u_int e = (kring->nr_ntc + ((((n + j) - kring->nr_ntc) % (n)) / 2)) % (n);

    if (unlikely(e >= n)) {
        D("This cannot happen");
        e = 0;
    }

    return e;
}

static int generic_set_tx_event(struct netmap_kring *kring, u_int e)
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

/* The generic txsync method transforms netmap buffers in mbufs and the invokes the
   driver ndo_start_xmit() method. This is not done directly, but using dev_queue_xmit(),
   since it implements the TX flow control (and takes some locks). */
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

    if (!netif_carrier_ok(ifp)) {
        return 0;
    }

    /* Take a copy of ring->cur now, and never read it again. */
    k = ring->cur;
    if (k > lim)
        return netmap_ring_reinit(kring);

    rmb();
    j = kring->nr_hwcur;
    if (j != k) {
        /* Process new packets to send: j is the current index in the netmap ring. */
        while (j != k) {
            struct netmap_slot *slot = &ring->slot[j]; /* Current slot in the netmap ring */
            void *addr = NMB(slot);
            u_int len = slot->len;
            struct mbuf *m;
            netdev_tx_t tx_ret;

            if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
                return netmap_ring_reinit(kring);
            }
            /* Tale a mbuf from the tx pool and copy in the user packet. */
            m = kring->tx_pool[j];
            if (unlikely(!m)) {
                D("This should never happen");
                return netmap_ring_reinit(kring);
            }
            /* TODO Support the slot flags (NS_FRAG, NS_INDIRECT). */
            skb_copy_to_linear_data(m, addr, len); // skb_store_bits(m, 0, addr, len);
            skb_put(m, len);
            NM_ATOMIC_INC(&m->users);
            m->dev = ifp;
            m->priority = 100;
            skb_set_queue_mapping(m, ring_nr);
            tx_ret = dev_queue_xmit(m);
            if (unlikely(tx_ret != NET_XMIT_SUCCESS)) {
                ND("start_xmit failed: err %d [%d,%d,%d]", tx_ret, j, k, kring->nr_hwavail);
                if (likely(tx_ret == NET_XMIT_DROP)) {
                    if (unlikely(generic_set_tx_event(kring,
                                            generic_tx_event_middle(kring, j)) > 0)) {
                        continue;
                    }
                    break;
                }
                D("start_xmit failed: HARD ERROR %d", tx_ret);
                return netmap_ring_reinit(kring);
            }
            slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
            if (unlikely(j++ == lim))
                j = 0;
            n++;
        }

        kring->nr_hwcur = j;
        kring->nr_hwavail -= n;
        IFRATE(rate_ctx.new.txpkt += n);
        if (ring->avail < 1) {
            generic_set_tx_event(kring, generic_tx_event_middle(kring, j));
        }
        ND("tx #%d, hwavail = %d", n, kring->nr_hwavail);
    }

    return 0;
#endif /* linux */
}

#ifdef linux
enum hrtimer_restart generic_timer_handler(struct hrtimer *t)
{
    struct netmap_generic_adapter *gna = container_of(t, struct netmap_generic_adapter, mit_timer);
    struct netmap_adapter *na = &gna->up.up;
    unsigned int work_done;

    if (gna->mit_pending) {
        /* Some work arrived while the timer was counting down: Reset the pending work
           flag, restart the timer and issue a notification. */
        gna->mit_pending = 0;
        netmap_irq_generic(na->ifp, 0, &work_done, 1);
        IFRATE(rate_ctx.new.rxirq++);
        hrtimer_forward_now(&gna->mit_timer, ktime_set(0, netmap_generic_mit));

        return HRTIMER_RESTART;
    }

    /* No pending work? Don't restart the timer. */
    return HRTIMER_NORESTART;
}

/* This handler is registered within the attached net_device in the Linux RX subsystem,
   so that every mbuf passed up by the driver can be stolen to the network stack.
   Stolen packets are put in a queue where the generic_netmap_rxsync() callback can
   extract them. */
rx_handler_result_t generic_netmap_rx_handler(struct mbuf **pm)
{
    struct netmap_adapter *na = NA((*pm)->dev);
    struct netmap_generic_adapter *gna = (struct netmap_generic_adapter*)na;
    unsigned int work_done;
    unsigned int rr = 0;

    if (unlikely(skb_queue_len(&na->rx_rings[rr].rx_queue) > 1024)) {
        m_freem(*pm);
    } else {
        skb_queue_tail(&na->rx_rings[rr].rx_queue, *pm);
    }

    if (netmap_generic_mit < 32768) {
        /* When rx mitigation is not used, never filter the notification. */
        netmap_irq_generic(na->ifp, rr, &work_done, 1);
        IFRATE(rate_ctx.new.rxirq++);
    } else {
        /* Filter the notification when there is a pending timer, otherwise
           start the timer and don't filter. */
        if (likely(hrtimer_active(&gna->mit_timer))) {
            /* Record that there is some pending work. */
            gna->mit_pending = 1;
        } else {
            netmap_irq_generic(na->ifp, rr, &work_done, 1);
            IFRATE(rate_ctx.new.rxirq++);
            hrtimer_start(&gna->mit_timer, ktime_set(0, netmap_generic_mit), HRTIMER_MODE_REL);
        }
    }

    return RX_HANDLER_CONSUMED;
}
#endif /* linux */

/* The generic rxsync() method extracts mbufs from the queue filled by
   generic_netmap_rx_handler() and puts their content in the netmap receive ring. */
static int
generic_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int flags)
{
#ifdef __FreeBSD__
    return 0;
#else /* linux */
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
            m = skb_dequeue(&kring->rx_queue);
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
#endif /* linux */
}

/* Use ethtool to find the current NIC rings lengths, so that the netmap rings can
   have the same lengths. */
static int
generic_find_num_desc(struct ifnet *ifp, unsigned int *tx, unsigned int *rx)
{

#ifdef __FreeBSD__
    D("using default values for %s tx %d rx %d", ifp->if_xname, *tx, *rx);
#else /* linux */
    struct ethtool_ringparam rp;

    if (ifp->ethtool_ops && ifp->ethtool_ops->get_ringparam) {
        ifp->ethtool_ops->get_ringparam(ifp, &rp);
        *tx = rp.tx_pending;
        *rx = rp.rx_pending;
    }
#endif /* linux */

    return 0;
}

static int
generic_netmap_dtor(struct netmap_adapter *na)
{
    struct ifnet *ifp = na->ifp;
    struct netmap_generic_adapter *gna = (struct netmap_generic_adapter*)na;
    struct netmap_adapter *prev_na = gna->prev;

    D("Released generic NA %p", na);
    WNA(ifp) = prev_na;
    netmap_adapter_put(prev_na);
    D("Restored native NA %p", prev_na);
    if_rele(ifp);
    na->ifp = NULL;
    return 1;
}

/* The generic netmap attach method makes it possible to attach netmap to a network
   interface that doesn't have explicit netmap support. The netmap ring size has no
   relationship to the NIC ring size: 256 could be a good default value. However, we
   usually get the best performance when the netmap ring size matches the NIC ring
   size. Since this function cannot be called by the driver, it is called by get_ifp(). */
int
generic_netmap_attach(struct ifnet *ifp)
{
    /* if *na is too large we do not want it on stack */
    struct netmap_adapter *na;
    int retval;
    unsigned int num_tx_desc = 256, num_rx_desc = 256;

    generic_find_num_desc(ifp, &num_tx_desc, &num_rx_desc);
    D("Netmap ring descriptors: TX = %d, RX = %d\n", num_tx_desc, num_rx_desc);

    na = malloc(sizeof(*na), M_DEVBUF, M_NOWAIT | M_ZERO);
    if (na == NULL) {
	D("no memory on attach, give up");
	return ENOMEM;
    }
    bzero(na, sizeof(*na));
    na->ifp = ifp;
    na->num_tx_desc = num_tx_desc;
    na->num_rx_desc = num_rx_desc;
    na->nm_register = &generic_netmap_register;
    na->nm_txsync = &generic_netmap_txsync;
    na->nm_rxsync = &generic_netmap_rxsync;
    na->nm_dtor = &generic_netmap_dtor;

    ND("[GNA] num_tx_queues(%d), real_num_tx_queues(%d), len(%lu)", ifp->num_tx_queues,
                                        ifp->real_num_tx_queues, ifp->tx_queue_len);
    ND("[GNA] num_rx_queues(%d), real_num_rx_queues(%d)", ifp->num_rx_queues,
                                                            ifp->real_num_rx_queues);
#ifdef __FreeBSD__
#else /* linux */
    na->num_tx_rings = ifp->real_num_tx_queues;
#endif /* linux */

    retval = netmap_attach_common(na, 1); // TODO ifp->real_num_rx_queues);
    if (retval) {
        free(na, M_DEVBUF);
        return retval;
    }
    return 0;
}
