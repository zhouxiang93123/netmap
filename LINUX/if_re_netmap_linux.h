/*
 * Copyright (C) 2011 Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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
 * $Id: if_re_netmap_linux.h 10679 2012-02-28 13:42:18Z luigi $
 *
 * netmap support for: r8169 (re, linux version)
 * For details on netmap support please see ixgbe_netmap.h
 * 1 tx ring, 1 rx ring, 1 lock, crcstrip ? reinit tx addr,
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>


static void rtl8169_wait_for_quiescence(struct ifnet *);
#define SOFTC_T	rtl8169_private


/*
 * Register/unregister, mostly the reinit task
 */
static int
re_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	int error = 0;

	rtnl_lock();
	rtl8169_wait_for_quiescence(ifp);
	rtl8169_close(ifp);

	/* enable or disable flags and callbacks in na and ifp */
	if (onoff) {
		nm_set_native_flags(na);

		if (rtl8169_open(ifp) < 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		nm_clear_native_flags(na);
		error = rtl8169_open(ifp) ? EINVAL : 0;
	}
	rtnl_unlock();
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
re_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
	struct ifnet *ifp = na->ifp;
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n, new_slots;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const cur = nm_txsync_prologue(kring, &new_slots);

	/* device-specific */
	struct SOFTC_T *sc = netdev_priv(ifp);
	void __iomem *ioaddr = sc->mmio_addr;

	if (cur > lim)	/* error checking in nm_txsync_prologue() */
		return netmap_ring_reinit(kring);

	rmb();

	/*
	 * First part: process new packets to send.
	 */
	if (!netif_carrier_ok(ifp)) {
		kring->nr_hwavail -= new_slots;
		goto out;
	}

	nm_i = kring->nr_hwcur;
	if (nm_i != cur) {	/* we have new packets to send */
		nic_i = sc->cur_tx; // XXX use internal macro ?
		for (n = 0; nm_i != cur; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			/* device specific */
			struct TxDesc *curr = &sc->TxDescArray[nic_i];
			uint32_t flags = slot->len | LastFrag | DescOwn | FirstFrag ;

			NM_CHECK_ADDR_LEN(addr, len);

			if (nic_i == lim)	/* mark end of ring */
				flags |= RingEnd;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
			}
			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			curr->opts1 = htole32(flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwcur = cur; /* the saved ring->cur */
		/* decrease avail by # of packets sent minus previous ones */
		kring->nr_hwavail -= new_slots;

		sc->cur_tx = nic_i;
		wmb(); /* synchronize writes to the NIC ring */
		RTL_W8(TxPoll, NPQ);	/* start ? */
	}

	/*
	 * Second part: reclaim buffers for completed transmissions.
	 */
	if (flags & NAF_FORCE_RECLAIM || kring->nr_hwavail < 1) {
		for (n = 0, nic_i = sc->dirty_tx; nic_i != sc->cur_tx; n++) {
			if (le32toh(sc->TxDescArray[nic_i].opts1) & DescOwn)
				break;
			if (++nic_i == NUM_TX_DESC)
				nic_i = 0;
		}
		if (n > 0) {
			sc->dirty_tx = nic_i;
			kring->nr_hwavail += n;
		}
	}
out:
	nm_txsync_finalize(kring, cur);
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
re_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *sc = netdev_priv(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;	/* index into the netmap ring */
	u_int nic_i;	/* index into the NIC ring */
	u_int n, resvd;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const cur = nm_rxsync_prologue(kring, &resvd); /* cur + res */
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;

	if (!netif_carrier_ok(ifp))
		return 0;

	if (cur > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * First part: import newly received packets.
	 *
	 * NOTE: This device uses all the buffers in the ring, so we
	 * need another termination condition in addition to DescOwn
	 * cleared (all buffers could have it cleared. The easiest one
	 * is to limit the amount of data reported up to 'lim'
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		nic_i = sc->cur_rx; /* next pkt to check */
		nm_i = netmap_idx_n2k(kring, nic_i);

		for (n = kring->nr_hwavail; n < lim ; n++) {
			struct RxDesc *cur_rx = &sc->RxDescArray[nic_i];
			uint32_t rxstat = le32toh(cur_rx->opts1);
			uint32_t total_len;

			if ((rxstat & DescOwn) != 0)
				break;
			total_len = rxstat & 0x00001FFF;
			/* XXX subtract crc */
			total_len = (total_len < 4) ? 0 : total_len - 4;
			ring->slot[nm_i].len = total_len;
			ring->slot[nm_i].flags = slot_flags;
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		if (n != kring->nr_hwavail) {
			sc->cur_rx = nic_i;
			ifp->stats.rx_packets += n - kring->nr_hwavail;
			kring->nr_hwavail = n;
		}
	}

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur;
	if (nm_i != cur) {
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != cur; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			struct RxDesc *curr = &sc->RxDescArray[nic_i];
			uint32_t flags = NETMAP_BUF_SIZE | DescOwn;

			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			if (nic_i == lim)	/* mark end of ring */
				flags |= RingEnd;

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr);
				curr->addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->opts1 = htole32(flags);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = cur;
		wmb(); // XXX needed ?
	}

	/* tell userspace that there might be new packets */
	ring->avail = kring->nr_hwavail - resvd;
	return 0;

ring_reset:
	return netmap_ring_reinit(kring);
}


/*
 * Additional routines to init the tx and rx rings.
 * In other drivers we do that inline in the main code.
 */
static int
re_netmap_tx_init(struct SOFTC_T *sc)
{
	struct netmap_adapter *na = NA(sc->dev);
	struct netmap_slot *slot;
	struct TxDesc *desc = sc->TxDescArray;
	int i, l;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_TX, 0, 0);
	/* slot is NULL if we are not in netmap mode XXX cannot happen */
	if (!slot)
		return 0;

	/* l points in the netmap ring, i points in the NIC ring */
	for (i = 0; i < na->num_tx_desc; i++) {
		l = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(slot + l, &paddr);
		desc[i].addr = htole64(paddr);
	}
	return 1;
}


static int
re_netmap_rx_init(struct SOFTC_T *sc)
{
	struct netmap_adapter *na = NA(sc->dev);
	struct netmap_slot *slot;
	struct RxDesc *desc = sc->RxDescArray;
	uint32_t cmdstat;
	int i, lim, l;
	uint64_t paddr;

        if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
            return 0;
        }

        slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;  /* XXX cannot happen */
	/*
	 * userspace knows that hwavail packets were ready before
	 * the reset, so only indexes < lim are made available for rx.
	 * XXX we use all slots, so no '-1' here
	 */
	lim = na->num_rx_desc /* - 1 */ - na->rx_rings[0].nr_hwavail;
	for (i = 0; i < na->num_rx_desc; i++) {
		l = netmap_idx_n2k(&na->rx_rings[0], i);
		PNMB(slot + l, &paddr);
		cmdstat = NETMAP_BUF_SIZE;
		if (i == na->num_rx_desc - 1)
			cmdstat |= RingEnd;
		if (i < lim)
			cmdstat |= DescOwn;
		desc[i].opts1 = htole32(cmdstat);
		desc[i].addr = htole64(paddr);
	}
	return 1;
}


static void
re_netmap_attach(struct SOFTC_T *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->dev;
	na.num_tx_desc = NUM_TX_DESC;
	na.num_rx_desc = NUM_RX_DESC;
	na.nm_txsync = re_netmap_txsync;
	na.nm_rxsync = re_netmap_rxsync;
	na.nm_register = re_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
