/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
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
 * $FreeBSD: head/sys/dev/netmap/if_lem_netmap.h 231881 2012-02-17 14:09:04Z luigi $
 *
 * netmap support for "lem"
 *
 * For details on netmap support please see ixgbe_netmap.h
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>


/*
 * Register/unregister
 */
static int
lem_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	int error = 0;

	EM_CORE_LOCK(adapter);

	lem_disable_intr(adapter);

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

#ifndef EM_LEGACY_IRQ // XXX do we need this ?
	taskqueue_block(adapter->tq);
	taskqueue_drain(adapter->tq, &adapter->rxtx_task);
	taskqueue_drain(adapter->tq, &adapter->link_task);
#endif /* !EM_LEGCY_IRQ */
	if (onoff) {
		nm_set_native_flags(na);
		lem_init_locked(adapter);
		if ((ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) == 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		nm_clear_native_flags(na);
		lem_init_locked(adapter);	/* also enable intr */
	}

#ifndef EM_LEGACY_IRQ
	taskqueue_unblock(adapter->tq); // XXX do we need this ?
#endif /* !EM_LEGCY_IRQ */

	EM_CORE_UNLOCK(adapter);

	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
lem_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int nm_i;
	u_int nic_i;
	u_int n;
	u_int const cur = ring->cur;
	u_int const lim = kring->nkr_num_slots - 1;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	if (cur > lim)
		return netmap_ring_reinit(kring);

	bus_dmamap_sync(adapter->txdma.dma_tag, adapter->txdma.dma_map,
			BUS_DMASYNC_POSTREAD);

	nm_i = kring->nr_hwcur;
	if (nm_i != cur) {	/* we have new packets to send */
		nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != cur; n++) {
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			struct e1000_tx_desc *curr = &adapter->tx_desc_base[nic_i];
			struct em_buffer *txbuf = &adapter->tx_buffer_area[nic_i];
			int flags = (slot->flags & NS_REPORT ||
				nic_i == 0 || nic_i == report_frequency) ?
					E1000_TXD_CMD_RS : 0;

			NM_CHECK_ADDR_LEN(addr, len);

			slot->flags &= ~NS_REPORT;
			if (1 || slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(adapter->txtag, txbuf->map, addr);
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->upper.data = 0;
			curr->lower.data =
			    htole32( adapter->txd_cmd | len |
				(E1000_TXD_CMD_EOP | flags) );

			bus_dmamap_sync(adapter->txtag, txbuf->map,
			    BUS_DMASYNC_PREWRITE);
			nm_i = nm_next(nm_i, lim);
			nic_i = nm_next(nic_i, lim);
		}
		ND("sent %d packets from %d, TDT now %d", n, kring->nr_hwcur, l);
		kring->nr_hwcur = cur; /* the saved ring->cur */
		kring->nr_hwavail -= n;

		bus_dmamap_sync(adapter->txdma.dma_tag, adapter->txdma.dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		E1000_WRITE_REG(&adapter->hw, E1000_TDT(0), nic_i);
	}

	if (flags & NAF_FORCE_RECLAIM || kring->nr_hwavail < 1) {
		int delta;

		/* record completed transmissions using TDH */
		nic_i = E1000_READ_REG(&adapter->hw, E1000_TDH(0));
		ND("tdh is now %d", l);
		if (nic_i >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("bad TDH %d", nic_i);
			nic_i -= kring->nkr_num_slots;
		}
		delta = nic_i - adapter->next_tx_to_clean;
		if (delta) {
			/* some tx completed, increment hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			if (netmap_verbose > 255)
				RD(5, "%s tx recover %d bufs",
					ifp->if_xname, delta);
			adapter->next_tx_to_clean = nic_i;
			kring->nr_hwavail += delta;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
lem_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
	struct ifnet *ifp = na->ifp;
	struct adapter *adapter = ifp->if_softc;
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	if (k > lim)
		return netmap_ring_reinit(kring);


	/* XXX check sync modes */
	bus_dmamap_sync(adapter->rxdma.dma_tag, adapter->rxdma.dma_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = adapter->next_rx_desc_to_check;
	j = netmap_idx_n2k(kring, l);
	ND("%s: next NIC %d kring %d (ofs %d), hwcur %d hwavail %d cur %d avail %d",
		ifp->if_xname,
		l, j,  kring->nkr_hwofs, kring->nr_hwcur, kring->nr_hwavail,
		ring->cur, ring->avail);
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = &adapter->rx_desc_base[l];
			uint32_t staterr = le32toh(curr->status);
			int len;

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			len = le16toh(curr->length) - 4; // CRC
			if (len < 0) {
				D("bogus pkt size at %d", j);
				len = 0;
			}
			ND("\n%s", nm_dump_buf(NMB(&ring->slot[j]),
				len, 128, NULL));
			ring->slot[j].len = len;
			ring->slot[j].flags = slot_flags;
			bus_dmamap_sync(adapter->rxtag,
				adapter->rx_buffer_area[l].map,
				    BUS_DMASYNC_POSTREAD);
			j = nm_next(j, lim);
			l = nm_next(l, lim);
		}
		if (n) { /* update the state variables */
			adapter->next_rx_desc_to_check = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur;	/* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) { /* userspace has released some packets. */
		l = netmap_idx_k2n(kring, j); /* NIC ring index */
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			struct e1000_rx_desc *curr = &adapter->rx_desc_base[l];
			struct em_buffer *rxbuf = &adapter->rx_buffer_area[l];
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(adapter->rxtag, rxbuf->map, addr);
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->status = 0;

			bus_dmamap_sync(adapter->rxtag, rxbuf->map,
			    BUS_DMASYNC_PREREAD);

			j = nm_next(j, lim);
			l = nm_next(l, lim);
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		bus_dmamap_sync(adapter->rxdma.dma_tag, adapter->rxdma.dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		l = (l == 0) ? lim : l - 1;
		E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), l);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;
	return 0;
}


static void
lem_netmap_attach(struct adapter *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->ifp;
	na.na_flags = NAF_BDG_MAYSLEEP;
	na.num_tx_desc = adapter->num_tx_desc;
	na.num_rx_desc = adapter->num_rx_desc;
	na.nm_txsync = lem_netmap_txsync;
	na.nm_rxsync = lem_netmap_rxsync;
	na.nm_register = lem_netmap_reg;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}

/* end of file */
