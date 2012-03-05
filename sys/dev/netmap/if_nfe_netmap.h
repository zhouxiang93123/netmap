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
 * $FreeBSD: head/sys/dev/netmap/if_em_netmap.h 231881 2012-02-17 14:09:04Z luigi $
 * $Id: if_nfe_netmap.h 10669 2012-02-27 18:55:05Z luigi $
 *
 * netmap support for nfe.
 *
 * For more details on netmap support please see ixgbe_netmap.h
 */


#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>


static void
nfe_netmap_lock_wrapper(struct ifnet *ifp, int what, u_int queueid)
{
	struct adapter *adapter = ifp->if_softc;

	ASSERT(queueid < adapter->num_queues);
	switch (what) {
	case NETMAP_CORE_LOCK:
		NFE_LOCK(adapter);
		break;
	case NETMAP_CORE_UNLOCK:
		NFE_UNLOCK(adapter);
		break;
	}
}


/*
 * Register/unregister routine
 */
static int
nfe_netmap_reg(struct ifnet *ifp, int onoff)
{
	struct nfe_softc *sc = ifp->if_softc;
	struct netmap_adapter *na = NA(ifp);

	if (na == NULL)
		return EINVAL;	/* no netmap support here */

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	if (onoff) {
		ifp->if_capenable |= IFCAP_NETMAP;

		na->if_transmit = ifp->if_transmit;
		ifp->if_transmit = netmap_start;

		nfe_init_locked(sc);
	} else {
		/* return to non-netmap mode */
		ifp->if_transmit = na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
		nfe_init_locked(sc);	/* also enable intr */
	}
	return (0);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
nfe_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct adapter *nfe_softc = ifp->if_softc;
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		NFE_LOCK(txr);
	bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
			BUS_DMASYNC_POSTREAD);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		struct nfe_desc32 *desc32 = NULL;
		struct nfe_desc64 *desc64 = NULL;

		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			u_int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				if (do_lock)
					NFE_UNLOCK(txr);
				return netmap_ring_reinit(kring);
			}
			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->txq.tx_data_tag,
				    sc->txq.data[l].tx_data_map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
			    desc64 = &sc->txq.desc64[l];
			    desc64->physaddr[0] = htole32(NFE_ADDR_HI(paddr));
			    desc64->physaddr[1] = htole32(NFE_ADDR_LO(paddr));
			    desc64->vtag = 0;
			    desc64->length = htole16(len - 1);
			    desc64->flags = htole16(0);
			} else {
			    desc32 = &sc->txq.desc32[l];
			    desc32->physaddr = htole32(NFE_ADDR_LO(paddr));
			    desc32->length = htole16(len - 1);
			    desc32->flags = htole16(0);
			}

			bus_dmamap_sync(sc->txq.tx_data_tag,
			    sc->txq.data[l].tx_data_map, BUS_DMASYNC_PREWRITE);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		kring->nr_hwavail -= n;
		l = (l == lim) ? 0 : l + 1;
		sc->txq_cur = l; /* the next ? */

		bus_dmamap_sync(sc->txq.tx_desc_tag, sc->txq.tx_desc_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		NFE_WRITE(sc, NFE_RXTX_CTL, NFE_RXTX_KICKTX | sc->rxtxctl);
	}

	if (n == 0 || kring->nr_hwavail < 1) {
		l = sc->txq.next;
		k = sc->txq.cur;
		for (n = 0; l != k; n++, NFE_INC(l, NFE_TX_RING_COUNT)) {
			uint16_t flags;
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
				desc64 = &sc->txq.desc64[l];
				flags = le16toh(desc64->flags);
			} else {
				desc32 = &sc->txq.desc32[l];
				flags = le16toh(desc32->flags);
			}
			if (flags & NFE_TX_VALID)
				break;
		}
		if (n > 0) {
			sc->txq.next = l;
			kring->nr_hwavail += n;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	if (do_lock)
		NFE_UNLOCK(txr);
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
nfe_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct nfe_softc *sc = ifp->if_softc;
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = do_lock || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);
 
	if (do_lock)
		NFE_LOCK(sc);

	/* XXX check sync modes */
	bus_dmamap_sync(sc->rxq.rx_desc_tag, sc->rxq.rx_desc_map,
			BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = sc->rxq.cur;
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		struct nfe_desc32 *desc32;
		struct nfe_desc64 *desc64;
		struct nfe_rx_data *data;
		uint16_t flags;

		for (n = 0; ; n++) {
			data = &sc->rxq.data[l];
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
			    desc64 = &sc->rxq.desc64[sc->rxq.cur];
			    flags = le16toh(desc64->flags);
			    len = le16toh(desc64->length) & NFE_RX_LEN_MASK;
			} else {
			    desc32 = &sc->rxq.desc32[sc->rxq.cur];
			    flags = le16toh(desc32->flags);
			    len = le16toh(desc32->length) & NFE_RX_LEN_MASK;
			}

			if (flags & NFE_RX_READY)
				break;

			ring->slot[j].len = len;
			bus_dmamap_sync(rxr->rxtag, rxr->rx_buffers[l].map,
				BUS_DMASYNC_POSTREAD);
			j = (j == lim) ? 0 : j + 1;
			/* make sure next_to_refresh follows next_to_check */
			rxr->next_to_refresh = l;	// XXX
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
			sc->rxq.cur = l;
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
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				if (do_lock)
					NFE_UNLOCK(rxr);
				return netmap_ring_reinit(kring);
			}

			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, reload map */
				netmap_reload_map(sc->rxq.rx_data_tag,
				    &sc->rxq.data[l].rx_data_map, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			if (sc->nfe_flags & NFE_40BIT_ADDR) {
				desc64 = &sc->rxq.desc64[l];
				desc64->physaddr[0] =
				    htole32(NFE_ADDR_HI(paddr));
				desc64->physaddr[1] =
				    htole32(NFE_ADDR_LO(paddr));
				desc64->length = htole16(NETMAP_BUF_SIZE);
				desc64->flags = htole16(NFE_RX_READY);
			} else {
				desc32 = &sc->rxq.desc32[l];
				desc32->physaddr =
				    htole32(NFE_ADDR_LO(paddr));
				desc32->length = htole16(NETMAP_BUF_SIZE);
				desc32->flags = htole16(NFE_RX_READY);
			}

			bus_dmamap_sync(rxr->rxtag, rxbuf->map,
			    BUS_DMASYNC_PREREAD);
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;
	if (do_lock)
		NFE_UNLOCK(rxr);
	return 0;
}


static void
nfe_netmap_attach(struct adapter *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->ifp;
	na.separate_locks = 0;
	na.num_tx_desc = NFE_TX_RING_COUNT;
	na.num_rx_desc = NFE_RX_RING_COUNT;
	na.nm_txsync = nfe_netmap_txsync;
	na.nm_rxsync = nfe_netmap_rxsync;
	na.nm_lock = nfe_netmap_lock_wrapper;
	na.nm_register = nfe_netmap_reg;
	netmap_attach(&na, 1);
}

/* end of file */
