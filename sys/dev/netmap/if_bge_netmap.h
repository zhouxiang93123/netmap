/*-
 * (C) 2011 Luigi Rizzo - Universita` di Pisa
 *
 * BSD copyright
 *
 * $Id$
 *
 * netmap support for if_bge.c
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>

static int bge_netmap_reg(struct ifnet *, int onoff);
static int bge_netmap_txsync(void *, u_int, int);
static int bge_netmap_rxsync(void *, u_int, int);
static void bge_netmap_lock_wrapper(void *, int, u_int);

static int bge_netmap_verbose = 0;

SYSCTL_NODE(_dev, OID_AUTO, bge, CTLFLAG_RW, 0, "bge card");

SYSCTL_INT(_dev_bge, OID_AUTO, verbose,
    CTLFLAG_RW, &bge_netmap_verbose, 0, "Verbose flag");

static void
bge_netmap_attach(struct bge_softc *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->bge_ifp;
	na.separate_locks = 0;
	na.num_tx_desc = BGE_TX_RING_CNT;
	na.num_rx_desc = BGE_STD_RX_RING_CNT;
	na.nm_txsync = bge_netmap_txsync;
	na.nm_rxsync = bge_netmap_rxsync;
	na.nm_lock = bge_netmap_lock_wrapper;
	na.nm_register = bge_netmap_reg;
	na.buff_size = MCLBYTES; // XXX check
	netmap_attach(&na, 1);
}


/*
 * wrapper to export locks to the generic code
 * We should not use the tx/rx locks
 */
static void
bge_netmap_lock_wrapper(void *_a, int what, u_int queueid)
{
	struct bge_softc *adapter = _a;

	switch (what) {
	case NETMAP_CORE_LOCK:
		BGE_LOCK(adapter);
		break;
	case NETMAP_CORE_UNLOCK:
		BGE_UNLOCK(adapter);
		break;

	case NETMAP_TX_LOCK:
	case NETMAP_RX_LOCK:
	case NETMAP_TX_UNLOCK:
	case NETMAP_RX_UNLOCK:
		D("invalid lock call %d, no tx/rx locks here", what);
		break;
	}
}


/*
 * support for netmap register/unregisted. We are already under core lock.
 * only called on the first register or the last unregister.
 */
static int
bge_netmap_reg(struct ifnet *ifp, int onoff)
{
	struct bge_softc *adapter = ifp->if_softc;
	struct netmap_adapter *na = NA(ifp);
	int error = 0;

	if (!na)
		return (EINVAL);	/* not attached */

	/* Tell the stack that the interface is no longer active */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

	bge_stop(adapter);

        if (onoff) {
		ifp->if_capenable |= IFCAP_NETMAP;

		/* save if_transmit and restore it */
		na->if_transmit = ifp->if_transmit;
		/* XXX if_start and if_qflush ??? */
		ifp->if_transmit = netmap_start;

		bge_init_locked(adapter);

		if ((ifp->if_drv_flags & (IFF_DRV_RUNNING | IFF_DRV_OACTIVE)) == 0) {
			error = ENOMEM;
			goto fail;
		}
	} else {
fail:
		/* restore if_transmit */
		ifp->if_transmit = na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
		bge_init_locked(adapter);	/* also enables intr */
	}
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 *
 * Userspace has filled tx slots up to cur (excluded).
 * The last unused slot previously known to the kernel was nr_hwcur,
 * and the last interrupt reported nr_hwavail slots available
 * (using the special value -1 to indicate idle transmit ring).
 * The function must first update avail to what the kernel
 * knows (translating the -1 to nkr_num_slots - 1),
 * subtract the newly used slots (cur - nr_hwcur)
 * from both avail and nr_hwavail, and set nr_hwcur = cur
 * issuing a dmamap_sync on all slots.
 */
static int
bge_netmap_txsync(void *a, u_int ring_nr, int do_lock)
{
	struct bge_softc *sc = a;
	bus_dmamap_t *txmap = sc->bge_cdata.bge_tx_dmamap;
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, k, n, lim = kring->nkr_num_slots - 1;
	uint32_t end;

	k = ring->cur;
	if ( (kring->nr_kflags & NR_REINIT) || k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		BGE_LOCK(sc);

#if 0
	bus_dmamap_sync(sc->bge_cdata.bge_status_tag,
		sc->bge_cdata.bge_status_map,
		BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
#endif
	end = sc->bge_ldata.bge_status_block->bge_idx[0].bge_tx_cons_idx;

	/* Sync the TX descriptor list */
	bus_dmamap_sync(sc->bge_cdata.bge_tx_ring_tag,
		sc->bge_cdata.bge_tx_ring_map, BUS_DMASYNC_POSTWRITE);

	/* record completed transmissions
	 * XXX unclear how the notification is done -- txeof() always
	 * scans all packets reported in bge_tx_cons_idx, even though
	 * the opackets counter is incremented only when the flag is set.
	 */
	n = end - sc->bge_tx_saved_considx;
	if (n < 0)
		n += BGE_TX_RING_CNT;
	if (n > 0) {
		sc->bge_tx_saved_considx = end;
		sc->bge_txcnt -= n;
		kring->nr_hwavail += n;
	}

	/* update avail to what the hardware knows */
	ring->avail = kring->nr_hwavail;
	
	/* we trust prodidx, not hwcur */
	j = kring->nr_hwcur = sc->bge_tx_prodidx;
	if (j != k) {	/* we have new packets to send */
		n = 0;
		while (j != k) {
			struct netmap_slot *slot = &ring->slot[j];
			struct bge_tx_bd *d = &sc->bge_ldata.bge_tx_ring[j];
			void *addr = NMB(slot);
			int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				if (do_lock)
					BGE_UNLOCK(sc);
				return netmap_ring_reinit(kring);
			}
			
			if (slot->flags & NS_BUF_CHANGED) {
				uint64_t paddr = vtophys(addr);
				d->bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
				d->bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
				/* buffer has changed, unload and reload map */
				netmap_reload_map(sc->bge_cdata.bge_tx_mtag,
					txmap[j], addr, na->buff_size);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			slot->flags &= ~NS_REPORT;
			d->bge_len = len;
			d->bge_flags = BGE_TXBDFLAG_END;
			bus_dmamap_sync(sc->bge_cdata.bge_tx_mtag,
				txmap[j], BUS_DMASYNC_PREWRITE);
			j = (j == lim) ? 0 : j + 1;
			n++;
		}
		kring->nr_hwcur = ring->cur;

		/* decrease avail by number of sent packets */
		ring->avail -= n;
		kring->nr_hwavail = ring->avail;

		/* let the start routine to the job */
		bge_start_locked(sc->bge_ifp);
	}
	if (do_lock)
		BGE_UNLOCK(sc);
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 *
 * Userspace has read rx slots up to cur (excluded).
 * The last unread slot previously known to the kernel was nr_hwcur,
 * and the last interrupt reported nr_hwavail slots available.
 * We must subtract the newly consumed slots (cur - nr_hwcur)
 * from nr_hwavail, clearing the descriptors for the next
 * read, tell the hardware that they are available,
 * and set nr_hwcur = cur and avail = nr_hwavail.
 * issuing a dmamap_sync on all slots.
 */
static int
bge_netmap_rxsync(void *a, u_int ring_nr, int do_lock)
{
	struct bge_softc *sc = a;
	struct bge_rx_bd *r = sc->bge_ldata.bge_rx_std_ring;
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, k, n, lim = kring->nkr_num_slots - 1;
	uint32_t end;

	k = ring->cur;
	if ( (kring->nr_kflags & NR_REINIT) || k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		BGE_LOCK(sc);
	/* XXX check sync modes */
        bus_dmamap_sync(sc->bge_cdata.bge_rx_return_ring_tag,
            sc->bge_cdata.bge_rx_return_ring_map, BUS_DMASYNC_POSTREAD);
        bus_dmamap_sync(sc->bge_cdata.bge_rx_std_ring_tag,
            sc->bge_cdata.bge_rx_std_ring_map, BUS_DMASYNC_POSTWRITE);

	j = sc->bge_rx_saved_considx;
	end = sc->bge_ldata.bge_status_block->bge_idx[0].bge_rx_prod_idx;
	for (n = 0; j != end; n++) {
		struct bge_rx_bd *cur_rx;
		uint32_t rxidx, len;

		cur_rx = &sc->bge_ldata.bge_rx_return_ring[j];
		rxidx = cur_rx->bge_idx;
		len = cur_rx->bge_len - ETHER_CRC_LEN;
		kring->ring->slot[j].len = len;
		/*  sync was in bge_newbuf() */
		bus_dmamap_sync(sc->bge_cdata.bge_rx_mtag,
			sc->bge_cdata.bge_rx_std_dmamap[j],
		    	BUS_DMASYNC_POSTREAD);
		j = j == lim ? 0 : j + 1;
	}
	if (n > 0) {
		sc->bge_rx_saved_considx = end;
		sc->bge_ifp->if_ipackets += n;
		kring->nr_hwavail += n;
	}

	/* skip past packets that userspace has already processed,
	 * making them available for reception.
	 * advance nr_hwcur and issue a bus_dmamap_sync on the
	 * buffers so it is safe to write to them.
	 * Also increase nr_hwavail
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* userspace has read some packets. */
		n = 0;
		while (j != k) {
			struct netmap_slot *slot = ring->slot + j;
			void *addr = NMB(slot);
			uint64_t paddr = vtophys(addr);

			if (addr == netmap_buffer_base) { /* bad buf */
				if (do_lock)
					BGE_UNLOCK(sc);
				return netmap_ring_reinit(kring);
			}

			slot->flags &= ~NS_REPORT;
			r[j].bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
			r[j].bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
			if (slot->flags & NS_BUF_CHANGED) {
				netmap_reload_map(sc->bge_cdata.bge_rx_mtag,
					sc->bge_cdata.bge_rx_std_dmamap[j],
					addr, na->buff_size);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			r[j].bge_flags = BGE_RXBDFLAG_END;
			r[j].bge_len = na->buff_size;
			r[j].bge_idx = j;
			bus_dmamap_sync(sc->bge_cdata.bge_rx_mtag,
				sc->bge_cdata.bge_rx_std_dmamap[j],
				BUS_DMASYNC_PREREAD);
			j = (j == lim) ? 0 : j + 1;
			n++;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		/* Flush the RX DMA ring */

		bus_dmamap_sync(sc->bge_cdata.bge_rx_return_ring_tag,
		    sc->bge_cdata.bge_rx_return_ring_map, BUS_DMASYNC_PREREAD);
		bus_dmamap_sync(sc->bge_cdata.bge_rx_std_ring_tag,
		    sc->bge_cdata.bge_rx_std_ring_map, BUS_DMASYNC_PREWRITE);

	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail ;
	if (do_lock)
		BGE_UNLOCK(sc);
	return 0;
}

static void
bge_netmap_tx_init(struct bge_softc *sc)
{   
	struct bge_tx_bd *d = sc->bge_ldata.bge_tx_ring;
	int i;
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_slot *slot = netmap_reset(na, NR_TX, 0, 0);

	/* slot is NULL if we are not in netmap mode */
	if (!slot)
		return;
	/* in netmap mode, overwrite addresses and maps */

	for (i = 0; i < BGE_TX_RING_CNT; i++) {
		void *addr = NMB(slot+i);
		uint64_t paddr = vtophys(addr);

		d[i].bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
		d[i].bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
		netmap_load_map(sc->bge_cdata.bge_tx_mtag,
			sc->bge_cdata.bge_tx_dmamap[i],
			addr, na->buff_size);
	}
}

static void
bge_netmap_rx_init(struct bge_softc *sc)
{
	/* slot is NULL if we are not in netmap mode */  
	struct netmap_adapter *na = NA(sc->bge_ifp);
	struct netmap_slot *slot = netmap_reset(na, NR_RX, 0, 0);
	struct bge_rx_bd *r = sc->bge_ldata.bge_rx_std_ring;
	int i;

	if (!slot)
		return;

	for (i = 0; i < BGE_STD_RX_RING_CNT; i++) {
		void *addr = NMB(slot+i);
		uint64_t paddr = vtophys(addr);

		r[i].bge_addr.bge_addr_lo = BGE_ADDR_LO(paddr);
		r[i].bge_addr.bge_addr_hi = BGE_ADDR_HI(paddr);
		r[i].bge_flags = BGE_RXBDFLAG_END;
		r[i].bge_len = na->buff_size;
		r[i].bge_idx = i;

		netmap_reload_map(sc->bge_cdata.bge_rx_mtag,
			sc->bge_cdata.bge_rx_std_dmamap[i],
			addr, na->buff_size);
	}
}
