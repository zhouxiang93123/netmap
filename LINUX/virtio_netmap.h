#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>


#define SOFTC_T	virtnet_info

/*
 * Register/unregister, similar to e1000_reinit_safe()
 */
static int
virtio_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *vi = netdev_priv(ifp);
	struct netmap_hw_adapter *hwna = (struct netmap_hw_adapter*)na;
	int error = 0;

	if (na == NULL)
		return EINVAL;

	rtnl_lock();

        virtnet_close(ifp);

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &hwna->nm_ndo;
	} else {
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		ifp->netdev_ops = (void *)na->if_transmit;
	}

        virtnet_open(ifp);

	rtnl_unlock();

	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
virtio_netmap_txsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        D("Called");
#if 0
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_tx_ring* txr = &adapter->tx_ring[ring_nr];
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;
	int new_slots;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	/* take a copy of ring->cur now, and never read it again */
	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	new_slots = k - j - kring->nr_hwreserved;
	if (new_slots < 0)
		new_slots += kring->nkr_num_slots;
	if (new_slots > kring->nr_hwavail) {
		RD(5, "=== j %d k %d d %d hwavail %d hwreserved %d",
			j, k, new_slots, kring->nr_hwavail, kring->nr_hwreserved);
		return netmap_ring_reinit(kring);
	}
	if (!netif_carrier_ok(ifp)) {
		/* All the new slots are now unavailable. */
		kring->nr_hwavail -= new_slots;
		goto out;
	}
	if (j != k) {	/* we have new packets to send */
		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			/* curr is the current slot in the nic ring */
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, l);
			int flags = ((slot->flags & NS_REPORT) ||
				j == 0 || j == report_frequency) ?
					E1000_TXD_CMD_RS : 0;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			u_int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				return netmap_ring_reinit(kring);
			}

			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, paddr);
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->upper.data = 0;
			curr->lower.data = htole32(adapter->txd_cmd | len |
					(E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | flags) );
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		/* hwcur becomes the saved ring->cur */
		kring->nr_hwcur = k;
		/* The new slots have been sent and so reported as
		 * unavailable. Note that if the previous loop sent
		 * previously reserved slots (as well as new slots),
		 * we have n > new_slots.
		 */
		kring->nr_hwavail -= new_slots;

		wmb(); /* synchronize writes to the NIC ring */

		txr->next_to_use = l;
		writel(l, adapter->hw.hw_addr + txr->tdt);
		mmiowb(); // XXX where do we need this ?
	}

	if (n == 0 || kring->nr_hwavail < 1) {
		int delta;

		/* record completed transmissions using TDH */
		l = readl(adapter->hw.hw_addr + txr->tdh);
		if (l >= kring->nkr_num_slots) { /* XXX can happen */
			D("TDH wrap %d", l);
			l -= kring->nkr_num_slots;
		}
		delta = l - txr->next_to_clean;
		if (delta) {
			/* some tx completed, increment hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			txr->next_to_clean = l;
			kring->nr_hwavail += delta;
		}
	}
out:
	/* recompute hwreserved */
	kring->nr_hwreserved = k - j;
	if (kring->nr_hwreserved < 0) {
		kring->nr_hwreserved += kring->nkr_num_slots;
	}

	/* update avail and reserved to what the kernel knows */
	ring->avail = kring->nr_hwavail;
	ring->reserved = kring->nr_hwreserved;

        return 0;
#endif
	return netmap_ring_reinit(&na->tx_rings[ring_nr]);
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
virtio_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
#if 0
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_rx_ring *rxr = &adapter->rx_ring[ring_nr];
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = rxr->next_to_clean;
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;

		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, l);
			uint32_t staterr = le32toh(curr->status);

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			ring->slot[j].len = le16toh(curr->length) - 4;
			ring->slot[j].flags = slot_flags;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur; /* netmap ring index */
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
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, l);
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				return netmap_ring_reinit(kring);
			}
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(...)
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->status = 0;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		wmb();
		rxr->next_to_use = l; // XXX not really used
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		l = (l == 0) ? lim : l - 1;
		writel(l, adapter->hw.hw_addr + rxr->rdt);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;

	return 0;
#endif
	return netmap_ring_reinit(&na->rx_rings[ring_nr]);
}



/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int virtio_netmap_init_buffers(struct SOFTC_T *adapter)
{
        return 0;
#if 0
	struct e1000_hw *hw = &adapter->hw;
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct e1000_tx_ring* txr = &adapter->tx_ring[0];
	unsigned int i, r, si;
	uint64_t paddr;

	if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
		return 0;
        }
	adapter->alloc_rx_buf = e1000_no_rx_alloc;
	for (r = 0; r < na->num_rx_rings; r++) {
		struct e1000_rx_ring *rxr;
		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}
		rxr = &adapter->rx_ring[r];

		for (i = 0; i < rxr->count; i++) {
			// XXX the skb check and cleanup can go away
			struct e1000_buffer *bi = &rxr->buffer_info[i];
			si = netmap_idx_n2k(&na->rx_rings[r], i);
			PNMB(slot + si, &paddr);
			if (bi->skb)
				D("rx buf %d was set", i);
			bi->skb = NULL;
			// netmap_load_map(...)
			E1000_RX_DESC(*rxr, i)->buffer_addr = htole64(paddr);
		}

		rxr->next_to_use = 0;
		/* preserve buffers already made available to clients */
		i = rxr->count - 1 - na->rx_rings[0].nr_hwavail;
		if (i < 0)
		i += rxr->count;
		D("i now is %d", i);
		wmb(); /* Force memory writes to complete */
		writel(i, hw->hw_addr + rxr->rdt);
	}
	/* now initialize the tx ring(s) */
	slot = netmap_reset(na, NR_TX, 0, 0);
	for (i = 0; i < na->num_tx_desc; i++) {
		si = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(slot + si, &paddr);
		// netmap_load_map(...)
		E1000_TX_DESC(*txr, i)->buffer_addr = htole64(paddr);
	}
	return 1;
#endif
}


static void
virtio_netmap_attach(struct SOFTC_T *vi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vi->netdev;
	na.num_tx_desc = 256;
	na.num_rx_desc = 256;
	na.nm_register = virtio_netmap_reg;
	na.nm_txsync = virtio_netmap_txsync;
	na.nm_rxsync = virtio_netmap_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);
}
/* end of file */
