/* TX */
#ifndef NMT_TX_INIT
static void __inline nmt_tx_init(nmt_txstate *s) {}
#endif
/* send new frames */
#ifndef NMT_TX_SLOTINIT
static void __inline nmt_tx_slotinit(nmt_txstate *s) {}
#endif
#ifndef NMT_TX_BUFCHANGED
static void __inline nmt_tx_bufchanged(nmt_txstate *s) {}
#endif
#ifndef NMT_TX_FILLSLOT
static void __inline nmt_tx_fillslot(nmt_txstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_TX_RINGUPDATE
static void __inline nmt_tx_ringupdate(nmt_txstate *s) {}
#endif
#ifndef NMT_TX_NICUPDATE
static void __inline nmt_tx_nicupdate(nmt_txstate *s) {}
#endif
/* reclaim completed slots */
#ifdef NMT_TXOPT_USENTC
#ifndef NMT_TX_REQREPORT
static int __inline nmt_tx_reqreport(nmt_txstate *s) { return 1; }
#endif
#ifndef NMT_TX_GETHWNTC
static u_int __inline nmt_tx_gethwntc(nmt_txstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_TX_GETSWNTC
static u_int __inline nmt_tx_getswntc(nmt_txstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_TX_SETSWNTC
static u_int __inline nmt_tx_getswntc(nmt_txstate *s) { <- /* NEEDED */ }
#endif
#else /* !NMT_TXOPT_USENTC */
#ifndef NMT_TX_STARTRECLM
static void __inline nmt_rx_startreclm(nmt_rxstate *s) {}
#endif
#ifndef NMT_TX_GETSLOT
static int __inline nmt_tx_getslot(nmt_rxstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_TX_UPDATESENT
static void __inline nmt_tx_updatesent(nmt_rxstate *s) {}
#endif
#endif /* NMT_TXOPT_USENTC */


/* RX */
#ifndef NMT_RX_INIT
static void __inline nmt_rx_init(nmt_rxstate *s) {}
#endif
/* process received frames */
#ifndef NMT_RX_GETSLOT
static int __inline nmt_rx_getslot(nmt_rxstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_RX_GETLEN
static u_int __inline nmt_rx_getlen(nmt_rxstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_RX_UPDATERECV
static void __inline nmt_rx_updaterecv(nmt_rxstate *s) {}
#endif

/* reclaim used slots */
#ifndef NMT_RX_SLOTINIT
static void __inline nmt_rx_slotinit(nmt_rxstate *s) {}
#endif
#ifndef NMT_RX_BUFCHANGED
static void __inline nmt_rx_bufchanged(nmt_rxstate *s) {}
#endif
#ifndef NMT_RX_FILLSLOT
static void __inline nmt_rx_fillslot(nmt_rxstate *s) { <- /* NEEDED */ }
#endif
#ifndef NMT_RX_RINGUPDATE
static void __inline nmt_rx_ringupdate(nmt_rxstate *s) {}
#endif
#ifndef NMT_RX_RINGUPDATE
static void __inline nmt_rx_nicupdate(nmt_rxstate *s) {}
#endif


/*
 * Reconcile kernel and user view of the transmit ring.
 * This routine might be called frequently so it must be efficient.
 *
 * Userspace has filled tx slots up to ring->cur (excluded).
 * The last unused slot previously known to the kernel was kring->nkr_hwcur,
 * and the last interrupt reported kring->nr_hwavail slots available.
 *
 * This function runs under lock (acquired from the caller or internally).
 * It must first update ring->avail to what the kernel knows,
 * subtract the newly used slots (ring->cur - kring->nkr_hwcur)
 * from both avail and nr_hwavail, and set ring->nkr_hwcur = ring->cur
 * issuing a dmamap_sync on all slots.
 *
 * Since ring comes from userspace, its content must be read only once,
 * and validated before being used to update the kernel's structures.
 * (this is also true for every use of ring in the kernel).
 *
 * ring->avail is never used, only checked for bogus values.
 *
 */


static int
nmt_callback(txsync)(struct ifnet *ifp, u_int ring_nr, int flags)
{
	nmt_txstate state, *s = &state;

	s->ifp = ifp;
	s->ring_nr = ring_nr;
	s->flags = flags;
	s->adapter = netdev_priv(s->ifp);
	s->na = NA(s->ifp);
	s->kring = &s->na->tx_rings[s->ring_nr];
	s->ring = s->kring->ring;
	s->k = s->ring->cur;
	s->lim = s->kring->nkr_num_slots - 1;


	if (!netif_carrier_ok(s->ifp))
		return 0;

	/* if cur is invalid reinitialize the ring. */
	if (s->k > s->lim)
		return netmap_ring_reinit(s->kring);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 * The two numbers differ because upon a *_init() we reset
	 * the NIC ring but leave the netmap ring unchanged.
	 * For the transmit ring, we have
	 *
	 *		j = kring->nr_hwcur
	 *		l = IXGBE_TDT (not tracked in the driver)
	 * and
	 * 		j == (l + kring->nkr_hwofs) % ring_size
	 *
	 * In this driver kring->nkr_hwofs >= 0, but for other
	 * drivers it might be negative as well.
	 */
	nmt_tx_init(s);

	s->j = s->kring->nr_hwcur;
	if (s->j != s->k) {	/* we have new packets to send */
		s->l = netmap_idx_k2n(s->kring, s->j);
		for (s->n = 0; s->j != s->k; s->n++) {
			/*
			 * Collect per-slot info.
			 * Note that txbuf and curr are indexed by l.
			 */
			s->slot = &s->ring->slot[s->j];
			s->addr = PNMB(s->slot, &s->paddr);
			s->len = s->slot->len;

			nmt_tx_slotinit(s);

			/*
			 * Quick check for valid addr and len.
			 * NMB() returns netmap_buffer_base for invalid
			 * buffer indexes (but the address is still a
			 * valid one to be used in a ring). slot->len is
			 * unsigned so no need to check for negative values.
			 */
			if (s->addr == netmap_buffer_base || s->len > NETMAP_BUF_SIZE) {
ring_reset:
				return netmap_ring_reinit(s->kring);
			}

			s->slot->flags &= ~NS_REPORT;
			if (s->slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				nmt_tx_bufchanged(s);
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
				s->slot->flags &= ~NS_BUF_CHANGED;
			}
			/*
			 * Fill the slot in the NIC ring.
			 */
			nmt_tx_fillslot(s);

			s->j = (s->j == s->lim) ? 0 : s->j + 1;
			s->l = (s->l == s->lim) ? 0 : s->l + 1;
		}
		s->kring->nr_hwcur = s->k; /* the saved ring->cur */
		/* decrease avail by number of packets  sent */
		s->kring->nr_hwavail -= s->n;

		nmt_tx_ringupdate(s);

		wmb();	/* synchronize writes to the NIC ring */
		/* (re)start the transmitter up to slot l (excluded) */
		nmt_tx_nicupdate(s);
	}

	/*
	 * Reclaim buffers for completed transmissions.
	 * Because this is expensive (we read a NIC register etc.)
	 * we only do it in specific cases (see below).
	 * In all cases kring->nr_kflags indicates which slot will be
	 * checked upon a tx interrupt (nkr_num_slots means none).
	 */
	if (s->flags & NAF_FORCE_RECLAIM) {
		s->j = 1; /* forced reclaim, ignore interrupts */
		s->kring->nr_kflags = s->kring->nkr_num_slots;
	} else if (s->kring->nr_hwavail > 0) {
		s->j = 0; /* buffers still available: no reclaim, ignore intr. */
		s->kring->nr_kflags = s->kring->nkr_num_slots;
	} else {
		/*
		 * no buffers available, locate a slot for which we request
		 * ReportStatus (approximately half ring after next_to_clean)
		 * and record it in kring->nr_kflags.
		 * If the slot has DD set, do the reclaim looking at TDH,
		 * otherwise we go to sleep (in netmap_poll()) and will be
		 * woken up when slot nr_kflags will be ready.
		 */
		s->j = nmt_tx_reqreport(s);
	}
	if (s->j) {
		/*
		 * Record completed transmissions.
		 */
#ifdef NMT_TXOPT_USENTC
		s->l = nmt_tx_gethwntc(s);
		if (s->l >= s->kring->nkr_num_slots) { /* XXX can happen */
			D("TDH wrap %d", s->l);
			s->l -= s->kring->nkr_num_slots;
		}
		s->delta = s->l - nmt_tx_getswntc(s);
		if (s->delta) {
			/* some tx completed, increment hwavail. */
			if (s->delta < 0)
				s->delta += s->kring->nkr_num_slots;
			nmt_tx_setswntc(s);
			s->kring->nr_hwavail += s->delta;
			if (s->kring->nr_hwavail > s->lim)
				goto ring_reset;
		}
#else /* !NMT_TXOPT_USENTC */
		s->l = nmt_tx_startreclm(s);
		for (n = 0; ; n++) {

			if (nmt_tx_getslot(s))
				break;
			
			s->l = (s->l == s->lim) ? 0 : s->l + 1;
		}
		if (n > 0) {
			nmt_tx_updatesent(s);
			s->kring->nr_hwavail += n;
		}
#endif /* NMT_TXOPT_USENT */
	}
	/* update avail to what the kernel knows */
	s->ring->avail = s->kring->nr_hwavail;

	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 * Same as for the txsync, this routine must be efficient and
 * avoid races in accessing the shared regions.
 *
 * When called, userspace has read data from slots kring->nr_hwcur
 * up to ring->cur (excluded).
 *
 * The last interrupt reported kring->nr_hwavail slots available
 * after kring->nr_hwcur.
 * We must subtract the newly consumed slots (cur - nr_hwcur)
 * from nr_hwavail, make the descriptors available for the next reads,
 * and set kring->nr_hwcur = ring->cur and ring->avail = kring->nr_hwavail.
 *
 */
static int
nmt_callback(rxsync)(struct ifnet *ifp, u_int ring_nr, int flags)
{
	struct nmt_rxstate state, *s = &state;

	s->ifp = ifp;
	s->ring_nr = ring_nr;
	s->flags = flags;
	s->adapter = netdev_priv(s->ifp);
	s->na = NA(s->ifp);
	s->kring = &s->na->rx_rings[s->ring_nr];
	s->ring = s->kring->ring;
	s->lim = s->kring->nkr_num_slots - 1;
	s->force_update = (s->flags & NAF_FORCE_READ) || s->kring->nr_kflags & NKR_PENDINTR;
	s->k = s->ring->cur, s->resvd = s->ring->reserved;


	if (!netif_carrier_ok(s->ifp))
		return 0;

	if (s->k > s->lim) /* userspace is cheating */
		return netmap_ring_reinit(s->kring);

	rmb();
	/*
	 * First part, import newly received packets into the netmap ring.
	 *
	 * j is the index of the next free slot in the netmap ring,
	 * and l is the index of the next received packet in the NIC ring,
	 * and they may differ in case if_init() has been called while
	 * in netmap mode. For the receive ring we have
	 *
	 *	j = (kring->nr_hwcur + kring->nr_hwavail) % ring_size
	 *	l = rxr->next_to_check;
	 * and
	 *	j == (l + kring->nkr_hwofs) % ring_size
	 *
	 * rxr->next_to_check is set to 0 on a ring reinit
	 */
	nmt_rx_init(s);

	s->j = netmap_idx_n2k(s->kring, s->l);

	if (netmap_no_pendintr || s->force_update) {
		s->slot_flags = s->kring->nkr_slot_flags;

		for (s->n = 0; ; s->n++) {

			if (nmt_rx_getslot(s))
				break;

			s->ring->slot[s->j].len = nmt_rx_getlen(s);

			s->ring->slot[s->j].flags = s->slot_flags;
			s->j = (s->j == s->lim) ? 0 : s->j + 1;
			s->l = (s->l == s->lim) ? 0 : s->l + 1;
		}
		if (s->n) { /* update the state variables */
			nmt_rx_updaterecv(s);

			s->kring->nr_hwavail += s->n;
		}
		s->kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Skip past packets that userspace has already released
	 * (from kring->nr_hwcur to ring->cur-ring->reserved excluded),
	 * and make the buffers available for reception.
	 * As usual j is the index in the netmap ring, l is the index
	 * in the NIC ring, and j == (l + kring->nkr_hwofs) % ring_size
	 */
	s->j = s->kring->nr_hwcur; /* netmap ring index */
	if (s->resvd > 0) {
		if (s->resvd + s->ring->avail >= s->lim + 1) {
			D("XXX invalid reserve/avail %d %d", s->resvd, s->ring->avail);
			s->ring->reserved = s->resvd = 0; // XXX panic...
		}
		s->k = (s->k >= s->resvd) ? s->k - s->resvd : s->k + s->lim + 1 - s->resvd;
	}
	if (s->j != s->k) { /* userspace has released some packets. */
		s->l = netmap_idx_k2n(s->kring, s->j);
		for (s->n = 0; s->j != s->k; s->n++) {
			/* collect per-slot info, with similar validations
			 * and flag handling as in the txsync code.
			 *
			 * NOTE curr and rxbuf are indexed by l.
			 */
			s->slot = &s->ring->slot[s->j];
			//union ixgbe_adv_rx_desc *curr = IXGBE_RX_DESC_ADV(rxr, l);
			s->addr = PNMB(s->slot, &s->paddr);
			nmt_rx_slotinit(s);

			if (s->addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			if (s->slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
				s->slot->flags &= ~NS_BUF_CHANGED;
				nmt_rx_bufchanged(s);
			}
			nmt_rx_fillslot(s);

			s->j = (s->j == s->lim) ? 0 : s->j + 1;
			s->l = (s->l == s->lim) ? 0 : s->l + 1;
		}
		s->kring->nr_hwavail -= s->n;
		s->kring->nr_hwcur = s->k;

		nmt_rx_ringupdate(s);

		wmb();
		/* IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		s->l = (s->l == 0) ? s->lim : s->l - 1;

		nmt_rx_nicupdate(s);
	}
	/* tell userspace that there are new packets */
	s->ring->avail = s->kring->nr_hwavail - s->resvd;

	return 0;

ring_reset:
	return netmap_ring_reinit(s->kring);
}

