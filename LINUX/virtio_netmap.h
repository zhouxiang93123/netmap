#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>


#define SOFTC_T	virtnet_info
static int virtnet_close(struct ifnet *ifp);
static int virtnet_open(struct ifnet *ifp);

/*
 * Register/unregister, similar to e1000_reinit_safe()
 */
static int
virtio_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	/* struct SOFTC_T *vi = netdev_priv(ifp); */
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
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *vi = netdev_priv(ifp);
        struct send_queue *sq = &vi->sq[ring_nr];
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
        struct netmap_adapter *token;
	u_int j, k, l, n, lim = kring->nkr_num_slots - 1;
	int new_slots;

        ND("[A] %d %d %d %d", ring->cur, kring->nr_hwcur,
			      kring->nr_hwavail, kring->nr_hwreserved);

        /* Free used slots. */
        n = 0;
        for (;;) {
                token = virtqueue_get_buf(sq->vq, &l);
                if (token == NULL)
                        break;
                if (token == na)
                        n++;
        }
        kring->nr_hwavail += n;
        ND("[B] %d %d %d %d", ring->cur, kring->nr_hwcur,
			      kring->nr_hwavail, kring->nr_hwreserved);

	/* Take a copy of ring->cur now, and never read it again. */
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
			void *addr = NMB(slot);
                        int err;

			if (unlikely(addr == netmap_buffer_base ||
                                     slot->len > NETMAP_BUF_SIZE))
				return netmap_ring_reinit(kring);

			slot->flags &= ~NS_REPORT;
                        sg_set_buf(sq->sg, addr, slot->len);
                        err = virtqueue_add_outbuf(sq->vq, sq->sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                                D("virtqueue_add_outbuf failed");
                                break;
                        }

			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = j;

		/* The new slots are reported as unavailable. */
		kring->nr_hwavail -= new_slots;

                virtqueue_kick(sq->vq);
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

        ND("[C] %d %d %d %d", ring->cur, kring->nr_hwcur,
			      kring->nr_hwavail, kring->nr_hwreserved);

        return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
virtio_netmap_rxsync(struct netmap_adapter *na, u_int ring_nr, int flags)
{
        struct ifnet *ifp = na->ifp;
	struct SOFTC_T *vi = netdev_priv(ifp);
        struct receive_queue *rq = &vi->rq[ring_nr];
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = (flags & NAF_FORCE_READ) || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;

        ND("[A] %d %d %d %d", ring->cur, ring->reserved, kring->nr_hwcur,
			      kring->nr_hwavail);

	if (k > lim)
		return netmap_ring_reinit(kring);

	rmb();
	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring.
	 */
	if (netmap_no_pendintr || force_update) {
		uint16_t slot_flags = kring->nkr_slot_flags;
                struct netmap_adapter *token;

                j = kring->nr_hwcur + kring->nr_hwavail;
                if (j >= kring->nkr_num_slots)
                        j -= kring->nkr_num_slots;
                n = 0;
		for (;;) {
                        token = virtqueue_get_buf(rq->vq, &l);
                        if (token == NULL)
                                break;
                        if (likely(token == na)) {
                            ring->slot[j].len = l;
                            ring->slot[j].flags = slot_flags;
                            j = (j == lim) ? 0 : j + 1;
                            n++;
                        }
		}
		kring->nr_hwavail += n;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
        ND("[B] %d %d %d %d", ring->cur, ring->reserved, kring->nr_hwcur,
			      kring->nr_hwavail);

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
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			void *addr = NMB(slot);
                        int err;

			if (addr == netmap_buffer_base) /* bad buf */
				return netmap_ring_reinit(kring);

			if (slot->flags & NS_BUF_CHANGED)
				slot->flags &= ~NS_BUF_CHANGED;

                        sg_set_buf(rq->sg, addr, ring->nr_buf_size);
                        err = virtqueue_add_inbuf(rq->vq, rq->sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                            D("virtqueue_add_inbuf failed");
                            return err;
                        }
			j = (j == lim) ? 0 : j + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;

                virtqueue_kick(rq->vq);
	}

	/* Tell userspace that there are new packets. */
	ring->avail = kring->nr_hwavail - resvd;

        ND("[C] %d %d %d %d", ring->cur, ring->reserved, kring->nr_hwcur,
			      kring->nr_hwavail);

	return 0;
}



/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int virtio_netmap_init_buffers(struct SOFTC_T *vi)
{
	struct ifnet *ifp = vi->dev;
	struct netmap_adapter* na = NA(ifp);
	unsigned int r;

	if (!na || !(na->na_flags & NAF_NATIVE_ON)) {
		return 0;
        }
	for (r = 0; r < na->num_rx_rings; r++) {
                struct netmap_ring *ring = na->rx_rings[r].ring;
                struct receive_queue *rq = &vi->rq[r];
	        struct netmap_slot* slot;
                unsigned int i;

		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}

		for (i = 0; rq->vq->num_free && i < na->num_rx_desc; i++) {
                        void *addr;
                        int err;

                        slot = &ring->slot[i];
                        addr = NMB(slot);
                        sg_set_buf(rq->sg, addr, ring->nr_buf_size);
                        err = virtqueue_add_inbuf(rq->vq, rq->sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                            D("virtqueue_add_inbuf failed");

                            return 0;
                        }
		}
	}

	return 1;
}


static void
virtio_netmap_attach(struct SOFTC_T *vi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vi->dev;
	na.num_tx_desc = virtqueue_get_vring_size(vi->sq[0].vq);
	na.num_rx_desc = virtqueue_get_vring_size(vi->rq[0].vq);
	na.nm_register = virtio_netmap_reg;
	na.nm_txsync = virtio_netmap_txsync;
	na.nm_rxsync = virtio_netmap_rxsync;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);

        D("virtio attached txd=%d rxd=%d", na.num_tx_desc, na.num_rx_desc);
}
/* end of file */
