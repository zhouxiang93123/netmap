#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>


#define SOFTC_T	virtnet_info

static int virtnet_close(struct ifnet *ifp);
static int virtnet_open(struct ifnet *ifp);
static void free_receive_bufs(struct virtnet_info *vi);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)

static void give_pages(struct SOFTC_T *vi, struct page *page);
static struct page *get_a_page(struct SOFTC_T *vi, gfp_t gfp_mask);
#define GIVE_PAGES(_vi, _i, _buf)	give_pages(_vi, _buf)
#define DECR_NUM(_vi, _i)		--(_vi)->num
#define GET_RX_VQ(_vi, _i)		(_vi)->rvq
#define GET_RX_SG(_vi, _i)		(_vi)->rx_sg
#define GET_TX_VQ(_vi, _i)		(_vi)->svq
#define GET_TX_SG(_vi, _i)		(_vi)->tx_sg
#define VQ_FULL(_vq, _err)		(_err > 0)

static void free_receive_bufs(struct SOFTC_T *vi)
{
	while (vi->pages)
		__free_pages(get_a_page(vi, GFP_KERNEL), 0);
}

#else   /* >= 3.8.0 */

static void give_pages(struct receive_queue *rq, struct page *page);
static struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask);
#define GIVE_PAGES(_vi, _i, _buf)	give_pages(&(_vi)->rq[_i], _buf)
#define DECR_NUM(_vi, _i)		--(_vi)->rq[_i].num
#define GET_RX_VQ(_vi, _i)		(_vi)->rq[_i].vq
#define GET_RX_SG(_vi, _i)		(_vi)->rq[_i].sg
#define GET_TX_VQ(_vi, _i)		(_vi)->sq[_i].vq
#define GET_TX_SG(_vi, _i)		(_vi)->sq[_i].sg
#define VQ_FULL(_vq, _err)		((_vq)->num_free == 0)

#endif  /* >= 3.8.0 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)

#define virtqueue_add_inbuf(_vq, _sg, _num, _tok, _gfp)	\
		virtqueue_add_buf(_vq, _sg, 0, _num, _tok, _gfp)
#define virtqueue_add_outbuf(_vq, _sg, _num, _tok, _gfp) \
		virtqueue_add_buf(_vq, _sg, _num, 0, _tok, _gfp)

#endif  /* 3.10.0 */


static void virtio_netmap_free_rx_unused_bufs(struct SOFTC_T* vi, int onoff)
{
	void *buf;
	int i, c;

	for (i = 0; i < vi->dev->num_rx_queues; i++) {
		struct virtqueue *vq = GET_RX_VQ(vi, i);

		c = 0;
		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL) {
			if (onoff) {
				if (vi->mergeable_rx_bufs || vi->big_packets)
					GIVE_PAGES(vi, i, buf);
				else
					dev_kfree_skb(buf);
			}
			DECR_NUM(vi, i);
			c++;
		}
		D("[%d] freed %d rx unused bufs on queue %d", onoff, c, i);
	}
}

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

        /* It's important to deny the registration if the interface is
           not up, otherwise the virtnet_close() is not matched by a
           virtnet_open(), and so a napi_disable() is not matched by
           a napi_enable(), which results in a deadlock. */
        if (!netif_running(ifp))
                return EBUSY;

	rtnl_lock();

        virtnet_close(ifp);

	if (onoff) {
		virtio_netmap_free_rx_unused_bufs(vi, onoff);
		free_receive_bufs(vi);

		/* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
                na->na_flags |= NAF_NATIVE_ON;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &hwna->nm_ndo;
	} else {
		ifp->if_capenable &= ~IFCAP_NETMAP;
                na->na_flags &= ~NAF_NATIVE_ON;
		ifp->netdev_ops = (void *)na->if_transmit;

		virtio_netmap_free_rx_unused_bufs(vi, onoff);
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
	struct virtqueue *vq = GET_TX_VQ(vi, ring_nr);
	struct scatterlist *sg = GET_TX_SG(vi, ring_nr);
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
                token = virtqueue_get_buf(vq, &l);
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
                        sg_set_buf(sg, addr, slot->len);
                        err = virtqueue_add_outbuf(vq, sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                                D("virtqueue_add_outbuf failed");
                                break;
                        }
			virtqueue_kick(vq);

			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = j;

		/* The new slots are reported as unavailable. */
		kring->nr_hwavail -= new_slots;

		if (kring->nr_hwavail == 0)
			virtqueue_enable_cb_delayed(vq);
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
	struct virtqueue *vq = GET_RX_VQ(vi, ring_nr);
	struct scatterlist *sg = GET_RX_SG(vi, ring_nr);
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
                        token = virtqueue_get_buf(vq, &l);
                        if (token == NULL)
                                break;
                        if (likely(token == na)) {
                            ring->slot[j].len = l;
                            ring->slot[j].flags = slot_flags;
                            j = (j == lim) ? 0 : j + 1;
                            n++;
                        } else {
                            struct netmap_slot *slot = &ring->slot[kring->nr_ntc];
                            void *addr = NMB(slot);
                            int err;

                            if (kring->nr_ntc < lim) {
                                sg_set_buf(sg, addr, ring->nr_buf_size);
                                err = virtqueue_add_inbuf(vq, sg, 1, na, GFP_ATOMIC);
                                if (err < 0) {
                                    D("virtqueue_add_inbuf failed");
                                    return err;
                                }
                                virtqueue_kick(vq);
                                kring->nr_ntc = (kring->nr_ntc == lim) ? 0 : kring->nr_ntc + 1;
                            }
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

                        sg_set_buf(sg, addr, ring->nr_buf_size);
                        err = virtqueue_add_inbuf(vq, sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                            D("virtqueue_add_inbuf failed");
                            return err;
                        }
                        virtqueue_kick(vq);
			j = (j == lim) ? 0 : j + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
	}

        virtqueue_enable_cb(vq);

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
		struct virtqueue *vq = GET_RX_VQ(vi, r);
		struct scatterlist *sg = GET_RX_SG(vi, r);
	        struct netmap_slot* slot;
                unsigned int i;
		int err = 0;

		slot = netmap_reset(na, NR_RX, r, 0);
		if (!slot) {
			D("strange, null netmap ring %d", r);
			return 0;
		}

		for (i = 0; i < na->num_rx_desc-1; i++) {
                        void *addr;

                        slot = &ring->slot[i];
                        addr = NMB(slot);
                        sg_set_buf(sg, addr, ring->nr_buf_size);
                        err = virtqueue_add_inbuf(vq, sg, 1, na, GFP_ATOMIC);
                        if (err < 0) {
                            D("virtqueue_add_inbuf failed");

                            return 0;
                        }
			if (VQ_FULL(vq, err))
				break;
		}
		D("added %d inbufs on queue %d", i, r);
	}

	return 1;
}

static int
virtio_netmap_config(struct netmap_adapter *na, u_int *txr, u_int *txd,
						u_int *rxr, u_int *rxd)
{
	struct ifnet *ifp = na->ifp;
	struct SOFTC_T *vi = netdev_priv(ifp);

	*txr = ifp->real_num_tx_queues;
	*txd = virtqueue_get_vring_size(GET_TX_VQ(vi, 0));
	*rxr = 1;
	*rxd = virtqueue_get_vring_size(GET_RX_VQ(vi, 0));
        D("virtio config txq=%d, txd=%d rxq=%d, rxd=%d",
					*txr, *txd, *rxr, *rxd);

	return 0;
}

static void
virtio_netmap_attach(struct SOFTC_T *vi)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = vi->dev;
	na.num_tx_desc = virtqueue_get_vring_size(GET_TX_VQ(vi, 0));
	na.num_rx_desc = virtqueue_get_vring_size(GET_RX_VQ(vi, 0));
	na.nm_register = virtio_netmap_reg;
	na.nm_txsync = virtio_netmap_txsync;
	na.nm_rxsync = virtio_netmap_rxsync;
	na.nm_config = virtio_netmap_config;
	na.num_tx_rings = na.num_rx_rings = 1;
	netmap_attach(&na);

        D("virtio attached txq=%d, txd=%d rxq=%d, rxd=%d",
			na.num_tx_rings, na.num_tx_desc,
			na.num_tx_rings, na.num_rx_desc);
}
/* end of file */
