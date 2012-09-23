/*
 * Copyright (C) 2012 Luigi Rizzo. All rights reserved.
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
 * $Id: mlx4_netmap_linux.h $
 *
 * netmap support for mlx4 (LINUX version)
 *
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#define SOFTC_T	mlx4_en_priv

/*
 * This driver is split in multiple small files.
 * The main device descriptor has type struct mlx4_en_priv *priv;
 * and we attach to the device in mlx4_en_init_netdev()
 * (do port numbers start from 1 ?)
 *
 * The reconfig routine is in mlx4_en_start_port() (also here)
 * which is called on a mlx4_en_restart() (watchdog), open and set-mtu.
 *
 *      priv->num_frags                         ??
 *      DS_SIZE                                 ??
 *              apparently each rx desc is followed by frag.descriptors
 *              and the rx desc is rounded up to a power of 2.
 *
 *   Receive code is in en_rx.c
 *      priv->rx_ring_num                       number of rx rings
 *      rxr = prov->rx_ring[ring_ind]           rx ring descriptor
 *      rxr->size                               number of slots
 *      rxr->prod                               producer
 *         probably written into a mmio reg at *rxr->wqres.db.db
 *         trimmed to 16 bits.
 *
 *      Rx init routine:
 *              mlx4_en_activate_rx_rings()
 *                mlx4_en_init_rx_desc()
 *   Transmit code is in en_tx.c
 */

int mlx4_netmap_config(struct SOFTC_T *);

#ifdef NETMAP_MLX4_MAIN
#warning --------------- compiling main code ----------------
static inline void
nm_pkt_dump(int i, char *buf, int len)
{
    uint8_t *s = buf+6, *d = buf;
    ND(10, "%d len %4d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
		i,
		len,
		s[0], s[1], s[2], s[3], s[4], s[5],
		d[0], d[1], d[2], d[3], d[4], d[5]);
}


/*
 * Register/unregister. We are already under (netmap) core lock.
 * Only called on the first register or the last unregister.
 */
static int
mlx4_netmap_reg(struct ifnet *ifp, int onoff)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct netmap_adapter *na = NA(ifp);
	int error = 0, need_load = 0;

	if (na == NULL)
		return EINVAL;	/* no netmap support here */
	/*
	 * On enable, flush pending ops, set flag and reinit rings.
	 * On disable, flush again, and restart the interface.
	 */
	D("setting netmap mode for %s to %s", ifp->if_xname, onoff ? "ON" : "OFF");
	rtnl_lock(); // ???
	if (netif_running(ifp)) {
		D("unloading the nic");
		// mlx4_nic_unload(adapter, UNLOAD_NORMAL);
		need_load = 1;
	}

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
		/* save if_transmit and replace with our routine */
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &na->nm_ndo;
		D("-------------- set the SKIP_INTR flag");
		// XXX na->na_flags |= NAF_SKIP_INTR; /* during load, use regular interrupts */
	} else { /* reset normal mode */
		ifp->netdev_ops = (void *)na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
	}
	if (need_load) {
		D("loading the NIC");
		// mlx4_nic_load(adapter, LOAD_NORMAL);
	}
	rtnl_unlock();
	return (error);
}


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
 * do_lock is set iff the function is called from the ioctl handler.
 * In this case, grab a lock around the body, and also reclaim transmitted
 * buffers irrespective of interrupt mitigation.
 */
static int
mlx4_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
#if 0
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct bnx2x_fastpath *fp = &adapter->fp[ring_nr];
	struct bnx2x_fp_txdata *txdata = &fp->txdata[0];
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k = ring->cur, n, lim = kring->nkr_num_slots - 1;
	uint16_t l;
	int error = 0;

	/* if cur is invalid reinitialize the ring. */
	if (k > lim)
		return netmap_ring_reinit(kring);
	if (do_lock)
		mtx_lock(&na->core_lock); // XXX exp
		// mtx_lock(&kring->q_lock);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding bd_prod index (uint16_t).
	 * XXX for the NIC ring index we must use TX_BD(l)
	 */
	j = kring->nr_hwcur;
	if (j > lim) {
		D("q %d nwcur overflow %d", j);
		error = EINVAL;
		goto err;
	}
	if (j != k) {	/* we have new packets to send */
		if (txdata->tx_desc_ring == NULL) {
			D("------------------- bad! tx_desc_ring not set");
			error = EINVAL;
			goto err;
		}
		l = txdata->tx_bd_prod;
		ND(10,"=======>========== send from %d to %d at bd %d", j, k, l);
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			struct eth_tx_start_bd *bd =
				&txdata->tx_desc_ring[TX_BD(l)].start_bd;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			uint16_t len = slot->len;
			uint16_t mac_type = UNICAST_ADDRESS;

			// nm_pkt_dump(j, addr, len);
			ND(5, "start_bd j %d l %d is %p", j, l, bd);
			/*
			 * Quick check for valid addr and len.
			 * PNMB() returns netmap_buffer_base for invalid
			 * buffer indexes (but the address is still a
			 * valid one to be used in a ring). slot->len is
			 * unsigned so no need to check for negative values.
			 */
			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				D("ring %d error, resetting", ring_nr);
				error = EINVAL;
				goto err;
			}

			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				/* buffer has changed, unload and reload map */
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			/*
			 * Fill the slot in the NIC ring. FreeBSD's if_bxe.c has
			 * a lot of notes including:
			 * - min number of nbd is 2 even if the parsing bd is not used,
			 *   otherwise we get an MC assert! error
			 * - if vlan is not used, firmware expect a packet number there.
			 * - do we care for mac-type ?
			 */

			bd->bd_flags.as_bitfield = ETH_TX_BD_FLAGS_START_BD;
			bd->vlan_or_ethertype = cpu_to_le16(txdata->tx_pkt_prod);

			bd->addr_lo = cpu_to_le32(U64_LO(paddr));
			bd->addr_hi = cpu_to_le32(U64_HI(paddr));
			bd->nbytes = cpu_to_le16(len);
			bd->nbd = cpu_to_le16(2);
			if (unlikely(is_multicast_ether_addr(addr))) {
				if (is_broadcast_ether_addr(addr))
					mac_type = BROADCAST_ADDRESS;
				else
					mac_type = MULTICAST_ADDRESS;
			}
			SET_FLAG(bd->general_data, ETH_TX_START_BD_ETH_ADDR_TYPE, mac_type);
			SET_FLAG(bd->general_data, ETH_TX_START_BD_HDR_NBDS, 1 /* XXX */ );

			j = (j == lim) ? 0 : j + 1;
			txdata->tx_pkt_prod++;
			l = NEXT_TX_IDX(l); // skip link fields.
			/* clear the parsing block */
			bzero(&txdata->tx_desc_ring[TX_BD(l)], sizeof(*bd));
			l = NEXT_TX_IDX(l); // skip link fields.
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		/* decrease avail by number of packets  sent */
		kring->nr_hwavail -= n;

		/* XXX Check how to deal with nkr_hwofs */
		/* these two are always in sync. */
		txdata->tx_bd_prod = l;
		txdata->tx_db.data.prod = l;	// update doorbell

		wmb();	/* synchronize writes to the NIC ring */
		barrier();	// XXX
		/* (re)start the transmitter up to slot l (excluded) */
		ND(5, "doorbell cid %d data 0x%x", txdata->cid, txdata->tx_db.raw);
		DOORBELL(adapter, ring_nr, txdata->tx_db.raw);
	}

	/*
	 * Reclaim buffers for completed transmissions, as in bnx2x_tx_int().
	 * Maybe we could do it lazily.
	 */
	for (n=0;n < 5;n++) {
		uint16_t delta;

		/*
		 * Record completed transmissions.
		 * The card writes the current (pkt ?) index in memory in
		 * 	le16_to_cpu(*txdata->tx_cons_sb);
		 * This seems to be a sequential index with no skips modulo 2^16
		 * irrespective of the actual ring size.
		 * We need to adjust buffer and packet indexes.
		 * In netmap we can use 1 pkt/1bd so the pkt_cons
		 * is an index in the netmap buffer. The bd_index
		 * however should be computed with some trick.
		 * We (re)use the driver's txr->tx_pkt_cons to keep
		 * track of the most recently completed transmission.
		 */
		l = le16_to_cpu(*txdata->tx_cons_sb);
		delta = l - txdata->tx_pkt_cons; // XXX buffers, not slots
		if (delta == 0) {
			if (n > 1 || (n == 0 && txdata->tx_pkt_cons !=
				    txdata->tx_pkt_prod))
				ND(5, "txr[%d] exit after %d cycles, pending %d", ring_nr, n, (uint16_t)(txdata->tx_pkt_prod - txdata->tx_pkt_cons));
			break;
		}
		if (delta) {
			ND(5, "txr %d completed %d packets", ring_nr, delta);
			/* some tx completed, increment hwavail. */
			kring->nr_hwavail += delta;
			/* XXX lazy solution - consume 2 buffers */
			for (;txdata->tx_pkt_cons != l; txdata->tx_pkt_cons++) {
				txdata->tx_bd_cons = NEXT_TX_IDX(txdata->tx_bd_cons);
				txdata->tx_bd_cons = NEXT_TX_IDX(txdata->tx_bd_cons);
			}
			if (kring->nr_hwavail > lim) {
				D("ring %d hwavail %d > lim", ring_nr, kring->nr_hwavail);
				error = EINVAL;
				goto err;
			}
		}
	}
	if (txdata->tx_pkt_cons != txdata->tx_pkt_prod) {
		// XXX kick the sender, does not seem to help.
		wmb();	/* synchronize writes to the NIC ring */
		barrier();	// XXX
		/* (re)start the transmitter up to slot l (excluded) */
		ND(5, "doorbell cid %d data 0x%x", txdata->cid, txdata->tx_db.raw);
		DOORBELL(adapter, ring_nr, txdata->tx_db.raw);
	}
	/* update avail to what the kernel knows */
	if (ring->avail == 0 && kring->nr_hwavail >0)
		ND(3,"txring %d restarted", ring_nr);
	ring->avail = kring->nr_hwavail;
	if (ring->avail == 0)
		ND(3,"txring %d full", ring_nr);

err:
	if (do_lock)
		mtx_unlock(&na->core_lock);
		// mtx_unlock(&kring->q_lock);
	if (error)
		return netmap_ring_reinit(kring);
#endif // 0
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
 * do_lock has a special meaning: please refer to txsync.
 */
static int
mlx4_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct mlx4_en_rx_ring *rxr = &adapter->rx_ring[ring_nr];
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = do_lock || kring->nr_kflags & NKR_PENDINTR;
	u_int k = ring->cur, resvd = ring->reserved;
	uint16_t hw_comp_cons, sw_comp_cons;

	if (k > lim) /* userspace is cheating */
		return netmap_ring_reinit(kring);

	if (do_lock)
		mtx_lock(&kring->q_lock);
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

	/* scan the completion queue to see what is going on.
	 * Note that we do not use l here.
	 */
#if 0 // XXX
	sw_comp_cons = RCQ_BD(rxr->rx_comp_cons);
	l = rxr->rx_bd_cons;
	j = netmap_idx_n2k(kring, j);
	hw_comp_cons = le16_to_cpu(*rxr->rx_cons_sb);
	if ((hw_comp_cons & MAX_RCQ_DESC_CNT) == MAX_RCQ_DESC_CNT)
		hw_comp_cons++;

	rmb(); // XXX
ND("start ring %d k %d lim %d hw_comp_cons %d", ring_nr, k, lim, hw_comp_cons);
goto done; // XXX debugging

	if (netmap_no_pendintr || force_update) {
		for (n = 0; sw_comp_cons != hw_comp_cons; sw_comp_cons = RCQ_BD(NEXT_RCQ_IDX(sw_comp_cons)) ) {
			union eth_rx_cqe *cqe = &rxr->rx_comp_ring[l];
			struct eth_fast_path_rx_cqe *cqe_fp = &cqe->fast_path_cqe;
			// XXX fetch event, process slowpath as in the main driver,
			if (1 /* slowpath */)
				continue;
			ring->slot[j].len = le16_to_cpu(cqe_fp->pkt_len_or_gro_seg_len);

			l = NEXT_RX_IDX(l);
			j = (j == lim) ? 0 : j + 1;
			n++;
		}
		if (n) { /* update the state variables */
			rxr->rx_comp_cons = sw_comp_cons; // XXX adjust nkr_hwofs
			rxr->rx_bd_cons = l; // XXX adjust nkr_hwofs
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/*
	 * Skip past packets that userspace has already released
	 * (from kring->nr_hwcur to ring->cur-ring->reserved excluded),
	 * and make the buffers available for reception.
	 * As usual j is the index in the netmap ring, l is the index
	 * in the NIC ring, and j == (l + kring->nkr_hwofs) % ring_size
	 */
	j = kring->nr_hwcur; /* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) { /* userspace has released some packets. */
		uint16_t sw_comp_prod = 0; // XXX
		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* collect per-slot info, with similar validations
			 * and flag handling as in the txsync code.
			 *
			 * NOTE curr and rxbuf are indexed by l.
			 * Also, this driver needs to update the physical
			 * address in the NIC ring, but other drivers
			 * may not have this requirement.
			 */
#if 0 // XXX
			struct netmap_slot *slot = &ring->slot[j];
			union ixgbe_adv_rx_desc *curr = IXGBE_RX_DESC_ADV(rxr, l);
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) /* bad buf */
				goto ring_reset;

			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_addr, addr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->wb.upper.status_error = 0;
			curr->read.pkt_addr = htole64(paddr);
#endif // XXX
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		// XXXX cons = ...
		wmb();
		/* Update producers */
		mlx4_update_rx_prod(adapter, rxr, l, sw_comp_prod,
				     rxr->rx_sge_prod);
	}
done:
#endif // 0 XXX
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;

	if (do_lock)
		mtx_unlock(&kring->q_lock);
	return 0;

ring_reset:
	if (do_lock)
		mtx_unlock(&kring->q_lock);
	return netmap_ring_reinit(kring);
}


/*
 * If in netmap mode, attach the netmap buffers to the ring and return true.
 * Otherwise return false.
 * Called at the end of bnx2x_alloc_fp_mem_at(), sets both tx and rx
 * buffer entries. At init time we allocate the max number of entries
 * for the card, but at runtime the card might use a smaller number,
 * so be careful on where we fetch the information.
 */
int
mlx4_netmap_config(struct SOFTC_T *priv)
{
	struct netmap_adapter *na = NA(priv->dev);
	struct netmap_slot *slot;
	struct mlx4_en_rx_ring *rxr;
	int j, ring_nr;
	int nq;	/* number of queues to use */

	slot = netmap_reset(na, NR_TX, 0, 0);	// quick test on first ring
	if (!slot)
		return 0;	// not in netmap;
	nq = na->num_rx_rings;	// XXX check how many
	D("rings: netmap %d, driver tx %d rx %d", nq,
		priv->tx_ring[0].size, priv->rx_ring[0].size);
	return 0; // early fail

	for (ring_nr = 0; ring_nr < nq; ring_nr++) {
		netmap_reset(na, NR_TX, ring_nr, 0);
	}
	/*
	 * Do nothing on the tx ring, addresses are set up at tx time.
	 */
	/*
	 * on the receive ring, must set buf addresses into the slots.
	 */
	for (ring_nr = 0; ring_nr < nq; ring_nr++) {
		slot = netmap_reset(na, NR_RX, ring_nr, 0);
		rxr = &priv->rx_ring[ring_nr];
		for (j = 0; j < na->num_rx_desc; j++) {
			uint64_t paddr;
			void *addr = PNMB(slot + j, &paddr);
		}
	}
	/* now use regular interrupts */
	D("------------- clear the SKIP_INTR flag");
	// XXX na->na_flags &= ~NAF_SKIP_INTR;
	return 1;
}


/*
 * The attach routine, called near the end of bnx2x_init_one(),
 * fills the parameters for netmap_attach() and calls it.
 * It cannot fail, in the worst case (such as no memory)
 * netmap mode will be disabled and the driver will only
 * operate in standard mode.
 */
static void
mlx4_netmap_attach(struct SOFTC_T *priv)
{
	struct netmap_adapter na;
	struct net_device *dev = priv->dev;
	int rxq, txq, nq;

	bzero(&na, sizeof(na));

	na.ifp = dev;
	na.separate_locks = 0; // XXX experimental
	rxq = priv->rx_ring_num;
	txq = priv->tx_ring_num;

	D("hw configured for %d/%d tx/rx rings", txq, rxq);
	if (txq < 1 && rxq < 1)
		txq = rxq = 1;
	/* this card has separate rx/tx locks */
	/* The ring size is the number of tx bd, but since we use 2 per
	 * packet, make the tx ring shorter.
	 * Let's see what to do with the 
	 * skipping those continuation blocks.
	 */
	na.num_tx_desc = priv->tx_ring[0].size;
	na.num_rx_desc = priv->rx_ring[0].size;
	na.nm_txsync = mlx4_netmap_txsync;
	na.nm_rxsync = mlx4_netmap_rxsync;
	na.nm_register = mlx4_netmap_reg;
	/* same number of tx and rx queues. queue 0 is somewhat special
	 * but we still cosider it. If FCOE is supported, the last hw
	 * queue is used for it.
 	 */
	netmap_attach(&na, priv->rx_ring_num);
	D("%d queues, tx: %d rx %d slots", na.num_rx_rings,
			na.num_tx_desc, na.num_rx_desc);
}
#endif /* NETMAP_BNX2X_MAIN */
/* end of file */
