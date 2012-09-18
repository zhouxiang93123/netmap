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
 * $Id: bnx2x_netmap_linux.h $
 *
 * netmap support for bnx2x (LINUX version)
 *
 * The programming manual is publicly available at
 *	http://www.broadcom.com/collateral/pg/57710_57711-PG200-R.pdf
 *	http://www.broadcom.com/collateral/pg/57XX-PG105-R.pdf
 * but they do not match the code in the Linux or FreeBSD driversi (bnx2x, bxe).
 * The FreeBSD driver has a number of comments in the code that explain a lot
 * of the constraints in the firmware.
 *
 * Of particular relevance:

The buffer descriptor (bd) and packet (pkt) indexes handled by
the firmware are 16-bit values, no matter how big the rings are.
The current driver then has a number of BD slots which is also
a power of 2 so truncation does the right thing when accessing the arrays.

Configuration in the linux driver:
BCM_PAGE_SIZE		4096		// Pages are 4 Kbytes
					rx_bd = 8 bytes
					tx_bd = 16 bytes
					cont_desc = 16 bytes
TX_DESC_CNT		4096/16=256	includes the cont.
NEXT_PAGE_TX_DESC_CNT	1
NUM_TX_RINGS		16		XXX this is really pages, not rings.
NUM_TX_BD		256*NUM_TX_RINGS	gross, includes the cont.
MAX_TX_BD		NUM_TX_BD-1	only to deal with indexes

MAX_TX_DESC_CNT		255		actual, per ring
MAX_TX_AVAIL		255*16-2	overall
TX_BD(x)		((x) & MAX_TX_BD)	modulo, all rings
TX_BD_POFF(x)		((x) & MAX_TX_DESC_CNT)	modulo, single ring

NUM_RX_RINGS		8		XXX this is really pages, not rings.
RX_DESC_CNT		4096/sizeof(rx_bd) = 512	includes cont
NEXT_PAGE_RX_DESC_CNT	2
MAX_RX_DESC_CNT		510
RX_DESC_MASK		511				within page ?
NUM_RX_BD		RX_DESC_CNT*NUM_RX_RINGS=4096
MAX_RX_BD		NUM_RX_BD-1
MAX_RX_AVAIL		MAX_RX_DESC_CNT*NUM_RX_RINGS - 2	4078, pure coincidence.

buffer descriptors are allocated in bnx2x_alloc_fp_mem_at().
For each Class Of Service (COS) we have NUM_TX_BD slots in total.

 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#define SOFTC_T	bnx2x

int bnx2x_netmap_config(struct SOFTC_T *adapter);

static inline void
nm_pkt_dump(int i, char *buf, int len)
{
    uint8_t *s = buf+6, *d = buf;
    RD(10, "%d len %4d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
		i,
		len,
		s[0], s[1], s[2], s[3], s[4], s[5],
		d[0], d[1], d[2], d[3], d[4], d[5]);
}

#ifdef NETMAP_BNX2X_MAIN
/*
 * Some diagnostic to figure out the configuration.
 */
static inline void
bnx2x_netmap_diag(struct ifnet *ifp)
{
	struct SOFTC_T *bp = netdev_priv(ifp);
	struct bnx2x_fastpath *fp = &bp->fp[0];
	struct bnx2x_fp_txdata *txdata = &fp->txdata[0];
	int i;

	D("---- device %s ---- fp0 %p txdata %p q %d txq %d rxq %d -------",
		ifp->if_xname, fp, txdata, BNX2X_NUM_QUEUES(bp),
		ifp->num_tx_queues, ifp->num_rx_queues);
	// txq is actually 48, whereas rxq is a reasonable number.
	for (i = 0; i < BNX2X_NUM_QUEUES(bp); i++) {
		fp = &bp->fp[i];
		txdata = &fp->txdata[0];
		D("TX%2d: desc_ring %p %p cid %d txq_index %d cons_sb %p", i,
			txdata->tx_desc_ring,
			&txdata->tx_desc_ring[10].start_bd,
			txdata->cid, txdata->txq_index,
			txdata->tx_cons_sb);
	}
}

/*
 * Register/unregister. We are already under (netmap) core lock.
 * Only called on the first register or the last unregister.
 */
static int
bnx2x_netmap_reg(struct ifnet *ifp, int onoff)
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
	// bnx2x_netmap_diag(ifp);

	rtnl_lock(); // required by bnx2x_nic_unload()
	if (netif_running(ifp)) {
		D("unloading the nic");
		bnx2x_nic_unload(adapter, UNLOAD_NORMAL);
		need_load = 1;
	}

if (0) // only load/unload
	error = EINVAL;
else
	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
		/* save if_transmit and replace with our routine */
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &na->nm_ndo;
		D("-------------- set the SKIP_INTR flag");
		na->na_flags |= NAF_SKIP_INTR; /* during load, use regular interrupts */
	} else { /* reset normal mode */
		ifp->netdev_ops = (void *)na->if_transmit;
		ifp->if_capenable &= ~IFCAP_NETMAP;
	}
	if (need_load) {
		D("loading the NIC");
		bnx2x_nic_load(adapter, LOAD_NORMAL);
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

Broadcom: the tx routine is bnx2x_start_xmit()

The card has 16 hardware queues ("fastpath contexts"),
each possibly with several "Class of Service" (COS) queues.
(the data sheet says up to 16 COS, but the software seems to use 4).
The linux driver numbers queues 0..15 for COS=0, 16..31 for COS=1,
and so on. The low 4 bits are used to indicate the fastpath context.

The tx ring is made of one or more pages containing Buffer Descriptors (BD)
stored in fp->tx_desc_ring[],
each 16-byte long (NOTE: different from the rx side). The last BD in a page
(also 16 bytes) points to the next page (8 for physical address + 8 reserved bytes).
These page are presumably contiguous in virtual address space so all it takes
is to skip the reserved entries when we reach the last entry on the page
(MAX_TX_DESC_CNT - 1, or 255).

The driver differs from the documentation. In particular the END_BD flag
seems not to exist anymore, presumably the firmware can derive the number
of buffers from the START_BD flag plus nbd.
It is unclear from the docs whether we can have only one BD per packet 
The field to initialize are (all in LE format)
	addr_lo, addr_hi	LE32, physical buffer address
	nbytes			LE16, packet size
	vlan			LE16 ?? producer index ???
	nbd			L8 2 seems the min required
	bd_flags.as_bitfield	L8 START_BD XXX no END_BD
	general_data		L8 0 0..5: header_nbd; 6-7: addr type

and once we are done 'ring the doorbell' (write to a register)
to tell the NIC the first empty slot in the queue.

	struct bnx2x_fastpath *fp = &bp->fp[ring_nr % 16];
	struct bnx2x_fp_txdata *txdata = &fp->txdata[ring_nr / 16];

In txdata, The HOST ring is tx_buf_ring, and the NIC RING tx_desc_ring,
cid is the 'context id' or ring_nr % 16 .

We operate under the assumption that we use only the first
set of queues.

 */
static int
bnx2x_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
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
		mtx_lock(&kring->q_lock);

	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding bd_prod index (uint16_t).
	 * XXX for the NIC ring index we must use TX_BD(l)
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		if (txdata->tx_desc_ring == NULL) {
			D("------------------- bad! tx_desc_ring not set");
			error = EINVAL;
			goto err;
		}
		l = txdata->tx_bd_prod;
		RD(10,"=======>========== send from %d to %d at bd %d", j, k, l);
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			struct eth_tx_start_bd *bd =
				&txdata->tx_desc_ring[TX_BD(l)].start_bd;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			uint16_t len = slot->len;
			uint16_t mac_type = UNICAST_ADDRESS;

nm_pkt_dump(j, addr, len);
RD(5, "start_bd j %d l %d is %p", j, l, bd);
			/*
			 * Quick check for valid addr and len.
			 * PNMB() returns netmap_buffer_base for invalid
			 * buffer indexes (but the address is still a
			 * valid one to be used in a ring). slot->len is
			 * unsigned so no need to check for negative values.
			 */
			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
ring_reset:
				if (do_lock)
					mtx_unlock(&kring->q_lock);
				return netmap_ring_reinit(kring);
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
{ uint32_t *pbd = (void *)(bd + 1);
RD(1, "------ txq %d cid %d bd %d[%d] tx_buf %d\n"
        "START: A 0x%08x 0x%08x nbd %d by %d vlan %d fl 0x%x gd 0x%x\n"
        "PARSE: 0x%08x 0x%08x 0x%08x 0x%08x",

        ring_nr, txdata->cid, l - 2, bd->nbd,
        txdata->tx_pkt_prod,
        bd->addr_hi, bd->addr_lo, bd->nbd,
        bd->nbytes, bd->vlan_or_ethertype,
        bd->bd_flags.as_bitfield, bd->general_data,
        pbd[0], pbd[1], pbd[2], pbd[3]
        );
}

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
		RD(5, "doorbell cid %d data 0x%x", txdata->cid, txdata->tx_db.raw);
		DOORBELL(adapter, ring_nr, txdata->tx_db.raw);
	}

	/*
	 * Reclaim buffers for completed transmissions, as in bnx2x_tx_int().
	 * Maybe we could do it lazily.
	 */
	if (1) {
		int delta;

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
		if (delta) {
			RD(5, "txr %d completed %d packets", ring_nr, delta);
			/* some tx completed, increment hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			kring->nr_hwavail += delta;
			/* XXX lazy solution - consume 2 buffers */
			for (;txdata->tx_pkt_cons != l; txdata->tx_pkt_cons++) {
				txdata->tx_bd_cons = NEXT_TX_IDX(txdata->tx_bd_cons);
				txdata->tx_bd_cons = NEXT_TX_IDX(txdata->tx_bd_cons);
			}
			if (kring->nr_hwavail > lim)
				goto ring_reset;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

err:
	if (do_lock)
		mtx_unlock(&kring->q_lock);
	if (error)
		return netmap_ring_reinit(kring);
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

Broadcom:

see bnx2x_cmn.c :: bnx2x_rx_int()

the software keeps two sets of producer and consumer indexes:
one in the completion queue (fp->rx_comp_cons, fp->rx_comp_prod)
and one in the buffer descriptors (fp->rx_bd_cons, fp->rx_bd_prod).

The processing loop iterates on the completion queue, and
buffers are consumed only after 'fastpath' events.

The hardware reports the first empty slot through
(*fp->rx_cons_sb) (skipping the link field).

20120913
The code in bnx2x_rx_int() has a strange thing, it keeps
two running counters bd_prod and bd_prod_fw which are
apparently the same.


 */
static int
bnx2x_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct bnx2x_fastpath *rxr = &adapter->fp[ring_nr];
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
	sw_comp_cons = RCQ_BD(rxr->rx_comp_cons);
	l = rxr->rx_bd_cons;
	j = netmap_idx_n2k(kring, j);
	hw_comp_cons = le16_to_cpu(*rxr->rx_cons_sb);
	if ((hw_comp_cons & MAX_RCQ_DESC_CNT) == MAX_RCQ_DESC_CNT)
		hw_comp_cons++;

	rmb(); // XXX
D("start ring %d k %d lim %d hw_comp_cons %d", ring_nr, k, lim, hw_comp_cons);
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
		bnx2x_update_rx_prod(adapter, rxr, l, sw_comp_prod,
				     rxr->rx_sge_prod);
	}
done:
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
bnx2x_netmap_config(struct SOFTC_T *bp)
{
	struct netmap_adapter *na = NA(bp->dev);
	struct netmap_slot *slot;
	struct bnx2x_fastpath *fp;
	struct bnx2x_fp_txdata *txdata;
	int j, ring_nr;
	int nq;	/* number of queues to use */

	slot = netmap_reset(na, NR_TX, 0, 0);	// quick test on first ring
	if (!slot)
		return 0;	// not in netmap;
	nq = na->num_rx_rings;
	D("# queues: tx %d rx %d act %d %d",
		bp->dev->num_tx_queues, bp->dev->num_rx_queues,
		BNX2X_NUM_QUEUES(bp), nq );
	if (BNX2X_NUM_QUEUES(bp) < nq) {
		nq = BNX2X_NUM_QUEUES(bp);
		D("******** wartning, truncate to %d rings", nq);
	}
	D("allocate memory, tx/rx slots: %d %d max %d %d",
		(int)bp->tx_ring_size, (int)bp->rx_ring_size,
		na->num_tx_desc, na->num_rx_desc);
	for (ring_nr = 0; ring_nr < nq; ring_nr++) {
		netmap_reset(na, NR_TX, ring_nr, 0);
	}
	/*
	 * Do nothing on the tx ring, addresses are set up at tx time.
	 */
	fp = &bp->fp[0];
	txdata = &fp->txdata[0];
	D("tx: pkt cons/prod %d -> %d, bd cons/prod %d -> %d, cons_sb %p",
		txdata->tx_pkt_cons, txdata->tx_pkt_prod,
		txdata->tx_bd_cons, txdata->tx_bd_prod,
		txdata->tx_cons_sb );
	/*
	 * on the receive ring, must set buf addresses into the slots.
	 */
	for (ring_nr = 0; ring_nr < nq; ring_nr++) {
		slot = netmap_reset(na, NR_RX, ring_nr, 0);
		fp = &bp->fp[ring_nr];
		txdata = &fp->txdata[0];
		D("rx: comp cons/prod %d -> %d, bd cons/prod %d -> %d, cons_sb %p",
			fp->rx_comp_cons, fp->rx_comp_prod,
			fp->rx_bd_cons, fp->rx_bd_prod,
			fp->rx_cons_sb );
		for (j = 0; j < na->num_rx_desc; j++) {
			uint64_t paddr;
			void *addr = PNMB(slot + j, &paddr);
		}
	}
	/* now use regular interrupts */
	D("------------- clear the SKIP_INTR flag");
	na->na_flags &= ~NAF_SKIP_INTR;
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
bnx2x_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;
	struct net_device *dev = adapter->dev;

	bzero(&na, sizeof(na));

	na.ifp = dev;
	na.separate_locks = 1;	/* this card has separate rx/tx locks */
	/* The ring size is the number of tx bd, but since we use 2 per
	 * packet, make the tx ring shorter.
	 * Let's see what to do with the 
	 * skipping those continuation blocks.
	 */
	na.num_tx_desc = adapter->tx_ring_size / 2;
	na.num_rx_desc = na.num_tx_desc; // XXX see above
	na.nm_txsync = bnx2x_netmap_txsync;
	na.nm_rxsync = bnx2x_netmap_rxsync;
	na.nm_register = bnx2x_netmap_reg;
	/* same number of tx and rx queues. queue 0 is somewhat special
	 * but we still cosider it. If FCOE is supported, the last hw
	 * queue is used for it.
 	 */
	netmap_attach(&na, 4); // BNX2X_NUM_ETH_QUEUES(adapter));
	D("%d queues, tx: %d rx %d slots", na.num_rx_rings,
			na.num_tx_desc, na.num_rx_desc);
}
#endif /* NETMAP_BNX2X_MAIN */
/* end of file */
