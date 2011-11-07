/*
 * (C) 2011 Luigi Rizzo, Matteo Landi - Universita` di Pisa
 *
 * BSD Copyright
 *
 */

#include <net/netmap.h>
#include <net/netmap/netmap_kern.h>

static void	e1000_netmap_lock_wrapper(struct net_device *, int, u_int);
static int	e1000_netmap_reg(struct net_device *, int onoff);
static int	e1000_netmap_txsync(struct net_device*, u_int, int);
static int	e1000_netmap_rxsync(struct net_device*, u_int, int);

static netdev_tx_t e1000_netmap_xmit(struct sk_buff *, struct net_device *);

static int e1000_netmap_isactive(struct net_device* dev)
{
    struct e1000_adapter *adapter = netdev_priv(dev);
    return (test_bit(__E1000_NETMAP, &adapter->flags));
}

static void
e1000_netmap_attach(struct e1000_adapter *adapter)
{
	struct netmap_adapter na;

        memset(&na, 0, sizeof na);

	na.ifp = adapter->netdev;
	na.separate_locks = 1;
	na.num_tx_desc = adapter->tx_ring[0].count;
	na.num_rx_desc = adapter->rx_ring[0].count;
        na.nm_isactive = e1000_netmap_isactive;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	na.nm_lock = e1000_netmap_lock_wrapper;

	/*
	 * adapter->rx_mbuf_sz is set bi SIOCSETMTU, but in netmap mode
	 * we allocate the buffers on the first register. So we must
	 * disallow a SIOCSETMTU when if_capenable & IFCAP_NETMAP is set.
	 */
	na.buff_size = 2048;
	netmap_attach(&na, 1);
}

static void
e1000_netmap_lock_wrapper(interface_t *netdev, int what, u_int queueid)
{
#warning  "fix e1000 netmap locking!"
    switch (what) {
    case NETMAP_CORE_LOCK:
    case NETMAP_CORE_UNLOCK:
        /* XXX !!! */
        break;

    case NETMAP_TX_LOCK:
        BUG_ON(queueid >= netdev->num_tx_queues);
        __netif_tx_lock_bh(netdev_get_tx_queue(netdev, queueid));
        break;

    case NETMAP_TX_UNLOCK:
        BUG_ON(queueid >= netdev->num_tx_queues);
        __netif_tx_unlock_bh(netdev_get_tx_queue(netdev, queueid));
        break;

    case NETMAP_RX_LOCK:
    case NETMAP_RX_UNLOCK:
        /* XXX !!! */
        break;
    }
}

static void e1000_netmap_alloc_rx_buffers(struct e1000_adapter *adapter,
                                          struct e1000_rx_ring *rx_ring,
                                          int cleaned_count)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
        struct netmap_adapter* na = NA(netdev);
        struct netmap_kring* kring = &na->rx_rings[0];
        struct netmap_ring* ring = kring->ring;
        
        struct netmap_slot* slot;

	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
        struct e1000_buffer *buffer_info;
	unsigned int i;
	/*unsigned int bufsz = adapter->rx_buffer_len;*/

	i = rx_ring->next_to_use;
        slot = &ring->slot[i];
        buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
                void* addr = NMB(slot);

#if 0
		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter, addr, bufsz)) {
			struct sk_buff *oldskb = skb;
			e_err(rx_err, "skb align check failed: %u bytes at "
			      "%p\n", bufsz, skb->data);
			/* Try again, without freeing the previous */
			skb = netdev_alloc_skb_ip_align(netdev, bufsz);
			/* Failed allocation, critical failure */
			if (!skb) {
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break;
			}

			if (!e1000_check_64k_bound(adapter, skb->data, bufsz)) {
				/* give up */
				dev_kfree_skb(skb);
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break; /* while !buffer_info->skb */
			}

			/* Use new allocation */
			dev_kfree_skb(oldskb);
		}
#endif

		buffer_info->skb = 0;
		buffer_info->length = adapter->rx_buffer_len;
		buffer_info->dma = dma_map_single(&pdev->dev,
						  addr,
						  buffer_info->length,
						  DMA_FROM_DEVICE);
		if (dma_mapping_error(&pdev->dev, buffer_info->dma)) {
                        /* XXX netmap_ring_reinit() ? */
                        
			buffer_info->skb = NULL;
			buffer_info->dma = 0;
			adapter->alloc_rx_buff_failed++;
			break; /* while !buffer_info->skb */
		}

#if 0
		/*
		 * XXX if it was allocated cleanly it will never map to a
		 * boundary crossing
		 */

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter,
					(void *)(unsigned long)buffer_info->dma,
					adapter->rx_buffer_len)) {
			e_err(rx_err, "dma align check failed: %u bytes at "
			      "%p\n", adapter->rx_buffer_len,
			      (void *)(unsigned long)buffer_info->dma);
			dev_kfree_skb(skb);
			buffer_info->skb = NULL;

			dma_unmap_single(&pdev->dev, buffer_info->dma,
					 adapter->rx_buffer_len,
					 DMA_FROM_DEVICE);
			buffer_info->dma = 0;

			adapter->alloc_rx_buff_failed++;
			break; /* while !buffer_info->skb */
		}
#endif

		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
                /*
                extern ssize_t netmap_off(void*);
                D("slot %d (at %ld) got %p", i, netmap_off(slot), addr);
                */
                slot++;
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64). */
		wmb();
		writel(i, hw->hw_addr + rx_ring->rdt);
	}
}


static bool e1000_netmap_clean_rx(struct e1000_adapter *adapter,
                                  struct e1000_rx_ring *rx_ring,
                                  int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
        struct netmap_adapter* na = NA(netdev);
        struct netmap_kring* kring = &na->rx_rings[0];
        struct netmap_ring* ring = kring->ring;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_buffer *buffer_info, *next_buffer;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes=0, total_rx_packets=0;

        printk(KERN_INFO "in e1000_netmap_clean_rx, next_clean=%u, next_use=%u\n", rx_ring->next_to_clean, rx_ring->next_to_use);

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
                struct netmap_slot* slot;
		u8 status;
                u32 length;

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;
		rmb(); /* read descriptor and rx_buffer_info after status DD */

		status = rx_desc->status;
                slot = &ring->slot[i];
                
		if (++i == rx_ring->count) i = 0;
		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;
		dma_unmap_single(&pdev->dev, buffer_info->dma,
				 buffer_info->length, DMA_FROM_DEVICE);
		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

#if 0
		/* !EOP means multiple descriptors were used to store a single
		 * packet, if thats the case we need to toss it.  In fact, we
		 * to toss every packet with the EOP bit clear and the next
		 * frame that _does_ have the EOP bit set, as it is by
		 * definition only a frame fragment
		 */
		if (unlikely(!(status & E1000_RXD_STAT_EOP)))
			adapter->discarding = true;

		if (adapter->discarding) {
			/* All receives must fit into a single buffer */
			e_dbg("Receive packet consumed multiple buffers\n");
			/* recycle */
			if (status & E1000_RXD_STAT_EOP)
				adapter->discarding = false;
			goto next_desc;
		}

		if (unlikely(rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK)) {
			u8 last_byte = *(skb->data + length - 1);
			if (TBI_ACCEPT(hw, status, rx_desc->errors, length,
				       last_byte)) {
				spin_lock_irqsave(&adapter->stats_lock, flags);
				e1000_tbi_adjust_stats(hw, &adapter->stats,
				                       length, skb->data);
				spin_unlock_irqrestore(&adapter->stats_lock,
				                       flags);
				length--;
			} else {
				/* recycle */
				buffer_info->skb = skb;
				goto next_desc;
			}
		}

#else
                if (unlikely((!(status & E1000_RXD_STAT_EOP)
                       || rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK))) {
                             /* XXX netmap_reset_ring() ? */
                        goto next_desc;
                }
#endif

		/* adjust length to remove Ethernet CRC, this must be
		 * done after the TBI_ACCEPT workaround above */
		length -= 4;

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += length;
		total_rx_packets++;

                slot->len = length;
                kring->nr_hwavail++;

next_desc:
		rx_desc->status = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = E1000_DESC_UNUSED(rx_ring);
	if (cleaned_count) {
		adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
                D("wake_up q %p", &kring->waitq);
                wake_up_interruptible(&kring->waitq);
        }

	adapter->total_rx_packets += total_rx_packets;
	adapter->total_rx_bytes += total_rx_bytes;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}


static netdev_tx_t e1000_netmap_xmit(struct sk_buff *skb, struct net_device *dev)
{
    /*XXX*/
    dev_kfree_skb(skb);
    return (NETDEV_TX_BUSY);
}

static struct net_device_ops e1000_netmap_ops;
static const struct net_device_ops* e1000_saved_ops;

/*
 * register-unregister routine
 */
static int
e1000_netmap_reg(struct net_device *dev, int onoff)
{
    struct e1000_adapter *adapter = netdev_priv(dev);
    struct netmap_adapter *na = NA(dev);
    int error = 0;

    if (na == NULL)
        return (-EINVAL);	/* no netmap support here */

    if (onoff && test_bit(__E1000_NETMAP, &adapter->flags)) {
        return (0);
    }

    if (test_bit(__E1000_DOWN, &adapter->flags)) {
        /* actually the opposite but wtf should we return */
        return (-EBUSY);
    }
    
    e1000_down(adapter);

    /*
    e1000_free_all_tx_resources(adapter);
    */
    e1000_free_all_rx_resources(adapter);

    if (onoff) {
        set_bit(__E1000_NETMAP, &adapter->flags);

        adapter->clean_rx = e1000_netmap_clean_rx;
        adapter->alloc_rx_buf = e1000_netmap_alloc_rx_buffers;

#ifdef notyet
        e1000_saved_ops = dev->netdev_ops;
        memcpy(&e1000_netmap_ops, dev->netdev_ops, sizeof e1000_netmap_ops);
        e1000_netmap_ops.ndo_start_xmit = e1000_netmap_xmit;
#endif
    } else {
        clear_bit(__E1000_NETMAP, &adapter->flags);
        /* XXX restore clean_rx(), alloc_rx_buf() */
#ifdef notyet
        dev->netdev_ops = e1000_saved_ops;
#endif 
    }

    /*
    e1000_setup_all_tx_resources(adapter);
    */
    e1000_setup_all_rx_resources(adapter);
    
    e1000_up(adapter);

    return (error);
}

/*
 * Reconcile hardware and user view of the transmit ring, see
 * ixgbe.c for details.
 */
static int
e1000_netmap_txsync(struct net_device* dev, u_int ring_nr, int do_lock)
{
        (void) dev;
        (void) ring_nr;
        (void) do_lock;
        
	return 0;
}

/*
 * Reconcile kernel and user view of the receive ring, see ixgbe.c
 */
static int
e1000_netmap_rxsync(struct net_device* dev, u_int ring_nr, int do_lock)
{
    struct e1000_adapter *adapter = netdev_priv(dev);
    struct netmap_adapter *na = NA(dev);
    struct e1000_rx_ring *rxr = &adapter->rx_ring[ring_nr];
    struct netmap_kring *kring = &na->rx_rings[ring_nr];
    struct netmap_ring *ring = kring->ring;
    int j, k, n, lim = kring->nkr_num_slots - 1;

    k = ring->cur;
    if ( (kring->nr_kflags & NR_REINIT) || k > lim)
        /* XXX */
        /* return netmap_ring_reinit(kring); */
        return 1;

#ifdef notyet
    if (do_lock)
        EM_RX_LOCK(rxr);

    /* XXX check sync modes */
    bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
                    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
#endif

    /* skip past packets that userspace has already processed:
     * making them available for reception.
     * advance nr_hwcur and issue a bus_dmamap_sync on the
     * buffers so it is safe to write to them.
     * Also increase nr_hwavail
     */
    j = kring->nr_hwcur;
    if (j != k) { /* userspace has read some packets. */
        n = 0;
        while (j != k) {
            struct netmap_slot *slot = &ring->slot[j];
            struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, j);
            /*struct em_buffer *rxbuf = &rxr->rx_buffers[j];*/
            void *addr = NMB(slot);

            if (addr == 0) { /* bad buf */
#ifdef notyet
                if (do_lock)
                    EM_RX_UNLOCK(rxr);
                return netmap_ring_reinit(kring);
#endif
                return (1);
            }


            curr->status = 0;
#ifdef notyet
            if (slot->flags & NS_BUF_CHANGED) {
                curr->buffer_addr = htole64(vtophys(addr));
                /* buffer has changed, unload and reload map */
                netmap_reload_map(rxr->rxtag, rxbuf->map,
                                  addr, na->buff_size);
                slot->flags &= ~NS_BUF_CHANGED;
            }
            
            bus_dmamap_sync(rxr->rxtag, rxbuf->map,
                            BUS_DMASYNC_PREREAD);
#endif
            
            j = (j == lim) ? 0 : j + 1;
            n++;
        }

        kring->nr_hwavail -= n;
        kring->nr_hwcur = ring->cur;
#ifdef notyet
        bus_dmamap_sync(rxr->rxdma.dma_tag, rxr->rxdma.dma_map,
			BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
#endif

#ifdef notyet
        /*
         * IMPORTANT: we must leave one free slot in the ring,
         * so move j back by one unit
         */
        j = (j == 0) ? lim : j - 1;
        E1000_WRITE_REG(&adapter->hw, E1000_RDT(rxr->me), j);
#endif
    }

    /* tell userspace that there are new packets */
    ring->avail = kring->nr_hwavail ;
#ifdef notyet
    if (do_lock)
        EM_RX_UNLOCK(rxr);
#endif

    return 0;
}
