/*
 * Copyright (C) 2013 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
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

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>


/* ======================== FREEBSD-SPECIFIC ROUTINES ================== */

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
   and -1 on error (which may be packet drops or other errors). */
int generic_xmit_frame(struct ifnet *ifp, struct mbuf *m,
	void *addr, u_int len, u_int ring_nr)
{
    netdev_tx_t ret;

    /* TODO Support the slot flags (NS_FRAG, NS_INDIRECT). */
    skb_copy_to_linear_data(m, addr, len); // skb_store_bits(m, 0, addr, len);
    skb_put(m, len);
    NM_ATOMIC_INC(&m->users);
    m->dev = ifp;
    m->priority = 100;
    skb_set_queue_mapping(m, ring_nr);

    ret = dev_queue_xmit(m);

    if (likely(ret == NET_XMIT_SUCCESS)) {
        return 0;
    }
    if (unlikely(ret != NET_XMIT_DROP)) {
        /* If something goes wrong in the TX path, there is nothing intelligent
           we can do (for now) apart from error reporting. */
        RD(5, "dev_queue_xmit failed: HARD ERROR %d", ret);
    }
    return -1;
}

/*
 * The following two functions are empty until we have a generic
 * way to extract the info from the ifp
 */
int
generic_find_num_desc(struct ifnet *ifp, unsigned int *tx, unsigned int *rx)
{
    return 0;
}

void
generic_find_num_queues(struct ifnet *ifp, u_int *txq, u_int *rxq)
{
    *txq = 1;
    *rxq = 1;
}

static struct device_driver *
linux_netmap_find_driver(struct device *dev)
{
	struct device_driver *dd;

	while ( (dd = dev->driver) == NULL ) {
		if ( (dev = dev->parent) == NULL )
			return NULL;
	}
	return dd;
}

struct net_device *
ifunit_ref(const char *name)
{
	struct net_device *ifp = dev_get_by_name(&init_net, name);
	struct device_driver *dd;

	if (ifp == NULL)
		return NULL;

	if ( (dd = linux_netmap_find_driver(&ifp->dev)) == NULL )
		goto error;

	if (!try_module_get(dd->owner))
		goto error;

	return ifp;
error:
	dev_put(ifp);
	return NULL;
}

void if_rele(struct net_device *ifp)
{
	struct device_driver *dd;
	dd = linux_netmap_find_driver(&ifp->dev);
	dev_put(ifp);
	if (dd)
		module_put(dd->owner);
}
