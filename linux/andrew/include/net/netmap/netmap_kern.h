/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * 
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the
 *      distribution.
 * 
 *   3. Neither the name of the authors nor the names of their contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY MATTEO LANDI AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MATTEO LANDI OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * $Id: netmap_kern.h 8969 2011-07-04 07:25:09Z luigi $
 *
 * $FreeBSD$
 *
 * The header contains the definitions of constants and function
 * prototypes used only in kernelspace.
 */

#ifndef _NET_NETMAP_KERN_H_
#define _NET_NETMAP_KERN_H_

#if defined(FreeBSD)
#include "netmap_bsd.h"
#elif defined(linux)
#include "netmap_linux.h"
#endif


struct netmap_adapter;

/*
 * private, kernel view of a ring.
 *
 * XXX 20110627-todo
 * The index in the NIC and netmap ring is offset by nkr_hwofs slots.
 * This is so that, on a reset, buffers owned by userspace are not
 * modified by the kernel. In particular:
 * RX rings: the next empty buffer (hwcur + hwavail + hwofs) coincides
 * 	the next empty buffer as known by the hardware (next_to_check or so).
 * TX rings: hwcur + hwofs coincides with next_to_send
 */
struct netmap_kring {
	struct netmap_ring *ring;
	u_int nr_hwcur;
	int nr_hwavail;
	u_int nr_kflags;
	u_int nkr_num_slots;

	u_int	nkr_hwofs;	/* offset between NIC and netmap ring */
	struct netmap_adapter *na;	 // debugging

	/* poll/select wait queue */
#if defined(FreeBSD)
	struct selinfo si;
#elif defined(linux)
        wait_queue_head_t waitq;
#endif
};

/*
 * This struct is part of and extends the 'struct adapter' (or
 * equivalent) device descriptor. It contains all fields needed to
 * support netmap operation.
 */
struct netmap_adapter {
	int refcount; /* number of user-space descriptors using this
			 interface, which is equal to the number of
			 struct netmap_if objs in the mapped region. */

	int separate_locks; /* set if the interface suports different
			       locks for rx, tx and core. */

	u_int num_queues; /* number of tx/rx queue pairs: this is
			   a duplicate field needed to simplify the
			   signature of ``netmap_detach``. */

	u_int num_tx_desc; /* number of descriptor in each queue */
	u_int num_rx_desc;
	u_int buff_size;

	u_int	flags;	/* NR_REINIT */
	/* tx_rings and rx_rings are private but allocated
	 * as a contiguous chunk of memory. Each array has
	 * N+1 entries, for the adapter queues and for the host queue.
	 */
	struct netmap_kring *tx_rings; /* array of TX rings. */
	struct netmap_kring *rx_rings; /* array of RX rings. */

	/* references to the ifnet and device routines, used by
	 * the generic netmap functions.
	 */
        interface_t *ifp;

#ifndef FreeBSD
        int (*nm_isactive)(interface_t*);
#endif
	int (*nm_register)(interface_t *, int onoff);
	void (*nm_lock)(interface_t *, int what, u_int ringid);
	int (*nm_txsync)(interface_t *, u_int ring, int lock);
	int (*nm_rxsync)(interface_t *, u_int ring, int lock);
};

/*
 * parameters for (*nm_lock)(adapter, what, index)
 */
enum {
	NETMAP_NO_LOCK = 0,
	NETMAP_CORE_LOCK, NETMAP_CORE_UNLOCK,
	NETMAP_TX_LOCK, NETMAP_TX_UNLOCK,
	NETMAP_RX_LOCK, NETMAP_RX_UNLOCK,
};

/*
 * The following are support routines used by individual drivers to
 * support netmap operation.
 *
 * netmap_attach() initializes a struct netmap_adapter, allocating the
 * 	struct netmap_ring's and the struct selinfo.
 *
 * netmap_detach() frees the memory allocated by netmap_attach().
 *
 * netmap_start() replaces the if_transmit routine of the interface,
 *	and is used to intercept packets coming from the stack.
 */
int netmap_attach(struct netmap_adapter *, int);
void netmap_detach(interface_t *);

#if defined(FreeBSD)
int netmap_start(struct ifnet *, struct mbuf *);
#elif defined(linux)
int netmap_start(struct net_device *, struct sk_buff *);
#endif

enum txrx { NR_RX = 0, NR_TX = 1 };
struct netmap_slot *netmap_reset(struct netmap_adapter *na,
	enum txrx tx, int n, u_int new_cur);

int netmap_ring_reinit(struct netmap_kring *);

extern int netmap_verbose;	// XXX debugging
enum {                                  /* verbose flags */
	NM_VERB_ON = 1,                 /* generic verbose */
	NM_VERB_HOST = 0x2,             /* verbose host stack */
	NM_VERB_RXSYNC = 0x10,          /* verbose on rxsync/txsync */
	NM_VERB_TXSYNC = 0x20,
	NM_VERB_RXINTR = 0x100,         /* verbose on rx/tx intr (driver) */
	NM_VERB_TXINTR = 0x200,
	NM_VERB_NIC_RXSYNC = 0x1000,    /* verbose on rx/tx intr (driver) */
	NM_VERB_NIC_TXSYNC = 0x2000,
};

/* Structure associated to each thread which registered an interface. */
struct netmap_priv_d {
	struct netmap_if *np_nifp;	/* netmap interface descriptor. */

	interface_t	*np_ifp;	/* device for which we hold a reference */

	int		np_ringid;	/* from the ioctl */
	u_int		np_qfirst, np_qlast;	/* range of rings to scan */
	uint16_t	np_txpoll;
};

/* functions that reside in netmap_core.c */
void netmap_init_bufmap(u_int bufsize, u_int total_buffers, uint32_t* bitmap);

extern int netmap_set_ringid(struct netmap_priv_d*, u_int);

extern void *netmap_if_new(const char *ifname, struct netmap_adapter *na);
extern void netmap_cleanup(struct netmap_priv_d*);

extern void netmap_sync_to_host(struct netmap_adapter *na);
extern int netmap_sync_from_host(struct netmap_adapter *na);

extern void netmap_clean_reinit(struct netmap_adapter *na);


/* functions that need to be provided by the os-specific
 * layer (ie netmap_bsd.c or netmap_linux.c)
 */
extern void * netmap_malloc(size_t size, const char *msg);
extern void netmap_free(void *addr, const char *msg);
extern ssize_t netmap_ptr_to_buffer_offset(const char*);

#endif /* _NET_NETMAP_KERN_H_ */
