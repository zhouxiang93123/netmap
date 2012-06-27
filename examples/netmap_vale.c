/*
 * Copyright (C) 2012 Luigi Rizzo. All rights reserved.
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

#define NM_BRIDGE

/*
 * This is a subset of the netmap bridging code used by VALE
 */

#ifdef NM_BRIDGE /* support for netmap bridge */

/*
 * system parameters.
 *
 * All switched ports have prefix NM_NAME.
 * The switch has a max of NM_BDG_MAXPORTS ports (often stored in a bitmap,
 * so a practical upper bound is 64).
 * Each tx ring is read-write, whereas rx rings are readonly (XXX not done yet).
 * The virtual interfaces use per-queue lock instead of core lock.
 * In the tx loop, we aggregate traffic in batches to make all operations
 * faster. The batch size is NM_BDG_BATCH
 */
#define	NM_NAME			"vale"	/* prefix for the interface */
#define NM_BDG_MAXPORTS		16	/* up to 64 ? */
#define NM_BRIDGE_RINGSIZE	1024	/* in the device */
#define NM_BDG_HASH		1024	/* forwarding table entries */
#define NM_BDG_BATCH		1024	/* entries in the forwarding buffer */

int netmap_bridge = NM_BDG_BATCH; /* bridge batch size */
SYSCTL_INT(_dev_netmap, OID_AUTO, bridge, CTLFLAG_RW, &netmap_bridge, 0 , "");
#ifdef linux
#define	ADD_BDG_REF(ifp)	(NA(ifp)->if_refcount++)
#define	DROP_BDG_REF(ifp)	(NA(ifp)->if_refcount-- <= 1)
#else
#define	ADD_BDG_REF(ifp)	(ifp)->if_refcount++
#define	DROP_BDG_REF(ifp)	refcount_release(&(ifp)->if_refcount)
#ifdef __FreeBSD__
#include <sys/endian.h>
#include <sys/refcount.h>
#endif
#endif /* !linux */

static void bdg_netmap_attach(struct ifnet *ifp);
static int bdg_netmap_reg(struct ifnet *ifp, int onoff);
/* per-tx-queue entry */
struct nm_bdg_fwd {	/* forwarding entry for a bridge */
	void *buf;
	uint64_t dst;	/* dst mask */
	uint32_t src;	/* src index ? */
	uint16_t len;	/* src len */
#if 0
	uint64_t src_mac;	/* ignore 2 MSBytes */
	uint64_t dst_mac;	/* ignore 2 MSBytes */
	uint32_t dst_idx;	/* dst index in fwd table */
	uint32_t dst_buf;	/* where we copy to */
#endif
};

struct nm_hash_ent {
	uint64_t	mac;	/* the top 2 bytes are the epoch */
	uint64_t	ports;
};

/*
 * Interfaces for a bridge are all in ports[].
 * The array has fixed size, an empty entry does not terminate
 * the search.
 */
struct nm_bridge {
	struct ifnet *bdg_ports[NM_BDG_MAXPORTS];
	int n_ports;
	uint64_t act_ports;
	int freelist;	/* first buffer index */
	NM_SELINFO_T si;	/* poll/select wait queue */
	NM_LOCK_T bdg_lock;	/* protect the selinfo ? */

	/* the forwarding table, MAC+ports */
	struct nm_hash_ent ht[NM_BDG_HASH];
};

struct nm_bridge nm_bridge;

#define BDG_LOCK(b)	mtx_lock(&(b)->bdg_lock)
#define BDG_UNLOCK(b)	mtx_unlock(&(b)->bdg_lock)

/*
 * NA(ifp)->bdg_port	port index
 */

#ifndef linux
static inline void prefetch (const void *x)
{
        __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));
}
#endif /* !linux */

// XXX only for multiples of 64 bytes, non overlapped.
static inline void
pkt_copy(void *_src, void *_dst, int l)
{
        uint64_t *src = _src;
        uint64_t *dst = _dst;
        if (unlikely(l >= 1024)) {
                bcopy(src, dst, l);
                return;
        }
        for (; likely(l > 0); l-=64) {
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
                *dst++ = *src++;
        }
}

#endif /* NM_BRIDGE */


static void
nm_if_rele(struct ifnet *ifp)
{
#ifndef NM_BRIDGE
	if_rele(ifp);
#else /* NM_BRIDGE */
	int i;
	struct nm_bridge *b = &nm_bridge;

	if (strncmp(ifp->if_xname, NM_NAME, sizeof(NM_NAME) - 1)) {
		if_rele(ifp);
		return;
	}
	if (!DROP_BDG_REF(ifp))
		return;
	BDG_LOCK(b);
	ND("want to disconnect %s from the bridge", ifp->if_xname);
	for (i = 0; i < NM_BDG_MAXPORTS; i++) {
		if (b->bdg_ports[i] == ifp) {
			b->bdg_ports[i] = NULL;
			bzero(ifp, sizeof(*ifp));
			free(ifp, M_DEVBUF);
			break;
		}
	}
	BDG_UNLOCK(b);
	if (i == NM_BDG_MAXPORTS)
		D("ouch, cannot find ifp to remove");
#endif /* NM_BRIDGE */
}


/*
 * get a refcounted reference to an interface.
 * Return ENXIO if the interface does not exist, EINVAL if netmap
 * is not supported by the interface.
 * If successful, hold a reference.
 */
static int
get_ifp(const char *name, struct ifnet **ifp)
{
#ifdef NM_BRIDGE
	struct ifnet *iter = NULL;
	struct nm_bridge *b = &nm_bridge;

	do {
		int i, l, cand = -1;

		if (strncmp(name, NM_NAME, sizeof(NM_NAME) - 1))
			break;
		D("looking for a virtual bridge %s", name);
		/* XXX locking */
		BDG_LOCK(b);
		/* lookup in the local list of bridges */
		for (i = 0; i < NM_BDG_MAXPORTS; i++) {
			iter = b->bdg_ports[i];
			if (iter == NULL) {
				if (cand == -1)
					cand = i; /* potential insert point */
				continue;
			}
			if (!strcmp(iter->if_xname, name)) {
				ADD_BDG_REF(iter);
				D("found existing interface");
				BDG_UNLOCK(b);
				break;
			}
		}
		if (i < NM_BDG_MAXPORTS) /* already unlocked */
			break;
		if (cand == -1) {
			D("bridge full, cannot create new port");
no_port:
			BDG_UNLOCK(b);
			*ifp = NULL;
			return EINVAL;
		}
		D("create new bridge port %s", name);
		/* space for forwarding list after the ifnet */
		l = sizeof(*iter) +
			 sizeof(struct nm_bdg_fwd)*NM_BDG_BATCH ;
		iter = malloc(l, M_DEVBUF, M_NOWAIT | M_ZERO);
		if (!iter)
			goto no_port;
		strcpy(iter->if_xname, name);
		bdg_netmap_attach(iter);
		b->bdg_ports[cand] = iter;
		ADD_BDG_REF(iter);
		BDG_UNLOCK(b);
		D("attaching virtual bridge");
	} while (0);
	*ifp = iter;
	if (! *ifp)
#endif /* NM_BRIDGE */
	*ifp = ifunit_ref(name);
	if (*ifp == NULL)
		return (ENXIO);
	/* can do this if the capability exists and if_pspare[0]
	 * points to the netmap descriptor.
	 */
	if ((*ifp)->if_capabilities & IFCAP_NETMAP && NA(*ifp))
		return 0;	/* valid pointer, we hold the refcount */
	nm_if_rele(*ifp);
	return EINVAL;	// not NETMAP capable
}


#ifdef NM_BRIDGE
/*
 *---- support for virtual bridge -----
 */

/* ----- FreeBSD if_bridge hash function ------- */

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 *
 * http://www.burtleburtle.net/bob/hash/spooky.html
 */
#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static __inline uint32_t
nm_bridge_rthash(const uint8_t *addr)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key

        b += addr[5] << 8;
        b += addr[4];
        a += addr[3] << 24;
        a += addr[2] << 16;
        a += addr[1] << 8;
        a += addr[0];

        mix(a, b, c);
#define BRIDGE_RTHASH_MASK	(NM_BDG_HASH-1)
        return (c & BRIDGE_RTHASH_MASK);
}

#undef mix


static int
bdg_netmap_reg(struct ifnet *ifp, int onoff)
{
	int i, err = 0;
	struct nm_bridge *b = &nm_bridge;

	BDG_LOCK(b);
	if (onoff) {
		/* the interface must be already in the list.
		 * only need to mark the port as active
		 */
		D("should attach %s to the bridge", ifp->if_xname);
		for (i=0; i < NM_BDG_MAXPORTS; i++)
			if (b->bdg_ports[i] == ifp)
				break;
		if (i == NM_BDG_MAXPORTS) {
			D("no more ports available");
			err = EINVAL;
			goto done;
		}
		D("setting %s in netmap mode", ifp->if_xname);
		ifp->if_capenable |= IFCAP_NETMAP;
		NA(ifp)->bdg_port = i;
		b->act_ports |= (1<<i);
		b->bdg_ports[i] = ifp;
	} else {
		/* should be in the list, too -- remove from the mask */
		D("removing %s from netmap mode", ifp->if_xname);
		ifp->if_capenable &= ~IFCAP_NETMAP;
		i = NA(ifp)->bdg_port;
		b->act_ports &= ~(1<<i);
	}
done:
	BDG_UNLOCK(b);
	return err;
}


static int
nm_bdg_flush(struct nm_bdg_fwd *ft, int n, struct ifnet *ifp, struct nm_bridge *b)
{
	int i, ifn;
	uint64_t all_dst, dst;
	uint32_t sh, dh;
	uint64_t mysrc = 1 << NA(ifp)->bdg_port;
	uint64_t smac, dmac;
	struct netmap_slot *slot;

	ND("prepare to send %d packets, act_ports 0x%x", n, b->act_ports);
	/* only consider valid destinations */
	all_dst = (b->act_ports & ~mysrc);
	/* first pass: hash and find destinations */
	for (i = 0; likely(i < n); i++) {
		uint8_t *buf = ft[i].buf;
		dmac = le64toh(*(uint64_t *)(buf)) & 0xffffffffffff;
		smac = le64toh(*(uint64_t *)(buf + 4));
		smac >>= 16;
		if (unlikely(netmap_verbose)) {
		    uint8_t *s = buf+6, *d = buf;
		    D("%d len %4d %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
			i,
			ft[i].len,
			s[0], s[1], s[2], s[3], s[4], s[5],
			d[0], d[1], d[2], d[3], d[4], d[5]);
		}
		/*
		 * The hash is somewhat expensive, there might be some
		 * worthwhile optimizations here.
		 */
		if ((buf[6] & 1) == 0) { /* valid src */
		    	uint8_t *s = buf+6;
			sh = nm_bridge_rthash(buf+6); // XXX hash of source
			/* update source port forwarding entry */
			b->ht[sh].mac = smac;	/* XXX expire ? */
			b->ht[sh].ports = mysrc;
			if (netmap_verbose)
			    D("src %02x:%02x:%02x:%02x:%02x:%02x on port %d",
				s[0], s[1], s[2], s[3], s[4], s[5], NA(ifp)->bdg_port);
		}
		dst = 0;
		if ( (buf[0] & 1) == 0) { /* unicast */
		    	uint8_t *d = buf;
			dh = nm_bridge_rthash(buf); // XXX hash of dst
			if (b->ht[dh].mac == dmac) {	/* found dst */
				dst = b->ht[dh].ports;
				if (netmap_verbose)
				    D("dst %02x:%02x:%02x:%02x:%02x:%02x to port %x",
					d[0], d[1], d[2], d[3], d[4], d[5], (uint32_t)(dst >> 16));
			}
		}
		if (dst == 0)
			dst = all_dst;
		dst &= all_dst; /* only consider valid ports */
		if (unlikely(netmap_verbose))
			D("pkt goes to ports 0x%x", (uint32_t)dst);
		ft[i].dst = dst;
	}

	/* second pass, scan interfaces and forward */
	all_dst = (b->act_ports & ~mysrc);
	for (ifn = 0; all_dst; ifn++) {
		struct ifnet *dst_ifp = b->bdg_ports[ifn];
		struct netmap_adapter *na;
		struct netmap_kring *kring;
		struct netmap_ring *ring;
		int j, lim, sent, locked;

		if (!dst_ifp)
			continue;
		ND("scan port %d %s", ifn, dst_ifp->if_xname);
		dst = 1 << ifn;
		if ((dst & all_dst) == 0)	/* skip if not set */
			continue;
		all_dst &= ~dst;	/* clear current node */
		na = NA(dst_ifp);

		ring = NULL;
		kring = NULL;
		lim = sent = locked = 0;
		/* inside, scan slots */
		for (i = 0; likely(i < n); i++) {
			if ((ft[i].dst & dst) == 0)
				continue;	/* not here */
			if (!locked) {
				kring = &na->rx_rings[0];
				ring = kring->ring;
				lim = kring->nkr_num_slots - 1;
				na->nm_lock(dst_ifp, NETMAP_RX_LOCK, 0);
				locked = 1;
			}
			if (unlikely(kring->nr_hwavail >= lim)) {
				if (netmap_verbose)
					D("rx ring full on %s", ifp->if_xname);
				break;
			}
			j = kring->nr_hwcur + kring->nr_hwavail;
			if (j > lim)
				j -= kring->nkr_num_slots;
			slot = &ring->slot[j];
			ND("send %d %d bytes at %s:%d", i, ft[i].len, dst_ifp->if_xname, j);
			pkt_copy(ft[i].buf, NMB(slot), ft[i].len);
			slot->len = ft[i].len;
			kring->nr_hwavail++;
			sent++;
		}
		if (locked) {
			ND("sent %d on %s", sent, dst_ifp->if_xname);
			if (sent)
				selwakeuppri(&kring->si, PI_NET);
			na->nm_lock(dst_ifp, NETMAP_RX_UNLOCK, 0);
		}
	}
	return 0;
}

/*
 * main dispatch routine
 */
static int
bdg_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int i, j, k, lim = kring->nkr_num_slots - 1;
	struct nm_bdg_fwd *ft = (struct nm_bdg_fwd *)(ifp + 1);
	int ft_i;	/* position in the forwarding table */

	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);
	if (do_lock)
		na->nm_lock(ifp, NETMAP_TX_LOCK, ring_nr);

	if (netmap_bridge <= 0) { /* testing only */
		j = k; // used all
		goto done;
	}
	if (netmap_bridge > NM_BDG_BATCH)
		netmap_bridge = NM_BDG_BATCH;

	ft_i = 0;	/* start from 0 */
	for (j = kring->nr_hwcur; likely(j != k); j = unlikely(j == lim) ? 0 : j+1) {
		struct netmap_slot *slot = &ring->slot[j];
		int len = ft[ft_i].len = slot->len;
		char *buf = ft[ft_i].buf = NMB(slot);

		prefetch(buf);
		if (unlikely(len < 14))
			continue;
		if (unlikely(++ft_i == netmap_bridge))
			ft_i = nm_bdg_flush(ft, ft_i, ifp, &nm_bridge);
	}
	if (ft_i)
		ft_i = nm_bdg_flush(ft, ft_i, ifp, &nm_bridge);
	/* count how many packets we sent */
	i = k - j;
	if (i < 0)
		i += kring->nkr_num_slots;
	kring->nr_hwavail = kring->nkr_num_slots - 1 - i;
	if (j != k)
		D("early break at %d/ %d, avail %d", j, k, kring->nr_hwavail);

done:
	kring->nr_hwcur = j;
	ring->avail = kring->nr_hwavail;
	if (do_lock)
		na->nm_lock(ifp, NETMAP_TX_UNLOCK, ring_nr);

	if (netmap_verbose)
		D("%s ring %d lock %d", ifp->if_xname, ring_nr, do_lock);
	return 0;
}

static int
bdg_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	int j, n, lim = kring->nkr_num_slots - 1;
	u_int k = ring->cur, resvd = ring->reserved;

	ND("%s ring %d lock %d avail %d",
		ifp->if_xname, ring_nr, do_lock, kring->nr_hwavail);

	if (k > lim)
		return netmap_ring_reinit(kring);
	if (do_lock)
		na->nm_lock(ifp, NETMAP_RX_LOCK, ring_nr);

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur;    /* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}

	if (j != k) { /* userspace has released some packets. */
		n = k - j;
		if (n < 0)
			n += kring->nkr_num_slots;
		ND("userspace releases %d packets", n);
                for (n = 0; likely(j != k); n++) {
                        struct netmap_slot *slot = &ring->slot[j];
                        void *addr = NMB(slot);

                        if (addr == netmap_buffer_base) { /* bad buf */
                                if (do_lock)
                                        na->nm_lock(ifp, NETMAP_RX_UNLOCK, ring_nr);
                                return netmap_ring_reinit(kring);
                        }
			/* decrease refcount for buffer */

			slot->flags &= ~NS_BUF_CHANGED;
                        j = unlikely(j == lim) ? 0 : j + 1;
                }
                kring->nr_hwavail -= n;
                kring->nr_hwcur = k;
        }
        /* tell userspace that there are new packets */
        ring->avail = kring->nr_hwavail - resvd;

	if (do_lock)
		na->nm_lock(ifp, NETMAP_RX_UNLOCK, ring_nr);
	return 0;
}

static void
bdg_netmap_attach(struct ifnet *ifp)
{
	struct netmap_adapter na;

	D("attaching virtual bridge");
	bzero(&na, sizeof(na));

	na.ifp = ifp;
	na.separate_locks = 1;
	na.num_tx_desc = NM_BRIDGE_RINGSIZE;
	na.num_rx_desc = NM_BRIDGE_RINGSIZE;
	na.nm_txsync = bdg_netmap_txsync;
	na.nm_rxsync = bdg_netmap_rxsync;
	na.nm_register = bdg_netmap_reg;
	netmap_attach(&na, 1);
}

#endif /* NM_BRIDGE */
