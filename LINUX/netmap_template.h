#ifndef NETMAP_TEMPLATE_H
#define NETMAP_TEMPLATE_H

#define nmt_concat(a, b)  a ## _ ## b
#define nmt_xconcat(a, b) nmt_concat(a, b)


#define nmt_name(f) nmt_xconcat(nmt, nmt_xconcat(NMT_DRVNAME, f))
#define nmt_callback(c) nmt_xconcat(NMT_DRVNAME, nmt_xconcat(netmap, c))

#define NMT_STATE			\
	struct ifnet *ifp;		\
	u_int ring_nr;			\
	int flags;			\
	struct SOFTC_T *adapter;	\
	struct netmap_adapter *na;	\
	struct netmap_kring *kring;	\
	struct netmap_ring *ring;	\
	u_int j, k, l, n, lim;		\
	struct netmap_slot *slot;	\
	void *addr;			\
	uint64_t paddr;			\

#define NMT_TXSTATE			\
struct nmt_txstate {			\
/* common state */			\
	NMT_STATE			\
/* tx specific state */			\
	int delta;			\
	u_int len;			\
/* nic specific tx state */		\
	NMT_TXDRVSTATE			\
};

#define NMT_RXSTATE			\
struct nmt_rxstate {			\
/* common state */			\
	NMT_STATE			\
/* rx specific state */			\
	int resvd;			\
	int force_update;		\
	int slot_flags;			\
/* nic specific rx state */		\
	NMT_RXDRVSTATE			\
};

struct nmt_txstate;
typedef struct nmt_txstate nmt_txstate;

struct nmt_rxstate;
typedef struct nmt_rxstate nmt_rxstate;

#endif
