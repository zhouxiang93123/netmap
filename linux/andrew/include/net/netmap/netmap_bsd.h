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
 * $Id$
 *
 * $FreeBSD$
 *
 * The header contains the definitions of constants and function
 * prototypes used only in kernelspace.
 */

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_NETMAP);
#endif

#define ND(format, ...)
#define D(format, ...)					\
	do {						\
		struct timeval __xxts;			\
		microtime(&__xxts);                     \
		printf("%03d.%06d %s [%d] " format "\n",                \
		(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec,		\
		__FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

typedef struct if_net interface_t;
#define IFC_NAME(ifc) (ifc->xname)
#define IFC_UNREF(ifc)  if_rele((ifc))


/*
 * return a pointer to the struct netmap adapter from the ifp
 */
#define	NA(_ifp)	((struct netmap_adapter *)(_ifp)->if_pspare[0])


/*
 * The combination of "enable" (ifp->if_capabilities &IFCAP_NETMAP)
 * and refcount gives the status of the interface, namely:
 *
 *	enable	refcount	Status
 *
 *	FALSE	0		normal operation
 *	FALSE	!= 0		-- (impossible)
 *	TRUE	1		netmap mode
 *	TRUE	0		being deleted.
 */

#define NETMAP_DELETING(_na)  (  ((_na)->refcount == 0) &&	\
	( (_na)->ifp->if_capenable & IFCAP_NETMAP) )


/*
 * XXX eventually, get rid of netmap_total_buffers and netmap_buffer_base
 * in favour of the structure
 */
// struct netmap_buf_pool;
// extern struct netmap_buf_pool nm_buf_pool;
extern u_int netmap_total_buffers;
extern char *netmap_buffer_base;

/*
 * return the address of a buffer.
 * XXX this is a special version with hardwired 2k bufs
 * On error return netmap_buffer_base which is detected as a bad pointer.
 */
static inline char *
NMB(struct netmap_slot *slot)
{
	uint32_t i = slot->buf_idx;
	return (i >= netmap_total_buffers) ? netmap_buffer_base :
		netmap_buffer_base + (i << 11);
}

/*
 * lock and unlock for the netmap memory allocator
 */
#define NMA_LOCK()	mtx_lock(&netmap_mem_d->nm_mtx);
#define NMA_UNLOCK()	mtx_unlock(&netmap_mem_d->nm_mtx);


/*
 * support routines for individual drivers
 *
 * netmap_load_map/netmap_reload_map are helper routines to set/reset
 *	the dmamap for a packet buffer
 *
 * netmap_reset() is a helper routine to be called in the driver
 *	when reinitializing a ring.
 */

void netmap_load_map(bus_dma_tag_t tag, bus_dmamap_t map,
        void *buf, bus_size_t buflen);
void netmap_reload_map(bus_dma_tag_t tag, bus_dmamap_t map,
        void *buf, bus_size_t buflen);
