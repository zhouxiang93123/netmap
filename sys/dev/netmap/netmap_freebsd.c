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

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>        /* bus_dmamap_* */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>


/* ======================== FREEBSD-SPECIFIC ROUTINES ================== */

/*
 * second argument is non-zero to intercept, 0 to restore
 */
int
netmap_catch_rx(struct netmap_adapter *na, int intercept)
{
    struct ifnet *ifp = na->ifp;

    if (intercept) {
        if (na->save_if_input) {
            D("cannot intercept again");
            return EINVAL; /* already set */
        }
        na->save_if_input = ifp->if_input;
        ifp->if_input = generic_rx_handler;
    } else {
        if (!na->save_if_input){
            D("cannot restore");
            return EINVAL;  /* not saved */
        }
        ifp->if_input = na->save_if_input;
        na->save_if_input = NULL;
    }

    return 0;
}

/* Transmit routine used by generic_netmap_txsync(). Returns 0 on success
   and -1 on error (which may be packet drops or other errors). */
int generic_xmit_frame(struct ifnet *ifp, struct mbuf *m,
	void *addr, u_int len, u_int ring_nr)
{
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

void netmap_mitigation_init(struct netmap_adapter *na)
{
    na->mit_pending = 0;
}

extern unsigned int netmap_generic_mit;

void netmap_mitigation_start(struct netmap_adapter *na)
{
}

void netmap_mitigation_restart(struct netmap_adapter *na)
{
}

int netmap_mitigation_active(struct netmap_adapter *na)
{
    return 0;
}

void netmap_mitigation_cleanup(struct netmap_adapter *na)
{
}

