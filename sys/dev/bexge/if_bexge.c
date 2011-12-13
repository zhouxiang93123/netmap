/*-
 * Copyright (c) 2011 Luigi Rizzo, Univ. di Pisa
 * All rights reserved.
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
 *
 * from: head/sys/dev/nxge/if_nxge.c 207554 2010-05-03 07:32:50Z sobomax
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>		// device_method_t
#include <sys/module.h>		// declare_module
#include <sys/conf.h>
#include <sys/types.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <machine/pci_cfgreg.h>

#include <sys/socket.h>	// ifru_addr
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>
#include <net/if_arp.h>

typedef	uint8_t		bool;
typedef	uint8_t		u8;
typedef	uint16_t	u16;
typedef	uint32_t	u32;
typedef	uint64_t	u64;
typedef unsigned long	ulong;
typedef volatile int	atomic_t;
typedef	void *		dma_addr_t;

#define __iomem
#define BUG_ON(x)
#define	DEFINE_DMA_UNMAP_ADDR(x)

#define	VLAN_N_VID	16	// XXX 4096
#define pci_read_config_dword(d, r, x)	(*(x) = pci_read_config(d, r, 4))
#define pci_read_config_word(d, r, x)	(*(x) = pci_read_config(d, r, 2))
#define pci_read_config_byte(d, r, x)	(*(x) = pci_read_config(d, r, 1))
#define pci_write_config_byte(d, r, x)	(pci_write_config(d, r, x, 1))
struct mutex {
};
typedef struct mutex spinlock_t;

struct msix_entry {
};
struct delayed_work {
};
struct completion {
};
struct napi_struct {
};

#define	sk_buf	mbuf

#define	ETH_ALEN	ETHER_ADDR_LEN
struct pci_dev {
	int vendor;
	int device;
};

#include <dev/bexge/be.h>

static struct pci_dev be_dev_ids[] = {
	{ BE_VENDOR_ID, BE_DEVICE_ID1 },
	{ BE_VENDOR_ID, BE_DEVICE_ID2 },
	{ BE_VENDOR_ID, OC_DEVICE_ID1 },
	{ BE_VENDOR_ID, OC_DEVICE_ID2 },
	{ EMULEX_VENDOR_ID, OC_DEVICE_ID3 },
	{ 0 }
};


/**
 * Returns
 * BUS_PROBE_DEFAULT if device is supported
 * ENXIO if device is not supported
 */
int
be_probe(device_t dev)
{
	int  devid    = pci_get_device(dev);
	int  vendorid = pci_get_vendor(dev);
	int  retValue = ENXIO;
	struct pci_dev *p;

	for (p = be_dev_ids; p->vendor || p->device; p++) {
		if (p->vendor == vendorid && p->device == devid)
	        	return BUS_PROBE_DEFAULT;
	}

	return ENXIO;
}

/**
 * be_attach
 * Connects driver to the system if probe was success
 */
int
be_attach(device_t dev)
{
	return ENXIO;
}

/**
 * be_detach
 * Detaches driver from the Kernel subsystem
 */
int
be_detach(device_t dev)
{
}

/**
 * be_shutdown
 * To shutdown device before system shutdown
 */
int
be_shutdown(device_t dev)
{
	return 0;
}


/**
 * be_methods
 *
 * FreeBSD device interface entry points
 */
static device_method_t be_methods[] = {
	DEVMETHOD(device_probe,     be_probe),
	DEVMETHOD(device_attach,    be_attach),
	DEVMETHOD(device_detach,    be_detach),
	DEVMETHOD(device_shutdown,  be_shutdown),
	{0, 0}
};

static driver_t be_driver = {
	"be",
	be_methods,
	sizeof(int), // XXX
};


static devclass_t be_devclass;

DRIVER_MODULE(be, pci, be_driver, be_devclass, 0, 0);
