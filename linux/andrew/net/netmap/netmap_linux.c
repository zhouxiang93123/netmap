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
 * $Id: netmap.c 8972 2011-07-04 09:39:32Z luigi $
 *
 * This module supports memory mapped access to network devices,
 * see netmap(4).
 *
 * The module uses a large, memory pool allocated by the kernel
 * and accessible as mmapped memory by multiple userspace threads/processes.
 * The memory pool contains packet buffers and "netmap rings",
 * i.e. user-accessible copies of the interface's queues.
 *
 * Access to the network card works like this:
 * 1. a process/thread issues one or more open() on /dev/netmap, to create
 *    select()able file descriptor on which events are reported.
 * 2. on each descriptor, the process issues an ioctl() to identify
 *    the interface that should report events to the file descriptor.
 * 3. on each descriptor, the process issues an mmap() request to
 *    map the shared memory region within the process' address space.
 *    The list of interesting queues is indicated by a location in
 *    the shared memory region.
 * 4. using the functions in the netmap(4) userspace API, a process
 *    can look up the occupation state of a queue, access memory buffers,
 *    and retrieve received packets or enqueue packets to transmit.
 * 5. using some ioctl()s the process can synchronize the userspace view
 *    of the queue with the actual status in the kernel. This includes both
 *    receiving the notification of new packets, and transmitting new
 *    packets on the output interface.
 * 6. select() or poll() can be used to wait for events on individual
 *    transmit or receive queues (or all queues for a given interface).
 */

#include <linux/if.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/netdevice.h>
#include <net/netmap.h>
#include <net/netmap/netmap_kern.h>


static int no_timestamp;

#ifdef notyet
SYSCTL_NODE(_dev, OID_AUTO, netmap, CTLFLAG_RW, 0, "Netmap args");
SYSCTL_INT(_dev_netmap, OID_AUTO, verbose,
    CTLFLAG_RW, &netmap_verbose, 0, "Verbose mode");
SYSCTL_INT(_dev_netmap, OID_AUTO, no_timestamp,
    CTLFLAG_RW, &no_timestamp, 0, "no_timestamp");
SYSCTL_INT(_dev_netmap, OID_AUTO, skip_poll,
    CTLFLAG_RW, &skip_poll, 0, "skip_poll");
SYSCTL_INT(_dev_netmap, OID_AUTO, total_buffers,
    CTLFLAG_RD, &nm_buf_pool.total_buffers, 0, "total_buffers");
SYSCTL_INT(_dev_netmap, OID_AUTO, free_buffers,
    CTLFLAG_RD, &nm_buf_pool.free, 0, "free_buffers");
#endif

/* Descriptor of the memory objects handled by our memory allocator.
 * XXX mostly copied from the bsd version, should re-organize this
 * to share code better
 */
struct netmap_mem_obj {
    struct list_head nmo_next;
    int nmo_used; /* flag set on used memory objects. */
    size_t nmo_size; /* size of the memory area reserved for the object. */
    void *nmo_data; /* pointer to the memory area. */
};


/* Descriptor of our custom memory allocator. */
struct netmap_mem_d {
    struct mutex nm_mtx; /* lock used to handle the chain of memory
                            objects. */
    struct list_head nm_molist;  /* list of memory objects */
    size_t nm_size; /* total amount of memory used for rings etc. */
    void *nm_buffer; /* pointer to the whole pre-allocated memory area. */

    /* space used for actual packet buffers */
    u_int nchunks;
    u_int chunksize;
    char** chunks;

    size_t nm_totalsize; /* total of memory for rings/etc plus buffers */
};

static struct netmap_mem_d netmap_mem; /* Our memory allocator. */

void NMA_LOCK() { mutex_lock(&netmap_mem.nm_mtx); }
void NMA_UNLOCK() { mutex_unlock(&netmap_mem.nm_mtx); }


/*------ netmap memory allocator -------*/
/*
 * Request for a chunk of memory.
 *
 * Memory objects are arranged into a list, hence we need to walk this
 * list until we find an object with the needed amount of data free. 
 * This sounds like a completely inefficient implementation, but given
 * the fact that data allocation is done once, we can handle it
 * flawlessly.
 *
 * Return NULL on failure.
 */
void *
netmap_malloc(size_t size, const char *msg)
{
    struct netmap_mem_obj* mem_obj;
    void *ret = NULL;

    NMA_LOCK();
    list_for_each_entry(mem_obj, &netmap_mem.nm_molist, nmo_next) {
        if (mem_obj->nmo_used != 0 || mem_obj->nmo_size < size) {
            continue;
        }

        if (size == mem_obj->nmo_size) {
            mem_obj->nmo_used = 1;
            memset(mem_obj->nmo_data, 0, mem_obj->nmo_size);
            ret = mem_obj->nmo_data;
        }
        else {
            struct netmap_mem_obj* new_mem_obj;
            new_mem_obj = kzalloc(sizeof(struct netmap_mem_obj), GFP_KERNEL);

            list_add(&new_mem_obj->nmo_next, &mem_obj->nmo_next);

            new_mem_obj->nmo_used = 1;
            new_mem_obj->nmo_size = size;
            new_mem_obj->nmo_data = mem_obj->nmo_data;
            memset(new_mem_obj->nmo_data, 0, new_mem_obj->nmo_size);

            mem_obj->nmo_size -= size;
            mem_obj->nmo_data = (char *) mem_obj->nmo_data + size;

            ret = new_mem_obj->nmo_data;
        }

        break;
    }

    NMA_UNLOCK();
    ND("%s: %d bytes at %p", msg, size, ret);

    return (ret);
}

/*
 * Return the memory to the allocator.
 *
 * While freeing a memory object, we try to merge adjacent chunks in
 * order to reduce memory fragmentation.
 */
void
netmap_free(void *addr, const char *msg)
{
    size_t size;
    struct netmap_mem_obj *cur, *prev, *next;

    if (addr == NULL) {
        D("NULL addr for %s", msg);
        return;
    }

    NMA_LOCK();
    list_for_each_entry(cur, &netmap_mem.nm_molist, nmo_next) {
        if (cur->nmo_data == addr && cur->nmo_used)
            break;
    }

    if (cur == NULL) {
        NMA_UNLOCK();
        D("invalid addr %s %p", msg, addr);
        return;
    }

    size = cur->nmo_size;
    cur->nmo_used = 0;

    /* merge current chunk of memory with the previous one,
       if present. */
    prev = list_entry(cur->nmo_next.prev, struct netmap_mem_obj, nmo_next);
    if (prev && prev->nmo_used == 0) {
        list_del(&cur->nmo_next);
        prev->nmo_size += cur->nmo_size;
        kfree(cur);
        cur = prev;
    }

    /* merge with the next one */
    next = list_entry(cur->nmo_next.next, struct netmap_mem_obj, nmo_next);
    if (next && next->nmo_used == 0) {
        list_del(&next->nmo_next);
        cur->nmo_size += next->nmo_size;
        kfree(next);
    }

    NMA_UNLOCK();
    ND("freed %s %d bytes at %p", msg, size, addr);
}

ssize_t netmap_ptr_to_buffer_offset(const char* p)
{
    return ((char*)netmap_mem.nm_buffer + netmap_mem.nm_size - p);
}

ssize_t netmap_off(void* p)
{
    return ((char*)p - (char*)netmap_mem.nm_buffer);
}
EXPORT_SYMBOL(netmap_off);



/* our buffer space is a bunch of "chunks".
 * for now the chunk size and number of chunks are hard-coded to
 * the page size, and a total of 64 MB.
 * this should be customizable, perhaps with module init arguments?
 */
#define TOTAL_BUFFER_SPACE (64*1024*1024)
#define BUFFER_CHUNK_ORDER (0)
#define TOTAL_CHUNKS (TOTAL_BUFFER_SPACE / (PAGE_SIZE << BUFFER_CHUNK_ORDER))

/*
 * A buffer takes 2k, a slot takes 8 bytes + ring overhead,
 * so the ratio is 200:1. In other words, we can use 1/200 of
 * the memory for the rings, and the rest for the buffers,
 * and be sure we never run out.
 */
#define NETMAP_MEMPOOL_SIZE  PAGE_ALIGN(TOTAL_BUFFER_SPACE/200)

static int netmap_memory_init(void)
{
    int i;
    u_int total_bufs;
    void* bitmap;
    struct netmap_mem_obj* mem_obj;
    
    netmap_mem.chunks = kzalloc(TOTAL_CHUNKS * sizeof(char*), GFP_KERNEL);
    if (netmap_mem.chunks == 0) {
        return (-ENOMEM);
    }

    netmap_mem.nchunks = TOTAL_CHUNKS;
    netmap_mem.chunksize = PAGE_SIZE << BUFFER_CHUNK_ORDER;
    D("allocating %lu chunks\n", TOTAL_CHUNKS);
    for (i=0; i<TOTAL_CHUNKS; i++) {
        netmap_mem.chunks[i]
            = (char*) __get_free_pages(GFP_KERNEL, BUFFER_CHUNK_ORDER);
        if (netmap_mem.chunks[i] == 0) {
            /* XXX cleanup */
            return (-ENOMEM);
        }
    }
    
    total_bufs = TOTAL_BUFFER_SPACE / NETMAP_BUF_SIZE;
    bitmap = kmalloc(total_bufs/8, GFP_KERNEL);
    if (bitmap == 0) { /* XXX */ return (-ENOMEM); }
    netmap_init_bufmap(NETMAP_BUF_SIZE, total_bufs, bitmap);

    mutex_init(&netmap_mem.nm_mtx);
    INIT_LIST_HEAD(&netmap_mem.nm_molist);

    netmap_mem.nm_buffer = kmalloc(NETMAP_MEMPOOL_SIZE, GFP_KERNEL);
    if (netmap_mem.nm_buffer == 0) {
        return (-ENOMEM);
    }
    netmap_mem.nm_size = NETMAP_MEMPOOL_SIZE;

    mem_obj = kzalloc(sizeof(struct netmap_mem_obj), GFP_KERNEL);
    list_add_tail(&mem_obj->nmo_next, &netmap_mem.nm_molist);
    mem_obj->nmo_used = 0;
    mem_obj->nmo_size = netmap_mem.nm_size;
    mem_obj->nmo_data = netmap_mem.nm_buffer;

    netmap_mem.nm_totalsize = netmap_mem.nm_size
        + (netmap_mem.nchunks * netmap_mem.chunksize);
    
    return (0);
}

static void netmap_memory_fini(void)
{
    int i;

    D("cleaning up");
    for (i=0; i<netmap_mem.nchunks; i++) {
        if (netmap_mem.chunks[i] != 0) {
            free_pages((unsigned long) netmap_mem.chunks[i], BUFFER_CHUNK_ORDER);
        }
    }

    /* kfree(netmap_mem.chunks); */
    /* XXX other structures too */
} 

char* NMB(struct netmap_slot *slot)
{
    u_int off = slot->buf_idx * NETMAP_BUF_SIZE;
    u_int32_t chunk = off / netmap_mem.chunksize;
    if (chunk >= netmap_mem.nchunks) { return (0); }

    return (netmap_mem.chunks[chunk] + (off % netmap_mem.chunksize));
}

EXPORT_SYMBOL(NMB);



#define NETMAP_MAJOR 61 /*XXX*/

static int netmap_mmap(struct file *, struct vm_area_struct *);
static int netmap_ioctl(struct inode *, struct file *,
                        unsigned int, unsigned long);
static unsigned int netmap_poll(struct file *, struct poll_table_struct *);
static int netmap_release(struct inode *, struct file *);


static struct file_operations netmap_fops = {
    .mmap = netmap_mmap,
    .ioctl = netmap_ioctl,
    .poll = netmap_poll,
    .release = netmap_release,
};

/*
 * Module loader.
 *
 * Create the /dev/netmap device and initialize all global
 * variables.
 *
 * Return 0 on success, errno on failure.
 */
static int __init netmap_init(void)
{
    int err;

    err = netmap_memory_init();
    if (err != 0) {
        printk(KERN_WARNING "netmap: unable to initialize the memory allocator.");
        return (err);
    }
    printk(KERN_INFO "netmap: loaded module with %d Mbytes\n",
           (netmap_mem.nchunks * netmap_mem.chunksize) >> 20);

    err = register_chrdev(NETMAP_MAJOR, "netmap", &netmap_fops);

    return (err);
}

static void __exit netmap_exit(void)
{
    unregister_chrdev(NETMAP_MAJOR, "netmap");
    
    netmap_memory_fini();

    printk(KERN_INFO "netmap: unloaded module.\n");
}

module_init(netmap_init);
module_exit(netmap_exit);




/*
 * mmap(2) support for the "netmap" device.
 *
 * Expose all the memory previously allocated by our custom memory
 * allocator: this way the user has only to issue a single mmap(2), and
 * can work on all the data structures flawlessly.
 *
 * Return 0 on success, -1 otherwise.
 */
static int
netmap_mmap(struct file *f, struct vm_area_struct *vma)
{
    int err = 0, i, j;
    unsigned long map_addr;

    if (vma->vm_pgoff != 0)
        return (-EINVAL);

    NMA_LOCK();

    if (netmap_mem.nm_totalsize != (vma->vm_end - vma->vm_start)) {
        err = -EINVAL;
        goto out;
    }

    map_addr = vma->vm_start;

    /* first map in the memory allocator pool */
    err = remap_pfn_range(vma, map_addr,
                          virt_to_phys(netmap_mem.nm_buffer) >> PAGE_SHIFT,
                          netmap_mem.nm_size, vma->vm_page_prot);
    if (err != 0) {
        goto out;
    }

    map_addr += netmap_mem.nm_size;
    
    /* now walk through our packet buffer chunks and map them */
    for (i=0; i<netmap_mem.nchunks; i++) {
        struct page* page = virt_to_page(netmap_mem.chunks[i]);
        for (j=0; j<(1<<BUFFER_CHUNK_ORDER); j++) {
            err = vm_insert_page(vma, map_addr, page);
            if (err != 0) { goto out; }
            page++;
            map_addr += PAGE_SIZE;
        }
    }

    err = 0;

out:
    NMA_UNLOCK();
    return (err);
}

/*
 * get a refcounted reference to an interface.
 * Return ENXIO if the interface does not exist, EINVAL if netmap
 * is not supported by the interface.
 * If successful, hold a reference.
 */
static int
get_netdev(const char *name, struct net_device **dev)
{
        *dev = dev_get_by_name(&init_net, name);
	if (*dev == NULL)
		return (-ENXIO);

	/* can do this if the capability exists and we have a netmap descriptor
	 */
        if ((*dev)->flags & IFCAP_NETMAP && NA(*dev))
		return 0;	/* valid pointer, we hold the refcount */

	dev_put(*dev);
	return (-EINVAL);	// not NETMAP capable
}

/*
 * ioctl(2) support for the "netmap" device.
 *
 * Following a list of accepted commands:
 * - NIOCGINFO
 * - SIOCGIFADDR	just for convenience
 * - NIOCREGIF
 * - NIOCUNREGIF
 * - NIOCTXSYNC
 * - NIOCRXSYNC
 *
 * Return 0 on success, errno otherwise.
 */
static int netmap_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg)
{
    int error = 0;
    struct netmap_priv_d *priv = file->private_data;
    struct nmreq nmr;
    struct net_device *dev;
    struct netmap_adapter *na;
    u_int i;
    struct netmap_if *nifp;

    if (copy_from_user(&nmr, (void*)arg, sizeof nmr) != 0) {
        return (-EFAULT);
    }

    D("ioctl %u", cmd);

    switch (cmd) {
    case NIOCGINFO:		/* return capabilities etc */
        nmr.nr_memsize = netmap_mem.nm_totalsize;
        nmr.nr_offset = 0;
        nmr.nr_numrings = 0;
        nmr.nr_numslots = 0;
        if (nmr.nr_name[0] == '\0')	/* just get memory info */
            break;

        error = get_netdev(nmr.nr_name, &dev); /* get a refcount */
        if (error) {
            D("get_netdev(%s) failed: %d", nmr.nr_name, error);
            break;
        }
        na = NA(dev); /* retrieve netmap_adapter */
        nmr.nr_numrings = na->num_queues;
        nmr.nr_numslots = na->num_tx_desc;
        dev_put(dev);	/* return the refcount */
        break;

    case NIOCREGIF:
        if (priv != NULL)	/* thread already registered */
            return netmap_set_ringid(priv, nmr.nr_ringid);

        /* find the interface and a reference */
        error = get_netdev(nmr.nr_name, &dev); /* keep reference */
        if (error)
            break;
        na = NA(dev); /* retrieve netmap adapter */

        /*
         * Allocate the private per-thread structure.
         * XXX perhaps we can use a blocking malloc ?
         */
        priv = kmalloc(sizeof(struct netmap_priv_d), GFP_KERNEL);
        if (priv == NULL) {
            error = ENOMEM;
            dev_put(dev);   /* return the refcount */
            break;
        }

        memset(priv, 0, sizeof(struct netmap_priv_d));

        for (i = 10; i > 0; i--) {
            na->nm_lock(dev, NETMAP_CORE_LOCK, 0);
            if (!NETMAP_DELETING(na))
                break;
            na->nm_lock(dev, NETMAP_CORE_UNLOCK, 0);
            msleep(10);
        }
        if (i == 0) {
            D("too many NIOCREGIF attempts, give up");
            error = -EINVAL;
            kfree(priv);
            dev_put(dev);	/* return the refcount */
            break;
        }

        priv->np_ifp = dev;	/* store the reference */
        error = netmap_set_ringid(priv, nmr.nr_ringid);
        if (error)
            goto error;

        nifp = netmap_if_new(nmr.nr_name, na);
        D("netmap_if_new completed");
        priv->np_nifp = nifp;

        if (nifp == NULL) { /* allocation failed */
            error = ENOMEM;
        }
        else {
            /* Otherwise set the card in netmap mode
             * and make it use the shared buffers.
             */
            error = na->nm_register(dev, 1); /* mode on */
            D("nm_register returned %d", error);
            if (error) {
                /*
                 * do something similar to netmap_dtor().
                 */
                netmap_free(na->tx_rings[0].ring, "rings, reg.failed");
                kfree(na->tx_rings);
                na->tx_rings = na->rx_rings = NULL;
                na->refcount--;
                netmap_free(nifp, "nifp, rings failed");
                nifp = NULL;
            }
        }
        na->nm_lock(dev, NETMAP_CORE_UNLOCK, 0);

        if (error) {	/* reg. failed, release priv and ref */
        error:
            kfree(priv);
            dev_put(dev);	/* return the refcount */
            break;
        }

        file->private_data = priv;

        if (error != 0) {
            /* could not assign the private storage for the
             * thread, call the destructor explicitly.
             */
            netmap_cleanup(priv);
            break;
        }

        /* return the offset of the netmap_if object */
        nmr.nr_numrings = na->num_queues;
        nmr.nr_numslots = na->num_tx_desc;
        nmr.nr_memsize = netmap_mem.nm_totalsize;
        nmr.nr_offset = ((char *) nifp - (char *) netmap_mem.nm_buffer);
        break;

    case NIOCUNREGIF:
        if (priv == NULL)
            return (-ENXIO);

        netmap_cleanup(priv);
        file->private_data = 0;
        break;

    case NIOCTXSYNC:
    case NIOCRXSYNC:
        if (priv == NULL)
            return (ENXIO);
        dev = priv->np_ifp;	/* we have a reference */
        na = NA(dev); /* retrieve netmap adapter */

        if (na->flags & NR_REINIT)
            netmap_clean_reinit(na);

        if (priv->np_qfirst == na->num_queues) {
            /* queues to/from host */
            if (cmd == NIOCTXSYNC)
                netmap_sync_to_host(na);
            else
                netmap_sync_from_host(na);
            return error;
        }

        for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
            if (cmd == NIOCTXSYNC) {
                struct netmap_kring *kring = &na->tx_rings[i];
                if (netmap_verbose & NM_VERB_TXSYNC)
                    D("sync tx ring %d cur %d hwcur %d",
                      i, kring->ring->cur,
                      kring->nr_hwcur);
                na->nm_txsync(dev, i, 1 /* do lock */);
                if (netmap_verbose & NM_VERB_TXSYNC)
                    D("after sync tx ring %d cur %d hwcur %d",
                      i, kring->ring->cur,
                      kring->nr_hwcur);
            } else {
                na->nm_rxsync(dev, i, 1 /* do lock */);
                do_gettimeofday(&na->rx_rings[i].ring->ts);
            }
        }

        break;

    default:
#ifdef notyet
        error = get_netdev(nmr.nr_name, &dev); /* keep reference */
        if (error)
            break;
        {
            /*
             * allow device calls
             */
            struct socket so;
            bzero(&so, sizeof(so));
            so.so_vnet = ifp->if_vnet;
            // so->so_proto not null.
            error = ifioctl(&so, cmd, data, td);
        }
        dev_put(dev);
#else
        error = -EINVAL;
#endif
    }

    if (copy_to_user((void*) arg, &nmr, sizeof nmr) != 0) {
        error = -EFAULT;
    }

    return (error);
}


/*
 * select(2) and poll(2) handlers for the "netmap" device.
 *
 * Can be called for one or more queues.
 * Return true the event mask corresponding to ready events.
 * If there are no ready events, do a selrecord on either individual
 * selfd or on the global one.
 * Device-dependent parts (locking and sync of tx/rx rings)
 * are done through callbacks.
 */
static unsigned int netmap_poll(struct file * file,
                                struct poll_table_struct *poll)
{
    struct netmap_priv_d *priv = file->private_data;
    struct net_device *dev = priv->np_ifp;
    struct netmap_adapter *na = NA(dev);
    struct netmap_kring *kring;
    u_int mask = 0, i;

    if (na == 0 || (! na->nm_isactive(dev)) || NETMAP_DELETING(na)) {
        D("na=%p, active=%d, refcount=%d",
          na, (na ? na->nm_isactive(dev) : 0),
          ( na ? na->refcount : 0));
          
        return (POLLERR);
    }

    if (netmap_verbose & 0x8000)
        D("device %s", dev->name);

    /* pending reinit, report up as a poll error. Pending
     * reads and writes are lost.
     */
    if (na->flags & NR_REINIT) {
        netmap_clean_reinit(na);
        mask |= POLLERR;
    }

#ifdef notyet
    if (priv->np_qfirst == na->num_queues) {
        /* push any packets up, then we are always ready */
        kring = &na->tx_rings[i];
        netmap_sync_to_host(na);
        mask |= POLLOUT | POLLWRNORM;

        /* check receive... */
        kring = &na->rx_rings[i];
        D("poll_wait on %p", &kring->waitq);
        poll_wait(file, &kring->waitq, poll);
        D("avail=%u", kring->ring->avail);
        if (kring->ring->avail == 0)
            netmap_sync_from_host(na);

        D("avail=%u", kring->ring->avail);
        if (kring->ring->avail > 0) {
            mask |= POLLIN | POLLRDNORM;
        }
    }
#endif

    /*
     * We start with a lock free round which is good if we have
     * data available. If this fails, then lock and call the sync
     * routines.
     */
    for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
        kring = &na->rx_rings[i];
        D("poll_wait on %p", &kring->waitq);
        poll_wait(file, &kring->waitq, poll);
        if (kring->ring->avail > 0) {
            mask |= POLLIN | POLLRDNORM;
        }

#ifdef notyet
        kring = &na->tx_rings[i];
        poll_wait(file, &kring->waitq, poll);
        if (kring->ring->avail > 0) {
            mask |= POLLOUT | POLLWRNORM;
        }
#endif
    }

    D("after lock-free, mask=%x", mask);

    if (mask != 0) { return (mask); }
    
    /*
     * If the card has only one lock, we just use that.
     * If the card has separate ring locks, we just use those
     * unless we are doing check_all, in which case the whole
     * loop is wrapped by the global lock.
     * We acquire locks only when necessary: if poll is called
     * when buffers are available, we can just return without locks.
     *
     * rxsync() is only called if we run out of buffers on a POLLIN.
     * txsync() is called if we run out of buffers on POLLOUT, or
     * there are pending packets to send. The latter can be disabled
     * passing NETMAP_NO_TX_POLL in the NIOCREG call.
     */

    /*
     * core_lock indicates what to do with the core lock.
     * The core lock is used when either the card has no individual
     * locks, or it has individual locks but we are cheking all
     * rings so we need the core lock to avoid missing wakeup events.
     *
     * It has three possible states:
     * NO_CL	we don't need to use the core lock, e.g.
     *		because we are protected by individual locks.
     * NEED_CL	we need the core lock. In this case, when we
     *		call the lock routine, move to LOCKED_CL
     *		to remember to release the lock once done.
     * LOCKED_CL	core lock is set, so we need to release it.
     */
    enum {NO_CL, NEED_CL, LOCKED_CL } core_lock = na->separate_locks ? NO_CL : NEED_CL;

#ifdef notyet
    /*
     * If we to push packets out (priv->np_txpoll) or want_tx is
     * still set, we do need to run the txsync calls (on all rings,
     * to avoid that the tx rings stall).
     */
    if (priv->np_txpoll || want_tx) {
        for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
            kring = &na->tx_rings[i];
            if (!want_tx && kring->ring->cur == kring->nr_hwcur)
                continue;
            if (core_lock == NEED_CL) {
                na->nm_lock(adapter, NETMAP_CORE_LOCK, 0);
                core_lock = LOCKED_CL;
            }
            if (na->separate_locks)
                na->nm_lock(adapter, NETMAP_TX_LOCK, i);
            if (netmap_verbose & NM_VERB_TXSYNC)
                D("send %d on %s %d",
                  kring->ring->cur,
                  ifp->if_xname, i);
            if (na->nm_txsync(adapter, i, 0 /* no lock */))
                revents |= POLLERR;

            if (want_tx) {
                if (kring->ring->avail > 0) {
                    /* stop at the first ring. We don't risk
                     * starvation.
                     */
                    revents |= want_tx;
                    want_tx = 0;
                }
                else if (!check_all) {
                    poll_wait(file, &kring->si, poll);
                }
            }
            if (na->separate_locks)
                na->nm_lock(adapter, NETMAP_TX_UNLOCK, i);
        }
    }
#endif
    
    /*
     * now rxsync each queue.
     * Do it on all rings because otherwise we starve.
     */
    for (i = priv->np_qfirst; i < priv->np_qlast; i++) {
        D("rxsync on %d", i);
        kring = &na->rx_rings[i];
        if (core_lock == NEED_CL) {
            na->nm_lock(dev, NETMAP_CORE_LOCK, 0);
            core_lock = LOCKED_CL;
        }
        else if (na->separate_locks) {
            na->nm_lock(dev, NETMAP_RX_LOCK, i);
        }

        if (na->nm_rxsync(dev, i, 0 /* no lock */))
            mask |= POLLERR;

#ifdef notyet
        if (no_timestamp == 0 || kring->ring->flags & NR_TIMESTAMP)
            microtime(&kring->ring->ts);
#endif

        if (kring->ring->avail > 0)
            mask |= POLLIN | POLLRDNORM;

        if (na->separate_locks) {
            na->nm_lock(dev, NETMAP_RX_UNLOCK, i);
        }
    }

    if (core_lock == LOCKED_CL) {
        na->nm_lock(dev, NETMAP_CORE_UNLOCK, 0);
    }

    return (mask);
}

static int
netmap_release(struct inode *inode, struct file *file)
{
        struct netmap_priv_d* priv = file->private_data;

        (void) inode;
        netmap_cleanup(priv);

        return (0);
}

