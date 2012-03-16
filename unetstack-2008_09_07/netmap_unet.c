/*
 * netmap interface for unetstack
 *
 * BSD license
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"
#include <errno.h>
#include <sys/poll.h>

#ifdef USE_PCAP
#include <pcap/pcap.h>
struct pcap *my_pcap = NULL;
#define DISPATCH pcap_dispatch
#define INJECT pcap_inject
#endif /* USE_PCAP */

#ifdef USE_NETMAP
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>
#define DISPATCH netmap_dispatch
#define INJECT netmap_inject
#endif


#ifdef USE_NETMAP
struct my_ring {
        struct nmreq nmr;

        int fd;
        char *mem;                      /* userspace mmap address */
        u_int memsize;
        u_int queueid;
        u_int begin, end;               /* first..last+1 rings to check */
        struct netmap_if *nifp;
  
        int snaplen;
        char *errbuf;
        int promisc;
        int to_ms;
        
        uint32_t if_flags;
        uint32_t if_reqcap;
        uint32_t if_curcap;
 
        char msg[128];
};

        
static int
do_ioctl(struct my_ring *me, int what)
{
        struct ifreq ifr;
        int error;
        
        bzero(&ifr, sizeof(ifr));
        strncpy(ifr.ifr_name, me->nmr.nr_name, sizeof(ifr.ifr_name));
        switch (what) {
        case SIOCSIFFLAGS:
                D("call SIOCSIFFLAGS 0x%x", me->if_flags);
                ifr.ifr_flagshigh = (me->if_flags >> 16) & 0xffff;
                ifr.ifr_flags = me->if_flags & 0xffff;
                break;
        case SIOCSIFCAP:
                ifr.ifr_reqcap = me->if_reqcap;
                ifr.ifr_curcap = me->if_curcap;
                break;
        }
        error = ioctl(me->fd, what, &ifr);
        if (error) {
                D("ioctl 0x%x error %d", what, error);
                return error;
        }
        switch (what) {
        case SIOCSIFFLAGS:
        case SIOCGIFFLAGS:
                me->if_flags = (ifr.ifr_flagshigh << 16) |
                        (0xffff & ifr.ifr_flags);
                D("flags are L 0x%x H 0x%x 0x%x",
                        (uint16_t)ifr.ifr_flags,
                        (uint16_t)ifr.ifr_flagshigh, me->if_flags);
                break;

        case SIOCGIFCAP:
                me->if_reqcap = ifr.ifr_reqcap;
                me->if_curcap = ifr.ifr_curcap;
                D("curcap are 0x%x", me->if_curcap);
                break;
        }
        return 0;
}

int
netmap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
        struct my_ring *me = p;
        int got = 0;
        u_int si;

        ND("cnt %d", cnt);
        /* scan all rings */
        for (si = me->begin; si < me->end; si++) {
                struct netmap_ring *ring = NETMAP_RXRING(me->nifp, si);
                ND("ring has %d pkts", ring->avail);
                if (ring->avail == 0)
                        continue;
                me->hdr.ts = ring->ts;
                while ((cnt == -1 || cnt != got) && ring->avail > 0) {
                        u_int i = ring->cur;
                        u_int idx = ring->slot[i].buf_idx;
                        if (idx < 2) {
                                D("%s bogus RX index %d at offset %d",
                                        me->nifp->ni_name, idx, i);
                                sleep(2);
                        }
                        u_char *buf = (u_char *)NETMAP_BUF(ring, idx);
                        me->hdr.len = me->hdr.caplen = ring->slot[i].len;
                        // D("call %p len %d", p, me->hdr.len);
                        callback(user, &me->hdr, buf);
                        ring->cur = NETMAP_RING_NEXT(ring, i);
                        ring->avail--;
                        got++;
                }
        }
        return got;
}

int
netmap_inject(pcap_t *p, const void *buf, size_t size)
{
        struct my_ring *me = p;
        u_int si;

        ND("cnt %d", cnt);
        /* scan all rings */
        for (si = me->begin; si < me->end; si++) {
                struct netmap_ring *ring = NETMAP_TXRING(me->nifp, si);

                ND("ring has %d pkts", ring->avail);
                if (ring->avail == 0)
                        continue;
                u_int i = ring->cur;
                u_int idx = ring->slot[i].buf_idx;
                if (idx < 2) {
                        D("%s bogus TX index %d at offset %d",
                                me->nifp->ni_name, idx, i);
                        sleep(2);
                }
                u_char *dst = (u_char *)NETMAP_BUF(ring, idx);
                ring->slot[i].len = size;
                bcopy(buf, dst, size);
                ring->cur = NETMAP_RING_NEXT(ring, i);
                ring->avail--;
                // if (ring->avail == 0) ioctl(me->fd, NIOCTXSYNC, NULL);
                return size;
        }
        errno = ENOBUFS;
        return -1;
}


int
netmap_open(struct my_ring *me, int ringid)
{
        int fd, err, l;
        u_int i;
        struct nmreq req;

        me->fd = fd = open("/dev/netmap", O_RDWR);
        if (fd < 0) {
                D("Unable to open /dev/netmap");
                return (-1);
        }
        bzero(&req, sizeof(req));
        strncpy(req.nr_name, me->nmr.nr_name, sizeof(req.nr_name));
        req.nr_ringid = ringid;
        err = ioctl(fd, NIOCGINFO, &req);
        if (err) {
                D("cannot get info on %s", me->nmr.nr_name);
                goto error;
        }
        me->memsize = l = req.nr_memsize;
        ND("memsize is %d MB", l>>20);
        err = ioctl(fd, NIOCREGIF, &req);
        if (err) {
                D("Unable to register %s", me->nmr.nr_name);
                goto error;
        }

        if (me->mem == NULL) {
                me->mem = mmap(0, l, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
                if (me->mem == MAP_FAILED) {
                        D("Unable to mmap");
                        me->mem = NULL;
                        goto error;
                }
        }

        me->nifp = NETMAP_IF(me->mem, req.nr_offset);
        me->queueid = ringid;
        if (ringid & NETMAP_SW_RING) {
                me->begin = req.nr_rx_rings;
                me->end = me->begin + 1;
        } else if (ringid & NETMAP_HW_RING) {
                me->begin = ringid & NETMAP_RING_MASK;
                me->end = me->begin + 1;
        } else {
                me->begin = 0;
                me->end = req.nr_rx_rings;
        }
        /* request timestamps for packets */
        for (i = me->begin; i < me->end; i++) {
                struct netmap_ring *ring = NETMAP_RXRING(me->nifp, i);
                ring->flags = NR_TIMESTAMP;
        }
        //me->tx = NETMAP_TXRING(me->nifp, 0);
        return (0);
error:
        close(me->fd);
        return -1;
}
#endif /* USE_NETMAP */

char *ifname = "eth0";
unsigned char packet_edst[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int netchannel_send_raw(struct nc_buff *ncb)
{
#ifdef USE_PCAP
	D("sending %d bytes", ncb->len);
	return pcap_inject(my_pcap, ncb->head, ncb->len);
#endif /* USE_PCAP */
	//sendto(ncb->nc->fd, ncb->head, ncb->len);

	return 0;
}

#ifdef USE_PCAP
static void
my_pcap_cb(u_char *d, const  struct  pcap_pkthdr *hdr, const u_char *snap)
{
	int len = hdr->caplen; // remove header
	struct nc_buff *ncb;
	uint16_t proto;
	if (len < 34)
		return; // too short for IP

	proto = ntohs(*(uint16_t *)(snap + 12));	// mac type
	if (proto != 0x800)
		return;		// not IP
	ncb = ncb_alloc(4096);
	if (!ncb)
		return;
	ncb->nc = (struct netchannel *)d;
	bcopy(snap, ncb->head, len);
D("got len %5d mac type 0x%x and trim", len, proto);
	ncb_trim(ncb, len);
	ncb_pull(ncb, 14); /* remove MAC header */
	packet_ip_process(ncb);
	ncb_put(ncb);
}
#endif
int netchannel_recv_raw(struct netchannel *nc, unsigned int tm)
{
	int err;
	struct pollfd pfd;

ND("prepare to poll on fd %d for %d ms", nc->fd, tm);
/* note itimers will wake us up */
again:
	bzero(&pfd, sizeof(pfd));
	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	syscall_recv += 1;
	err = poll(&pfd, 1, tm * 5);
	if (err < 0) {
		D("failed to poll");
		if ((errno == EINTR || errno == EAGAIN))
			goto again;
		perror("error");
		return err;
	}
	ND("poll gets %d", err);
	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data, revents: %x.\n", __func__, pfd.revents);
		return -EAGAIN;
	}

	syscall_recv += 1;

	DISPATCH(my_pcap, 1, my_pcap_cb, (u_char *)nc);
	return 0;

}

static int netchannel_create_raw(struct netchannel *nc __unused)
{
#ifdef USE_PCAP
	char errbuff[PCAP_ERRBUF_SIZE];
	int ret;
	D("device %s start", ifname);
	my_pcap = pcap_open_live(ifname, 2000, 1, 1000, errbuff);
	if (my_pcap == NULL)
		return -1;

	ret = pcap_fileno(my_pcap);
	D("activate gives %d", pcap_activate(my_pcap));
	D("device %s fileno %d", ifname, ret);
	return ret;
#endif
#ifdef USE_NETMAP
#endif
}




void netchannel_remove(struct netchannel *nc)
{
	close(nc->fd);
}

struct netchannel *netchannel_create(struct netchannel_control *ctl, unsigned int state)
{
	int err = 0;
	struct common_protocol *proto;
	struct netchannel *nc;

D("called");
	if (ctl->saddr.proto == IPPROTO_TCP)
		proto = &atcp_common_protocol;
	else if (ctl->saddr.proto == IPPROTO_UDP)
		proto = &udp_common_protocol;
	else
		return NULL;

	nc = malloc(sizeof(struct netchannel) + proto->size);
	if (!nc)
		return NULL;

	memset(nc, 0, sizeof(struct netchannel) + proto->size);
	ncb_queue_init(&nc->recv_queue);

	nc->proto = (struct common_protocol *)(nc + 1);
	nc->state = state;
	nc->header_size = MAX_HEADER_SIZE;

	memcpy(nc->proto, proto, sizeof(struct common_protocol));
	memcpy(&nc->ctl, ctl, sizeof(struct netchannel_control));

	nc->fd = netchannel_create_raw(nc);
	if (nc->fd < 0) {
		ulog_err("Failed to create netchannel");
		goto err_out_free;
	}
	D("down to proto_create for %d", ctl->saddr.proto);
	err = nc->proto->create(nc);
	if (err)
		goto err_out_free;

	return nc;

err_out_free:
	free(nc);
	return NULL;
}

int netchannel_send(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_out(nc, buf, size);
}

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_in(nc, buf, size);
}
