/*
 * $Id$
 */

#include "connlib.h"

static int verbose = 1;
static int verbose_arp = 1;

#define TX_ALLQUEUE 1 /* if 0 send_udp_packet function will use only the first
                       * queue */
#define STATS 1 /* print statistics on socket closure */

/* reduce a 64 bit nuumber to a 16 bit checksum */
#define CKSUM_REDUCE(d64) ({                    \
        uint64_t tmp = (d64);                   \
        tmp = (tmp & 0xffffffff) + (tmp >> 32); \
        tmp = (tmp & 0xffffffff) + (tmp >> 32); \
        tmp = (tmp & 0xffff) + (tmp >> 16);     \
        tmp = (tmp & 0xffff) + (tmp >> 16);     \
        (uint16_t)tmp;                          \
})

#if STATS
static u_int numrxpoll = 0, numslothunter = 0, maxslotavail = 0;
#endif

#if !TX_ALLQUEUE
static int sync_done = 0;
#endif

/*
 * Put MAC and IP addresses of interface `if_name' into the netmap socket
 * information.
 *
 * Return 0 if ok, 1 on error.
 */
static int
get_if_info(struct params *p, char *if_name)
{
	struct ifaddrs *head, *cur;
	struct sockaddr_dl *sa_dl;
	struct sockaddr_in *sa_in;
	uint8_t *mac;
	int found = 0;

	if (getifaddrs(&head) == -1) {
		D("an errror occurred while retrieving interface info");
		return(1);
	}
	for (cur = head; cur; cur = cur->ifa_next) {
		if (strcmp(cur->ifa_name, if_name) != 0)
			continue;
		sa_dl = (struct sockaddr_dl *) cur->ifa_addr;
		sa_in = (struct sockaddr_in *) cur->ifa_addr;
		if (!sa_dl && !sa_in)
			continue;
		if (sa_in->sin_family != AF_INET &&
		    sa_dl->sdl_family != AF_LINK) {
			continue;
		}
		if (sa_in->sin_family == AF_INET) {
			if (verbose)
				D("interface %s ip address: %s",
				  if_name,
				  inet_ntoa(sa_in->sin_addr));
			memcpy(&p->rx, sa_in, sizeof(struct sockaddr_in));
			memcpy(&p->if_ip_address,
			       &sa_in->sin_addr,
			       sizeof(struct in_addr));
			found++;
		} else if (sa_dl->sdl_family == AF_LINK) {
			mac = (uint8_t *) LLADDR(sa_dl);
			memcpy(&p->if_mac_address, mac, ETHER_ADDR_LEN);
			if (verbose)
				D("interface %s hw address: %s",
				  if_name,
				  ether_ntoa(&p->if_mac_address));
			found += 2;
		}
	}
	freeifaddrs(head);
	if (found < 3) {
		switch(found) {
		case 0:
			D("ERROR: unable to retrieve IP and MAC addresses"
			  " of interface %s", if_name);
			break;
		case 1:
			D("ERROR: unable to retrieve MAC address"
			  " of interface %s", if_name);
			break;
		case 2:
			D("ERROR: unable to retrieve IP address"
			  " of interface %s", if_name);
		}
		return(1);
	}
	return(0);
}

/*
 * Perform a query in the ARP table, looking for a MAC address correspondig to
 * `p->dst_ip_address'.
 *
 * Return 0 on success, 1 otherwise.
 */
static int
find_mac_address(struct params *p)
{
	int mib[6];
	size_t needed;
	char *buf, *lim, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	int st, not_found = 1;
	uint8_t *mac;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
#ifdef RTF_LLINFO
	mib[5] = RTF_LLINFO;
#else
	mib[5] = 0;
#endif
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		D("route-sysctl-estimate");
		return(0);
	}
	if (needed == 0)	/* empty table */
		return(0);
	buf = NULL;
	for (;;) {
		buf = reallocf(buf, needed);
		if (buf == NULL) {
			D("could not reallocate memory");
			return(0);
		}
		st = sysctl(mib, 6, buf, &needed, NULL, 0);
		if (st == 0 || errno != ENOMEM)
			break;
		needed += needed/8;
	}
	if (st == -1) {
		free(buf);
		D("actual retrieval of routing table");
		return(0);
	}
	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *) next;
		sin = (struct sockaddr_inarp *) (rtm + 1);
		sdl = (struct sockaddr_dl *) ((char *)sin + SA_SIZE(sin));

		if (p->tx.sin_addr.s_addr != sin->sin_addr.s_addr)
			continue;
		not_found = 0;
		mac = (uint8_t *) LLADDR(sdl);
		memcpy(&p->dst_mac_address, mac, ETHER_ADDR_LEN);
		if (verbose_arp)
			D("MAC address of destination found: %s",
			  ether_ntoa(&p->dst_mac_address));
		break;
	}
	free(buf);
	return(not_found);
}

/*
 * Netmap device opener.
 *
 * Return 0 on success, -1 otherwise.
 */
static int
nm_open(struct my_ring *me, int ringid)
{
	int fd, err, l;
	struct nmreq req;

	me->fd = fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D("Unable to open /dev/netmap");
		return (-1);
	}
	bzero(&req, sizeof(struct nmreq));
	strncpy(req.nr_name, me->ifname, sizeof(req.nr_name));
	req.nr_ringid = ringid;
	err = ioctl(fd, NIOCGINFO, &req);
	if (err) {
		D("cannot get info on %s", me->ifname);
		goto error;
	}
	me->memsize = l = req.nr_memsize;
	if (verbose)
		D("memsize is %d MB", l>>20);
	err = ioctl(fd, NIOCREGIF, &req);
	if (err) {
		D("Unable to register %s", me->ifname);
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
		me->begin = req.nr_numrings;
		me->end = me->begin + 1;
	} else if (ringid & NETMAP_HW_RING) {
		me->begin = ringid & NETMAP_RING_MASK;
		me->end = me->begin + 1;
	} else {
		me->begin = 0;
		me->end = req.nr_numrings;
	}
	me->tx = NETMAP_TXRING(me->nifp, me->begin);
	me->rx = NETMAP_RXRING(me->nifp, me->begin);
	return (0);
error:
	close(me->fd);
	return -1;
}

/*
 * Close netmap device.
 */
static void
nm_close(struct my_ring *me)
{
	if (verbose)
		D("*****");
	if (me->mem)
		munmap(me->mem, me->memsize);
	close(me->fd);
}

/*
 * Allocate and initialize `params' structure.
 *
 * Return a pointer to it on success, NULL otherwise.
 */
struct params*
nm_socket(char *if_name, int domain, int protocol)
{
	int sockfd, ret;
	struct ifreq ifr;
	struct params *p;

	if (domain != PF_INET) {
		D("ERROR: unsupported protocol family");
		return(NULL);
	}
	if (protocol != UDP) {
		D("ERROR: unsupported protocol");
		return(NULL);
	}
	p = calloc(1, sizeof(struct params));
	if (p == NULL) {
		D("ERROR: unable to allocate `params' structure");
		return(NULL);
	}
	/* netmap */
	p->me[0].ifname = p->me[1].ifname = if_name; /* 0: stack - 1: nic */
	if (nm_open(p->me, NETMAP_SW_RING)) {
		D("an error occurred while opening netmap software ring");
		goto fail;
	}
	if (nm_open(&p->me[1], 0)) {
		D("an error occurred while opening netmap hardware ring");
		D("closing software ring...");
		nm_close(p->me);
		goto fail;
	}
	if (get_if_info(p, if_name)) {
		nm_close(&p->me[0]);
		nm_close(&p->me[1]);
		goto fail;
	}
	p->rx.sin_port = htons(55555); /* default port, will be overwritten in
	                                * nm_bind */
	/* get interface MTU */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if ((ret = ioctl(sockfd, SIOCGIFMTU, &ifr)) != -1) {
		p->max_payload_size = ifr.ifr_ifru.ifru_mtu -
		                      sizeof(struct ether_header) -
		                      sizeof(struct ip) -
		                      sizeof(struct udphdr);
	} else {
		D("WARNING: unable to get interface MTU, setting packet size"
		  " to 1500 bytes");
		p->max_payload_size = 1500 -
		                      sizeof(struct ether_header) -
		                      sizeof(struct ip) -
		                      sizeof(struct udphdr);
	}
	p->minlen = sizeof(struct ether_header) +
	            sizeof(struct ip) +
	            sizeof(struct udphdr);
	p->stackring_idx = p->nicring_idx = -1;
	return(p);
fail:
	free(p);
	return NULL;
}

/*
 * Initialize the header of an UDP packet, which will be sent by the
 * transmitter.
 */
static void
build_udp_header(struct params *p)
{
	struct ether_header *eh = &p->udp_pkt_hdr.eh;
	struct ip *ip = &p->udp_pkt_hdr.ip;
	struct udphdr *udp = &p->udp_pkt_hdr.udp;

	bzero(&p->udp_pkt_hdr, sizeof(struct udp_packet_headers));

	/* ethernet header */
	eh->ether_type = htons(ETHERTYPE_IP);
	bcopy(&p->if_mac_address, eh->ether_shost, ETHER_ADDR_LEN);
	bcopy(&p->dst_mac_address, eh->ether_dhost, ETHER_ADDR_LEN);

	/* IP header */
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_p = IPPROTO_UDP;
	memcpy(&ip->ip_src, &p->if_ip_address, sizeof(struct in_addr));
	memcpy(&ip->ip_dst, &p->tx.sin_addr, sizeof(struct in_addr));

	/* UDP header */
	udp->uh_sport = p->rx.sin_port;
	udp->uh_dport = p->tx.sin_port;
}

/*
 * Allocate an ARP request packet.
 *
 * Return a pointer to it on success, NULL otherwise.
 */
static struct arp_packet*
build_arp_request_packet(const struct params *p)
{
	struct arp_packet *pkt = calloc(1, 60);
	struct ether_header *eh = &pkt->eh;
	struct arphdr *arp = &pkt->arp;

	/*
	   sizeof(struct ether_header) +
	   sizeof(struct arphdr)       +
	   2 * sizeof(struct in_addr)  +
	   2 * ETHER_ADDR_LEN          =
	   -----------------------------
	   42 bytes

	   Ethernet minimum frame size = 60 bytes (+ 4 bytes CRC)
	*/

	if (pkt == NULL) {
		D("ERROR: an error occurred while allocating packet memory");
		return(NULL);
	}
	if (verbose_arp) {
		D("***DEBUG*** p->rx.sin_addr %s", inet_ntoa(p->rx.sin_addr));
		D("***DEBUG*** p->if_ip_address %s",
		  inet_ntoa(p->if_ip_address));
		D("***DEBUG*** p->tx.sin_addr %s", inet_ntoa(p->tx.sin_addr));
	}

	bcopy(&p->if_mac_address, eh->ether_shost, ETHER_ADDR_LEN);
	bcopy(ether_aton("FF:FF:FF:FF:FF:FF"), eh->ether_dhost, ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERTYPE_ARP);

	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = ETHER_ADDR_LEN;
	arp->ar_pln = 4;	// XXX is there a MACRO for this?
	arp->ar_op = htons(ARPOP_REQUEST);
	bcopy(&p->if_mac_address, ar_sha(arp), ETHER_ADDR_LEN);
	/*bcopy(&p->rx.sin_addr, ar_spa(arp), sizeof(struct in_addr));*/
	bcopy(&p->if_ip_address, ar_spa(arp), sizeof(struct in_addr));
	bcopy(&p->tx.sin_addr, ar_tpa(arp), sizeof(struct in_addr));
	return(pkt);
}

/*
 * Copy the UDP packet in the first available slot of nic tx ring.
 *
 * Return 1 on success, 0 if there are no available slots.
 */
static int
send_udp_packet(struct params *p, const void *payload, int payload_len)
{
	char *pnt;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	u_int cur, index = p->me[1].begin;

#if TX_ALLQUEUE
	/* scroll nic tx rings */
	while (index < p->me[1].end) {
		ring = NETMAP_TXRING(p->me[1].nifp, index);
		if (ring->avail == 0) {
			index++;
			continue;
		} else {
#else
			ring = NETMAP_TXRING(p->me[1].nifp, index);
			if (ring->avail == 0)
				return(0);
#endif
			cur = ring->cur;
			slot = &ring->slot[cur];
			pnt = NETMAP_BUF(ring, slot->buf_idx);
			memcpy(pnt,
			       &p->udp_pkt_hdr,
			       sizeof(struct udp_packet_headers));
			memcpy(pnt + sizeof(struct udp_packet_headers),
			       payload,
			       payload_len);
			slot->len = sizeof(struct udp_packet_headers) +
			            payload_len;
			cur = NETMAP_RING_NEXT(ring, cur);
			ring->avail--;
			ring->cur = cur;
#if !TX_ALLQUEUE
			if (ring->avail < 200) {
				if (!sync_done) {
					/* make an ioctl to free some space in
					 * nic tx ring */
					ioctl(p->me[1].fd, NIOCTXSYNC, NULL);
					sync_done = 1; /* do it only once */
				} else if (ring->avail == 0) {
					sync_done = 0;
				}
			} else if (sync_done) {
				sync_done = 0;
			}
#endif
			return(1);
#if TX_ALLQUEUE
		}
	}
	return(0);
#endif
}

/*
 * Analyze `packet' and (if it is an ARP reply) copy MAC address in the socket
 * structure.
 *
 * Return 1 if it's an ARP reply addressed to "this" host, 0 otherwise.
 */
static int
is_arp_reply(struct params *p, char *packet)
{
	struct ether_header *eh = (struct ether_header *) packet;
	struct arphdr *arp = (struct arphdr *) &eh[1];

	/* ethernet header */
	if (memcmp(eh->ether_dhost, &p->if_mac_address, ETHER_ADDR_LEN)) {
		if (verbose_arp)
			D("***DEBUG*** ethernet address %s doesn't match"
			  " my address = %s",
			  ether_ntoa((struct ether_addr *) eh->ether_dhost),
			  ether_ntoa(&p->if_mac_address));
		return(0);
	}
	if (ntohs(eh->ether_type) != ETHERTYPE_ARP) {
		if (verbose_arp)
			D("***DEBUG*** ethernet type doesn't match %d",
			  ntohs(eh->ether_type));
		return(0);
	}

	/* ARP header */
	if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
	    ntohs(arp->ar_pro) != ETHERTYPE_IP ||
	    arp->ar_hln != ETHER_ADDR_LEN ||
	    arp->ar_pln != 4 ||
	    ntohs(arp->ar_op) != ARPOP_REPLY) {
		if (verbose_arp)
			D("***DEBUG*** ARP header doesn't match");
		return(0);
	}
	if (memcmp(ar_tha(arp),
	           &p->if_mac_address,
	           ETHER_ADDR_LEN) ||
	    memcmp((struct in_addr *) ar_spa(arp),
	           &p->tx.sin_addr,
	           sizeof(struct in_addr)) ||
	    memcmp((struct in_addr *) ar_tpa(arp),
	           &p->if_ip_address,
	           sizeof(struct in_addr))) {
		if (verbose_arp) {
			D("***DEBUG*** ARP addresses don't match");
			D("***DEBUG*** spa %s",
			  inet_ntoa(* ((struct in_addr *) ar_spa(arp))));
			D("***DEBUG*** tpa %s",
			  inet_ntoa(* ((struct in_addr *) ar_tpa(arp))));
		}
		return(0);
	}

	/* copy MAC address */
	bzero(&p->dst_mac_address, ETHER_ADDR_LEN);
	memcpy(&p->dst_mac_address, ar_sha(arp), ETHER_ADDR_LEN);
	return(1);
}

/*
 * Send an ARP request for `p->dst_ip_address', receive ARP response and route
 * it to the stack.
 *
 * Return 0 on success, 1 if unable to send ARP request or ARP reply hasn't
 * been catched.
 */
static int
handle_arp_request(struct params *p)
{
	char *pkt, *pnt;
	int sent = 0, ret, avail, received = 0, swapped, i, timeout = 30000000;
	u_int si, di, j, k;
	uint32_t index, cur;
	struct netmap_ring *stackring, *nicring;
	struct pollfd pollfd;
	struct arp_packet *ap;
	struct netmap_slot *nicslot, *stackslot;

	ap = build_arp_request_packet(p);
	if (ap == NULL) {
		D("unable to build an ARP request packet");
		return(1);
	}
	bzero(&pollfd, sizeof(struct pollfd));
	pollfd.fd = p->me[1].fd;
	pollfd.events |= POLLOUT;
	for (i = 0; i < timeout;) {
		pollfd.revents = 0;
		ret = poll(&pollfd, 1, 100);
		if (ret <= 0) {
			if (pollfd.revents & POLLERR)
				D("error on fd, txavail %d / txcur %d",
				  p->me[1].tx->avail, p->me[1].tx->cur);
			if (++i == timeout) {
				free(ap);
				goto error;
			}
			continue;
		} else if (pollfd.events & POLLOUT) {
			/* send ARP request */
			di = p->me[1].begin;
			while (di < p->me[1].end) {
				nicring = NETMAP_TXRING(p->me[1].nifp, di);
				if (nicring->avail == 0) {
					di++;
					continue;
				} else {
					cur = nicring->cur;
					nicslot = &nicring->slot[cur];
					pnt = NETMAP_BUF(nicring,
					                 nicslot->buf_idx);
					memcpy(pnt, ap, 60);
					nicslot->len = 60;
					cur = NETMAP_RING_NEXT(nicring, cur);
					nicring->avail--;
					nicring->cur = cur;
					ioctl(p->me[1].fd, NIOCTXSYNC, NULL);
					free(ap);
					pollfd.events = POLLIN;
					i = 0; /* reset counter */
					sent = 1;
					if (verbose_arp)
						D("ARP request sent,"
						  " waiting for reply...");
					break;
				}
			}
			if (sent) {
				continue;
			} else {
				if (++i == timeout) {
					free(ap);
					goto error;
				}
			}
		} else if (pollfd.events & POLLIN) {
			/* get ARP reply and give it to the stack */
			si = p->me[1].begin;
			di = p->me[0].begin;
			while (si < p->me[1].end && di < p->me[0].end) {
				nicring = NETMAP_RXRING(p->me[1].nifp, si);
				stackring = NETMAP_TXRING(p->me[0].nifp, di);
				if (nicring->avail == 0) {
					si++;
					continue;
				}
				if (stackring->avail == 0) {
					di++;
					continue;
				}
				avail = MIN(nicring->avail, stackring->avail);
				j = nicring->cur;
				k = stackring->cur;
				swapped = 0;
				while (avail-- > 0) {
					nicslot = &nicring->slot[j];
					stackslot = &stackring->slot[k];
					pkt = NETMAP_BUF(nicring,
					                 nicslot->buf_idx);
					/* check if it's an ARP reply */
					if (is_arp_reply(p, pkt)) {
						if (verbose_arp) {
							D("***DEBUG*** ARP"
							  " reply received");
							D("***DEBUG***"
							  " destination MAC"
							  " address: %s",
					  ether_ntoa(&p->dst_mac_address));
						}
						received = 1;
					}
					index = stackslot->buf_idx;
					stackslot->buf_idx = nicslot->buf_idx;
					nicslot->buf_idx = index;
					/* copy the packet lenght */
					stackslot->len = nicslot->len;
					/* report the buffer change */
					stackslot->flags |= NS_BUF_CHANGED;
					nicslot->flags |= NS_BUF_CHANGED;
					swapped++;
					j = NETMAP_RING_NEXT(nicring, j);
					k = NETMAP_RING_NEXT(stackring, k);
					if (received)
						break;
				}
				nicring->avail -= swapped;
				stackring->avail -= swapped;
				nicring->cur = j;
				stackring->cur = k;
				if (received)
					return(0);
			}
			if (++i == timeout)
				goto error;
		}
	}
error:
	if (verbose_arp) {
		if (pollfd.events & POLLOUT)
			D("Unable to send ARP request");
		else
			D("Unable to catch ARP reply");
	}
	return(1);
}

/*
 * Copy destination informations in `params' structure.
 * Eventually retrieve destination MAC address (if not known yet).
 * Set UDP header info; compute fixed part of IP and UDP checksums.
 *
 * Return 0 on success, 1 otherwise.
 */
int
nm_connect(struct params *p, const struct sockaddr *name, socklen_t namelen)
{
	uint32_t *d;

	if (p == NULL) {
		D("ERROR: invalid pointer to struct params");
		return(1);
	}
	if (name == NULL) {
		D("ERROR: invalid pointer to struct sockaddr");
		return(1);
	}
	if (namelen != sizeof(struct sockaddr_in)) {
		D("ERROR: wrong size %d need %d", namelen,
			sizeof(struct sockaddr_in));
		return(1);
	}
	/* XXX if initialized... */
	if (memcmp(name, &p->tx, namelen) == 0) {
		return 0; // socket already set
	}
	memcpy(&p->tx, name, namelen);
	/* retrieve destination MAC address in the ARP table */
	if (find_mac_address(p)) {
		D("unable to retrieve MAC address of destination from the ARP"
		  " table");
		/* send an ARP request and get the reply */
		if (handle_arp_request(p))
			return(1);
	}
	/*
	 * create a template ip and udp header for the packet.
	 * No options, and contiguous IP and UDP.
	 */
	/* initialize header structure for UDP packets */
	build_udp_header(p);
	/* compute checksum for constant header fields.
	 * The partial ip checksum is the sum of the 20bytes with unknown
	 * fields (len, id, ofs, csum) set to 0.
	 * The partial udp checksum is the sum of
	 * src, dest and src/dst port. They are contiguous
	 * in the structure (d[3], d[4], d[5])
	 */
	d = (uint32_t *)&p->udp_pkt_hdr.ip;
	p->ip_const_hdr = CKSUM_REDUCE(d[0] + d[1] + d[2] + d[3] + d[4]);
	p->udp_const_hdr = CKSUM_REDUCE(d[3] + d[4] + d[5]);
	return(0);
}

/*
 * Close all netmap devices and free the memory belonging to `params'
 * structure.
 */
void
nm_close_socket(struct params *p)
{
#if STATS
	int i, count = 0;
	uint64_t sum = 0;
#endif

	if (p == NULL || sizeof(*p) != sizeof(struct params)) {
		D("WARNING: invalid socket pointer");
		return;
	}
	/* Send remaining packets (if any) */
	ioctl(p->me[1].fd, NIOCTXSYNC, NULL);
#if STATS
	if (p->cur != 0) {
		for (i = 0; i < NUMTS; i++) {
			if (p->ts[i].container[0] != 0 &&
			    p->ts[i].container[1] != 0) {
				sum += (p->ts[i].container[1] -
				        p->ts[i].container[0]);
				count++;
			}
		}
		if (count)
			D("average delta: %llu, count = %d", sum/count, count);
	}
	if (numrxpoll != 0)
		D("poll number %u", numrxpoll);
	if (numslothunter != 0)
		D("slot-hunter number %u", numslothunter);
	if (maxslotavail != 0)
		D("max number of available slot %u", maxslotavail);
#endif
	nm_close(&p->me[0]);
	nm_close(&p->me[1]);
	free(p);
}

static inline uint64_t
sum32u(const unsigned char *addr, int count, uint64_t sum)
{
	const uint32_t *p = (uint32_t *) addr;

	for (; count >= 32; count -= 32) {
		sum += (uint64_t) p[0] + p[1] + p[2] + p[3] +
		                  p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
	for (; count >= 16; count -= 16) {
		sum += (uint64_t) p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	for (; count >= 4; count -= 4) {
		sum += *p++;
	}
	addr = (unsigned char *)p;
	if (count > 1) {
		sum += * (uint16_t *) addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	return sum;
}

/*
 * Scan stack and nic rings: store ring indexes and slot counts of most
 * populated ones.
 */
static void
slothunter(struct params *p)
{
	u_int i;
	struct my_ring *stack = &p->me[0], *nic = &p->me[1];
	struct netmap_ring *ring;

	/* reset indexes and counters */
	p->stackring_idx = p->nicring_idx = -1;
	p->stackring_avail = p->nicring_avail = 0;
	for (i = stack->begin; i < stack->end; i++) {
		ring = NETMAP_RXRING(stack->nifp, i);
		if (ring->avail > p->stackring_avail) {
			p->stackring_idx = i;
			p->stackring_avail = ring->avail;
		}
	}
	for (i = nic->begin; i < nic->end; i++) {
		ring = NETMAP_RXRING(nic->nifp, i);
		if (ring->avail > p->nicring_avail) {
			p->nicring_idx = i;
			p->nicring_avail = ring->avail;
		}
	}
#if STATS
	numslothunter++;
#endif
}

/*
 * MUST follow a nm_connect.
 * Update packet headers and execute a poll loop until it will be sent.
 *
 * Return the number of bytes sent.
 */
int
nm_send(struct params *p, const void *buf, int buf_len)
{
	int ret;
	uint64_t sum;
	struct ip *ip = &p->udp_pkt_hdr.ip;
	struct udphdr *udp = &p->udp_pkt_hdr.udp;
	struct pollfd pollfd;

	if (buf_len > p->max_payload_size){
		D("ERROR: buffer length exceeds maximum payload size");
		return -1;
	}
	/* update IP header and checksum.
	 * We need to fill the ip_id and ip_len, and add to the
	 * constant part we computed before.
	 */
	ip->ip_len = htons(sizeof(struct ip) +
	                   sizeof(struct udphdr) +
	                   buf_len);
	ip->ip_id = htons(p->ip_id++);
	sum = p->ip_const_hdr + * (uint32_t *) (void *) &ip->ip_len;
	ip->ip_sum = ~CKSUM_REDUCE(sum);
	/* update UDP header and checksum.
	 * Here we need to update the udp length XXX
	 * find a better reference RFC768
	 */
	udp->uh_ulen = htons(sizeof(struct udphdr) + buf_len);
	/* pseudo header checksum */
	sum = p->udp_const_hdr +
	      (uint16_t) (IPPROTO_UDP << 8) +
	      2*udp->uh_ulen;
	/* payload checksum */
	sum = sum32u((unsigned char *) buf, buf_len, sum);
	udp->uh_sum = ~CKSUM_REDUCE(sum);

	if (send_udp_packet(p, buf, buf_len))
		return(buf_len);
	pollfd.fd = p->me[1].fd;
	pollfd.events = POLLOUT;
	for (;;) {
		pollfd.revents = 0;
		ret = poll(&pollfd, 1, 100);
		if (ret <= 0) {
			if (pollfd.revents & POLLERR)
				D("error on fd, txavail %d / txcur %d",
				  p->me[1].tx->avail,
				  p->me[1].tx->cur);
			continue;
		}
		if (send_udp_packet(p, buf, buf_len))
			break;
	}
	return(buf_len);
}

/*
 * Compare `to' with the informations in the socket: if they don't match, call
 * nm_connect.
 * Call nm_send.
 *
 * Return the number of bytes sent.
 */
int
nm_sendto(struct params *p, const void *buf, int buf_len,
          const struct sockaddr *to, socklen_t tolen)
{
	u_int bytes_sent;

	/*
	 * quick check to validate addresses. We only care about
	 * the first 64 bits in the sockaddr.
	 */
	if (tolen != sizeof(struct sockaddr_in) ||
	    * (uint64_t *) to != * (uint64_t *) &p->tx) {
		struct sockaddr_in *sin = (struct sockaddr_in *)to;

		if (sin->sin_family != AF_INET) {
			D("ERROR: family protocol not supported: %d",
			  sin->sin_family);
			return(-1);
		}
		if (tolen != sizeof(struct sockaddr_in)) {
			D("ERROR: bad tolen %d", tolen);
			return(-1);
		}
		if (nm_connect(p, to, tolen)) {
			D("ERROR: netmap connect returned -1");
			return(-1);
		}
	}
	if (buf == NULL) {
		// XXX use default payload?
		D("ERROR: buffer pointer is NULL");
		return(-1);
	}
	bytes_sent = nm_send(p, buf, buf_len);
	return(bytes_sent);
}

/*
 * Analyze the content of `pkt'.
 *
 * Return 1 if it's an UDP packet addressed to "this" host, 0 otherwise.
 */
static int
check_udp_packet(struct params *p, char *pkt, uint16_t packet_size)
{
	uint16_t iplen, udplen;
	uint32_t *d;
	uint64_t sum;
	struct ether_header *eh = (struct ether_header *) pkt;
	struct ip *ip = (struct ip *) &eh[1];
	struct udphdr *udp = (struct udphdr *) &ip[1];

	if (packet_size < p->minlen) {
		if (verbose)
			D("***DEBUG*** wrong packet length");
		return(0);
	}

	/* ethernet header */
	if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
		if (verbose)
			D("***DEBUG*** ethernet type doesn't match %d",
			  ntohs(eh->ether_type));
		return(0);
	}
	// XXX try to remove the MAC address check
	if (0 && memcmp(eh->ether_dhost, &p->if_mac_address, ETHER_ADDR_LEN)) {
		// XXX match with broadcast ethernet?
		if (verbose)
			D("***DEBUG*** ethernet destination address"
			  " doesn't match");
		return(0);
	}

	/* IP header */
	/* check version, IHL, proto, len */
	if (* (uint8_t *) ip != 0x45 || ip->ip_p != IPPROTO_UDP) {
		if (verbose && * (uint8_t *) ip != 0x45)
			D("IP version/header-length don't match");
		else if (verbose)
			D("IP protocol is not UDP");
		return(0);
	}
	udplen = ntohs(udp->uh_ulen);
	iplen = ntohs(ip->ip_len);
	if (udplen + sizeof(struct ip) > iplen ||
	    iplen + sizeof(struct ether_header) > packet_size) {
		if (verbose)
			D("***DEBUG*** short packet");
		return(0);
	}
	if (!p->inaddr_any_enabled &&
	    memcmp(&ip->ip_dst,
	           &p->rx.sin_addr,
	           sizeof(struct in_addr))) {	// XXX match with broadcast IP?
		if (verbose) {
			D("***DEBUG*** IP destination address doesn't match");
			D("***DEBUG*** ip->ip_dst %s", inet_ntoa(ip->ip_dst));
			D("***DEBUG*** p->rx.sin_addr %s",
			  inet_ntoa(p->rx.sin_addr));
		}
		return(0);
	}

	/* UDP port */
	if (udp->uh_dport != p->rx.sin_port) {
		if (verbose)
			D("***DEBUG*** UDP header doesn't match: uh_sport %d"
			  " uh_dport %d tx.sin_port %d rx.sin_port %d",
			  ntohs(udp->uh_sport), ntohs(udp->uh_dport),
			  ntohs(p->tx.sin_port), ntohs(p->rx.sin_port));
		return(0);
	}

	/* IP checksum control */
	d = (uint32_t *)ip;
	sum = (uint64_t) d[0] + d[1] + d[2] + d[3] + d[4];
	/* wrap into 16-bit */
	if ((uint16_t) ~CKSUM_REDUCE(sum) != 0) {
		if (verbose)
			D("***DEBUG*** bad IP checksum");
		return(0);
	}

	/* UDP checksum control */
	/* pseudo header checksum */
	sum = (uint64_t) d[3] + d[4] + d[5] + d[6] +
	      (uint16_t) (IPPROTO_UDP << 8) + udp->uh_ulen ;
	sum = sum32u((unsigned char *) &udp[1],
	             udplen - sizeof(struct udphdr),
	             sum);
	/* wrap into 16-bit */
	if ((uint16_t) ~CKSUM_REDUCE(sum) != 0) {
		if (verbose)
			D("***DEBUG*** bad UDP checksum");
		return(0);
	}

	return(1);
}

/*
 * Move packets from `src' to `dst' swapping their slots.
 *
 * Return ring pointer if find an UDP packet coming from the nic; NULL
 * otherwise.
 *
 * `direction' = 0 stack -> nic
 * `direction' = 1 nic -> stack
 */
static struct netmap_ring*
process_rings(struct params *p, struct my_ring *src, struct my_ring *dst)
{
	int direction = (src->queueid & NETMAP_SW_RING) ? 0 : 1;
	u_int j, k, count, swapped, bookmark, si, di = dst->begin;
	uint32_t index;
	char *pkt;
	struct netmap_slot *rs, *ts;
	struct netmap_ring *txring, *rxring;

	if (direction)
		/* nic -> stack */
		bookmark = (p->nicring_idx > -1) ?
			(u_int) p->nicring_idx : src->begin;
	else
		/* stack -> nic */
		bookmark = (p->stackring_idx > -1) ?
			(u_int) p->stackring_idx : src->begin;
	si = bookmark;
	for (;;) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		/* find available slot in rx and tx ring */
		if (rxring->avail == 0) {
			si = (si + 1)%src->end;
			if (si == bookmark)
				break;
			continue;
		}
		if (txring->avail == 0) {
			if (++di == dst->end)
				break;
			continue;
		}
		j = rxring->cur;
		k = txring->cur;
		swapped = 0;
		/* number of slot we can process with this pair of ring */
		count = MIN(rxring->avail, txring->avail);
		/* scroll every available slot in the ring */
		while (count-- > 0) {
			rs = &rxring->slot[j];
			if (direction) {
				/* nic -> stack */
				pkt = NETMAP_BUF(rxring, rs->buf_idx);
				prefetch(pkt);
				if (check_udp_packet(p, pkt, rs->len))
					goto packet_found;
				else
					/* forward the packet to the stack */
					p->exchanges++;
			}
			ts = &txring->slot[k];
			/* swap slot index */
			index = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = index;
#if 0
			if (rs->len < 14 || rs->len > 2048)
				D("WARNING: wrong len %d rx[%d] -> tx[%d]",
				  rs->len,
				  j,
				  k);
#endif
			/* copy packet length */
			ts->len = rs->len;
			/* report buffer change */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			j = NETMAP_RING_NEXT(rxring, j);
			k = NETMAP_RING_NEXT(txring, k);
			swapped++;
		}
		/* update ring info */
		rxring->avail -= swapped;
		txring->avail -= swapped;
		rxring->cur = j;
		txring->cur = k;
		if (direction) {
			if ((p->count += swapped) > SYNC_LIM) {
				/* gradually make usable freed slots */
				ioctl(p->me[1].fd, NIOCRXSYNC, NULL);
				p->count = 0;
			}
			if ((p->nicring_avail = rxring->avail) == 0)
				p->nicring_idx = -1;
			else
				p->nicring_idx = si;
		} else {
			if ((p->stackring_avail = rxring->avail) == 0)
				p->stackring_idx = -1;
			else
				p->stackring_idx = si;
		}
	}
	return(NULL);

packet_found:
	/* update ring info */
	rxring->avail -= swapped;
	txring->avail -= swapped;
	rxring->cur = j;
	txring->cur = k;
	if ((p->count += (swapped + 1)) > SYNC_LIM) {
		/* gradually make usable freed slots */
		ioctl(p->me[1].fd, NIOCRXSYNC, NULL);
		p->count = 0;
	}
	if ((p->nicring_avail = (rxring->avail - 1)) == 0)
		p->nicring_idx = -1;
	else
		p->nicring_idx = si;
#if STATS
	if (rxring->avail > maxslotavail)
		maxslotavail = rxring->avail;
#endif
	/* the packet is now in the slot cur of rxring, indexes will be updated
	 * in the function `nm_recvfrom' after the copy of its payload */
	return(rxring);
}

/*
 * Add IP address and port to the netmap socket informations.
 *
 * Return 0 on success, 1 otherwise.
 */
int
nm_bind(struct params *p, const struct sockaddr *addr, socklen_t addrlen)
{
	if (p == NULL || sizeof(*p) != sizeof(struct params)) {
		D("ERROR: invalid pointer to struct params");
		return(1);
	}
	if (addr == NULL) {
		D("ERROR: invalid pointer to struct sockaddr");
		return(1);
	}
	if (((struct sockaddr_in *) addr)->sin_family != AF_INET) {
		D("ERROR: family protocol not supported");
		return(1);
	}
	if (((struct sockaddr_in *) addr)->sin_addr.s_addr == INADDR_ANY)
		p->inaddr_any_enabled = 1;
	else
		p->inaddr_any_enabled = 0;
	/* even if p->inaddr_any_enabled = 1, make a copy anyway for the port
	 * value */
	if (memcmp(addr, &p->rx, addrlen)) {
		bzero(&p->rx, sizeof(struct sockaddr_in));
		memcpy(&p->rx, addr, addrlen);
	}
	return(0);
}

/*
 * Wait for an UDP packet coming from the nic and copy its payload in the
 * user-supplied buffer. Slots contatining other kind of packets both from the
 * stack and the nic will be swapped.
 *
 * Return the number of bytes received.
 *
 * TODO check `from' if sockaddr_in*
 */
int
nm_recvfrom(struct params *p, void *buf, int len,
            struct sockaddr *from, socklen_t fromlen)
{
	int bytes;
	char *packet;
	struct pollfd pollfd[2];
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	struct ip *ip;
	struct udphdr *udp;

	pollfd[0].events = pollfd[1].events = POLLIN;
	pollfd[0].fd = p->me[0].fd;	/* stack */
	pollfd[1].fd = p->me[1].fd;	/* nic */

#if 0
	if (p->cur < NUMTS)
		netmap_rdtsc(p->ts[p->cur].container[0]);
	if (p->cur < NUMTS) {
		netmap_rdtsc(p->ts[p->cur].container[1]);
		p->cur++;
	}
#endif
	if (fromlen < sizeof(struct sockaddr_in)) {
		// XXX nuttcp uses `sockaddr_storage'
		// removing this check will trigger warning on unused `fromlen'
		// parameter
		D("ERROR: wrong fromlen");
		return(-1);
	}
	for (;;) {
		/* look for "readable" slots in stack and nic rings */
		if (p->stackring_idx == -1 && p->nicring_idx == -1)
			slothunter(p);
		if ((p->stackring_idx == -1 && p->nicring_idx == -1) ||
		    p->exchanges > 0) {
			/* there are no packets in stack/nic rings or nic slots
			 * have been swapped with stack ones */
			pollfd[0].events = POLLIN;
make_poll:
			pollfd[0].revents = pollfd[1].revents = 0;
			p->count = p->exchanges = 0;
#if STATS
			numrxpoll++;
#endif
			if (poll(pollfd, 2, 100) <= 0) {
				if (pollfd[0].revents & POLLERR)
					D("error on fd0, rxcur %d@%d",
					  p->me[0].rx->avail,
					  p->me[0].rx->cur);
				if (pollfd[1].revents & POLLERR)
					D("error on fd1, rxcur %d@%d",
					  p->me[1].rx->avail,
					  p->me[1].rx->cur);
				continue;
			}
		}
		/* stack -> nic */
		if (p->stackring_idx > -1 || (pollfd[0].revents & POLLIN)) {
			process_rings(p, &p->me[0], &p->me[1]);
			if (p->nicring_idx > -1) {
				/* may occur starvation if there's high traffic
				 * coming from the stack */
				p->stackring_idx = -1;
				p->stackring_avail = 0;
				pollfd[0].events = 0;
			} else {
				pollfd[0].events = POLLIN;
			}
			goto make_poll;
		}
		/* nic -> stack */
		if (p->nicring_idx > -1 || (pollfd[1].revents & POLLIN)) {
			if ((ring = process_rings(p,
			                          &p->me[1],
			                          &p->me[0])) != NULL) {
				slot = &ring->slot[ring->cur];
				/* get packet from slot */
				packet = NETMAP_BUF(ring, slot->buf_idx);
				goto payload_copy;
			}
		}
	}

payload_copy:
	ip = (struct ip *) (packet + sizeof(struct ether_header));
	udp = (struct udphdr *) &ip[1];

	((struct sockaddr_in *) from)->sin_addr.s_addr = ip->ip_src.s_addr;
	((struct sockaddr_in *) from)->sin_port = udp->uh_sport;
	bytes = MIN((u_int) len, (ntohs(udp->uh_ulen) - sizeof(struct udphdr)));
	// XXX erase buffer before copy?
	memcpy(buf, &udp[1], bytes);
	/* update ring indexes */
	ring->avail--;
	ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
	return(bytes);
}

