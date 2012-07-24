/*
 * $Id: connlib.h 208 2012-03-26 16:44:33Z 27148317-unipi $
 */

#include <signal.h>
#include <fcntl.h>	/* open */
#include <stdio.h>	/* fprintf */
#include <stdlib.h>	/* exit */
#include <unistd.h>	/* close */
#include <string.h>	/* strncpy */
#include <strings.h>	/* bzero */
#include <ifaddrs.h>	/* getifaddrs */
#include <errno.h>

#include <sys/mman.h>	/* PROT_* */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>	/* inet_ntoa */

#include <net/if.h>		/* ifreq */
#include <net/netmap.h>
#include <net/netmap_user.h>
#include <net/if_dl.h>		/* LLADDR */
#include <net/route.h>		/* RTF_LLINFO */

#include <netinet/in.h>		/* inet_ntoa */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>	/* struct sockaddr_inarp */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define UDP 1
#define TCP 2

#define D(format, ...) do {                         \
        fprintf(stderr, "%s [%d] - " format "\n",   \
        __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
} while (0)

/******************************************/
/* Wrapper around `rdtsc' to take reliable timestamps flushing the pipeline */
#define netmap_rdtsc(t) \
	do { \
		u_int __regs[4];					\
									\
		do_cpuid(0, __regs);					\
		(t) = rdtsc();						\
	} while (0)

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax));
}

static __inline uint64_t
rdtsc(void)
{
	uint64_t rv;

	__asm __volatile("rdtsc" : "=A" (rv));
	return (rv);
}
/******************************************/

/*
 * Info on a ring we handle.
 */
struct my_ring {
	const char *ifname;
	int fd;
	char *mem;			/* userspace mmap address */
	u_int memsize;
	u_int queueid;
	u_int begin, end;		/* first..last+1 rings to check */
	struct netmap_if *nifp;
	struct netmap_ring *tx, *rx;	/* shortcuts to first tx/rx ring */

	uint32_t if_flags;
	uint32_t if_reqcap;
	uint32_t if_curcap;
};

struct arp_packet {
	struct ether_header eh;
	struct arphdr arp;
} __attribute__((__packed__));	/* 1 byte alignment */

struct udp_packet_headers {
	struct ether_header eh;
	struct ip ip;
	struct udphdr udp;
} __attribute__((__packed__));	/* 1 byte alignment */

/*
 * Netmap socket info.
 */
struct params {
	struct my_ring me[2];	/* 0: STACK; 1: NIC */
	struct ether_addr if_mac_address, dst_mac_address;
	struct sockaddr_in rx, tx; /* IP addresses and ports of
	                            * ingoing / outgoing connections */
	struct in_addr if_ip_address; /* IP address of the interface passed
	                               * to nm_socket() function (needed for
	                               * ARP request process) */
	int inaddr_any_enabled; /* if 1 nm_recvfrom() won't check IP
	                         * destination address field */
	u_int exchanges; /* number of NIC slots swapped with STACK slots in
	                  * nm_recvfrom() loop */
	int max_payload_size, minlen; /* maximum payload size and
	                               * minimum packet length */
	struct udp_packet_headers udp_pkt_hdr;
	uint16_t udp_const_hdr; /* checksum of constant fields of the UDP
	                         * header */
	uint16_t ip_const_hdr; /* checksum of constant fields of the IP
	                        * header */
	uint16_t ip_id;		/* pseudo random... */

	int stackring_idx, nicring_idx; /* indexes of ring with usable slots
	                                 * (-1 if there aren't) */
	u_int stackring_avail, nicring_avail; /* number of usable slot in
	                                       * `stackring_idx' and
	                                       * `nicring_idx' */
	u_int count; /* number of slot freed in nic rings since last
	              * poll/ioctl */
#define SYNC_LIM 500 /* counter limit (of nic freed slots) to next
                      * synchronization ioctl */

	// XXX rdtsc debug
#define NUMTS 10000000
	struct stats {
		uint64_t container[2];
	} ts[NUMTS];
	u_int cur;
};

#if defined(__i386__) || defined(__amd64__)
static __inline
void prefetch(void *x)
{
        __asm volatile("prefetcht0 %0" :: "m" (*(unsigned long *)x));
}
#else
#define prefetch(x)
#endif

struct params* nm_socket(char *, int, int);
int nm_connect(struct params *, const struct sockaddr *, socklen_t);
void nm_close_socket(struct params *);
int nm_send(struct params *, const void *, int);
int nm_sendto(struct params *, const void *, int ,
              const struct sockaddr *, socklen_t);
int nm_bind(struct params *, const struct sockaddr *, socklen_t);
int nm_recvfrom(struct params *, void *, int, struct sockaddr *, socklen_t);

