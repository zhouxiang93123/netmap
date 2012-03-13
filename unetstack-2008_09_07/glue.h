#ifndef GLUE_H
#define GLUE_H
#include <sys/types.h>
#include <unistd.h>

typedef	uint32_t	__u32;
typedef	uint16_t	__u16;
typedef	uint8_t		__u8;
typedef	int32_t		__s32;
typedef	int16_t		__s16;
typedef	int8_t		__s8;

#define __NETCHANNEL_H

#define NETCHANNEL_ADDR_SIZE            16

struct netchannel_addr {
        uint8_t proto;
        uint8_t size;
        uint16_t port;
        uint8_t addr[NETCHANNEL_ADDR_SIZE];
};

/*
 * Destination and source addresses/ports are from receiving point ov view,
 * i.e. when packet is being received, destination is local address.
 */

struct netchannel_control
{
        struct netchannel_addr          saddr, daddr;
        unsigned int                    packet_limit;
};


#define _NETINET_UDP_H_	/* disable system header */
#define _NETINET_TCP_H_	/* disable system header */
#include <netinet/in.h>

#define	ETH_ALEN	6

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };

struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};



struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};

#endif /* GLUE_H */
