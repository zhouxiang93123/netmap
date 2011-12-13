/*
 * $Id$
 *
 * glue for building linux net drivers under freebsd.
 *
 * Import the ofed stuff ?
 */

#ifndef LINUX_BSD_GLUE_H
#define LINUX_BSD_GLUE_H

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>            // device_method_t
#include <sys/kernel.h>
#include <sys/module.h>         // declare_module
#include <sys/types.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <machine/pci_cfgreg.h>

#include <sys/socket.h> // ifru_addr
#include <net/if.h>
#include <net/ethernet.h>
//#include <net/if_vlan_var.h>
#include <net/if_arp.h>

/* linux compatibility stuff */
typedef uint8_t         u8;
typedef uint8_t         __u8;
typedef int8_t          s8;
typedef uint16_t        u16;
typedef uint16_t        __u16;
typedef uint16_t        __be16;
typedef uint16_t        __sum16;
typedef uint16_t        ushort;
typedef uint32_t        u32;
typedef uint32_t        __u32;
typedef uint32_t        __be32;
typedef int32_t         s32; 
typedef uint64_t        u64;
typedef uint64_t        ulong;
typedef boolean_t       bool;
typedef volatile int	atomic_t;
#define	__iomem
typedef	void *		dma_addr_t;
#define	ETH_HLEN	14
#define ETH_ALEN	6
#define	ETH_FCS_LEN	4
#define ETHTOOL_FLASH_MAX_FILENAME       128

#define	likely(x)	(x)
#define	unlikely(x)	(x)
#define	true		1
#define	false		0

#define	typeof(x)	__typeof__(x)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#if BYTE_ORDER == LITTLE_ENDIAN
#define	cpu_to_le16(x)	(x)
#else
#define	cpu_to_le16(x)	ntohs(x)
#endif

#define	BITS_PER_LONG __LONG_BIT
#if BITS_PER_LONG == 64

# define do_div(n,base) ({                                      \
        uint32_t __base = (base);                               \
        uint32_t __rem;                                         \
        __rem = ((uint64_t)(n)) % __base;                       \
        (n) = ((uint64_t)(n)) / __base;                         \
        __rem;                                                  \
 })

#elif BITS_PER_LONG == 32

extern uint32_t __div64_32(uint64_t *dividend, uint32_t divisor);

/* The unnecessary pointer compare is there
 * to check for type safety (n must be 64bit)
 */
# define do_div(n,base) ({                              \
        uint32_t __base = (base);                       \
        uint32_t __rem;                                 \
        (void)(((typeof((n)) *)0) == ((uint64_t *)0));  \
        if (likely(((n) >> 32) == 0)) {                 \
                __rem = (uint32_t)(n) % __base;         \
                (n) = (uint32_t)(n) / __base;           \
        } else                                          \
                __rem = __div64_32(&(n), __base);       \
        __rem;                                          \
 })

#else /* BITS_PER_LONG == ?? */

# error do_div() does not yet support the C64

#endif


//--	typecheck.h
/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({      type __dummy; \
        typeof(x) __dummy2; \
        (void)(&__dummy == &__dummy2); \
        1; \
})

#define printk(fmt , args...) printf(fmt , ##args)
#define	KERN_INFO       "<6>"   /* informational */

extern int jiffies;
extern int HZ;

struct device {
};

//--	include/linux/netdevice.h

struct net_device_stats {
        unsigned long   rx_packets;
        unsigned long   tx_packets;
        unsigned long   rx_bytes;            
        unsigned long   tx_bytes;
        unsigned long   rx_errors;
        unsigned long   tx_errors;
        unsigned long   rx_dropped;
        unsigned long   tx_dropped;
        unsigned long   multicast;
        unsigned long   collisions;
        unsigned long   rx_length_errors;
        unsigned long   rx_over_errors;
        unsigned long   rx_crc_errors;
        unsigned long   rx_frame_errors;
        unsigned long   rx_fifo_errors;
        unsigned long   rx_missed_errors;
        unsigned long   tx_aborted_errors;
        unsigned long   tx_carrier_errors;
        unsigned long   tx_fifo_errors;
        unsigned long   tx_heartbeat_errors;
        unsigned long   tx_window_errors;
        unsigned long   rx_compressed;
        unsigned long   tx_compressed;
};

struct net_device;

#define HAVE_NET_DEVICE_OPS
struct net_device_ops {
        int                     (*ndo_init)(struct net_device *dev);
        void                    (*ndo_uninit)(struct net_device *dev);
        int                     (*ndo_open)(struct net_device *dev);
        int                     (*ndo_stop)(struct net_device *dev);
        netdev_tx_t             (*ndo_start_xmit) (struct sk_buff *skb,
                                                   struct net_device *dev);
        u16                     (*ndo_select_queue)(struct net_device *dev,
                                                    struct sk_buff *skb);
        void                    (*ndo_change_rx_flags)(struct net_device *dev,
                                                       int flags);
        void                    (*ndo_set_rx_mode)(struct net_device *dev);
        void                    (*ndo_set_multicast_list)(struct net_device *dev);
        int                     (*ndo_set_mac_address)(struct net_device *dev,
                                                       void *addr);
        int                     (*ndo_validate_addr)(struct net_device *dev);
        int                     (*ndo_do_ioctl)(struct net_device *dev,
                                                struct ifreq *ifr, int cmd);
        int                     (*ndo_set_config)(struct net_device *dev,
                                                  struct ifmap *map);
        int                     (*ndo_change_mtu)(struct net_device *dev,
                                                  int new_mtu);
        int                     (*ndo_neigh_setup)(struct net_device *dev,
                                                   struct neigh_parms *);
        void                    (*ndo_tx_timeout) (struct net_device *dev);

        struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
                                                     struct rtnl_link_stats64 *storage);
        struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

        void                    (*ndo_vlan_rx_register)(struct net_device *dev,
                                                        struct vlan_group *grp);
        void                    (*ndo_vlan_rx_add_vid)(struct net_device *dev,
                                                       unsigned short vid);
        void                    (*ndo_vlan_rx_kill_vid)(struct net_device *dev,
                                                        unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
        void                    (*ndo_poll_controller)(struct net_device *dev);
        int                     (*ndo_netpoll_setup)(struct net_device *dev,
                                                     struct netpoll_info *info);
        void                    (*ndo_netpoll_cleanup)(struct net_device *dev);
#endif
        int                     (*ndo_set_vf_mac)(struct net_device *dev,
                                                  int queue, u8 *mac);
        int                     (*ndo_set_vf_vlan)(struct net_device *dev,
                                                   int queue, u16 vlan, u8 qos);
        int                     (*ndo_set_vf_tx_rate)(struct net_device *dev,
                                                      int vf, int rate);
        int                     (*ndo_get_vf_config)(struct net_device *dev,
                                                     int vf,
                                                     struct ifla_vf_info *ivf);
        int                     (*ndo_set_vf_port)(struct net_device *dev,
                                                   int vf,
                                                   struct nlattr *port[]);
        int                     (*ndo_get_vf_port)(struct net_device *dev,
                                                   int vf, struct sk_buff *skb);
        int                     (*ndo_setup_tc)(struct net_device *dev, u8 tc);
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
        int                     (*ndo_fcoe_enable)(struct net_device *dev);
        int                     (*ndo_fcoe_disable)(struct net_device *dev);
        int                     (*ndo_fcoe_ddp_setup)(struct net_device *dev,
                                                      u16 xid,
                                                      struct scatterlist *sgl,
                                                      unsigned int sgc);
        int                     (*ndo_fcoe_ddp_done)(struct net_device *dev,
                                                     u16 xid);
        int                     (*ndo_fcoe_ddp_target)(struct net_device *dev,
                                                       u16 xid,
                                                       struct scatterlist *sgl,
                                                       unsigned int sgc);
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
        int                     (*ndo_fcoe_get_wwn)(struct net_device *dev,
                                                    u64 *wwn, int type);
#endif
#ifdef CONFIG_RFS_ACCEL
        int                     (*ndo_rx_flow_steer)(struct net_device *dev,
                                                     const struct sk_buff *skb,
                                                     u16 rxq_index,
                                                     u32 flow_id);
#endif
        int                     (*ndo_add_slave)(struct net_device *dev,
                                                 struct net_device *slave_dev);
        int                     (*ndo_del_slave)(struct net_device *dev,
                                                 struct net_device *slave_dev);
        u32                     (*ndo_fix_features)(struct net_device *dev,
                                                    u32 features);
        int                     (*ndo_set_features)(struct net_device *dev,
                                                    u32 features);
};

struct net_device {
	char                    name[IFNAMSIZ];

	unsigned char           *dev_addr;
	unsigned char		addr_len;
	struct net_device_stats stats;

	unsigned int            flags;  /* interface flags (a la BSD)   */
	unsigned int            mtu;    /* interface MTU value          */


	unsigned int            irq;            /* device IRQ number    */

};

void netif_carrier_on(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);


//--	include/linux/pci.h
struct pci_dev {
	// u16	vendor;
	u16	device;
	struct device dev;
};
int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val);
int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val);

int pci_write_config_byte(struct pci_dev *dev, int where, u8 val);

//--	include/linux/jhash.h
u32 jhash(const void *key, u32 length, u32 initval);

#if defined(__i386__) || defined(__amd64__)
static __inline
void prefetch(void *x)
{
        __asm volatile("prefetcht0 %0" :: "m" (*(unsigned long *)x));
}
#else
#define prefetch(x)
#endif

#define	module_param(a, b, c)
#define	MODULE_PARM_DESC(a, b)
struct pci_devtab {
        u16 vendor;
        u16 device;
};

#define	DEFINE_PCI_DEVICE_TABLE(x)	struct pci_devtab x[]
#define	PCI_DEVICE(v, d)	v, d
#define	MODULE_DEVICE_TABLE(bus, ids)

#define netdev_priv(dev)	((void *)(dev))

// /home/luigi/IMAGES/linux-2.6.39.4/include/linux/dma-mapping-broken.h
typedef int gfp_t;
#define BUG_ON(x)

#define	GFP_KERNEL	0	// XXX
#define ioread32(a)	(*(u32 *)(a))
#define iowrite32(d, a)	*(u32 *)(a) = (d)
extern void *
dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle,
                   gfp_t flag);

extern void
dma_free_coherent(struct device *dev, size_t size, void *cpu_addr,
                    dma_addr_t dma_handle);

// include/linux/etherdevice.h
static inline int is_multicast_ether_addr(const u8 *addr)
{
        return 0x01 & addr[0];
}
static inline int is_zero_ether_addr(const u8 *addr)
{ 
        return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}
static inline int is_valid_ether_addr(const u8 *addr)
{ 
        /* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
         * explicitly check for it here. */
        return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

//--	include/linux/jiffies.h
#define time_after(a,b)         \
        (typecheck(unsigned long, a) && \
         typecheck(unsigned long, b) && \
         ((long)(b) - (long)(a) < 0))

#define time_before(a,b) time_after(b,a)

//--	include/linux/skbuff.h

enum {
        SKB_GSO_TCPV4 = 1 << 0,
        SKB_GSO_UDP = 1 << 1,

        /* This indicates the skb is from an untrusted source. */
        SKB_GSO_DODGY = 1 << 2,
 
        /* This indicates the tcp segment has CWR set. */
        SKB_GSO_TCP_ECN = 1 << 3,

        SKB_GSO_TCPV6 = 1 << 4,

        SKB_GSO_FCOE = 1 << 5,
};

#if BITS_PER_LONG > 32
#define NET_SKBUFF_DATA_USES_OFFSET 1
#endif

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif

#define CHECKSUM_PARTIAL 3
#define MAX_SKB_FRAGS 16UL

typedef struct skb_frag_struct skb_frag_t;

struct skb_frag_struct {
        struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
        __u32 page_offset;
        __u32 size;
#else
        __u16 page_offset;
        __u16 size;
#endif
};

struct skb_shared_info {
	unsigned short  nr_frags;
	unsigned short  gso_size;
	unsigned short  gso_type;

	skb_frag_t      frags[MAX_SKB_FRAGS];

};

struct sk_buff {
	unsigned int            len;
	unsigned int            data_len;
	u8		ip_summed;

	__u16                   vlan_tci;

        /* These elements must be at the end, see alloc_skb() for details.  */
        sk_buff_data_t          end;
	unsigned char           *head,
                                *data;

};

#ifdef NET_SKBUFF_DATA_USES_OFFSET
static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
        return skb->head + skb->end;
}
#else
static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
        return skb->end;
}
#endif

#define skb_shinfo(SKB)   ((struct skb_shared_info *)(skb_end_pointer(SKB)))

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
        return skb->len - skb->data_len;
}

static inline int skb_is_gso(const struct sk_buff *skb)
{       
        return skb_shinfo(skb)->gso_size;
}
static inline int skb_is_gso_v6(const struct sk_buff *skb)
{
        return skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6;
}


//---		include/linux/if_link.h
struct ifla_vf_info {
        __u32 vf;
        __u8 mac[32];
        __u32 vlan;
        __u32 qos;
        __u32 tx_rate;
};

//---------
struct msix_entry {
	int		entry;
};

struct mutex {
};
typedef	void * spinlock_t;

struct napi_struct {
};

struct delayed_work {
};
struct completion {
};

#define DEFINE_DMA_UNMAP_ADDR(x)	void * x
#include <netinet/in.h>
// #include <netinet/ip.h>
#include <netinet/ip6.h>
// include/linux/ip.h
struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
        __u8    ihl:4,
                version:4;
#elif BYTE_ORDER == BIG_ENDIAN
        __u8    version:4,
                ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __be16  tot_len;
        __be16  id;
        __be16  frag_off;
        __u8    ttl;
        __u8    protocol;
        __sum16 check;  
        __be32  saddr;
        __be32  daddr;
        /*The options start here. */
};


static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
        return 0; // XXX (struct iphdr *)skb_network_header(skb);
}
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
        return 0; // XXX (struct iphdr *)skb_network_header(skb);
}


//--	include/linux/ipv6.h
struct ipv6hdr {
#if BYTE_ORDER == LITTLE_ENDIAN
        __u8                    priority:4,
                                version:4;
#elif BYTE_ORDER == BIG_ENDIAN
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __be16                  payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};

struct rcu_head {
};

//--	 include/linux/if_vlan.h
#define VLAN_PRIO_MASK          0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT         13
#define VLAN_CFI_MASK           0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT        VLAN_CFI_MASK
#define VLAN_VID_MASK           0x0fff /* VLAN Identifier */
#define VLAN_N_VID              4096
#define VLAN_GROUP_ARRAY_SPLIT_PARTS  8
#define VLAN_GROUP_ARRAY_PART_LEN     (VLAN_N_VID/VLAN_GROUP_ARRAY_SPLIT_PARTS)

struct hlist_node {
};

struct vlan_group {
        struct net_device       *real_dev; /* The ethernet(like) device
                                            * the vlan is attached to.
                                            */
        unsigned int            nr_vlans;
        int                     killall;
        struct hlist_node       hlist;  /* linked list */
        struct net_device **vlan_devices_arrays[VLAN_GROUP_ARRAY_SPLIT_PARTS];
        struct rcu_head         rcu;
};


#define vlan_tx_tag_present(__skb)      ((__skb)->vlan_tci & VLAN_TAG_PRESENT)
#define vlan_tx_tag_get(__skb)          ((__skb)->vlan_tci & ~VLAN_TAG_PRESENT)

static inline void vlan_group_set_device(struct vlan_group *vg,
                                         u16 vlan_id,
                                         struct net_device *dev)
{
        struct net_device **array;
        if (!vg)
                return;
        array = vg->vlan_devices_arrays[vlan_id / VLAN_GROUP_ARRAY_PART_LEN];
        array[vlan_id % VLAN_GROUP_ARRAY_PART_LEN] = dev;
}
 

//--		 include/net/ipv6.h:
#define NEXTHDR_TCP		6	// XXX
#define NEXTHDR_UDP		17	// XXX

#endif /* LINUX_BSD_GLUE_H */
