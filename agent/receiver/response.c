#include <linux/byteorder/little_endian.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/ctx/xdp.h>
#include <bpf/builtins.h>
#include <bpf/helpers.h>
#include <lib/endian.h>
#include <lib/csum.h>

#define NULL ((void *)0)

#define PING_PORT   65532
#define DONE        8
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2

#define ETH_HLEN            __ETH_HLEN

#define IP_HLEN             sizeof(struct iphdr)
#define TCP_CSUM_OFFSET     (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFFSET     (ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check))
#define ACK_SEQ_OFFSET      (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, ack_seq))

#define TCP_FLAG_FIELD_OFFSET ( (__u64)&tcp_flag_word( (struct tcphdr *)0 ) )
#define TCP_FLAG_OFFSET       (ETH_HLEN + IP_HLEN + TCP_FLAG_FIELD_OFFSET)

#define bpf_printk(fmt, ...)    ({                             \
    const char ____fmt[] = fmt;                                \
    trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
})
#define BPF_FUNC_clone_redirect 52
#define BPF_FUNC_skb_adjust_room 50

static __inline int bpf_skb_adjust_room(struct __sk_buff *skb, int len_diff, __u32 mode, __u64 flags) {
    return ((int (*)(struct __sk_buff *, int, __u32, __u64)) BPF_FUNC_skb_adjust_room)(skb, len_diff, mode, flags);
}
static __inline int bpf_clone_redirect(struct __sk_buff *skb, __u32 ifindex, __u64 flags) {
    return ((int (*)(struct __sk_buff *, __u32, __u64)) BPF_FUNC_clone_redirect)(skb, ifindex, flags);
}

static __always_inline void compute_ip_checksum(struct iphdr *iph);
static __always_inline void compute_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);

// static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)6;

typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

#define __uint(name,val) int (*name)[val]
#define __type(name,val) typeof(val) *name
#define SEC(NAME) __attribute__((section(NAME), used))

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

static inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp_mac[ETH_ALEN];

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);
}

static inline void swap_ip(struct iphdr *ip)
{
    struct in_addr tmp_ip;

    memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
    memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
    memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));
}

static inline void swap_ip6(struct ipv6hdr *ip6)
{
    struct in6_addr tmp_ip6;

    memcpy(&tmp_ip6, &ip6->saddr, sizeof(tmp_ip6));
    memcpy(&ip6->saddr, &ip6->daddr, sizeof(tmp_ip6));
    memcpy(&ip6->daddr, &tmp_ip6, sizeof(tmp_ip6));
}

static inline void swap_port(struct tcphdr *tcp)
{
    __u16 tmp_port;

    memcpy(&tmp_port, &tcp->source, sizeof(tmp_port));
    memcpy(&tcp->source, &tcp->dest, sizeof(tmp_port));
    memcpy(&tcp->dest, &tmp_port, sizeof(tmp_port));
}

static inline void swap_portu(struct udphdr *udp)
{
    __u16 tmp_port;

    memcpy(&tmp_port, &udp->source, sizeof(tmp_port));
    memcpy(&udp->source, &udp->dest, sizeof(tmp_port));
    memcpy(&udp->dest, &tmp_port, sizeof(tmp_port));
}

struct rtt_event_t {
    __u64 rtt;
    __u64 prot;     // 0:TCP, 1:UDP, 2:ICMP
    // __u32 src_ip;
    // __u32 dst_ip;
    // __u16 src_port;
    // __u16 dst_port;
} __attribute__((packed));

struct debug_event_t {
    __u64 tag;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, CPU);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, 1);
} debug_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, CPU);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, 1);
} rtt_events SEC(".maps");

struct rtt_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 protocol;
    __u32 seq;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rtt_key_t);
    __type(value, __u64);
    __uint(pinning, 1);
} rtt_start SEC(".maps");

static __always_inline int mac_equal(const __u8 *a, const __u8 *b) {
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

__section("xdp")
int xdp_ping(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int ret = 0;

    /* eth */
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);
    if (unlikely(data + nh_off > data_end))
        return XDP_DROP;

    __be16 h_proto = eth->h_proto;

    /* vlan */
    __u64 vlanhdr_len = 0;
    // handle double tags in ethernet frames
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (bpf_htons(ETH_P_8021Q) == h_proto || bpf_htons(ETH_P_8021AD) == h_proto) {
            struct vlanhdr *vhdr = data + nh_off;

            nh_off += sizeof(*vhdr);
            if (data + nh_off > data_end)
                return XDP_DROP;

            vlanhdr_len += sizeof(*vhdr);
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    // // 判断是否是 RST+ACK 包（计算 RTT）
    // if (bpf_htons(ETH_P_IPV6) == h_proto) {
    //     // IPv6
    //     struct ipv6hdr *ip6 = data + nh_off;
    //     if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
    //         return XDP_DROP;
    //     if (ip->daddr != bpf_htonl(IP6)) {
    //         return XDP_PASS;
    //     }

    //     if (IPPROTO_ROUTING == ip6->nexthdr) {
    //         // Parse SRH header
    //         struct ipv6_sr_hdr {
    //             __u8 nexthdr;
    //             __u8 hdrlen;
    //             __u8 type;
    //             __u8 segments_left;
    //             __u8 last_entry;
    //             __u8 flags;
    //             __u16 reserved;
    //             struct in6_addr segments[0];
    //         };
    //         struct ipv6_sr_hdr *srh = (void *)ip6 + sizeof(*ip6);            
    //         if (unlikely((void *)srh + sizeof(*srh) > data_end))
    //             return XDP_DROP;

    //         if (srh->type != 4) {
    //             return XDP_PASS;
    //         }

    //         if (IPPROTO_TCP == srh->nexthdr) {
    //             struct tcphdr *tcp = (void *)srh + 8 + 8*srh->hdrlen;
    //             if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
    //                 return XDP_DROP;
    //             if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
    //                 return XDP_PASS;
    //             }

    //             // 确保 payload 存在
    //             void *payload = (void *)tcp + sizeof(*tcp);
    //             if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) >= data_end))
    //                 return XDP_DROP;
                
    //             __u64* direct = payload;
    //             char* tag = payload + sizeof(__u64);
    //             __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //             struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                
    //             if ((tcp->ack == 1) && (tcp->rst == 1) && (tcp->syn == 0)) {
    //                 // 计算 RTT
    //                 __u64 now = bpf_ktime_get_ns();
    //                 struct rtt_event_t evt = {};
    //                 evt.rtt = now - *start;
    //                 evt.prot = 0;
    //                 bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    //                 return XDP_DROP;
    //             }
    //             return XDP_PASS;
    //         }
    //         else if (IPPROTO_UDP == srh->nexthdr) {
    //             struct udphdr *udp = (void *)srh + 8 + 8*srh->hdrlen;
    //             if (unlikely((void *)udp + sizeof(*udp) > data_end))
    //                 return XDP_DROP;

    //             if (bpf_ntohs(udp->dest) != PING_PORT && bpf_ntohs(udp->source) != PING_PORT) {
    //                 return XDP_PASS;
    //             }

    //             // 确保 payload 存在
    //             void *payload = (void *)udp + sizeof(*udp);
    //             if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) >= data_end))
    //                 return XDP_DROP;
                
    //             __u64* direct = payload;
    //             char* tag = payload + sizeof(__u64);
    //             __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //             struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
    //             if (*direct == 1) {
    //                 // 计算 RTT
    //                 __u64 now = bpf_ktime_get_ns();
    //                 struct rtt_event_t evt = {};
    //                 evt.rtt = now - *start;
    //                 evt.prot = 1;
    //                 bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    //                 return XDP_DROP;
    //             }
    //             return XDP_PASS;
    //         }
    //         else if (IPPROTO_ICMPV6 == srh->nexthdr) {
    //             struct icmp6hdr *icmp6 = (void *)srh + 8 + 8*srh->hdrlen;
    //             if (unlikely((void *)icmp6 + sizeof(*icmp6) > data_end))
    //                 return XDP_DROP;

    //             // 确保 payload 存在
    //             void *payload = (void *)icmp6 + sizeof(*icmp6);
    //             if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) >= data_end))
    //                 return XDP_DROP;
                
    //             __u64* direct = payload;
    //             char* tag = payload + sizeof(__u64);
    //             __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //             struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                
    //             if (icmp6->icmp6_type == ICMPV6_ECHO_REPLY) {
    //                 // 计算 RTT
    //                 __u64 now = bpf_ktime_get_ns();
    //                 struct rtt_event_t evt = {};
    //                 evt.rtt = now - *start;
    //                 evt.prot = 2;
    //                 bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    //                 return XDP_DROP;
    //             }
    //             return XDP_PASS;
    //         }
    //     }
    //     return XDP_PASS;
    // }

    /* ipv4 */
    if (bpf_htons(ETH_P_IP) != h_proto)
        return XDP_PASS;

    struct iphdr *ip = data + nh_off;
    if (unlikely((void *)ip + sizeof(*ip) > data_end))
        return XDP_DROP;

    /* tcp */
    if (IPPROTO_TCP == ip->protocol) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
            return XDP_DROP;

        if (bpf_ntohs(tcp->dest) != PING_PORT || bpf_ntohs(tcp->source) != PING_PORT) {
            return XDP_PASS;
        }

        /* main logic */
        if (tcp->ack) {
            // bpf_printk("rst SELF: %d", SELF);
            // bpf_printk("rst");
            struct rtt_key_t key = {};
            key.src_ip = ip->daddr;
            key.dst_ip = ip->saddr;
            key.src_port = tcp->dest;
            key.dst_port = tcp->source;
            key.protocol = ip->protocol;
            // key.seq = tcp->seq;
            key.seq = bpf_htonl(bpf_ntohl(tcp->ack_seq)-1);
            // bpf_printk("2 ack_seq: %u", bpf_ntohl(tcp->ack_seq));
            // bpf_printk("2 src_ip: %u.", (bpf_ntohl(key.src_ip) >> 24) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.src_ip) >> 16) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.src_ip) >> 8) & 0xFF);
            // bpf_printk("%u", bpf_ntohl(key.src_ip) & 0xFF);
            // bpf_printk("2 dst_ip: %u.", (bpf_ntohl(key.dst_ip) >> 24) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.dst_ip) >> 16) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.dst_ip) >> 8) & 0xFF);
            // bpf_printk("%u", bpf_ntohl(key.dst_ip) & 0xFF);

            // bpf_printk("2 src_port: %u", bpf_ntohs(key.src_port));
            // bpf_printk("2 dst_port: %u", bpf_ntohs(key.dst_port));
            // bpf_printk("2 protocol: %u", key.protocol);
            // bpf_printk("2 seq: %u", bpf_ntohl(key.seq));

            // __u64* start = bpf_map_lookup_elem(&rtt_start, &key);

            // 确保 payload 存在
            void *payload = (void *)tcp + sizeof(*tcp);
            if (unlikely(payload + 2*sizeof(__u64) + 2*sizeof(__u32) > data_end))
                return XDP_PASS;
            
            __u64* start = payload;
            __u64* direct = payload + sizeof(__u64);
            __u32* src = payload + 2*sizeof(__u64);
            __u32* dst = payload + 2*sizeof(__u64) + sizeof(__u32);
            // bpf_printk("tcp back0");

            if (bpf_ntohl(*src) == (__u32)SELF) {
            // if (start) {
                // bpf_printk("tcp back1");
                __u64 now = bpf_ktime_get_ns();
                struct rtt_event_t evt = {};
                if (unlikely((void *)start + sizeof(*start) > data_end))
                    return XDP_PASS;
                // bpf_printk("tcp back2");
                evt.rtt = now - *start;
                evt.prot = 0;
                // if (unlikely(evt.rtt > 10000000)) {
                //     return XDP_DROP;
                // }
                bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                // bpf_printk("tcp back3");
                // bpf_map_delete_elem(&rtt_start, &key);
                return XDP_DROP;
            }
            return XDP_PASS;
        }
        // 确保 payload 存在
        void *payload = (void *)tcp + sizeof(*tcp);
        if (unlikely(payload + 2*sizeof(__u64) + 2*sizeof(__u32) > data_end))
            return XDP_PASS;
        
        // __u64* start = payload;
        __u64* direct = payload + sizeof(__u64);
        __u32* src = payload + 2*sizeof(__u64);
        __u32* dst = payload + 2*sizeof(__u64) + sizeof(__u32);

        // // bpf_printk("in daddr: %u", (ip->daddr >> 24) & 0xFF);
        // // bpf_printk("in daddr: %u", (ip->daddr >> 16) & 0xFF);
        // // bpf_printk("in daddr: %u", (ip->daddr >> 8) & 0xFF);
        // // bpf_printk("in daddr: %u", ip->daddr & 0xFF);

        // // bpf_printk("in src: %u", bpf_ntohl(*src));
        // // bpf_printk("in dst: %u", bpf_ntohl(*dst));
        // // bpf_printk("in SELF: %d", SELF);

        if (1 != tcp->syn)
            return XDP_PASS;
        
        if (bpf_ntohl(*dst) != (__u32)SELF) {
            return XDP_PASS;
        }
        // // bpf_printk("in pass");
        // // bpf_printk("syn");

        // // 使用 bpf_xdp_adjust_tail 缩小数据包大小，移除 TCP 负载
        // int ret = ctx_adjust_troom(ctx, -PAYLOAD_LENGTH);
        // if (ret != 0) {
        //     // 调整失败，返回原始数据包
        //     return XDP_PASS;
        // }
        
        // // 重新获取指针，因为 bpf_xdp_adjust_tail 可能会改变数据区域
        // data_end = (void *)(long)ctx->data_end;
        // data = (void *)(long)ctx->data;

        // eth = data;
        // ip = data + nh_off;
        // tcp = (void *)ip + sizeof(*ip);
        // if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
        //     return XDP_DROP;

        // // 更新 IP 总长度字段（以字节为单位）
        // __u16 old_ip_tot_len = bpf_ntohs(ip->tot_len);
        // __u16 new_ip_tot_len = old_ip_tot_len - PAYLOAD_LENGTH;
        // ip->tot_len = bpf_htons(new_ip_tot_len);

        swap_mac(eth);
        swap_ip(ip);
        swap_port(tcp);

        __u16 *tcp_flag = (void *)tcp + TCP_FLAG_FIELD_OFFSET;
        __u16 old_tcp_flag = *tcp_flag;
        __u16 new_tcp_flag = *tcp_flag;

        /* clear syn bit */
        new_tcp_flag &= ~TCP_FLAG_SYN;
        /* set rst bit */
        // new_tcp_flag |= TCP_FLAG_RST;
        new_tcp_flag &= ~TCP_FLAG_RST;
        /* set ack bit */
        new_tcp_flag |= TCP_FLAG_ACK;

        ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_tcp_flag, new_tcp_flag, 0);
        if (unlikely(ret)) {
            return XDP_DROP;
        }

        memcpy(data + TCP_FLAG_OFFSET + vlanhdr_len, &new_tcp_flag, sizeof(new_tcp_flag));

        /* calculate and set ack sequence */
        __be32 old_ack_seq = tcp->ack_seq;
        __be32 new_ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
        // // bpf_printk("old seq: %u", bpf_ntohl(tcp->seq));
        // // bpf_printk("new ack seq: %u", bpf_ntohl(new_ack_seq));

        ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_ack_seq, new_ack_seq, 0);
        if (unlikely(ret)) {
            return XDP_DROP;
        }
        // // // bpf_printk("back new_ack_seq: %u", bpf_ntohl(new_ack_seq));

        memcpy(data + ACK_SEQ_OFFSET + vlanhdr_len, &new_ack_seq, sizeof(new_ack_seq));

        // // 重新计算 IP 校验和
        // compute_ip_checksum(ip);
        
        // // 重新计算 TCP 校验和
        // if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
        //     return XDP_DROP;
        // }
        // compute_tcp_checksum(ip, tcp);
        // // bpf_printk("new tcp check: %x", tcp->check);
        
        // // bpf_printk("back daddr: %u", (ip->daddr >> 24) & 0xFF);
        // // bpf_printk("back daddr: %u", (ip->daddr >> 16) & 0xFF);
        // // bpf_printk("back daddr: %u", (ip->daddr >> 8) & 0xFF);
        // // bpf_printk("back daddr: %u", ip->daddr & 0xFF);
        // // bpf_printk("back tag: %u", tcp->syn);
        // // bpf_printk("back ack: %u", tcp->ack);
        // // bpf_printk("back rst: %u", tcp->rst);
        // // bpf_printk("back seq: %u", bpf_ntohl(tcp->seq));
        // // bpf_printk("back ack seq: %u", bpf_ntohl(tcp->ack_seq));
        // // bpf_printk("back");
        return XDP_TX;
    }
    else if (IPPROTO_UDP == ip->protocol) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if (unlikely((void *)udp + sizeof(*udp) > data_end))
            return XDP_DROP;
        if (bpf_ntohs(udp->dest) != PING_PORT && bpf_ntohs(udp->source) != PING_PORT) {
            return XDP_PASS;
        }

        /* main logic */
        // 确保 payload 存在
        void *payload = (void *)udp + sizeof(*udp);
        if (unlikely(payload + 2*sizeof(__u64) + 2*sizeof(__u32) > data_end))
            return XDP_PASS;
        
        __u64* start = payload;
        __u64* direct = payload + sizeof(__u64);
        __u32* src = payload + 2*sizeof(__u64);
        __u32* dst = payload + 2*sizeof(__u64) + sizeof(__u32);
            
        // bpf_printk("udp");
        if (*direct == (__u64)1) {
            if (bpf_ntohl(*src) != (__u32)SELF) {
                return XDP_PASS;
            }
            // bpf_printk("udp SELF: %d", SELF);
            // bpf_printk("udp rtt");
            // 收到回包
            __u64 now = bpf_ktime_get_ns();
            struct rtt_event_t evt = {};
            evt.rtt = now - *start;
            evt.prot = 1;
            bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            return XDP_DROP;
        }
        // bpf_printk("udp SELF: %d", SELF);
        if (bpf_ntohl(*dst) != (__u32)SELF) {
            return XDP_PASS;
        }

        swap_mac(eth);
        swap_ip(ip);
        swap_portu(udp);

        *direct = (__u64)1;
        // bpf_printk("back");
        return XDP_TX;
    }
    return XDP_PASS;
}

// IP 校验和计算函数（与之前提供的相同）
static __always_inline void compute_ip_checksum(struct iphdr *iph)
{
    // 首先将校验和字段设为 0
    iph->check = 0;
    
    // 计算校验和
    __u16 *iph_words = (__u16 *)iph;
    __u32 csum = 0;
    
    // IP 头部长度是 iph->ihl * 4 字节
    for (int i = 0; i < sizeof(*iph) / 2; i++) {
        csum += bpf_ntohs(iph_words[i]);
        csum = (csum & 0xFFFF) + (csum >> 16);
        // bpf_printk("words: %x", bpf_ntohs(iph_words[i]));
        // bpf_printk("ip sum: %x", csum);
    }
    
    // 处理进位
    csum = (csum & 0xFFFF) + (csum >> 16);
    // bpf_printk("ip sum: %x", csum);
    
    // 取反
    iph->check = bpf_ntohs(~csum);
    // bpf_printk("ip check: %x", iph->check);
}

// TCP 校验和计算函数（与之前提供的相同）
static __always_inline void compute_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph)
{
    // TCP 校验和计算需要 IP 伪头部 + TCP 头部 + TCP 数据
    // 首先将校验和字段设为 0
    tcph->check = 0;
    
    // 计算 TCP 数据的长度（IP 总长度减去 IP 头部长度）
    __u16 tcp_len = sizeof(*tcph);
    
    // 计算伪头部的校验和
    __u32 csum = 0;
    
    // 添加源 IP 和目的 IP 到校验和
    __u32 *saddr = &iph->saddr;
    csum += (bpf_ntohl(*saddr) >> 16) & 0xFFFF;
    csum += bpf_ntohl(*saddr) & 0xFFFF;
    // // bpf_printk("src ip: %x", bpf_ntohl(*saddr));
    // // bpf_printk("src ip: %x", (bpf_ntohl(*saddr) >> 16) & 0xFFFF);
    // // bpf_printk("src ip: %x", bpf_ntohl(*saddr) & 0xFFFF);
    // // bpf_printk("csum: %x", csum);
    csum = (csum & 0xFFFF) + (csum >> 16);
    
    __u32 *daddr = &iph->daddr;
    csum += (bpf_ntohl(*daddr) >> 16) & 0xFFFF;
    csum += bpf_ntohl(*daddr) & 0xFFFF;
    // // bpf_printk("dst ip: %x", bpf_ntohl(*daddr));
    // // bpf_printk("dst ip: %x", (bpf_ntohl(*daddr) >> 16) & 0xFFFF);
    // // bpf_printk("dst ip: %x", bpf_ntohl(*daddr) & 0xFFFF);
    // // bpf_printk("csum: %x", csum);
    csum = (csum & 0xFFFF) + (csum >> 16);
    
    // 添加协议和 TCP 长度
    csum += (__u16)iph->protocol;
    // // bpf_printk("ip protocol: %x", (__u16)iph->protocol);
    csum += (__u16)tcp_len;
    // // bpf_printk("tcp len: %x", tcp_len);
    csum = (csum & 0xFFFF) + (csum >> 16);

    // // bpf_printk("ip sum: %x", csum);
    
    // 添加 TCP 头部和数据到校验和
    __u16 *tcp_words = (__u16 *)tcph;
    __u16 payload_words = tcp_len / 2;
    
    for (int i = 0; i < payload_words; i++) {
        csum += bpf_ntohs(tcp_words[i]);
        csum = (csum & 0xFFFF) + (csum >> 16);
        // // bpf_printk("words: %x", bpf_ntohs(tcp_words[i]));
        // // bpf_printk("tcp sum: %x", csum);
    }
    
    // 如果 TCP 数据长度为奇数，处理最后一个字节
    // if (tcp_len & 1) {
    //     __u8 *last_byte = (__u8 *)tcph + tcp_len - 1;
    //     csum += bpf_ntohl(*last_byte) << 8;
    // }
    
    // // bpf_printk("tcp sum: %x", csum);
    
    // 处理进位
    csum = (csum & 0xFFFF) + (csum >> 16);
    // // bpf_printk("tcp sum: %x", csum);
    
    // 取反
    tcph->check = bpf_htons(~csum);
    // // bpf_printk("new tcp check: %x", tcph->check);
}

SEC("tc")
int trace_egress(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int ret = 0;

    /* eth */
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);
    if (unlikely(data + nh_off > data_end))
        return TC_ACT_SHOT;

    __be16 h_proto = eth->h_proto;

    /* vlan */
    __u64 vlanhdr_len = 0;
    // handle double tags in ethernet frames
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (bpf_htons(ETH_P_8021Q) == h_proto || bpf_htons(ETH_P_8021AD) == h_proto) {
            struct vlanhdr *vhdr = data + nh_off;

            nh_off += sizeof(*vhdr);
            if (data + nh_off > data_end)
                return TC_ACT_SHOT;

            vlanhdr_len += sizeof(*vhdr);
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    // // 判断是否是 RST+ACK 包（计算 RTT）
    // if (bpf_htons(ETH_P_IPV6) == h_proto) {
    //     // IPv6
    //     struct ipv6hdr *ip6 = data + nh_off;
    //     if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
    //         return TC_ACT_SHOT;

    //         if (IPPROTO_ROUTING == ip6->nexthdr) {
    //             // Parse SRH header
    //             struct ipv6_sr_hdr {
    //                 __u8 nexthdr;
    //                 __u8 hdrlen;
    //                 __u8 type;
    //                 __u8 segments_left;
    //                 __u8 last_entry;
    //                 __u8 flags;
    //                 __u16 reserved;
    //                 struct in6_addr segments[0];
    //             };
    //             struct ipv6_sr_hdr *srh = (void *)ip6 + sizeof(*ip6);            
    //             if (unlikely((void *)srh + sizeof(*srh) > data_end))
    //                 return TC_ACT_SHOT;
    
    //             if (srh->type != 4) {
    //                 return TC_ACT_OK;
    //             }
    //             if (srh->segments_left != 0) {
    //                 return TC_ACT_OK;
    //             }
    
    //             /* TCP */
    //             if (IPPROTO_TCP == srh->nexthdr) {
    //                 // // // bpf_printk("TC 333333");
    //                 struct tcphdr *tcp = (void *)srh + 8 + 8*srh->hdrlen;
    //                 if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
    //                     return TC_ACT_SHOT;
    //                 // // // bpf_printk("TC 444444");
            
    //                 if (!tcp->syn || tcp->ack || tcp->rst) {
    //                     return TC_ACT_OK;
    //                 }
    //                 // // // bpf_printk("TC 555555");
            
    //                 if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
    //                     return TC_ACT_OK;
    //                 }
    //                 // // // bpf_printk("TC 666666");
            
    //                 // 确保 payload 存在
    //                 void *payload = (void *)tcp + sizeof(*tcp);
    //                 if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
    //                     return TC_ACT_SHOT;
    //                 // // // bpf_printk("TC 777777");
                    
    //                 __u64* direct = payload;
    //                 char* tag = payload + sizeof(__u64);
    //                 __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //                 struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);

    //                 // 修改 map 的内容
    //                 __u64 time = bpf_ktime_get_ns();
    //                 memcpy(start, &time, sizeof(time));
    //                 memcpy(addr, &ip6->saddr, sizeof(ip6->saddr));
    //                 // // // bpf_printk("TC 888888");
            
    //                 // // 修改 payload 的内容
    //                 // __u64 new_payload = 0x12345678; // 新的 payload 内容
    //                 // int payload_len = sizeof(new_payload);
            
    //                 // // 确保修改不会越界
    //                 // if ((void *)payload + payload_len > data_end)
    //                 //     return TC_ACT_SHOT;
            
    //                 // new_payload = bpf_ktime_get_ns();
    //                 // // 将新的 payload 写入数据包
    //                 // memcpy(payload, &new_payload, payload_len);
    //                 return TC_ACT_OK;
    //             }
    //             else if (IPPROTO_UDP == srh->nexthdr) {
    //                 struct udphdr *udp = (void *)srh + 8 + 8*srh->hdrlen;
    //                 if (unlikely((void *)udp + sizeof(*udp) > data_end))
    //                     return TC_ACT_SHOT;

    //                 if (bpf_ntohs(udp->dest) != PING_PORT && bpf_ntohs(udp->source) != PING_PORT) {
    //                     return TC_ACT_OK;
    //                 }
    //                 // 确保 payload 存在
    //                 void *payload = (void *)udp + sizeof(*udp);
    //                 if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
    //                     return TC_ACT_SHOT;
                    
    //                 __u64* direct = payload;
    //                 char* tag = payload + sizeof(__u64);
    //                 __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //                 struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                    
    //                 if (*direct == 0) {
    //                     // 修改 map 的内容
    //                     __u64 time = bpf_ktime_get_ns();
    //                     memcpy(start, &time, sizeof(time));
    //                     memcpy(addr, &ip6->saddr, sizeof(ip6->saddr));
    //                 }
    //                 return TC_ACT_OK;
    //             }
    //             else if (IPPROTO_ICMPV6 == srh->nexthdr) {
    //                 struct icmp6hdr *icmp6 = (void *)srh + 8 + 8*srh->hdrlen;
    //                 if (unlikely((void *)icmp6 + sizeof(*icmp6) > data_end))
    //                     return TC_ACT_SHOT;

    //                 if (icmp6->icmp6_type != ICMPV6_ECHO_REQUEST)
    //                     return TC_ACT_OK;
                    
    //                 // 确保 payload 存在
    //                 void *payload = (void *)icmp6 + sizeof(*icmp6);
    //                 if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
    //                     return TC_ACT_SHOT;
                    
    //                 __u64* direct = payload;
    //                 char* tag = payload + sizeof(__u64);
    //                 __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //                 struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                    
    //                 if (*direct == 0) {
    //                     // 修改 map 的内容
    //                     __u64 time = bpf_ktime_get_ns();
    //                     memcpy(start, &time, sizeof(time));
    //                     memcpy(addr, &ip6->saddr, sizeof(ip6->saddr));
    //                 }
    //                 return TC_ACT_OK;
    //             }
    //         }
    //     return TC_ACT_OK;
    // }

    if (bpf_htons(ETH_P_IP) != h_proto)
        return TC_ACT_OK;

    struct iphdr *ip = data + nh_off;
    if (unlikely((void *)ip + sizeof(*ip) > data_end))
        return TC_ACT_SHOT;

    /* tcp */
    if (IPPROTO_TCP == ip->protocol) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
            return TC_ACT_SHOT;
    
        if (!tcp->syn || tcp->ack || tcp->rst) {
            return TC_ACT_OK;
        }
    
        if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
            return TC_ACT_OK;
        }
    
        // 确保 payload 存在
        void *payload = (void *)tcp + sizeof(*tcp);
        if (unlikely(payload + 2*sizeof(__u64) + 2*sizeof(__u32) > data_end))
            return TC_ACT_OK;
        
        __u64* start = payload;
        __u64* direct = payload + sizeof(__u64);
        __u32* src = payload + 2*sizeof(__u64);
        __u32* dst = payload + 2*sizeof(__u64) + sizeof(__u32);
        // bpf_printk("src: %d", bpf_ntohl(*src));
        // bpf_printk("dst: %d", bpf_ntohl(*dst));
        // bpf_printk("SELF: %d", SELF);
        // bpf_printk("egress pass: %d", bpf_ntohl(*src) == SELF);
        // bpf_printk("egress pass: %d", bpf_ntohl(*src) == (__u32)SELF);
        if (bpf_ntohl(*src) != (__u32)SELF) {
            return TC_ACT_OK;
        }
        // __u64* direct = payload;
        // char* tag = payload + sizeof(__u64);
        // __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
        // struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
            
        // if (*direct == 0) {
            // 修改 map 的内容
            __u64 time = bpf_ktime_get_ns();
            struct rtt_key_t key = {};
            key.src_ip = ip->saddr;
            key.dst_ip = ip->daddr;
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
            key.protocol = ip->protocol;
            key.seq = tcp->seq;
    
            // bpf_printk("1 src_ip: %u.", (bpf_ntohl(key.src_ip) >> 24) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.src_ip) >> 16) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.src_ip) >> 8) & 0xFF);
            // bpf_printk("%u", bpf_ntohl(key.src_ip) & 0xFF);
            // bpf_printk("1 dst_ip: %u.", (bpf_ntohl(key.dst_ip) >> 24) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.dst_ip) >> 16) & 0xFF);
            // bpf_printk("%u.", (bpf_ntohl(key.dst_ip) >> 8) & 0xFF);
            // bpf_printk("%u", bpf_ntohl(key.dst_ip) & 0xFF);
            // bpf_printk("1 src_port: %u", bpf_ntohs(key.src_port));
            // bpf_printk("1 dst_port: %u", bpf_ntohs(key.dst_port));
            // bpf_printk("1 protocol: %u", key.protocol);
            // bpf_printk("1 seq: %u", bpf_ntohl(key.seq));
            // bpf_map_update_elem(&rtt_start, &key, &time, BPF_ANY);
            if ((void *)start + sizeof(time) > data_end) {
                return TC_ACT_OK;
            }
            memcpy(start, &time, sizeof(time));

            compute_tcp_checksum(ip, tcp);
        // }
        return TC_ACT_OK;
    }
    /* UDP */
    else if (IPPROTO_UDP == ip->protocol) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if (unlikely((void *)udp + sizeof(*udp) > data_end))
            return TC_ACT_SHOT;

        if (bpf_ntohs(udp->dest) != PING_PORT && bpf_ntohs(udp->source) != PING_PORT) {
            return TC_ACT_OK;
        }
        // 确保 payload 存在
        void *payload = (void *)udp + sizeof(*udp);
        if (unlikely(payload + 2*sizeof(__u64) + 2*sizeof(__u32) > data_end))
            return TC_ACT_OK;
        
        __u64* start = payload;
        __u64* direct = payload + sizeof(__u64);
        __u32* src = payload + 2*sizeof(__u64);
        __u32* dst = payload + 2*sizeof(__u64) + sizeof(__u32);
        // bpf_printk("udp src: %d", bpf_ntohl(*src));
        // bpf_printk("udp dst: %d", bpf_ntohl(*dst));
        // bpf_printk("udp SELF: %d", SELF);
        // bpf_printk("udp egress pass: %d", bpf_ntohl(*src) == (__u32)SELF);
        if (bpf_ntohl(*src) != (__u32)SELF) {
            return TC_ACT_OK;
        }

        if (*direct == 0) {
            // 修改 map 的内容
            __u64 time = bpf_ktime_get_ns();
            // bpf_printk("udp add time: %d", time);
            if ((void *)start + sizeof(time) > data_end) {
                return TC_ACT_SHOT;
            }
            memcpy(start, &time, sizeof(time));
        }
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

// __section("xdp")
// int record_tcptt(struct xdp_md *ctx) {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct rtt_event_t evt = {};
//     evt.rtt = 0;
//     evt.src_ip = 0;
//     evt.dst_ip = 0;
//     evt.src_port = 0;
//     evt.dst_port = 0;
//     bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

//     // 解析以太网头部
//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end) {
//         return XDP_PASS;
//     }

//     // 仅处理 IPv4和IPv6 数据包
//     if (eth->h_proto != __constant_htons(ETH_P_IP) && eth->h_proto != __constant_htons(ETH_P_IPV6)) {
//         return XDP_PASS;
//     }

//     // 获取网卡的 MAC 地址（需要在加载程序时传入）
//     unsigned char local_mac[ETH_ALEN] = LOCAL_MAC;

//     // 判断数据包方向
//     _Bool is_outgoing = mac_equal(eth->h_source, local_mac);
//     _Bool is_incoming = mac_equal(eth->h_dest, local_mac);

//     // _Bool is_outgoing = __builtin_memcmp(eth->h_source, local_mac, ETH_ALEN) == 0;
//     // _Bool is_incoming = __builtin_memcmp(eth->h_dest, local_mac, ETH_ALEN) == 0;

//     struct tcphdr *tcp = NULL;
//     __u32 src_ip, dst_ip = 0;
//     if (eth->h_proto == __constant_htons(ETH_P_IP)) {
//         // 解析 IP 头部
//         struct iphdr *ip = (void *)(eth + 1);
//         if ((void *)(ip + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // TODO: 多协议 （仅处理 TCP 数据包）
//         if (ip->protocol != IPPROTO_TCP) {
//             return XDP_PASS;
//         }
//         // 解析 TCP 头部
//         tcp = (void *)ip + ip->ihl * 4;
//         if ((void *)(tcp + 1) > data_end) {
//             return XDP_PASS;
//         }
//         src_ip = ip->saddr;
//         dst_ip = ip->daddr;
//     }

//     else {
//         // 解析 IPv6 头部
//         struct ipv6hdr *ip6 = (void *)(eth + 1);
//         if ((void *)(ip6 + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // TODO: 多协议 （仅处理 TCP 数据包）
//         if (ip6->nexthdr != IPPROTO_TCP) {
//             return XDP_PASS;
//         }
//         // 解析 TCP 头部
//         tcp = (void *)ip6 + sizeof(struct ipv6hdr);
//         if ((void *)(tcp + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // 最后32位ipv6地址
//         src_ip = ip6->saddr.s6_addr32[3];
//         dst_ip = ip6->daddr.s6_addr32[3];
//     }

//     // 判断是否是 SYN 包（发送时间记录）
//     if (is_outgoing && (tcp->syn == 1) && (tcp->ack == 0) && (tcp->rst == 0)) {
//         if (tcp->dest != PING_PORT && tcp->source != PING_PORT) {
//             return XDP_PASS;
//         }

//         // 获取当前时间戳
//         __u64 timestamp = bpf_ktime_get_ns();

//         struct rtt_key_t key = {};
//         key.src_ip = src_ip;
//         key.dst_ip = dst_ip;
//         key.src_port = tcp->source;
//         key.dst_port = tcp->dest;
//         key.proto = IPPROTO_TCP;
//         key.seq = tcp->seq;

//         bpf_map_update_elem(&rtt_start, &key, &timestamp, BPF_ANY);
//         return XDP_PASS;
//     }

//     // 判断是否是 RST+ACK 包（计算 RTT）
//     if (is_incoming && (tcp->ack == 1) && (tcp->rst == 1)) {
//         if (tcp->dest != PING_PORT && tcp->source != PING_PORT) {
//             return XDP_PASS;
//         }

//         struct rtt_key_t reverse_key = {};
//         reverse_key.src_ip = dst_ip;
//         reverse_key.dst_ip = src_ip;
//         reverse_key.src_port = tcp->dest;
//         reverse_key.dst_port = tcp->source;
//         reverse_key.proto = IPPROTO_TCP;
//         reverse_key.seq = tcp->ack_seq - 1;

//         __u64 *start = bpf_map_lookup_elem(&rtt_start, &reverse_key);
//         if (start) {
//             __u64 now = bpf_ktime_get_ns();
//             struct rtt_event_t evt = {};
//             evt.rtt = now - *start;
//             evt.src_ip = reverse_key.src_ip;
//             evt.dst_ip = reverse_key.dst_ip;
//             evt.src_port = reverse_key.src_port;
//             evt.dst_port = reverse_key.dst_port;
//             evt.tag = DONE;

//             bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
//             bpf_map_delete_elem(&rtt_start, &reverse_key);
//         }
//     }

//     return XDP_PASS;
// }

// char LICENSE[] SEC("license") = "Dual BSD/GPL";

BPF_LICENSE("GPL");

// #include <linux/byteorder/little_endian.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/in6.h>
// #include <linux/ip.h>
// #include <linux/ipv6.h>
// #include <linux/tcp.h>
// #include <linux/bpf.h>
// #include <bpf/ctx/xdp.h>
// #include <bpf/builtins.h>
// #include <bpf/helpers.h>
// // #include <bpf/bpf_helpers.h>
// #include <lib/endian.h>
// #include <lib/csum.h>

// #define NULL ((void *)0)

// #define PING_PORT           65532
// #define DONE        8

// #define TC_ACT_OK      0
// #define TC_ACT_SHOT    2

// #define ETH_HLEN            __ETH_HLEN

// #define IP_HLEN             sizeof(struct iphdr)
// #define TCP_CSUM_OFFSET     (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check))
// #define ACK_SEQ_OFFSET      (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, ack_seq))

// #define TCP_FLAG_FIELD_OFFSET ( (__u64)&tcp_flag_word( (struct tcphdr *)0 ) )
// #define TCP_FLAG_OFFSET       (ETH_HLEN + IP_HLEN + TCP_FLAG_FIELD_OFFSET)

// #define // // bpf_printk(fmt, ...)    ({                             \
//     const char ____fmt[] = fmt;                                \
//     trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
// })
// // static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)6;

// typedef unsigned long long __u64;
// typedef unsigned int __u32;
// typedef unsigned short __u16;
// typedef unsigned char __u8;

// #define __uint(name,val) int (*name)[val]
// #define __type(name,val) typeof(val) *name
// #define SEC(NAME) __attribute__((section(NAME), used))

// struct vlanhdr {
//     __be16 h_vlan_TCI;
//     __be16 h_vlan_encapsulated_proto;
// } __attribute__((packed));

// static inline void swap_mac(struct ethhdr *eth)
// {
//     __u8 tmp_mac[ETH_ALEN];

//     memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
//     memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
//     memcpy(eth->h_source, tmp_mac, ETH_ALEN);
// }

// static inline void swap_ip(struct iphdr *ip)
// {
//     struct in_addr tmp_ip;

//     memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
//     memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
//     memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));
// }

// static inline void swap_port(struct tcphdr *tcp)
// {
//     __u16 tmp_port;

//     memcpy(&tmp_port, &tcp->source, sizeof(tmp_port));
//     memcpy(&tcp->source, &tcp->dest, sizeof(tmp_port));
//     memcpy(&tcp->dest, &tmp_port, sizeof(tmp_port));
// }

// struct rtt_event_t {
//     __u64 rtt;
//     // __u32 src_ip;
//     // __u32 dst_ip;
//     // __u16 src_port;
//     // __u16 dst_port;
// } __attribute__((packed));

// struct debug_event_t {
//     __u64 tag;
// } __attribute__((packed));

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(max_entries, CPU);
//     __uint(key_size, sizeof(int));
//     __uint(value_size, sizeof(__u32));
//     __uint(pinning, 1);
// } debug_events SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(max_entries, CPU);
//     __uint(key_size, sizeof(int));
//     __uint(value_size, sizeof(__u32));
//     __uint(pinning, 1);
// } rtt_events SEC(".maps");

// // struct rtt_key_t {
// //     __u32 src_ip;
// //     __u32 dst_ip;
// //     __u16 src_port;
// //     __u16 dst_port;
// //     __u32 seq;
// // };

// // struct {
// //     __uint(type, BPF_MAP_TYPE_HASH);
// //     __uint(max_entries, 1024);
// //     __type(key, struct rtt_key_t);
// //     __type(value, __u64);
// // } rtt_start SEC(".maps");

// static __always_inline int mac_equal(const __u8 *a, const __u8 *b) {
//     #pragma unroll
//     for (int i = 0; i < ETH_ALEN; i++) {
//         if (a[i] != b[i])
//             return 0;
//     }
//     return 1;
// }

// __section("xdp")
// int xdp_ping(struct xdp_md *ctx)
// {
//     // // // bpf_printk("111111");
//     // RTT 事件
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     int ret = 0;

//     /* eth */
//     struct ethhdr *eth = data;
//     __u64 nh_off = sizeof(*eth);
//     if (unlikely(data + nh_off > data_end))
//         return XDP_DROP;

//     __be16 h_proto = eth->h_proto;

//     /* vlan */
//     __u64 vlanhdr_len = 0;
//     // handle double tags in ethernet frames
//     #pragma unroll
//     for (int i = 0; i < 2; i++) {
//         if (bpf_htons(ETH_P_8021Q) == h_proto || bpf_htons(ETH_P_8021AD) == h_proto) {
//             struct vlanhdr *vhdr = data + nh_off;

//             nh_off += sizeof(*vhdr);
//             if (data + nh_off > data_end)
//                 return XDP_DROP;

//             vlanhdr_len += sizeof(*vhdr);
//             h_proto = vhdr->h_vlan_encapsulated_proto;
//         }
//     }

//     // 判断是否是 RST+ACK 包（计算 RTT）
//     if (bpf_htons(ETH_P_IPV6) == h_proto) {
//         // // // bpf_printk("6: 333333");
//         // IPv6
//         struct ipv6hdr *ip6 = data + nh_off;
//         if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
//             return XDP_DROP;

//         /* tcp */
//         if (IPPROTO_TCP != ip6->nexthdr)
//             return XDP_PASS;

//         struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
//         if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
//             return XDP_DROP;
        
//         // // // bpf_printk("6: 444444");

//         if ((tcp->ack == 1) && (tcp->rst == 1) && (tcp->syn == 0)) {
            
//             // // // bpf_printk("TCin 6: 555555");
            
//             if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
//                 return XDP_PASS;
//             }
    
//             // 确保 payload 存在
//             void *payload = (void *)tcp + sizeof(*tcp);
//             if (unlikely(payload + sizeof(__u64) >= data_end))
//                 return XDP_DROP;
                
//             // // // bpf_printk("xdp 6: 666666");

//             // Payload: starttime, startip, dstip

//             __u64 *start = payload;

//             // struct rtt_key_t reverse_key = {};
//             // reverse_key.src_ip = bpf_ntohl(ip6->daddr.s6_addr32[3]);
//             // reverse_key.dst_ip = bpf_ntohs(ip6->saddr.s6_addr32[3]);
//             // reverse_key.src_port = bpf_ntohs(tcp->dest);
//             // reverse_key.dst_port = bpf_ntohs(tcp->source);
//             // reverse_key.seq = bpf_ntohl(tcp->ack_seq) - 1;
    
//             // __u64 *start = bpf_map_lookup_elem(&rtt_start, &reverse_key);
//             // // // bpf_printk("xdp 6: 666666");
//             if (!start) {
//                 return XDP_PASS;
//             }
//             // // // bpf_printk("TCin 6: 777777");
//             // bugevt.tag = 777777;
//             // bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &bugevt, sizeof(bugevt));
        
//             __u64 now = bpf_ktime_get_ns();
//             struct rtt_event_t evt = {};
//             evt.rtt = now - *start;
//             // evt.src_ip = reverse_key.src_ip;
//             // evt.dst_ip = reverse_key.dst_ip;
//             // evt.src_port = reverse_key.src_port;
//             // evt.dst_port = reverse_key.dst_port;
//             // // // bpf_printk("TCin 6: 888888");
//             // // // bpf_printk("start: %llu", *start);
//             // // // bpf_printk("now: %llu", now);
//             // // // bpf_printk("rtt: %llu", evt.rtt);

//             bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
//             // // // bpf_printk("TCin 6: 5");
//             // bpf_map_delete_elem(&rtt_start, &reverse_key);
//             return XDP_DROP;
//         }

//         if (PING_PORT != bpf_ntohs(tcp->dest) || 1 != tcp->syn)
//             return XDP_PASS;

//         /* IPv6 processing */
//         swap_mac(eth);
//         swap_ip(ip6);
//         swap_port(tcp);
//         __u16 *tcp_flag = (void *)tcp + TCP_FLAG_FIELD_OFFSET;
//         __u16 old_tcp_flag = *tcp_flag;
//         __u16 new_tcp_flag = *tcp_flag;

//         /* clear syn bit */
//         new_tcp_flag &= ~TCP_FLAG_SYN;
//         /* set rst bit */
//         new_tcp_flag |= TCP_FLAG_RST;
//         /* set ack bit */
//         new_tcp_flag |= TCP_FLAG_ACK;

//         ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_tcp_flag, new_tcp_flag, 0);
//         if (unlikely(ret)) {
//             // // bpf_printk("l4_csum_replace tcp_flag error");
//             return XDP_DROP;
//         }

//         memcpy(data + TCP_FLAG_OFFSET + vlanhdr_len, &new_tcp_flag, sizeof(new_tcp_flag));

//         /* calculate and set ack sequence */
//         __be32 old_ack_seq = tcp->ack_seq;
//         __be32 new_ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);

//         ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_ack_seq, new_ack_seq, 0);
//         if (unlikely(ret)) {
//             // // bpf_printk("l4_csum_replace ack_seq error");
//             return XDP_DROP;
//         }

//         memcpy(data + ACK_SEQ_OFFSET + vlanhdr_len, &new_ack_seq, sizeof(new_ack_seq));
//         // // bpf_printk("6: 999999");
//         return XDP_TX;
//     }

//     // // // bpf_printk("4: 333333");
//     /* ipv4 */
//     if (bpf_htons(ETH_P_IP) != h_proto)
//         return XDP_PASS;

//     struct iphdr *ip = data + nh_off;
//     if (unlikely((void *)ip + sizeof(*ip) > data_end))
//         return XDP_DROP;

//     /* tcp */
//     if (IPPROTO_TCP != ip->protocol)
//         return XDP_PASS;

//     struct tcphdr *tcp = (void *)ip + sizeof(*ip);
//     if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
//         return XDP_DROP;

//     /* main logic */
        
//     // // // bpf_printk("xdp 4: 666666");

//     // // // bpf_printk("4: 444444");
//     if ((tcp->ack == 1) && (tcp->rst == 1) && (tcp->syn == 0)) {
//         // // // bpf_printk("TCin 4: 555555");
//         if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
//             return XDP_PASS;
//         }
//         // 确保 payload 存在
//         void *payload = (void *)tcp + sizeof(*tcp);
//         if (unlikely(payload + sizeof(__u64) >= data_end))
//             return XDP_DROP;

//         // struct rtt_key_t reverse_key = {};
//         // reverse_key.src_ip = bpf_ntohl(ip->daddr);
//         // reverse_key.dst_ip = bpf_ntohl(ip->saddr);
//         // reverse_key.src_port = bpf_ntohs(tcp->dest);
//         // reverse_key.dst_port = bpf_ntohs(tcp->source);
//         // reverse_key.seq = bpf_ntohl(tcp->ack_seq) - 1;

//         __u64 *start = payload;
        
//         // // // bpf_printk("TCin 4: 666666");
//         // // // bpf_printk("seq: %u", reverse_key.seq);
//         // // // bpf_printk("src_ip: %u", reverse_key.src_ip);
//         // // // bpf_printk("dst_ip: %u", reverse_key.dst_ip);
//         // // // bpf_printk("src_port: %u", reverse_key.src_port);
//         // // // bpf_printk("dst_port: %u", reverse_key.dst_port);
        
//         if (start) {
//             // // // bpf_printk("TCin 4: 777777");
//             __u64 now = bpf_ktime_get_ns();
//             struct rtt_event_t evt = {};
//             evt.rtt = now - *start;
//             // evt.src_ip = reverse_key.src_ip;
//             // evt.dst_ip = reverse_key.dst_ip;
//             // evt.src_port = reverse_key.src_port;
//             // evt.dst_port = reverse_key.dst_port;
//             // // // bpf_printk("TCin 4: 888888");
//             // // // bpf_printk("start: %llu", *start);
//             // // // bpf_printk("now: %llu", now);
//             // // // bpf_printk("rtt: %llu", evt.rtt);

//             bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
//             // // // bpf_printk("TCin 4: 999999");
//             // bpf_map_delete_elem(&rtt_start, &reverse_key);
//             return XDP_DROP;
//         }
//     }

//     if (PING_PORT != bpf_ntohs(tcp->dest) || 1 != tcp->syn)
//         return XDP_PASS;

//     swap_mac(eth);
//     swap_ip(ip);
//     swap_port(tcp);

//     __u16 *tcp_flag = (void *)tcp + TCP_FLAG_FIELD_OFFSET;
//     __u16 old_tcp_flag = *tcp_flag;
//     __u16 new_tcp_flag = *tcp_flag;

//     /* clear syn bit */
//     new_tcp_flag &= ~TCP_FLAG_SYN;
//     /* set rst bit */
//     new_tcp_flag |= TCP_FLAG_RST;
//     /* set ack bit */
//     new_tcp_flag |= TCP_FLAG_ACK;

//     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_tcp_flag, new_tcp_flag, 0);
//     if (unlikely(ret)) {
//         // // // bpf_printk("l4_csum_replace tcp_flag error");
//         return XDP_DROP;
//     }

//     memcpy(data + TCP_FLAG_OFFSET + vlanhdr_len, &new_tcp_flag, sizeof(new_tcp_flag));

//     /* calculate and set ack sequence */
//     __be32 old_ack_seq = tcp->ack_seq;
//     __be32 new_ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
//     // __be32 new_ack_seq = tcp->seq + 1;

//     // // // bpf_printk("old_seq: %u", tcp->seq);
//     // // // bpf_printk("old_seq 0: %u", bpf_htonl(bpf_ntohl(tcp->seq)));
//     // // // bpf_printk("old_seq 1: %u", bpf_ntohl(tcp->seq));
//     // // // bpf_printk("old_seq 2: %u", bpf_ntohl(tcp->seq) + 1);
//     // // // bpf_printk("old_seq 3: %u", bpf_htonl(bpf_ntohl(tcp->seq) + 1));
//     // // // bpf_printk("old_ack_seq: %u", old_ack_seq);
//     // // // bpf_printk("new_ack_seq: %u", new_ack_seq);

//     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_ack_seq, new_ack_seq, 0);
//     if (unlikely(ret)) {
//         // // // bpf_printk("l4_csum_replace ack_seq error");
//         return XDP_DROP;
//     }

//     memcpy(data + ACK_SEQ_OFFSET + vlanhdr_len, &new_ack_seq, sizeof(new_ack_seq));

//     // // // bpf_printk("4: 999999");
//     // // // bpf_printk("srcip: %d ", (bpf_ntohl(ip->saddr) >> 24) & 0xFF);
//     // // // bpf_printk("srcip: %d ", (bpf_ntohl(ip->saddr) >> 16) & 0xFF);
//     // // // bpf_printk("srcip: %d ", (bpf_ntohl(ip->saddr) >> 8) & 0xFF);
//     // // // bpf_printk("srcip: %d", (bpf_ntohl(ip->saddr)) & 0xFF);
//     // // // bpf_printk("dstip: %d ", (bpf_ntohl(ip->daddr) >> 24) & 0xFF);
//     // // // bpf_printk("dstip: %d ", (bpf_ntohl(ip->daddr) >> 16) & 0xFF);
//     // // // bpf_printk("dstip: %d ", (bpf_ntohl(ip->daddr) >> 8) & 0xFF);
//     // // // bpf_printk("dstip: %d", (bpf_ntohl(ip->daddr)) & 0xFF);
//     return XDP_TX;
// }

// SEC("tc")
// int trace_egress(struct __sk_buff *ctx) {
//     // // // bpf_printk("TC 111111");
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     int ret = 0;

//     /* eth */
//     struct ethhdr *eth = data;
//     __u64 nh_off = sizeof(*eth);
//     if (unlikely(data + nh_off > data_end))
//         return TC_ACT_SHOT;

//     __be16 h_proto = eth->h_proto;

//     /* vlan */
//     __u64 vlanhdr_len = 0;
//     // handle double tags in ethernet frames
//     #pragma unroll
//     for (int i = 0; i < 2; i++) {
//         if (bpf_htons(ETH_P_8021Q) == h_proto || bpf_htons(ETH_P_8021AD) == h_proto) {
//             struct vlanhdr *vhdr = data + nh_off;

//             nh_off += sizeof(*vhdr);
//             if (data + nh_off > data_end)
//                 return TC_ACT_SHOT;

//             vlanhdr_len += sizeof(*vhdr);
//             h_proto = vhdr->h_vlan_encapsulated_proto;
//         }
//     }

//     // 判断是否是 RST+ACK 包（计算 RTT）
//     if (bpf_htons(ETH_P_IPV6) == h_proto) {
//         // IPv6
//         struct ipv6hdr *ip6 = data + nh_off;
//         if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
//             return TC_ACT_SHOT;

//         /* tcp */
//         if (IPPROTO_TCP != ip6->nexthdr)
//             return TC_ACT_SHOT;

//         struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
//         if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
//             return TC_ACT_SHOT;

//         if (!tcp->syn || tcp->ack || tcp->rst) {
//             return TC_ACT_OK;
//         }

//         if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
//             return TC_ACT_OK;
//         }
//         // // // bpf_printk("TC 6: 444444");

//         // 确保 payload 存在
//         void *payload = (void *)tcp + sizeof(*tcp);
//         if (unlikely(payload >= data_end))
//             return TC_ACT_SHOT;
            
//         // // // bpf_printk("TC 6: 555555");

//         // 修改 payload 的内容
//         __u64 new_payload = 0x12345678; // 新的 payload 内容
//         int payload_len = sizeof(new_payload);

//         // 确保修改不会越界
//         if ((void *)payload + payload_len > data_end)
//             return TC_ACT_SHOT;
//         // // // bpf_printk("TC 6: 666666");

//         new_payload = bpf_ktime_get_ns();
//         // 将新的 payload 写入数据包
//         memcpy(payload, &new_payload, payload_len);
//         // TODO: 修改checksum

//         // // // bpf_printk("Payload modified %llu", new_payload);
    
//         // struct rtt_key_t key = {};
//         // key.src_ip = bpf_ntohl(ip6->saddr.s6_addr32[3]);
//         // key.dst_ip = bpf_ntohl(ip6->daddr.s6_addr32[3]);
//         // key.src_port = bpf_ntohs(tcp->source);
//         // key.dst_port = bpf_ntohs(tcp->dest);
//         // key.seq = bpf_ntohl(tcp->seq);
//         // // // bpf_printk("TC 6: 444444555");
    
//         // __u64 *ts = 0;
//         // // // bpf_printk("TC 6: 555555");
//         // // // bpf_printk("TC 6: seq: %u", key.seq);
//         // // // bpf_printk("TC 6: src_ip: %u", key.src_ip);
//         // // // bpf_printk("TC 6: dst_ip: %u", key.dst_ip);
//         // // // bpf_printk("TC 6: src_port: %u", key.src_port);
//         // // // bpf_printk("TC 6: dst_port: %u", key.dst_port);
//         // bpf_map_update_elem(&rtt_start, &key, &ts, BPF_ANY);
//         // // // bpf_printk("TC 6: 666666");
//         return TC_ACT_OK;
//     }

//     // // // bpf_printk("TC 4: 1111");
//     if (bpf_htons(ETH_P_IP) != h_proto)
//         return TC_ACT_OK;
//     // // // bpf_printk("TC 4: 2222");

//     struct iphdr *ip = data + nh_off;
//     if (unlikely((void *)ip + sizeof(*ip) > data_end))
//         return TC_ACT_SHOT;
//     // // // bpf_printk("TC 4: 3333");

//     /* tcp */
//     if (IPPROTO_TCP != ip->protocol)
//         return TC_ACT_OK;
//     // // // bpf_printk("TC 4: 4444");

//     struct tcphdr *tcp = (void *)ip + sizeof(*ip);
//     if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
//         return TC_ACT_SHOT;
//     // // // bpf_printk("TC 4: 5555");

//     if (!tcp->syn || tcp->ack || tcp->rst) {
//         return TC_ACT_OK;
//     }
//     // // // bpf_printk("TC 4: 6666");

//     if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
//         return TC_ACT_OK;
//     }
//     // // // bpf_printk("TC 4: 444444");

//     // 确保 payload 存在
//     void *payload = (void *)tcp + sizeof(*tcp);
//     if (unlikely(payload >= data_end))
//         return TC_ACT_SHOT;
        
//     // // // bpf_printk("TC 6: 555555");

//     // 修改 payload 的内容
//     __u64 new_payload = 0x12345678; // 新的 payload 内容
//     int payload_len = sizeof(new_payload);

//     // 确保修改不会越界
//     if ((void *)payload + payload_len > data_end)
//         return TC_ACT_SHOT;
//     // // // bpf_printk("TC 6: 666666");

//     new_payload = bpf_ktime_get_ns();
//     // 将新的 payload 写入数据包
//     memcpy(payload, &new_payload, payload_len);
//     bpf_l4_csum_replace(__u32 csum, __u32 offset, __u64 from, __u64 to, __u64 flags);

//     // // // bpf_printk("Payload modified %llu", new_payload);

//     // struct rtt_key_t key = {};
//     // key.src_ip = bpf_ntohl(ip->saddr);
//     // key.dst_ip = bpf_ntohl(ip->daddr);
//     // key.src_port = bpf_ntohs(tcp->source);
//     // key.dst_port = bpf_ntohs(tcp->dest);
//     // key.seq = bpf_ntohl(tcp->seq);
//     // // // bpf_printk("TC 4: 444444555");

//     // __u64 ts = bpf_ktime_get_ns();
//     // // // bpf_printk("TC 4: 555555");
//     // // // bpf_printk("TC 4: seq: %u", key.seq);
//     // // // bpf_printk("TC 4: src_ip: %u", key.src_ip);
//     // // // bpf_printk("TC 4: dst_ip: %u", key.dst_ip);
//     // // // bpf_printk("TC 4: src_port: %u", key.src_port);
//     // // // bpf_printk("TC 4: dst_port: %u", key.dst_port);
//     // bpf_map_update_elem(&rtt_start, &key, &ts, BPF_ANY);
//     // __u64 *start = bpf_map_lookup_elem(&rtt_start, &key);
//     // // // bpf_printk("TC 4: 666666");
//     return TC_ACT_OK;
// }

// BPF_LICENSE("GPL");

// __section("xdp")
// int record_tcptt(struct xdp_md *ctx) {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct rtt_event_t evt = {};
//     evt.rtt = 0;
//     evt.src_ip = 0;
//     evt.dst_ip = 0;
//     evt.src_port = 0;
//     evt.dst_port = 0;
//     bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

//     // 解析以太网头部
//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end) {
//         return XDP_PASS;
//     }

//     // 仅处理 IPv4和IPv6 数据包
//     if (eth->h_proto != __constant_htons(ETH_P_IP) && eth->h_proto != __constant_htons(ETH_P_IPV6)) {
//         return XDP_PASS;
//     }

//     // 获取网卡的 MAC 地址（需要在加载程序时传入）
//     unsigned char local_mac[ETH_ALEN] = LOCAL_MAC;

//     // 判断数据包方向
//     _Bool is_outgoing = mac_equal(eth->h_source, local_mac);
//     _Bool is_incoming = mac_equal(eth->h_dest, local_mac);

//     // _Bool is_outgoing = __builtin_memcmp(eth->h_source, local_mac, ETH_ALEN) == 0;
//     // _Bool is_incoming = __builtin_memcmp(eth->h_dest, local_mac, ETH_ALEN) == 0;

//     struct tcphdr *tcp = NULL;
//     __u32 src_ip, dst_ip = 0;
//     if (eth->h_proto == __constant_htons(ETH_P_IP)) {
//         // 解析 IP 头部
//         struct iphdr *ip = (void *)(eth + 1);
//         if ((void *)(ip + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // TODO: 多协议 （仅处理 TCP 数据包）
//         if (ip->protocol != IPPROTO_TCP) {
//             return XDP_PASS;
//         }
//         // 解析 TCP 头部
//         tcp = (void *)ip + ip->ihl * 4;
//         if ((void *)(tcp + 1) > data_end) {
//             return XDP_PASS;
//         }
//         src_ip = ip->saddr;
//         dst_ip = ip->daddr;
//     }

//     else {
//         // 解析 IPv6 头部
//         struct ipv6hdr *ip6 = (void *)(eth + 1);
//         if ((void *)(ip6 + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // TODO: 多协议 （仅处理 TCP 数据包）
//         if (ip6->nexthdr != IPPROTO_TCP) {
//             return XDP_PASS;
//         }
//         // 解析 TCP 头部
//         tcp = (void *)ip6 + sizeof(struct ipv6hdr);
//         if ((void *)(tcp + 1) > data_end) {
//             return XDP_PASS;
//         }
//         // 最后32位ipv6地址
//         src_ip = ip6->saddr.s6_addr32[3];
//         dst_ip = ip6->daddr.s6_addr32[3];
//     }

//     // 判断是否是 SYN 包（发送时间记录）
//     if (is_outgoing && (tcp->syn == 1) && (tcp->ack == 0) && (tcp->rst == 0)) {
//         if (tcp->dest != PING_PORT && tcp->source != PING_PORT) {
//             return XDP_PASS;
//         }

//         // 获取当前时间戳
//         __u64 timestamp = bpf_ktime_get_ns();

//         struct rtt_key_t key = {};
//         key.src_ip = src_ip;
//         key.dst_ip = dst_ip;
//         key.src_port = tcp->source;
//         key.dst_port = tcp->dest;
//         key.proto = IPPROTO_TCP;
//         key.seq = tcp->seq;

//         bpf_map_update_elem(&rtt_start, &key, &timestamp, BPF_ANY);
//         return XDP_PASS;
//     }

//     // 判断是否是 RST+ACK 包（计算 RTT）
//     if (is_incoming && (tcp->ack == 1) && (tcp->rst == 1)) {
//         if (tcp->dest != PING_PORT && tcp->source != PING_PORT) {
//             return XDP_PASS;
//         }

//         struct rtt_key_t reverse_key = {};
//         reverse_key.src_ip = dst_ip;
//         reverse_key.dst_ip = src_ip;
//         reverse_key.src_port = tcp->dest;
//         reverse_key.dst_port = tcp->source;
//         reverse_key.proto = IPPROTO_TCP;
//         reverse_key.seq = tcp->ack_seq - 1;

//         __u64 *start = bpf_map_lookup_elem(&rtt_start, &reverse_key);
//         if (start) {
//             __u64 now = bpf_ktime_get_ns();
//             struct rtt_event_t evt = {};
//             evt.rtt = now - *start;
//             evt.src_ip = reverse_key.src_ip;
//             evt.dst_ip = reverse_key.dst_ip;
//             evt.src_port = reverse_key.src_port;
//             evt.dst_port = reverse_key.dst_port;
//             evt.tag = DONE;

//             bpf_perf_event_output(ctx, &rtt_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
//             bpf_map_delete_elem(&rtt_start, &reverse_key);
//         }
//     }

//     return XDP_PASS;
// }

// char LICENSE[] SEC("license") = "Dual BSD/GPL";
