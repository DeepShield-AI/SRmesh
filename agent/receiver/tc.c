#include <linux/byteorder/little_endian.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/ctx/skb.h>
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

SEC("ingress")
int trace_ingress(struct __sk_buff *ctx) {
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

    if (bpf_htons(ETH_P_IPV6) == h_proto) {
        // IPv6
        struct ipv6hdr *ip6 = data + nh_off;
        if (unlikely((void *)ip6 + sizeof(*ip6) > data_end))
            return TC_ACT_SHOT;

        if (IPPROTO_ROUTING == ip6->nexthdr) {
            // Parse SRH header
            struct ipv6_sr_hdr {
                __u8 nexthdr;
                __u8 hdrlen;
                __u8 type;
                __u8 segments_left;
                __u8 last_entry;
                __u8 flags;
                __u16 reserved;
                struct in6_addr segments[0];
            };
            struct ipv6_sr_hdr *srh = (void *)ip6 + sizeof(*ip6);            
            if (unlikely((void *)srh + sizeof(*srh) > data_end))
                return TC_ACT_SHOT;

            if (srh->type != 4) {
                return TC_ACT_OK;
            }
            if (srh->segments_left != 0) {
                return TC_ACT_OK;
            }

            /* TCP */
            if (IPPROTO_TCP == srh->nexthdr) {
                struct tcphdr *tcp = (void *)srh + 8 + 8*srh->hdrlen;
                if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
                    return TC_ACT_SHOT;
                if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
                    return TC_ACT_OK;
                }

                // 确保 payload 存在
                void *payload = (void *)tcp + sizeof(*tcp);
                if (unlikely((void *)payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) + srh->hdrlen*8 > data_end))
                    return TC_ACT_SHOT;
                
                __u64* direct = payload;
                char* tag = payload + sizeof(__u64);
                __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
                struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                struct in6_addr* sr_list = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr);
                if ((void *)sr_list + sizeof(struct in6_addr) > data_end) {
                    return TC_ACT_SHOT;
                }
                char tags[10] = {0};
                memcpy(tags, tag, sizeof(tags));
                
                if (tcp->syn != 1) {
                    return TC_ACT_OK;
                }
                // 修改方向
                __u64 new_direct = *direct + 1;

                memcpy(direct, &new_direct, sizeof(new_direct));

                // Construct return SRH list
                
                int sr_count = srh->last_entry + 1;
                __u64 new_sr_count = 0;

                if (sr_count >= 2){
                    for (int i = 0; i < sr_count - 1 && i < 3; i++) {
                        if (tags[sr_count-1-i] == '1') {
                            new_sr_count += 3;
                            // Add loopback for ECMP
                        } else {
                            // Add direct path
                            new_sr_count += 3;
                        }
                    }
                    if (tags[0] == '1') {
                        new_sr_count += 3;
                    }
                    else {
                        new_sr_count += 1;
                    }
                    new_sr_count += 1;
                }

                // Update SRH for return path
                // srh->segments_left = new_sr_count - 1;
                // srh->last_entry = new_sr_count - 1;
                // srh->hdrlen = 8 + 8 * new_sr_count;
                // Reverse the new_sr_list
                // for (__u64 i = 0; i < (new_sr_count >> 1); i++) {
                //     struct in6_addr temp = new_sr_list[i];
                //     new_sr_list[i] = new_sr_list[new_sr_count - 1 - i];
                //     new_sr_list[new_sr_count - 1 - i] = temp;
                // }
                struct in6_addr *new_sr_list = &srh->segments;

                // Check if new_sr_list is longer than sr_list
                if (new_sr_count > sr_count) {
                    // Calculate the additional space needed
                    int additional_space = (new_sr_count - sr_count) * sizeof(struct in6_addr);
                    // Adjust packet size to accommodate the new SRH
                    if (bpf_skb_adjust_room(ctx, additional_space, BPF_ADJ_ROOM_NET, 0)) {
                        return TC_ACT_SHOT;
                    }

                    // Recalculate pointers after adjusting the packet size
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    ip6 = data + nh_off;
                    srh = (void *)ip6 + sizeof(*ip6);
                    tcp = (void *)srh + 8 + 16*new_sr_count;
                    new_sr_list = (struct in6_addr *)((void *)srh + 8);
                    payload = (void *)tcp + sizeof(*tcp);                    
                    direct = payload;
                    tag = payload + sizeof(__u64);
                    start = payload + sizeof(__u64) + sizeof("1010101010");
                    addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                    sr_list = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr);

                    // Ensure the new pointers are within bounds
                    if ((void *)new_sr_list + new_sr_count * sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }
                    if ((void *)new_sr_list + sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }
                    if ((void *)addr + sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }
                    if ((void *)tcp + sizeof(*tcp) > data_end) {
                        return TC_ACT_SHOT;
                    }
                    if ((void *)sr_list + sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }

                    srh->hdrlen = 2*new_sr_count;
                    srh->last_entry = new_sr_count - 1;
                    srh->segments_left = new_sr_count - 1;
                    srh->nexthdr = IPPROTO_TCP;
                    srh->type = 4;
                    srh->reserved = 0;
                    srh->flags = 0;
                }

                // Copy new_sr_list into sr_list
                if (sr_count >= 2){
                    for (int i = 0; i < sr_count - 1 && i < 3; i++) {
                        if (sr_count - 1 - i >= 10) {
                            return TC_ACT_SHOT;
                        }
                        if (tags[sr_count-1-i] == '1') {
                            if ((void *)new_sr_list + (new_sr_count+1)*sizeof(struct in6_addr) > data_end) {
                                return TC_ACT_SHOT;
                            }
                            new_sr_list[new_sr_count--] = *addr;
                            // Add loopback for ECMP
                        } else {
                            // Add direct path
                            new_sr_count += 3;
                        }
                    }
                    if (tags[0] == '1') {
                        new_sr_count += 3;
                    }
                    else {
                        new_sr_count += 1;
                    }
                    new_sr_count += 1;
                }
                // memcpy(sr_list, new_sr_list, sizeof(new_sr_list));
                // if (sr_count >= 2){
                //     new_sr_count --;
                //     for (int i = 0; i < sr_count - 1; i++) {
                //         if ((void *)tag + (sr_count-i)*sizeof(char) > data_end) {
                //             return TC_ACT_SHOT;
                //         }
                //         if (tag[sr_count-1-i] == '1') {
                //             tag[sr_count-1-i] = '0';
                //             // Add loopback for ECMP
                //             // return TC_ACT_OK;
                //             memcpy(new_sr_list + new_sr_count*sizeof(struct in6_addr), sr_list + (i+1)*sizeof(struct in6_addr), sizeof(struct in6_addr));
                //             // new_sr_count--;
                //             // memcpy(new_sr_list + (new_sr_count)*sizeof(struct in6_addr), sr_list + i*sizeof(struct in6_addr), sizeof(struct in6_addr));
                //             // new_sr_count--;
                //             // memcpy(new_sr_list + (new_sr_count)*sizeof(struct in6_addr), sr_list + (i+1)*sizeof(struct in6_addr), sizeof(struct in6_addr));
                //             // new_sr_count--;
                //             // new_sr_list[new_sr_count--] = old_sr_list[i+1];
                //             // new_sr_list[new_sr_count--] = sr_list[i+1];
                //             // new_sr_list[new_sr_count--] = sr_list[i];
                //             // new_sr_list[new_sr_count--] = sr_list[i+1];
                //         } else {
                //             // Add direct path
                //             // new_sr_list[new_sr_count--] = sr_list[i+1];
                //         }
                //     }
                //     if (tag[0] == '1') {
                //         // new_sr_list[new_sr_count--] = *addr;
                //         // new_sr_list[new_sr_count--] = sr_list[sr_count - 1];
                //         // new_sr_list[new_sr_count--] = *addr;
                //     }
                //     else {
                //         // new_sr_list[new_sr_count--] = sr_list[sr_count - 1];
                //     }
                //     // new_sr_list[new_sr_count--] = *addr;
                // }

                /* IPv6 processing */
                swap_mac(eth);
                swap_ip6(ip6);
                swap_port(tcp);
                __u16 *tcp_flag = (void *)tcp + TCP_FLAG_FIELD_OFFSET;
                __u16 old_tcp_flag = *tcp_flag;
                __u16 new_tcp_flag = *tcp_flag;

                /* clear syn bit */
                new_tcp_flag &= ~TCP_FLAG_SYN;
                /* set rst bit */
                new_tcp_flag |= TCP_FLAG_RST;
                /* set ack bit */
                new_tcp_flag |= TCP_FLAG_ACK;

                ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_tcp_flag, new_tcp_flag, 0);
                if (unlikely(ret)) {
                    return TC_ACT_SHOT;
                }

                // if (tcp_flag > data_end) {
                //     return TC_ACT_SHOT;
                // }
                // if (tcp_flag + sizeof(new_tcp_flag) > data_end) {
                //     return TC_ACT_SHOT;
                // }
                // memcpy(tcp_flag, &new_tcp_flag, sizeof(new_tcp_flag));
                memcpy(data + TCP_FLAG_OFFSET + vlanhdr_len, &new_tcp_flag, sizeof(new_tcp_flag));

                /* calculate and set ack sequence */
                __be32 old_ack_seq = tcp->ack_seq;
                __be32 new_ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);

                // 计算tcp校验和
                ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_ack_seq, new_ack_seq, 0);
                if (unlikely(ret)) {
                    return TC_ACT_SHOT;
                }

                memcpy(data + ACK_SEQ_OFFSET + vlanhdr_len, &new_ack_seq, sizeof(new_ack_seq));

                // // Recalculate checksum for IPv6 header
                // ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + (new_sr_count - sr_count) * sizeof(struct in6_addr));
                // ret = bpf_bpf_l3_csum_replace(ctx, offsetof(struct ipv6hdr, payload_len), 0, ip6->payload_len, 0);
                // if (unlikely(ret)) {
                //     return TC_ACT_SHOT;
                // }

                bpf_clone_redirect(ctx, ctx->ifindex, 0);
                return TC_ACT_SHOT;
            }
            else if (IPPROTO_UDP == srh->nexthdr) {
                struct udphdr *udp = (void *)srh + 8 + 8*srh->hdrlen;
                if (unlikely((void *)udp + sizeof(*udp) > data_end))
                    return TC_ACT_SHOT;

                if (bpf_ntohs(udp->dest) != PING_PORT && bpf_ntohs(udp->source) != PING_PORT) {
                    return TC_ACT_OK;
                }
                // 确保 payload 存在
                void *payload = (void *)udp + sizeof(*udp);
                if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) + srh->hdrlen*8 > data_end))
                    return TC_ACT_SHOT;
                
                __u64* direct = payload;
                char* tag = payload + sizeof(__u64);
                __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
                struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                struct in6_addr* sr_list = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr);
                
                if (direct != 0) {
                    return TC_ACT_OK;
                }
                // 修改方向
                __u64 new_direct = *direct + 1;
                memcpy(direct, &new_direct, sizeof(new_direct));

                // Construct return SRH list
                
                int sr_count = srh->last_entry + 1;
                struct in6_addr new_sr_list[5];
                __u64 new_sr_count = 0;

                if (sr_count >= 2){
                    #pragma unroll
                    for (int i = 0; i < sr_count - 1 && i < 3; i++) {
                        if (tag[sr_count-1-i] == '1') {
                            // Add loopback for ECMP
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                            new_sr_list[new_sr_count++] = sr_list[i];
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                        } else {
                            // Add direct path
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                        }
                    }
                    if (tag[0] == '1') {
                        new_sr_list[new_sr_count++] = *addr;
                        new_sr_list[new_sr_count++] = sr_list[sr_count - 1];
                        new_sr_list[new_sr_count++] = *addr;
                    }
                    else {
                        new_sr_list[new_sr_count++] = sr_list[sr_count - 1];
                    }
                    new_sr_list[new_sr_count++] = *addr;
                }

                // Update SRH for return path
                srh->segments_left = new_sr_count - 1;
                srh->last_entry = new_sr_count - 1;
                srh->hdrlen = 8 + 8 * new_sr_count;
                // Reverse the new_sr_list
                for (__u64 i = 0; i < (new_sr_count >> 1); i++) {
                    struct in6_addr temp = new_sr_list[i];
                    new_sr_list[i] = new_sr_list[new_sr_count - 1 - i];
                    new_sr_list[new_sr_count - 1 - i] = temp;
                }

                // Check if new_sr_list is longer than sr_list
                if (new_sr_count > sr_count) {
                    // Calculate the additional space needed
                    int additional_space = (new_sr_count - sr_count) * sizeof(struct in6_addr);

                    // Adjust packet size to accommodate the new SRH
                    if (bpf_skb_adjust_room(ctx, additional_space, BPF_ADJ_ROOM_NET, 0)) {
                        return TC_ACT_SHOT;
                    }

                    // Recalculate pointers after adjusting the packet size
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    ip6 = data + nh_off;
                    srh = (void *)ip6 + sizeof(*ip6);
                    sr_list = (struct in6_addr *)((void *)srh + 8);

                    // Ensure the new pointers are within bounds
                    if ((void *)sr_list + new_sr_count * sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }

                    srh->hdrlen = 8 + 8 * new_sr_count;
                    srh->last_entry = new_sr_count - 1;
                    srh->segments_left = new_sr_count - 1;
                    srh->nexthdr = IPPROTO_UDP;
                    srh->type = 4;
                    srh->reserved = 0;
                    srh->flags = 0;
                }

                // Copy new_sr_list into sr_list
                memcpy(sr_list, new_sr_list, sizeof(new_sr_list));

                /* IPv6 processing */
                swap_mac(eth);
                swap_ip6(ip6);
                swap_portu(udp);

                // // Recalculate checksum for IPv6 header
                // ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + (new_sr_count - sr_count) * sizeof(struct in6_addr));
                // ret = bpf_l3_csum_replace(ctx, offsetof(struct ipv6hdr, payload_len), 0, ip6->payload_len, 0);
                // if (unlikely(ret)) {
                //     return TC_ACT_SHOT;
                // }

                bpf_clone_redirect(ctx, ctx->ifindex, 0);
                return TC_ACT_SHOT;
            }
            else if (IPPROTO_ICMPV6 == srh->nexthdr) {
                struct icmp6hdr *icmp6 = (void *)srh + 8 + 8*srh->hdrlen;
                if (unlikely((void *)icmp6 + sizeof(*icmp6) > data_end))
                    return TC_ACT_SHOT;
                if (icmp6->icmp6_type != ICMPV6_ECHO_REPLY) {
                    return TC_ACT_SHOT;
                }

                // 确保 payload 存在
                void *payload = (void *)icmp6 + sizeof(*icmp6);
                if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) + srh->hdrlen*8 > data_end))
                    return TC_ACT_SHOT;
                
                __u64* direct = payload;
                char* tag = payload + sizeof(__u64);
                __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
                struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
                struct in6_addr* sr_list = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr);
                
                if (direct != 0) {
                    return TC_ACT_OK;
                }
                // 修改方向
                __u64 new_direct = *direct + 1;
                memcpy(direct, &new_direct, sizeof(new_direct));
                icmp6->icmp6_type = ICMPV6_ECHO_REPLY;

                // Construct return SRH list
                
                int sr_count = srh->last_entry + 1;
                struct in6_addr new_sr_list[5];
                __u64 new_sr_count = 0;

                if (sr_count >= 2){
                    #pragma unroll
                    for (int i = 0; i < sr_count - 1 && i < 3; i++) {
                        if (tag[sr_count-1-i] == '1') {
                            // Add loopback for ECMP
                            if (new_sr_count >= 5) {
                                return TC_ACT_OK;
                            }
                            if ((void *)(sr_list+i+1) > data_end) {
                                return TC_ACT_OK;
                            }
                            // Add loopback for ECMP
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                            new_sr_list[new_sr_count++] = sr_list[i];
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                        } else {
                            // Add direct path
                            new_sr_list[new_sr_count++] = sr_list[i+1];
                        }
                    }
                    if (tag[0] == '1') {
                        new_sr_list[new_sr_count++] = *addr;
                        new_sr_list[new_sr_count++] = sr_list[sr_count - 1];
                        new_sr_list[new_sr_count++] = *addr;
                    }
                    else {
                        new_sr_list[new_sr_count++] = sr_list[sr_count - 1];
                    }
                    new_sr_list[new_sr_count++] = *addr;
                }

                // Update SRH for return path
                srh->segments_left = new_sr_count - 1;
                srh->last_entry = new_sr_count - 1;
                srh->hdrlen = 8 + 8 * new_sr_count;
                // Reverse the new_sr_list
                for (__u64 i = 0; i < (new_sr_count >> 1); i++) {
                    struct in6_addr temp = new_sr_list[i];
                    new_sr_list[i] = new_sr_list[new_sr_count - 1 - i];
                    new_sr_list[new_sr_count - 1 - i] = temp;
                }

                // Check if new_sr_list is longer than sr_list
                if (new_sr_count > sr_count) {
                    // Calculate the additional space needed
                    int additional_space = (new_sr_count - sr_count) * sizeof(struct in6_addr);

                    // Adjust packet size to accommodate the new SRH
                    if (bpf_skb_adjust_room(ctx, additional_space, BPF_ADJ_ROOM_NET, 0)) {
                        return TC_ACT_SHOT;
                    }

                    // Recalculate pointers after adjusting the packet size
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    ip6 = data + nh_off;
                    srh = (void *)ip6 + sizeof(*ip6);
                    sr_list = (struct in6_addr *)((void *)srh + 8);

                    // Ensure the new pointers are within bounds
                    if ((void *)sr_list + new_sr_count * sizeof(struct in6_addr) > data_end) {
                        return TC_ACT_SHOT;
                    }

                    srh->hdrlen = 8 + 8 * new_sr_count;
                    srh->last_entry = new_sr_count - 1;
                    srh->segments_left = new_sr_count - 1;
                    srh->nexthdr = IPPROTO_UDP;
                    srh->type = 4;
                    srh->reserved = 0;
                    srh->flags = 0;
                }

                // Copy new_sr_list into sr_list
                memcpy(sr_list, new_sr_list, sizeof(new_sr_list));

                /* IPv6 processing */
                swap_mac(eth);
                swap_ip6(ip6);

                // // Recalculate checksum for IPv6 header
                // ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + (new_sr_count - sr_count) * sizeof(struct in6_addr));
                // ret = bpf_l3_csum_replace(ctx, offsetof(struct ipv6hdr, payload_len), 0, ip6->payload_len, 0);
                // if (unlikely(ret)) {
                //     return TC_ACT_SHOT;
                // }
                
                bpf_clone_redirect(ctx, ctx->ifindex, 0);
                return TC_ACT_SHOT;
            }
        }
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
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
    //                 // bpf_printk("TC 333333\n");
    //                 struct tcphdr *tcp = (void *)srh + 8 + 8*srh->hdrlen;
    //                 if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
    //                     return TC_ACT_SHOT;
    //                 // bpf_printk("TC 444444\n");
            
    //                 if (!tcp->syn || tcp->ack || tcp->rst) {
    //                     return TC_ACT_OK;
    //                 }
    //                 // bpf_printk("TC 555555\n");
            
    //                 if (bpf_ntohs(tcp->dest) != PING_PORT && bpf_ntohs(tcp->source) != PING_PORT) {
    //                     return TC_ACT_OK;
    //                 }
    //                 // bpf_printk("TC 666666\n");
            
    //                 // 确保 payload 存在
    //                 void *payload = (void *)tcp + sizeof(*tcp);
    //                 if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
    //                     return TC_ACT_SHOT;
    //                 // bpf_printk("TC 777777\n");
                    
    //                 __u64* direct = payload;
    //                 char* tag = payload + sizeof(__u64);
    //                 __u64* start = payload + sizeof(__u64) + sizeof("1010101010");
    //                 struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);

    //                 // 修改 map 的内容
    //                 __u64 time = bpf_ktime_get_ns();
    //                 memcpy(start, &time, sizeof(time));
    //                 memcpy(addr, &ip6->saddr, sizeof(ip6->saddr));
    //                 // bpf_printk("TC 888888\n");


            
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
        if (unlikely(payload + 2*sizeof(__u64) > data_end))
            return TC_ACT_SHOT;
        // if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
            // return TC_ACT_SHOT;
        
        // __u64* start = payload;
        // char* tag = payload + sizeof(__u64);
        __u64* direct = payload + sizeof(__u64);
        __u32* start = payload;
        __u32* start2 = payload + sizeof(__be32);
        // __u64* direct = payload + sizeof(__u64) + sizeof("1010101010");
        // __u32* start2 = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u32);
        // struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
        
        if (*direct == 0) {
            // 修改 map 的内容
            __u64 time = bpf_ktime_get_ns();
            struct rtt_key_t key = {};
            key.src_ip = ip->saddr;
            key.dst_ip = ip->daddr;
            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
            key.protocol = ip->protocol;
            key.seq = tcp->seq;
    
            bpf_map_update_elem(&rtt_start, &key, &time, BPF_ANY);
            // skb_store_bytes(ctx, start - data, &time, sizeof(time), BPF_F_RECOMPUTE_CSUM);
            // __u32 old_start = *start;
            // __u32 old_start2 = *start2;
            // __u32 new_start = (__u32)(time >> 32 & 0xFFFFFFFF);
            // __u32 new_start2 = (__u32)(time & 0xFFFFFFFF);
            // if (start + sizeof(new_start) > data_end) {
            //     return TC_ACT_SHOT;
            // }
            // if (start2 + sizeof(new_start2) > data_end) {
            //     return TC_ACT_SHOT;
            // }

            // if (bpf_ntohl(tcp->seq) == 0) {
            //     // memcpy(start, &time, sizeof(time));
            //     memcpy(start, &new_start, sizeof(new_start));
            //     memcpy(start2, &new_start2, sizeof(new_start2));
            //     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_start, time, 0);
            //     if (unlikely(ret)) {
            //         return TC_ACT_SHOT;
            //     }
            //     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_start, time, 0);
            //     if (unlikely(ret)) {
            //         return TC_ACT_SHOT;
            //     }
            // }
            // memcpy(start, &new_start, sizeof(new_start));
            // memcpy(start2, &new_start2, sizeof(new_start2));
            // if (tcp->seq == 2) {
            //     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_start, new_start, 4);
            //     if (unlikely(ret)) {
            //         return TC_ACT_SHOT;
            //     }
            // }
            // else if (tcp->seq == 1) {
            //     ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_start, new_start, 2);
            //     if (unlikely(ret)) {
            //         return TC_ACT_SHOT;
            //     }
            // }
            // else if (tcp->seq == 0) {
            // }
            // ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_start2, new_start2, 4);
            // if (unlikely(ret)) {
            //     return TC_ACT_SHOT;
            // }
        }
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
        if (unlikely(payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64) + sizeof(struct in6_addr) > data_end))
            return TC_ACT_SHOT;
        
        __u64* direct = payload;
        char* tag = payload + sizeof(__u64);
        __u32* start = payload + sizeof(__u64) + sizeof("1010101010");
        __u32* start2 = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u32);
        struct in6_addr* addr = payload + sizeof(__u64) + sizeof("1010101010") + sizeof(__u64);
        
        if (*direct == 0) {
            // 修改 map 的内容
            __u64 time = bpf_ktime_get_ns();
            if (start + sizeof(time) > data_end) {
                return TC_ACT_SHOT;
            }
            __u32 old_start = *start;
            __u32 old_start2 = *start2;
            __u32 new_start = (__u32)(time >> 32);
            __u32 new_start2 = (__u32)(time & 0xFFFFFFFF);
            memcpy(start, &time, sizeof(time));
            ret = l4_csum_replace(ctx, UDP_CSUM_OFFSET + vlanhdr_len, old_start, new_start, 0);
            if (unlikely(ret)) {
                return TC_ACT_SHOT;
            }
            ret = l4_csum_replace(ctx, UDP_CSUM_OFFSET + vlanhdr_len, old_start2, new_start2, 0);
            if (unlikely(ret)) {
                return TC_ACT_SHOT;
            }
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