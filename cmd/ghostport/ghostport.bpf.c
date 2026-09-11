//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct traffic_key {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u8 protocol;
    __u8 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct traffic_key);
    __type(value, __u64);
} traffic_counts SEC(".maps");

char __license[] SEC("license") = "GPL";

SEC("tc")
int ghostport_ingress_monitor(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Check for IPv4 packets (0x0800 in network byte order)
    if (eth->h_proto != __builtin_bswap16(0x0800))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_header_len = iph->ihl * 4;
    if (ip_header_len < sizeof(*iph) || (void *)iph + ip_header_len > data_end)
        return TC_ACT_OK;

    struct traffic_key key = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .protocol = iph->protocol,
    };

    void *transport = (void *)iph + ip_header_len;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.dport = bpf_ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.dport = bpf_ntohs(udp->dest);
    }

    __u64 *count = bpf_map_lookup_elem(&traffic_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&traffic_counts, &key, &initial_count, BPF_ANY);
    }

    return TC_ACT_OK;
}
