//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IPv4 address
    __type(value, __u64); // Interception count
} packet_counts SEC(".maps");

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

    __u32 saddr = iph->saddr;
    __u64 *count = bpf_map_lookup_elem(&packet_counts, &saddr);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&packet_counts, &saddr, &initial_count, BPF_ANY);
    }

    return TC_ACT_OK;
}
