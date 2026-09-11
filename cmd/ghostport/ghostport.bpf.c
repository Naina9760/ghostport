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

// IPv4 fragment-offset mask (RFC 791): the low 13 bits of the 16-bit
// fragment-control field, in 8-byte units. A non-zero value means this
// packet is a non-initial fragment and does not carry a transport header.
#define IP_FRAG_OFFSET_MASK 0x1FFF

struct traffic_key {
    // saddr/daddr are copied directly from the packet's network-byte-order
    // fields without a byte swap. GhostPort's userspace reader (main.go)
    // relies on this: it decodes the raw map bytes with the host's native
    // byte order, which cancels out correctly only because the eBPF target
    // and every supported host architecture (amd64, arm64) are
    // little-endian. If either side changes independently this breaks
    // silently; see TestSourceIPUsesNativeByteOrder in main_test.go, which
    // pins the current, intentional behavior.
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u8 protocol;
    __u8 padding;
};

// LRU_HASH bounds userspace memory and BPF map memory at max_entries
// regardless of how many distinct flows are observed: once full, the
// kernel evicts the least-recently-used entry to make room for a new one
// instead of failing the insert. This trades exact long-term counts for a
// live view that always reflects the busiest recent flows, which matters
// for scan detection (a scanner touching thousands of ports must not be
// able to starve new-flow tracking by filling the map with entries that
// are never evicted). Eviction means a flow's counter can reset to 1 if it
// falls out of the LRU window and later reappears; TestMapEvictionUnderLoad
// in bpf_program_test.go documents and exercises this.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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

    // Only the initial fragment (or an unfragmented packet) carries a
    // transport header at this offset. Later fragments of the same
    // datagram are still counted by source, destination, and protocol,
    // but without a destination port, instead of reading fragment payload
    // bytes as if they were a TCP/UDP header.
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    __u8 is_later_fragment = (frag_off & IP_FRAG_OFFSET_MASK) != 0;

    if (!is_later_fragment) {
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
    }

    // Concurrent packets for a brand-new key on different CPUs can both
    // miss this lookup and both call update_elem below; BPF_ANY makes the
    // second call overwrite the first, so at most one increment out of the
    // race is lost. This is a bounded, self-correcting undercount (every
    // later packet for that key increments atomically via
    // __sync_fetch_and_add) rather than a safety issue, and is accepted
    // here rather than adding a per-CPU map and the userspace aggregation
    // it would require.
    __u64 *count = bpf_map_lookup_elem(&traffic_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&traffic_counts, &key, &initial_count, BPF_ANY);
    }

    return TC_ACT_OK;
}
