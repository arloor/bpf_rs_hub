#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// copy from #include <linux/if_ether.h>
#define ETH_HLEN 14 /* Total octets in header.	 */
// copy from  <linux/if_packet.h>
#define PACKET_OUTGOING 4 /* Outgoing of any type */

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define IP_DEST_OFF offsetof(struct iphdr, daddr)

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} traffic SEC(".maps");

/*
 * Track size of outgoing ICMP and UDP packets
 */
SEC("socket")
int bpf_program(struct __sk_buff *skb)
{

    __u32 key = 0; // egress = 0
    if (skb->pkt_type != PACKET_OUTGOING)
    {
        key = 1; // ingress = 1
    }

    long *value = bpf_map_lookup_elem(&traffic, &key);
    if (value)
    {
        __sync_fetch_and_add(value, skb->len);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
