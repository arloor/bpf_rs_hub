#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} process_traffic SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb)
{
    __u32 key = 0; // egress = 0

    long *value = bpf_map_lookup_elem(&process_traffic, &key);
    if (value)
    {
        __sync_fetch_and_add(value, skb->len);
    }
    bpf_printk("Egress packet: %d\n", skb->len);

    return 1;
}