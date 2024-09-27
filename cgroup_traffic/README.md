`cgroup_traffic` is a library to monitor the network traffic of a cgroup. By passing a pid to this library, it will attach to the cgroup of the pid and monitor the network traffic of the cgroup.

It use ebpf program `BPF_PROG_TYPE_CGROUP_SKB` to monitor the network traffic. Now it's only tested for Cgroup V2. It doesn't support Cgroup V1, because it cannot parse the path of cgroup V1.

## Examples

```rust
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
    loop {
        println!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
```
 
Refer to `cgroup_traffic::init_cgroup_skb_monitor` if you want to attach to a specific cgroup path.
