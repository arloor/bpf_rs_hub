`cgroup_traffic` is a library for monitoring the network traffic of a cgroup. By passing a PID to this library, it attaches to the process's cgroup and monitors that cgroup's network traffic.

This library supports **cgroup v2 only**. It uses eBPF programs of type `BPF_PROG_TYPE_CGROUP_SKB` and attaches them to a cgroup with the kernel cgroup BPF attach API. That API accepts only cgroup v2 directory file descriptors; attaching to a cgroup v1 directory fails with `EBADF`. Consequently, adding cgroup v1 path parsing alone cannot make this implementation support cgroup v1.

## Examples

```rust
#![deny(warnings)]
use std::mem::MaybeUninit;

use log::info;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let mut open_object = MaybeUninit::uninit(); // make the ebpf prog lives as long as the process.
    let (cgroup_transmit_counter, _links) = cgroup_traffic::init_cgroup_skb_for_process_name(
        &mut open_object,
        "^rust-analyzer$|ssh|rust_http_proxy",
    )?; // _links cannot be replaced by _， because it holds the life of bpf prog.
    loop {
        info!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

```
 
Use `cgroup_traffic::CgroupTransmitCounter::attach_cgroup` if you want to attach to a specific cgroup v2 path.

## Limitations

- cgroup v1 is not supported by this implementation. Supporting it would require a different monitoring mechanism or an additional cgroup v2 hierarchy; it cannot be enabled by changing path parsing alone.
