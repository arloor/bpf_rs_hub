`cgroup_traffic` is a library to monitor the network traffic of a cgroup. By passing a pid to this library, it will attach to the cgroup of the pid and monitor the network traffic of the cgroup.

It use ebpf program `BPF_PROG_TYPE_CGROUP_SKB` to monitor the network traffic. Now it's only tested for Cgroup V2. It doesn't support Cgroup V1, because it cannot parse the path of cgroup V1.

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
 
Refer to `cgroup_traffic::init_cgroup_skb_monitor` if you want to attach to a specific cgroup path.

## Limitations

- Support for Cgroup V1 is NOT tested.