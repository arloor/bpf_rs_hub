
use epbf program type `BPF_PROG_TYPE_SOCKET_FILTER` to monitor the network traffic of the host.

# Example

```rust
use std::{mem::MaybeUninit, thread::sleep, time::Duration};

fn main() {
    let open_object = Box::leak(Box::new(MaybeUninit::uninit())); // make the ebpf prog lives as long as the process.
    let socket_filter = socket_filter::TransmitCounter::new(
        &["lo", "podman", "veth", "flannel", "cni0", "utun"],
        open_object,
    );
    loop {
        println!(
            "current bytes: {} {}",
            socket_filter.get_egress(),
            socket_filter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
```