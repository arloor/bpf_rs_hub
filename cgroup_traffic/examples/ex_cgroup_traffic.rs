#![deny(warnings)]
use std::mem::MaybeUninit;

use log::info;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let open_object = Box::leak(Box::new(MaybeUninit::uninit())); // make the ebpf prog lives as long as the process.
    let (cgroup_transmit_counter, _) =
        cgroup_traffic::init_cgroup_skb_for_process_name(open_object, "^rust-analyzer$")?;
    // let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
    loop {
        info!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
