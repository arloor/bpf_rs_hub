#![deny(warnings)]
use std::{thread::sleep, time::Duration};

type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let cgroup_transmit_counter = cgroup_traffic::init_self_cgroup_skb_monitor()?;
    loop {
        println!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
