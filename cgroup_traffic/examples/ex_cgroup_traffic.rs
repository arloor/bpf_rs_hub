#![deny(warnings)]
use std::{thread::sleep, time::Duration};

use log::info;

type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();
    let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
    loop {
        info!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
