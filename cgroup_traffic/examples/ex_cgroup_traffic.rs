#![deny(warnings)]
use std::{thread::sleep, time::Duration};

use cgroup_traffic::start;
type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let cgroup_transmit_counter = start("/sys/fs/cgroup/system.slice/nginx.service")?;
    loop {
        println!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
