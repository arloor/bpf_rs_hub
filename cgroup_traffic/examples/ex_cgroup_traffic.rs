#![deny(warnings)]
use std::time::Duration;

use cgroup_traffic::start;
type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let transmit_counter = start("/sys/fs/cgroup/unified/c")?;
    loop {
        transmit_counter.get_egress();
        std::thread::sleep(Duration::from_secs(1));
    }
}
