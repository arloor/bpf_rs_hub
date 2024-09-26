#![deny(warnings)]
use std::{mem::MaybeUninit, thread::sleep, time::Duration};

type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let (cgroup_transmit_counter, _links) = cgroup_traffic::attach_self_cgroup(open_object)?;
    // let cgroup_transmit_counter = cgroup_traffic::attach_cgroup("/sys/fs/cgroup/system.slice/nginx.service")?;
    loop {
        println!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
