#![deny(warnings)]
use std::{error::Error, mem::MaybeUninit, os::fd::AsRawFd, thread::sleep, time::Duration};

use cgroup_traffic::get_self_cgroup;

type DynError = Box<dyn std::error::Error>;

pub fn main() -> Result<(), DynError> {
    let cgroup_transmit_counter = init_cgroup_traffic_monitor()?;
    loop {
        println!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}

fn init_cgroup_traffic_monitor() -> Result<cgroup_traffic::CgroupTransmitCounter, Box<dyn Error>> {
    let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut cgroup_transmit_counter = cgroup_traffic::attach_self_cgroup(open_object)?;
    let cgroup = get_self_cgroup()?;
    println!(
        "attach to self's cgroup: [ {} ], pids: {:?}",
        cgroup.0, cgroup.1
    );
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(cgroup.0)?;
    let cgroup_fd = f.as_raw_fd();
    let progs = &mut cgroup_transmit_counter.skel.progs;
    let link_egress = progs.count_egress_packets.attach_cgroup(cgroup_fd)?;
    Box::leak(Box::new(link_egress));
    let link_ingress = progs.count_ingress_packets.attach_cgroup(cgroup_fd)?;
    Box::leak(Box::new(link_ingress));
    Ok(cgroup_transmit_counter)
}
