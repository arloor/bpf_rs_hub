#![deny(warnings)]
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
// use object::{Object, ObjectSymbol};
use libbpf_rs::{Link, MapFlags};
use std::os::fd::AsRawFd;

mod prog {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/program.skel.rs"
    ));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;

pub struct CgroupTransmitCounter {
    skel: ProgramSkel<'static>,
    #[allow(dead_code)]
    link_egress: Link,
    #[allow(dead_code)]
    link_ingress: Link,
}

struct Direction(u32);
const EGRESS: Direction = Direction(0);
const INGRESS: Direction = Direction(1);
fn get(skel: &ProgramSkel<'static>, direction: Direction) -> u64 {
    let maps = skel.maps();
    let map = maps.process_traffic();
    let key = unsafe { plain::as_bytes(&direction.0) };
    let mut value: u64 = 0;
    if let Ok(Some(buf)) = map.lookup(key, MapFlags::ANY) {
        plain::copy_from_bytes(&mut value, &buf).expect("Invalid buffer");
    }
    value
}

impl CgroupTransmitCounter {
    pub fn get_egress(&self) -> u64 {
        get(&self.skel, EGRESS)
    }

    pub fn get_ingress(&self) -> u64 {
        get(&self.skel, INGRESS)
    }
}

fn bump_memlock_rlimit() -> Result<(), DynError> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        println!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn start(path: &str) -> Result<CgroupTransmitCounter, DynError> {
    let mut skel_builder = ProgramSkelBuilder::default();

    skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;
    // if let Some(pid) = opts.pid {
    //     open_skel.rodata().target_pid = pid;
    // }
    let mut skel = open_skel.load()?;

    let f = std::fs::OpenOptions::new()
        //.custom_flags(libc::O_DIRECTORY)
        //.create(true)
        .read(true)
        .write(false)
        .open(path)?;
    let cgroup_fd = f.as_raw_fd();
    let mut progs: ProgramProgsMut<'_> = skel.progs_mut();
    let link_egress = progs.count_egress_packets().attach_cgroup(cgroup_fd)?;
    let link_ingress = progs.count_ingress_packets().attach_cgroup(cgroup_fd)?;
    Ok(CgroupTransmitCounter {
        skel,
        link_egress,
        link_ingress,
    })
}
