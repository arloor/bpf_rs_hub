#![deny(warnings)]
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
// use object::{Object, ObjectSymbol};
use libbpf_rs::MapFlags;
use std::os::fd::AsRawFd;

mod prog {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/program.skel.rs"
    ));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;

pub struct TransmitCounter {
    skel: ProgramSkel<'static>,
}

impl TransmitCounter {
    pub fn get_egress(&self) {
        let maps = self.skel.maps();
        let map = maps.process_traffic();
        for ele in map.keys() {
            let mut key: u32 = 0;
            plain::copy_from_bytes(&mut key, &ele).expect("Invalid buffer");
            let mut value: u64 = 0;
            if let Ok(Some(buf)) = map.lookup(&ele, MapFlags::ANY) {
                plain::copy_from_bytes(&mut value, &buf).expect("Invalid buffer");
            }
            println!("key: {}, value: {}", key, value);
        }
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

pub fn start(path: &str) -> Result<TransmitCounter, DynError> {
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
    let mut a = skel.progs_mut();
    let prog = a.count_egress_packets();
    println!("prog name: {}", prog.name());
    println!("prog name: {}", prog.attach_type());
    println!("prog name: {}", prog.prog_type());
    prog.attach_cgroup(cgroup_fd)?;
    Ok(TransmitCounter { skel })
}
