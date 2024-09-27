#![deny(warnings)]
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
// use object::{Object, ObjectSymbol};
use libbpf_rs::{MapCore, MapFlags};
use std::mem::MaybeUninit;

mod prog {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/program.skel.rs"
    ));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;

pub struct CgroupTransmitCounter {
    pub skel: ProgramSkel<'static>,
}

struct Direction(u32);
const EGRESS: Direction = Direction(0);
const INGRESS: Direction = Direction(1);
fn get(skel: &ProgramSkel<'static>, direction: Direction) -> u64 {
    let maps = &skel.maps;
    let map = &maps.process_traffic;
    let key = unsafe { plain::as_bytes(&direction.0) };
    let mut count: u64 = 0;
    if let Ok(Some(buf)) = map.lookup_percpu(key, MapFlags::ANY) {
        for ele in buf.iter() {
            let mut value: u64 = 0;
            plain::copy_from_bytes(&mut value, ele).expect("Invalid buffer");
            count += value;
        }
    }
    count
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

use std::fs::File;
use std::io::{self, BufRead, Read};
use std::path::Path;

pub fn list_pids_in_cgroup(cgroup_path: &str) -> io::Result<Vec<i32>> {
    let procs_path = Path::new(cgroup_path).join("cgroup.procs");
    let mut file = File::open(procs_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let pids = content
        .lines()
        .filter_map(|line| line.parse::<i32>().ok())
        .collect();

    Ok(pids)
}
pub const SELF: &str = "self";
pub fn init_cgroup_skb_monitor(
    pid: &str,
) -> Result<CgroupTransmitCounter, Box<dyn std::error::Error>> {
    let open_object = Box::leak(Box::new(std::mem::MaybeUninit::uninit())); // leak it to make it 'static, so our bpf prog lives 'static
    let mut cgroup_transmit_counter = load_ebpf_skel(open_object)?;
    let cgroup = get_pid_cgroup(pid)?;
    log::info!(
        "attach to {pid}'s cgroup: [ {} ], pids: {:?}",
        cgroup.0,
        cgroup.1
    );
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(cgroup.0)?; // a standalone line, to make `file` leave longer.
    use std::os::fd::AsRawFd;
    let cgroup_fd = file.as_raw_fd();
    let progs = &mut cgroup_transmit_counter.skel.progs;
    let link_egress = progs.count_egress_packets.attach_cgroup(cgroup_fd)?;
    Box::leak(Box::new(link_egress)); // leak it to make it 'static, so our bpf prog lives 'static
    let link_ingress = progs.count_ingress_packets.attach_cgroup(cgroup_fd)?;
    Box::leak(Box::new(link_ingress)); // leak it to make it 'static, so our bpf prog lives 'static
    Ok(cgroup_transmit_counter)
}

pub(crate) fn get_pid_cgroup(pid: &str) -> io::Result<(String, Vec<i32>)> {
    let cgroup_dir = Path::new("/sys/fs/cgroup");
    if !cgroup_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "/sys/fs/cgroup directory does not exist",
        ));
    }

    let proc_fs = format!("/proc/{}/cgroup", pid);
    let path = Path::new(proc_fs.as_str());
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.contains("0::") {
            let parts: Vec<&str> = line.split("::").collect();
            if parts.len() == 2 {
                let cgroup_path = cgroup_dir.join(parts[1].trim_start_matches('/'));
                let cgroup_path = cgroup_path.to_string_lossy().into_owned();
                let pids = list_pids_in_cgroup(&cgroup_path)?;
                return Ok((cgroup_path, pids));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Cgroup path not found",
    ))
}

pub(crate) fn load_ebpf_skel(
    open_object: &'static mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<CgroupTransmitCounter, DynError> {
    let mut skel_builder = ProgramSkelBuilder::default();

    skel_builder.obj_builder.debug(false);

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open(open_object)?;
    // if let Some(pid) = opts.pid {
    //     open_skel.rodata().target_pid = pid;
    // }
    let skel: ProgramSkel<'_> = open_skel.load()?;
    Ok(CgroupTransmitCounter { skel })
}
