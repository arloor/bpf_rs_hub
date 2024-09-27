#![deny(warnings)]
//! # cgroup_traffic
//!
//! `cgroup_traffic` is a library to monitor the network traffic of a cgroup. By passing a pid to this library, it will attach to the cgroup of the pid and monitor the network traffic of the cgroup.
//!
//! It use ebpf program `BPF_PROG_TYPE_CGROUP_SKB` to monitor the network traffic. Now it's only tested for Cgroup V2. It doesn't support Cgroup V1, because it cannot parse the path of cgroup V1.
//!
//! ## Example
//!
//! ```rust
//! // monitor self's cgroup traffic
//! let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
//! loop {
//!     println!(
//!         "current bytes: {} {}",
//!         cgroup_transmit_counter.get_egress(),
//!         cgroup_transmit_counter.get_ingress()
//!     );
//!     std::thread::sleep(std::time::Duration::from_secs(1));
//! }
//! ```
//!
//! Refer to `cgroup_traffic::init_cgroup_skb_monitor` for more information.

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
// use object::{Object, ObjectSymbol};
use libbpf_rs::{MapCore, MapFlags};
use std::error::Error;
use std::mem::MaybeUninit;

mod prog {
    include!(concat!(env!("OUT_DIR"), "/program.skel.rs"));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;

/// The CgroupTransmitCounter is a struct to monitor the network traffic of a cgroup.
///
/// It contains two methods to get the egress and ingress bytes of the cgroup.
pub struct CgroupTransmitCounter {
    pub(crate) skel: ProgramSkel<'static>,
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
    /// Create a new CgroupTransmitCounter.
    ///
    /// It will load the ebpf program and return a CgroupTransmitCounter.
    pub fn new() -> Result<CgroupTransmitCounter, Box<dyn Error>> {
        let open_object = Box::leak(Box::new(std::mem::MaybeUninit::uninit()));
        let cgroup_transmit_counter = load_ebpf_skel(open_object)?;
        Ok(cgroup_transmit_counter)
    }

    /// Attach the ebpf program to a cgroup.
    ///
    /// The cgroup_path should be a full path to the cgroup directory.
    pub fn attach_cgroup(&mut self, cgroup_path: String) -> Result<(), Box<dyn Error>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(cgroup_path)?;
        // a standalone line, to make `file` live longer. https://github.com/libbpf/libbpf-rs/issues/197
        use std::os::fd::AsRawFd;
        let cgroup_fd = file.as_raw_fd();
        let progs = &mut self.skel.progs;
        let link_egress = progs.count_egress_packets.attach_cgroup(cgroup_fd)?;
        Box::leak(Box::new(link_egress));
        let link_ingress = progs.count_ingress_packets.attach_cgroup(cgroup_fd)?;
        Box::leak(Box::new(link_ingress));
        Ok(())
    }

    /// Get the egress bytes of the cgroup.
    pub fn get_egress(&self) -> u64 {
        get(&self.skel, EGRESS)
    }

    /// Get the ingress bytes of the cgroup.
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

/// List all PIDs in a cgroup.
///
/// The cgroup path should be a full path to the cgroup directory.
///
/// Returns a list of PIDs in the cgroup.
///
/// ONLY support Cgroup V2
pub fn list_pids_in_cgroup(cgroup_path: &str) -> io::Result<Vec<i32>> {
    let procs_path = Path::new(cgroup_path).join(CGROUP_PROCS);
    let mut file = File::open(procs_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let pids = content
        .lines()
        .filter_map(|line| line.parse::<i32>().ok())
        .collect();

    Ok(pids)
}
/// Helpful constant to monitor /proc/self/cgroup
pub const SELF: &str = "self";
const CGROUP_PROCS: &str = "cgroup.procs";

/// Initialize the cgroup skb monitor.
///
/// It will attach to the cgroup of the pid. The pid should be a string of the process id.
///
/// Steps:
/// 1. Load the ebpf program
/// 2. Get the cgroup path of the pid. ONLY support CgroupV2
/// 3. Attach the ebpf program to the cgroup
///
/// You can replace step 2 with a specific cgroup path as you like.
pub fn init_cgroup_skb_monitor(
    pid: &str,
) -> Result<CgroupTransmitCounter, Box<dyn std::error::Error>> {
    let mut cgroup_transmit_counter = CgroupTransmitCounter::new()?;
    let cgroup = get_pid_cgroup(pid)?;
    log::info!(
        "attach to {pid}'s cgroup: [ {} ], contain these pids: {:?}",
        cgroup.0,
        cgroup.1
    );
    let cgroup_path = cgroup.0;
    cgroup_transmit_counter.attach_cgroup(cgroup_path)?;
    Ok(cgroup_transmit_counter)
}

/// Get the cgroup path of a pid.
///
/// The pid should be a string of the process id.
///
/// Use `/sys/fs/cgroup` and  `/proc/{pid}/cgroup` to get the actual cgroup path.
pub fn get_pid_cgroup(pid: &str) -> io::Result<(String, Vec<i32>)> {
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
