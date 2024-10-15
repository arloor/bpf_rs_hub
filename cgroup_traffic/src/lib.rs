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
//! pub fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
//!     loop {
//!         println!(
//!             "current bytes: {} {}",
//!             cgroup_transmit_counter.get_egress(),
//!             cgroup_transmit_counter.get_ingress()
//!         );
//!         std::thread::sleep(std::time::Duration::from_secs(1));
//!     }
//! }
//! ```
//!
//! Refer to `cgroup_traffic::init_cgroup_skb_monitor` for more information.

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
// use object::{Object, ObjectSymbol};
use libbpf_rs::{Link, MapCore, MapFlags};
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::process::Command;

mod prog {
    include!(concat!(env!("OUT_DIR"), "/program.skel.rs"));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;

/// The CgroupTransmitCounter is a struct to monitor the network traffic of a cgroup.
///
/// It contains two methods to get the egress and ingress bytes of the cgroup.
pub struct CgroupTransmitCounter<'a> {
    pub(crate) skel: ProgramSkel<'a>,
}

struct Direction(u32);
const EGRESS: Direction = Direction(0);
const INGRESS: Direction = Direction(1);
fn get(skel: &ProgramSkel<'_>, direction: Direction) -> u64 {
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

impl<'a> CgroupTransmitCounter<'a> {
    /// Create a new CgroupTransmitCounter.
    ///
    /// It will load the ebpf program and return a CgroupTransmitCounter.
    pub fn new(
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<CgroupTransmitCounter, DynError> {
        let cgroup_transmit_counter = load_ebpf_skel(open_object)?;
        Ok(cgroup_transmit_counter)
    }

    /// Attach the ebpf program to a cgroup.
    ///
    /// The cgroup_path should be a full path to the cgroup directory.
    pub fn attach_cgroup(&mut self, cgroup_path: String) -> Result<(Link, Link), DynError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(cgroup_path)?;
        // a standalone line, to make `file` live longer. https://github.com/libbpf/libbpf-rs/issues/197
        use std::os::fd::AsRawFd;
        let cgroup_fd = file.as_raw_fd();
        let progs = &mut self.skel.progs;
        let link_egress = progs.count_egress_packets.attach_cgroup(cgroup_fd)?;
        let link_ingress = progs.count_ingress_packets.attach_cgroup(cgroup_fd)?;
        Ok((link_ingress, link_egress))
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
        return Err("Failed to increase rlimit".into());
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
pub fn init_cgroup_skb_monitor<'a>(
    open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    pid: &str,
) -> Result<(CgroupTransmitCounter<'a>, (Link, Link)), Box<dyn std::error::Error>> {
    let cgroup = get_pid_cgroup(pid)?;
    let mut cgroup_transmit_counter = CgroupTransmitCounter::new(open_object)?;
    log::info!(
        "attach to {pid}'s cgroup: [ {} ], contain these pids: {:?}",
        cgroup.0,
        cgroup.1
    );
    let cgroup_path = cgroup.0;
    let links = cgroup_transmit_counter.attach_cgroup(cgroup_path)?;
    Ok((cgroup_transmit_counter, links))
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
    open_object: &mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<CgroupTransmitCounter<'_>, DynError> {
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

fn get_pids_of(process_name: &str) -> Result<Vec<(u32, String)>, DynError> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            r#"ps -eo pid,comm | awk '$2 ~ /{}/ {{print $1",,"$2}}'"#,
            process_name
        ))
        .output()?;
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split(",,").collect();
            if parts.len() == 2 {
                let pid = parts[0].parse::<u32>().ok()?;
                let name = parts[1].to_string();
                return Some((pid, name));
            }
            None
        })
        .collect::<Vec<_>>())
}

fn get_cgroups_of(process_name: &str) -> Result<Vec<String>, DynError> {
    let a: HashSet<_> = get_pids_of(process_name)?
        .iter()
        .filter_map(
            |(pid, process_name)| match get_pid_cgroup(&pid.to_string()) {
                Ok((cgroup_path, _)) => {
                    log::info!(
                        "process:{:^10}, pid:{:^10}, cgroup: {cgroup_path}",
                        process_name,
                        pid,
                    );
                    Some(cgroup_path)
                }
                Err(e) => {
                    log::error!("Failed to find cgroup path for pid: {}", e);
                    None
                }
            },
        )
        .collect();
    Ok(a.into_iter().collect())
}

/// Initialize the eBPF program for monitoring the cgroup traffic of processes with the process name.
/// It will attach to a group of cgroups that the processes belongs to.
/// process_name can be `grep -E` pattern(EREs), like "sshd|nginx|^rust-analyzer$".
pub fn init_cgroup_skb_for_process_name<'a>(
    open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    process_name: &str,
) -> Result<(CgroupTransmitCounter<'a>, Vec<Link>), Box<dyn std::error::Error>> {
    let cgroups = get_cgroups_of(process_name)?;
    if cgroups.is_empty() {
        return Err("No cgroup found".into());
    }
    let mut cgroup_transmit_counter = CgroupTransmitCounter::new(open_object)?;
    let mut links = vec![];
    for cgroup in cgroups.iter() {
        log::info!(
            "attach to cgroup: [ {} ], contains pid: {:?}",
            cgroup,
            list_pids_in_cgroup(cgroup)?
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(cgroup)?; // a standalone line, to make `file` leave longer.
        use std::os::fd::AsRawFd;
        let cgroup_fd = file.as_raw_fd();
        let progs = &mut cgroup_transmit_counter.skel.progs;
        let link_egress = progs.count_egress_packets.attach_cgroup(cgroup_fd)?;
        let link_ingress = progs.count_ingress_packets.attach_cgroup(cgroup_fd)?;
        links.push(link_egress);
        links.push(link_ingress);
    }
    Ok((cgroup_transmit_counter, links))
}
