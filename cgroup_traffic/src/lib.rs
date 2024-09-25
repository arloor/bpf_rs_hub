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
    skel: Option<ProgramSkel<'static>>,
    #[allow(dead_code)]
    egress_link: Option<Link>,
    #[allow(dead_code)]
    ingress_link: Option<Link>,
}

struct Direction(u32);
const EGRESS: Direction = Direction(0);
const INGRESS: Direction = Direction(1);
fn get(skel: &Option<ProgramSkel<'static>>, direction: Direction) -> u64 {
    if let Some(skel) = skel {
        let maps = skel.maps();
        let map = maps.process_traffic();
        let key = unsafe { plain::as_bytes(&direction.0) };
        let mut value: u64 = 0;
        if let Ok(Some(buf)) = map.lookup(key, MapFlags::ANY) {
            plain::copy_from_bytes(&mut value, &buf).expect("Invalid buffer");
        }
        value
    } else {
        0
    }
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

fn list_pids_in_cgroup(cgroup_path: &str) -> io::Result<Vec<i32>> {
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

fn get_self_cgroup() -> io::Result<(String, Vec<i32>)> {
    let cgroup_dir = Path::new("/sys/fs/cgroup");
    if !cgroup_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "/sys/fs/cgroup directory does not exist",
        ));
    }

    let path = Path::new("/proc/self/cgroup");
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

pub fn attach_self_cgroup() -> CgroupTransmitCounter {
    match attach_self_cgroup_internal() {
        Ok(counter) => counter,
        Err(err) => {
            log::error!("Failed to attach to self's cgroup: {}", err);
            CgroupTransmitCounter {
                skel: None,
                egress_link: None,
                ingress_link: None,
            }
        }
    }
}

fn attach_self_cgroup_internal() -> Result<CgroupTransmitCounter, DynError> {
    let cgroup = get_self_cgroup()?;
    log::info!("attach to self's cgroup: {}", cgroup.0);
    log::info!("self's cgroup contains: {:?}", cgroup.1);
    attach_cgroup(&cgroup.0)
}

pub fn attach_cgroup(path: &str) -> Result<CgroupTransmitCounter, DynError> {
    let mut skel_builder = ProgramSkelBuilder::default();

    skel_builder.obj_builder.debug(false);

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
        skel: Some(skel),
        egress_link: Some(link_egress),
        ingress_link: Some(link_ingress),
    })
}
