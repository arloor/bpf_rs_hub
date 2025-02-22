#![deny(warnings)]
//! # socket_filter
//!
//! `socket_filter` is a library to monitor the network traffic of a network interface. By passing a list of interface names to this library, it will attach to the interfaces and monitor the network traffic of the interfaces.
//!
use libc::{
    bind, close, if_nametoindex, sockaddr_ll, socket, AF_PACKET, PF_PACKET, SOCK_CLOEXEC,
    SOCK_NONBLOCK, SOCK_RAW,
};
use log::info;
use prog::*;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::{ffi::CString, os::fd::AsFd};
mod prog {
    include!(concat!(env!("OUT_DIR"), "/program.skel.rs"));
}
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};
use pnet::datalink;
use std::mem::{size_of_val, MaybeUninit};

pub const IGNORED_IFACE: &[&str; 7] =
    &["lo", "podman", "veth", "flannel", "cni0", "utun", "docker"];

pub struct TransmitCounter<'a>(pub ProgramSkel<'a>);

impl TransmitCounter<'_> {
    /// Get the number of bytes transmitted.
    pub fn get_egress(&self) -> u64 {
        get(&self.0, EGRESS)
    }

    /// Get the number of bytes received.
    pub fn get_ingress(&self) -> u64 {
        get(&self.0, INGRESS)
    }

    /// Create a new `TransmitCounter` instance.
    /// `ignored_interfaces` is a list of interface names to ignore.
    pub fn new<'a>(
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        ignored_interfaces: &[&'a str],
    ) -> Result<TransmitCounter<'a>, DynError> {
        bump_memlock_rlimit()?;

        let skel = open_and_load_socket_filter_prog(open_object)?;
        let all_interfaces = datalink::interfaces();

        // 遍历接口列表
        for iface in all_interfaces {
            if ignored_interfaces
                .iter()
                .any(|&ignored| iface.name.starts_with(ignored))
            {
                continue;
            }
            info!("load bpf socket filter for Interface: {}", iface.name);
            set_socket_opt_bpf(&skel, iface.name.as_str())?;
        }
        Ok(TransmitCounter(skel))
    }
}

fn open_and_load_socket_filter_prog(
    open_object: &'_ mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<ProgramSkel<'_>, DynError> {
    let builder = ProgramSkelBuilder::default();
    let open_skel = builder.open(open_object)?;
    Ok(open_skel.load()?)
}
type DynError = Box<dyn std::error::Error>;
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

fn set_socket_opt_bpf(skel: &ProgramSkel<'_>, name: &str) -> Result<(), DynError> {
    unsafe {
        let sock = open_raw_sock(name)?;

        let prog_fd = skel.progs.bpf_program.as_fd().as_raw_fd();
        let value = &prog_fd as *const i32;
        let option_len = size_of_val(&prog_fd) as libc::socklen_t;

        let sockopt = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            value as *const libc::c_void,
            option_len,
        );
        if sockopt != 0 {
            return Err("Failed to set socket option".into());
        }
    };
    Ok(())
}

struct Direction(u32);
const EGRESS: Direction = Direction(0);
const INGRESS: Direction = Direction(1);
fn get(skel: &ProgramSkel<'_>, direction: Direction) -> u64 {
    let maps = &skel.maps;
    let map = &maps.traffic;
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

fn open_raw_sock(name: &str) -> Result<RawFd, String> {
    unsafe {
        let protocol = (libc::ETH_P_ALL as libc::c_short).to_be() as libc::c_int;
        let sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if sock < 0 {
            return Err("Failed to create raw socket".to_string());
        }

        let name_cstring = CString::new(name).unwrap();
        let sll = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: protocol as u16,
            sll_ifindex: if_nametoindex(name_cstring.as_ptr()) as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        if bind(
            sock,
            &sll as *const _ as *const _,
            std::mem::size_of::<sockaddr_ll>() as u32,
        ) < 0
        {
            let err = CString::new("Failed to bind to interface: ".to_string() + name).unwrap();
            close(sock);
            return Err(err.to_str().unwrap().to_string()
                + ": "
                + &std::io::Error::last_os_error().to_string());
        }

        Ok(sock)
    }
}
