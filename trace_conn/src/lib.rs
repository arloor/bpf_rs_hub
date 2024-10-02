#![deny(warnings)]
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::PerfBufferBuilder;
use object::{Object, ObjectSymbol};
use plain::Plain;
use std::fs;
use std::mem::MaybeUninit;
use std::path::Path;
use std::time::Duration;

mod prog {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tracecon.skel.rs"
    ));
}
use prog::*;

type DynError = Box<dyn std::error::Error>;
// export Event
pub type Event = crate::types::event;
unsafe impl Plain for Event {}

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

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize, DynError> {
    let path = Path::new(so_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or("symbol not found")?;

    Ok(symbol.address() as usize)
}

pub fn start<F>(
    glibc: &str,
    handler: F,
    open_object: &'static mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<(), DynError>
where
    F: FnMut(i32, &[u8]),
{
    let mut skel_builder = TraceconSkelBuilder::default();

    skel_builder.obj_builder.debug(false);

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open(open_object)?;
    // if let Some(pid) = opts.pid {
    //     open_skel.rodata().target_pid = pid;
    // }
    let skel = open_skel.load()?;
    let address = get_symbol_address(glibc, "getaddrinfo")?;

    let _uprobe = skel
        .progs
        .getaddrinfo_enter
        .attach_uprobe(false, -1, glibc, address)?;

    let _uretprobe = skel
        .progs
        .getaddrinfo_exit
        .attach_uprobe(true, -1, glibc, address)?;

    let _kprobe = skel
        .progs
        .tcp_v4_connect_enter
        .attach_kprobe(false, "tcp_v4_connect")?;

    let _kretprobe = skel
        .progs
        .tcp_v4_connect_exit
        .attach_kprobe(true, "tcp_v4_connect")?;

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handler)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
