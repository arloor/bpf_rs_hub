#![deny(warnings)]
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use object::{Object, ObjectSymbol};

mod prog {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tracecon.skel.rs"
    ));
}
use prog::*;

type DynError=Box<dyn std::error::Error>;

type Event = tracecon_types::event;
unsafe impl Plain for Event {}

fn bump_memlock_rlimit() -> Result<(),DynError> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        println!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize,DynError> {
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

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

    match event.tag {
        0 => println!("ip event: {}", Ipv4Addr::from(event.ip)),
        1 => println!("host event: {}", String::from_utf8_lossy(&event.hostname)),
        _ => {}
    }
}

pub fn start(glibc:&str) -> Result<(),DynError> {
    let mut skel_builder = TraceconSkelBuilder::default();

    skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;
    // if let Some(pid) = opts.pid {
    //     open_skel.rodata().target_pid = pid;
    // }
    let mut skel = open_skel.load()?;
    let address = get_symbol_address(glibc, "getaddrinfo")?;

    let _uprobe =
        skel.progs_mut()
            .getaddrinfo_enter()
            .attach_uprobe(false, -1, glibc, address)?;

    let _uretprobe =
        skel.progs_mut()
            .getaddrinfo_exit()
            .attach_uprobe(true, -1, glibc, address)?;

    let _kprobe = skel
        .progs_mut()
        .tcp_v4_connect_enter()
        .attach_kprobe(false, "tcp_v4_connect")?;

    let _kretprobe = skel
        .progs_mut()
        .tcp_v4_connect_exit()
        .attach_kprobe(true, "tcp_v4_connect")?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}