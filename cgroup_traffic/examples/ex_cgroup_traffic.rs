#![deny(warnings)]
use std::mem::MaybeUninit;

use log::info;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    use chrono::Local;
    use std::io::Write;
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.module_path().unwrap_or("<unnamed>"),
                &record.args()
            )
        })
        .try_init();

    let mut open_object = MaybeUninit::uninit(); // make the ebpf prog lives as long as the process.
    let (cgroup_transmit_counter, _links) = cgroup_traffic::init_cgroup_skb_for_process_name(
        &mut open_object,
        "^rust-analyzer$|ssh|rust_http_proxy",
    )?; // _links cannot be replaced by _， because it holds the life of bpf prog.
    loop {
        info!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
