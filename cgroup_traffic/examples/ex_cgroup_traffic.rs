#![deny(warnings)]
use log::info;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();
    let cgroup_transmit_counter =
        cgroup_traffic::init_cgroup_skb_for_process_name("sshd|nginx|rust-analyzer")?;
    // let cgroup_transmit_counter = cgroup_traffic::init_cgroup_skb_monitor(cgroup_traffic::SELF)?;
    loop {
        info!(
            "current bytes: {} {}",
            cgroup_transmit_counter.get_egress(),
            cgroup_transmit_counter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
