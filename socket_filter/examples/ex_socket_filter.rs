use std::mem::MaybeUninit;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut open_object = MaybeUninit::uninit(); // make the ebpf prog lives as long as the process.
    let socket_filter =
        socket_filter::TransmitCounter::new(&mut open_object, socket_filter::IGNORED_IFACE)?;
    loop {
        println!(
            "current bytes: {} {}",
            socket_filter.get_egress(),
            socket_filter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
