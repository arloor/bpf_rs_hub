use std::mem::MaybeUninit;

use socket_filter::TransmitCounter;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut open_object = MaybeUninit::uninit(); // make the ebpf prog lives as long as the process.
    let skel =
        socket_filter::TransmitCounter::init(&mut open_object, socket_filter::IGNORED_IFACE)?;
    let socket_filter = TransmitCounter(skel);
    loop {
        println!(
            "current bytes: {} {}",
            socket_filter.get_egress(),
            socket_filter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
