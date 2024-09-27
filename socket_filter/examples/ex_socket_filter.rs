pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_filter = socket_filter::TransmitCounter::new(socket_filter::IGNORED_IFACE)?;
    loop {
        println!(
            "current bytes: {} {}",
            socket_filter.get_egress(),
            socket_filter.get_ingress()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
