use std::{thread::sleep, time::Duration};

fn main() {
    let socket_filter = socket_filter::TransmitCounter::default();
    loop {
        println!(
            "current bytes: {} {}",
            socket_filter.get_egress(),
            socket_filter.get_ingress()
        );
        sleep(Duration::from_secs(1));
    }
}
