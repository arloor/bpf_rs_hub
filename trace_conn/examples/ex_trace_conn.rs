use std::net::Ipv4Addr;
use trace_conn::Event;
fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

    match event.tag {
        0 => println!("ip event: {}", Ipv4Addr::from(event.ip)),
        1 => println!("host event: {}", String::from_utf8_lossy(&event.hostname)),
        _ => {}
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    // find / -name libc.so.6 
    let glibc = "/usr/lib64/libc.so.6";
    // let glibc = "/lib64/libc.so.6";
    println!("start trace connection");
    trace_conn::start(glibc,handle_event)
}