use std::{mem::MaybeUninit, net::Ipv4Addr, process::Command};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // find / -name libc.so.6
    // let glibc = "/usr/lib64/libc.so.6";
    // let glibc = "/lib64/libc.so.6";
    let cmd = Command::new("bash")
        .arg("-c")
        .arg("find / -name libc.so.6|grep 64|grep -v containers|grep -v overlay|head -n 1")
        .output();
    let glibc = match cmd {
        Ok(output) => String::from_utf8(output.stdout)
            .unwrap_or("unknown".to_string())
            .trim()
            .to_owned(),
        Err(e) => return Err(e.into()),
    };
    println!("glibc: {glibc}");

    println!("start trace connection");
    let mut open_object = MaybeUninit::uninit();
    trace_conn::start(glibc.as_str(), handle_event, &mut open_object)
}
