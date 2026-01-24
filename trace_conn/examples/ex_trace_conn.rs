use std::{mem::MaybeUninit, net::Ipv4Addr};
use trace_conn::Event;
fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

    match event.tag {
        0 => log::info!("ip event: {}", Ipv4Addr::from(event.ip)),
        1 => log::info!("host event: {}", String::from_utf8_lossy(&event.hostname)),
        _ => {}
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use chrono::Local;
    use std::io::Write;
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
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
    // find /usr -name libc.so.6
    // /usr/lib32/libc.so.6
    // /usr/lib/x86_64-linux-gnu/libc.so.6
    let glibc = "/lib/x86_64-linux-gnu/libc.so.6".to_string();
    log::info!("glibc: {glibc}");

    log::info!("start trace connection");
    let mut open_object = MaybeUninit::uninit();
    trace_conn::start(glibc.as_str(), handle_event, &mut open_object)
}
