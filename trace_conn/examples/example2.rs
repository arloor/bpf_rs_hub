fn main() -> Result<(), Box<dyn std::error::Error>>{
    // find / -name libc.so.6 
    let glibc = "/usr/lib64/libc.so.6";
    // let glibc = "/lib64/libc.so.6";
    trace_conn::start(glibc)
}