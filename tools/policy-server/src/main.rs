#[cfg(any(target_os = "linux", target_os = "macos"))]
mod admin;
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    if let Err(code) = admin::run() {
        eprintln!("tirith-policy-server: {code}");
        std::process::exit(1);
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    eprintln!("tirith-policy-server: native private storage is unavailable on this platform");
    std::process::exit(1);
}
