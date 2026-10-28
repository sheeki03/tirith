//! Optional team policy service. Personal clients do not start or depend on it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod http;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod private_fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod store;
