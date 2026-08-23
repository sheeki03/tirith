#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../cli/package_approval_authority_helper.rs"]
mod package_approval_authority_helper;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../cli/package_approval_authority_native.rs"]
mod package_approval_authority_native;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    std::process::exit(package_approval_authority_helper::helper_main());
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!(
        "tirith-package-approval-authority: blocked_native: package approval issuance is supported only for redeemable x86_64 Linux installs"
    );
    std::process::exit(1);
}
