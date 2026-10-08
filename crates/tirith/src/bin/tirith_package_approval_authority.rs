//! Fixed-path package-approval helper kept in the release packages.
//!
//! `tirith pkg approve` refuses with `private_input_execution_unqualified`
//! because contained package execution, the only consumer of an approval, is
//! disabled. The helper therefore refuses every operation on every platform: it
//! reads no request, creates no authority key or directory, and signs nothing.
//! It stays installed at its fixed path so installers, packages, and
//! `tirith update` keep one stable file set.

fn main() {
    eprintln!(
        "tirith-package-approval-authority: blocked_native: package approval is disabled in this release (private_input_execution_unqualified); this helper issues no approvals and creates no authority state"
    );
    std::process::exit(1);
}
