#![no_main]
//! Fuzz target for the npm-family command grammar (`tirith_core::npm_command`).
//!
//! The complete invocation is security state: launcher, operation, normalized
//! subcommand, package identities and version intents, child boundary, child
//! arguments, and truncation all feed downstream decisions. Comparing selected
//! counts or enum fields can therefore miss nondeterminism in the rest of the
//! object.

use std::cmp::Ordering;

use libfuzzer_sys::fuzz_target;

use tirith_core::npm_command::{self, MAX_PACKAGES_PER_INVOCATION};
use tirith_core::tokenize::ShellType;

fuzz_target!(|data: &str| {
    for shell in [
        ShellType::Posix,
        ShellType::Fish,
        ShellType::PowerShell,
        ShellType::Cmd,
    ] {
        let first = npm_command::parse_input(data, shell);
        let second = npm_command::parse_input(data, shell);

        // Compare the complete object graph, not only invocation/package counts
        // and operations. `NpmInvocation: Eq` includes launcher, subcommand,
        // every full PackageRef, the complete child command/argv, and the
        // truncation bit.
        assert_eq!(
            first, second,
            "npm grammar produced different complete invocations for identical input"
        );

        for invocation in &first {
            let package_count = invocation.explicit_packages.len();

            // These are the exact legal cap states. Exactly-at-cap may be
            // complete (256 unique packages) or truncated (a later unique
            // package was refused). Below-cap can never be truncated, and
            // above-cap is impossible.
            match (
                package_count.cmp(&MAX_PACKAGES_PER_INVOCATION),
                invocation.truncated,
            ) {
                (Ordering::Less, false) | (Ordering::Equal, _) => {}
                (Ordering::Less, true) => {
                    panic!("npm invocation reported truncation before reaching its package cap")
                }
                (Ordering::Greater, _) => {
                    panic!("npm package list exceeded MAX_PACKAGES_PER_INVOCATION")
                }
            }

            // The cap is over distinct PackageRef objects. A duplicate inside
            // the retained prefix would waste capacity and could push a later
            // security-relevant package past the bound.
            for (index, package) in invocation.explicit_packages.iter().enumerate() {
                assert!(
                    !invocation.explicit_packages[..index].contains(package),
                    "npm invocation retained a duplicate complete PackageRef"
                );
            }
        }
    }

    // The standalone lexical helpers consume the same attacker-controlled
    // string. Their complete return values must be deterministic as well.
    let first_spec = npm_command::parse_npm_package_spec(data);
    let second_spec = npm_command::parse_npm_package_spec(data);
    assert_eq!(
        first_spec, second_spec,
        "npm package-spec parsing is not deterministic"
    );
    let first_launcher = npm_command::is_package_runner_name(data);
    let second_launcher = npm_command::is_package_runner_name(data);
    assert_eq!(
        first_launcher, second_launcher,
        "npm launcher recognition is not deterministic"
    );
});
