//! Authenticated caller-shell diagnostic adapter. Raw loaded definitions travel
//! over bounded stdin, are hashed in memory, and are never persisted or printed.
use sha2::{Digest as _, Sha256};
use tirith_core::execution_state::{
    self, ShellReceiptChannel, ShellVerificationHookDecision, ShellVerificationProbe,
    ShellVerificationStatus,
};

const MAX_LOADED_STATE: usize = 256 * 1024;

pub(crate) fn exact_probe(command: &str) -> bool {
    let Some(rest) = command.strip_prefix("_tirith_verification_probe ") else {
        return false;
    };
    let Some((id, kind)) = rest.split_once(' ') else {
        return false;
    };
    matches!(kind, "allowed" | "blocked" | "status")
        && uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id)
}

fn fingerprint(bytes: &[u8]) -> Result<String, String> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > MAX_LOADED_STATE || bytes.contains(&0) {
        return Err("missing, invalid or over-limit loaded shell state".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "loaded shell state is not UTF-8")?;
    if !text.starts_with("tirith-loaded-shell-v1\n") {
        return Err("loaded shell state lacks its versioned frame".into());
    }
    let facts: Vec<_> = text
        .lines()
        .last()
        .unwrap_or("")
        .split_ascii_whitespace()
        .collect();
    if !facts.contains(&"protection=blocks")
        || !facts.contains(&"protocol=3")
        || facts.contains(&"bypass=0")
    {
        return Err(
            "caller shell is off, warn-only, degraded or lacks strict blocking state".into(),
        );
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn read_fingerprint() -> Result<String, String> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return Err("loaded shell state must arrive through the authenticated helper input".into());
    }
    fingerprint(
        &super::read_stdin_capped((MAX_LOADED_STATE + 1) as u64)
            .map_err(|error| format!("cannot read loaded shell state: {error}"))?,
    )
}

/// Ordinary checks neither consume stdin nor authenticate a diagnostic record.
/// Exact probes must carry a freshly sampled fingerprint from the live hook.
pub(crate) fn observe_check(
    command: &str,
    channel: ShellReceiptChannel,
) -> Result<ShellVerificationHookDecision, String> {
    if !exact_probe(command) {
        return Ok(ShellVerificationHookDecision::NotProbe);
    }
    if std::env::var("TIRITH").as_deref() == Ok("0") {
        return Err("caller-shell verification is unavailable while TIRITH=0".into());
    }
    let capture = if std::env::var("_TIRITH_VERIFICATION_CAPTURE").as_deref() == Ok("1") {
        Some(read_fingerprint()?)
    } else {
        None
    };
    execution_state::observe_shell_verification_hook(command, channel, capture.as_deref())
}

fn configuration_paths(channel: ShellReceiptChannel) -> Result<Vec<std::path::PathBuf>, String> {
    let family = match channel {
        ShellReceiptChannel::BashEnter | ShellReceiptChannel::BashPreexec => "bash",
        ShellReceiptChannel::Zsh => "zsh",
        ShellReceiptChannel::Fish => "fish",
        _ => return Err("caller-shell verification is unavailable for this shell channel".into()),
    };
    let target = super::shell_target::resolve_current()?;
    if target.shell != family || target.identity_source != "observed-ancestor-process" {
        return Err("cannot resolve the authenticated caller's actual shell configuration".into());
    }
    if let Some(reason) = target.unsupported_reason {
        // An explicitly sourced hook in a no-profile shell can prove current
        // interception. This never certifies automatic activation on restart.
        if target.startup_mode != "no-profile" {
            return Err(format!(
                "caller startup mode requires manual verification: {reason}"
            ));
        }
    }
    let mut paths: Vec<_> = target
        .profiles
        .into_iter()
        .map(|profile| profile.path)
        .collect();
    // Include the actual integration source when an external bundle is selected.
    // Embedded integration bytes are already bound by the authenticated binary.
    if let Some(dir) = super::init::find_hook_dir_readonly() {
        let name = match family {
            "bash" => "bash-hook.bash",
            "zsh" => "zsh-hook.zsh",
            _ => "fish-hook.fish",
        };
        let path = dir.join("lib").join(name);
        if !path.is_absolute() {
            return Err("shell integration directory must be absolute for verification".into());
        }
        // Reject traversal instead of normalizing through a linked ancestor.
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn run(action: &str, id: Option<&str>, channel: ShellReceiptChannel) -> i32 {
    let result = (|| -> Result<i32, String> {
        let loaded = read_fingerprint()?;
        if action == "start" && id.is_none() {
            let paths = configuration_paths(channel)?;
            let challenge = execution_state::start_shell_verification(channel, &paths, &loaded)?;
            println!("Run these three commands separately in this same shell, in order:");
            println!(
                "{}\n{}\n{}",
                challenge.allowed_command, challenge.blocked_command, challenge.status_command
            );
            println!("The blocked command is inert. Its body must not execute. Evidence expires after five minutes.");
            return Ok(0);
        }
        let id = id.ok_or("a challenge ID is required")?;
        if action == "status" {
            let proof =
                execution_state::finish_shell_verification_authenticated(id, channel, &loaded)?;
            return Ok(super::status::run_authenticated(proof));
        }
        let observation = match action {
            "allowed" => execution_state::execute_shell_verification_probe(
                id,
                ShellVerificationProbe::Allowed,
                channel,
                &loaded,
            )?,
            "blocked" => execution_state::execute_shell_verification_probe(
                id,
                ShellVerificationProbe::Blocked,
                channel,
                &loaded,
            )?,
            _ => return Err("unsupported shell verification action".into()),
        };
        let evidence = super::protection_evidence::ProtectionEvidence::from_report(&observation);
        if !super::write_json_stdout(
            &serde_json::json!({"observation": observation, "protection": evidence}),
            "tirith: cannot write shell verification result",
        ) {
            return Ok(1);
        }
        // Allowed-body success means the inert body was observed, not that the
        // challenge is already verified. Status is the strict machine route.
        Ok(
            if action == "allowed" && observation.status == ShellVerificationStatus::Pending {
                0
            } else {
                1
            },
        )
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tirith: shell verification unavailable: {error}");
            1
        }
    }
}

pub fn instructions(json: bool) -> i32 {
    let value = serde_json::json!({
        "schema_version": 1,
        "state": "activation-required",
        "verified_blocking": false,
        "scope": "current_shell_only",
        "start_command": "_tirith_verification_probe start",
        "supported_channels": ["bash-enter", "bash-preexec", "zsh", "fish"],
        "message": "Run the start command in the shell to verify, then enter its three exact challenge commands separately. An external process cannot authenticate its parent by itself."
    });
    if json {
        return if super::write_json_stdout(&value, "tirith: cannot write verification instructions")
        {
            0
        } else {
            1
        };
    }
    println!("In the shell you want to verify, run:\n  _tirith_verification_probe start\nThen enter its three exact challenge commands separately, in order.\nThe final helper returns canonical status and succeeds only for fresh observed blocking.\nIf the helper is unavailable, activate the current integration in a fresh shell.\nPowerShell and Nushell do not yet have an authenticated verification adapter.");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_parser_accepts_only_the_exact_inert_command() {
        let id = "85d25009-90d2-4f47-8258-df5976567a7b";
        for kind in ["allowed", "blocked", "status"] {
            assert!(exact_probe(&format!(
                "_tirith_verification_probe {id} {kind}"
            )));
        }
        for text in [
            format!(" _tirith_verification_probe {id} blocked"),
            format!("_tirith_verification_probe {id} blocked; true"),
            format!("_tirith_verification_probe {id}  blocked"),
            format!("_tirith_verification_probe {} blocked", id.to_uppercase()),
            "_tirith_verification_probe start".into(),
        ] {
            assert!(!exact_probe(&text));
        }
    }
    #[test]
    fn loaded_state_is_bounded_and_binds_the_actual_helper_definition() {
        let a = b"tirith-loaded-shell-v1\n_tirith_verification_probe () { native_call; }\nprotocol=3 protection=blocks bypass=1\n";
        let b = b"tirith-loaded-shell-v1\n_tirith_verification_probe () { :; }\nprotocol=3 protection=blocks bypass=1\n";
        assert_ne!(fingerprint(a).unwrap(), fingerprint(b).unwrap());
        assert!(fingerprint(b"").is_err());
        assert!(fingerprint(b"unframed").is_err());
        for mode in ["off", "warn-only", "degraded", "unknown"] {
            assert!(fingerprint(
                format!("tirith-loaded-shell-v1\nprotocol=3 protection={mode} bypass=1\n")
                    .as_bytes()
            )
            .is_err());
        }
        assert!(
            fingerprint(b"tirith-loaded-shell-v1\nprotocol=3 protection=blocks bypass=0\n")
                .is_err()
        );
        assert!(fingerprint(&vec![b'x'; MAX_LOADED_STATE + 1]).is_err());
    }
}
