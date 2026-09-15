//! Silent, child-free receipt operations for the exact automatic Zsh ABI.
//! The main-thread self deadline and bounded runtime policy scope already hold.
//! These routes retain ordinary receipt authority; fixed syntax grants none.

use tirith_core::execution_state::{self, ShellReceiptChannel};
use tirith_core::threatdb_api::RuntimeThreatNetwork;

use crate::cli::automatic_deadline::{parse_zsh_automatic_probe_command, ReceiptAction};

const FRAME_CAP: u64 = 160;

#[derive(Debug, PartialEq, Eq)]
enum Frame<'a> {
    Consume { token: &'a str, command: &'a str },
    Reconcile { token: &'a str },
    Discard { token: &'a str },
}

fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse(action: ReceiptAction, bytes: &[u8]) -> Option<Frame<'_>> {
    if bytes.len() as u64 > FRAME_CAP || bytes.contains(&b'\r') {
        return None;
    }
    // Zsh here-strings add one LF. Remove exactly that transport terminator;
    // the command passed to the receipt's exact binding never contains it.
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    match action {
        ReceiptAction::Consume => {
            let (token, command) = text.split_once('\n')?;
            if !valid_token(token) {
                return None;
            }
            parse_zsh_automatic_probe_command(command)?;
            Some(Frame::Consume { token, command })
        }
        ReceiptAction::Reconcile | ReceiptAction::Discard => {
            if !valid_token(text) {
                return None;
            }
            Some(match action {
                ReceiptAction::Reconcile => Frame::Reconcile { token: text },
                ReceiptAction::Discard => Frame::Discard { token: text },
                ReceiptAction::Consume => unreachable!(),
            })
        }
    }
}

pub(super) fn run(action: ReceiptAction) -> i32 {
    execute(action).map_or(1, |()| 0)
}

fn execute(action: ReceiptAction) -> Result<(), String> {
    let bytes = crate::cli::read_stdin_capped(FRAME_CAP)
        .map_err(|_| "automatic receipt input unavailable")?;
    let frame = parse(action, &bytes).ok_or("automatic receipt input is malformed")?;
    // Actual initialized hooks already have a valid session. Never synthesize
    // a fallback session for an internal receipt invocation lacking one.
    tirith_core::session::env_session_id().ok_or("automatic receipt session is unavailable")?;
    let channel = ShellReceiptChannel::Zsh;
    match frame {
        Frame::Consume { token, command } => {
            let context = execution_state::shell_execution_receipt_context(token, channel)?;
            let prepared = crate::cli::check::prepare_receipt_consumption_with_network(
                command,
                &context,
                RuntimeThreatNetwork::CacheOnly,
            )?;
            execution_state::consume_shell_execution_receipt(
                token,
                channel,
                command,
                prepared,
                execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
            )?;
        }
        Frame::Reconcile { token } => {
            if !execution_state::reconcile_shell_execution_receipt(
                token,
                channel,
                execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
            )? {
                // Exact absence is not authorization. The hook can follow with
                // discard to recognize an explicitly abandoned receipt.
                return Err("automatic receipt has no committed transition".into());
            }
        }
        Frame::Discard { token } => {
            execution_state::discard_shell_execution_receipt(token, channel)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ID: &str = "12345678-9abc-4def-8123-456789abcdef";

    #[test]
    fn consume_accepts_only_canonical_inert_commands_with_one_optional_wire_lf() {
        for action in ["allowed", "blocked", "status"] {
            let command = format!("_tirith_verification_probe {ID} {action}");
            for terminator in ["", "\n"] {
                let bytes = format!("{TOKEN}\n{command}{terminator}");
                assert_eq!(
                    parse(ReceiptAction::Consume, bytes.as_bytes()),
                    Some(Frame::Consume {
                        token: TOKEN,
                        command: &command,
                    })
                );
            }
        }
    }

    #[test]
    fn cleanup_frames_accept_no_command_or_extra_terminator() {
        for action in [ReceiptAction::Reconcile, ReceiptAction::Discard] {
            for terminator in ["", "\n"] {
                let bytes = format!("{TOKEN}{terminator}");
                assert_eq!(
                    parse(action, bytes.as_bytes()),
                    Some(match action {
                        ReceiptAction::Reconcile => Frame::Reconcile { token: TOKEN },
                        ReceiptAction::Discard => Frame::Discard { token: TOKEN },
                        ReceiptAction::Consume => unreachable!(),
                    })
                );
            }
            for tail in ["\n\n", "\r", "\r\n", " ", "\ncommand", "\0"] {
                assert_eq!(parse(action, format!("{TOKEN}{tail}").as_bytes()), None);
            }
        }
    }

    #[test]
    fn consume_rejects_shell_syntax_extra_bytes_and_noncanonical_identity() {
        for command in [
            format!("_tirith_verification_probe {ID} allowed\n\n"),
            format!("_tirith_verification_probe {ID} allowed\r"),
            format!("_tirith_verification_probe {ID} allowed "),
            format!("_tirith_verification_probe {ID} allowed; true"),
            format!("_tirith_verification_probe {ID} allowed\ntrue"),
            format!("_tirith_verification_probe {ID} allowed\0"),
            format!("_tirith_verification_probe {ID} unknown"),
            format!("_tirith_verification_probe  {ID} allowed"),
            format!("_tirith_verification_probe\t{ID} allowed"),
            format!("_tirith_verification_probe '{ID}' allowed"),
            format!("_tirith_verification_probe {} allowed", ID.to_uppercase()),
            "_tirith_verification_probe 00000000-0000-0000-0000-000000000000 allowed".into(),
            "echo allowed".into(),
            String::new(),
        ] {
            let bytes = format!("{TOKEN}\n{command}");
            assert_eq!(parse(ReceiptAction::Consume, bytes.as_bytes()), None);
        }
        assert_eq!(parse(ReceiptAction::Consume, TOKEN.as_bytes()), None);
    }

    #[test]
    fn all_actions_refuse_invalid_tokens_encoding_and_overlong_frames() {
        for action in [
            ReceiptAction::Consume,
            ReceiptAction::Reconcile,
            ReceiptAction::Discard,
        ] {
            for token in [
                String::new(),
                "a".repeat(63),
                "a".repeat(65),
                TOKEN.to_uppercase(),
                "g".repeat(64),
                format!(" {TOKEN}"),
                format!("{TOKEN}\r"),
            ] {
                let frame = if action == ReceiptAction::Consume {
                    format!("{token}\n_tirith_verification_probe {ID} allowed")
                } else {
                    token
                };
                assert_eq!(parse(action, frame.as_bytes()), None);
            }
            assert_eq!(parse(action, &[0xff; 64]), None);
            assert_eq!(parse(action, &[b'a'; FRAME_CAP as usize + 1]), None);
        }
    }
}
