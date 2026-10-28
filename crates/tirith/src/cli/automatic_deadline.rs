//! A self-only time limit for audited, child-free automatic activation routes.
//! Matching argv is an admission hint for a time limit, never authentication.
//! The automatic probe route must independently reject missing/manual records.
//! Keep manual verification/status and capsule-child execution outside this API.
//!
//! Before enabling, arm before stdin/config/capability work and retain the guard
//! through the whole admitted route. No admitted path may fork, exec, or spawn a
//! child: `_exit` terminates only this process, not its descendants. The broker
//! and relay must receive their own guards, in their own processes.
//!
//! The budget starts at the continuous-clock sample inside `arm`, after Rust
//! startup and exact argv matching. It does not bound process creation, loader
//! work, or time before that sample. Enforcement also needs the watchdog thread
//! to run; thread creation and OS scheduling have no hard latency guarantee.
//! An externally observed spawn-to-exit duration is a separate measurement.

// Unsupported targets retain the exact parser and refusal route; the native
// deadline implementation is deliberately unreachable there.
#![cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]

use std::ffi::OsString;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const EXIT_DEADLINE: i32 = 124;
const EXIT_CLOCK_FAILURE: i32 = 125;
const ACTIVE: u8 = 0;
const CANCELLED: u8 = 1;
const FIRED: u8 = 2;
const INERT_PREFIX: &str = "_tirith_verification_probe ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeAction {
    Allowed,
    Blocked,
    Status,
}

impl ProbeAction {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "allowed" => Some(Self::Allowed),
            "blocked" => Some(Self::Blocked),
            "status" => Some(Self::Status),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptAction {
    Consume,
    Reconcile,
    Discard,
    Acknowledge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiagnosticInvocation {
    Probe(ProbeAction),
    ReceiptCheck(ProbeAction),
    Receipt(ReceiptAction),
}

/// The exact inert command shared by automatic receipt preparation/consumption.
/// Matching syntax never authenticates a receipt or an issued automatic stage.
pub(super) fn parse_zsh_automatic_probe_command(input: &str) -> Option<ProbeAction> {
    if input.len() > INERT_PREFIX.len() + 36 + 1 + 7 {
        return None;
    }
    let input = input.strip_prefix(INERT_PREFIX)?;
    let (id, action) = input.split_once(' ')?;
    canonical_non_nil_uuid(id)?;
    ProbeAction::parse(action)
}

/// Exact raw argv, including argv[0]. No environment, stdin, filesystem,
/// capability, UUID generation, or shell parsing is consulted. This does not
/// authorize a probe, validate a receipt, or select the broker/relay budgets.
pub(crate) fn match_zsh_automatic_diagnostic(argv: &[OsString]) -> Option<DiagnosticInvocation> {
    match argv {
        [_, command, verb, channel_flag, channel]
            if command == "__setup-activation"
                && channel_flag == "--channel"
                && channel == "zsh" =>
        {
            if verb.len() > "receipt-acknowledge".len() {
                return None;
            }
            let action = match verb.to_str()? {
                "receipt-consume" => ReceiptAction::Consume,
                "receipt-reconcile" => ReceiptAction::Reconcile,
                "receipt-discard" => ReceiptAction::Discard,
                "receipt-acknowledge" => ReceiptAction::Acknowledge,
                _ => return None,
            };
            Some(DiagnosticInvocation::Receipt(action))
        }
        [_, command, verb, action, channel_flag, channel, id_flag, id]
            if command == "__setup-activation"
                && verb == "probe"
                && channel_flag == "--channel"
                && channel == "zsh"
                && id_flag == "--id" =>
        {
            if id.len() != 36 || action.len() > 7 {
                return None;
            }
            canonical_non_nil_uuid(id.to_str()?)?;
            Some(DiagnosticInvocation::Probe(ProbeAction::parse(
                action.to_str()?,
            )?))
        }
        [_, command, approval, non_interactive, interactive, shell_flag, shell, receipt_flag, channel, offline, separator, input]
            if command == "check"
                && approval == "--approval-check"
                && non_interactive == "--non-interactive"
                && interactive == "--interactive"
                && shell_flag == "--shell"
                && shell == "posix"
                && receipt_flag == "--execution-receipt"
                && channel == "zsh"
                && offline == "--offline"
                && separator == "--" =>
        {
            if input.len() > INERT_PREFIX.len() + 36 + 1 + 7 {
                return None;
            }
            Some(DiagnosticInvocation::ReceiptCheck(
                parse_zsh_automatic_probe_command(input.to_str()?)?,
            ))
        }
        _ => None,
    }
}

fn canonical_non_nil_uuid(value: &str) -> Option<()> {
    if value.len() != 36 {
        return None;
    }
    let mut nonzero = false;
    for (index, byte) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else if byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) {
            nonzero |= byte != b'0';
        } else {
            return None;
        }
    }
    nonzero.then_some(())
}

/// Exact coordinator shape selects only its fixed self deadline. Request
/// parsing and live native authentication still run inside that deadline.
pub(crate) fn match_zsh_automatic_coordinator(argv: &[OsString]) -> Option<DeadlineBudget> {
    match argv {
        [_, command, verb, channel_flag, channel]
            if command == "__setup-activation"
                && verb == "modules"
                && channel_flag == "--channel"
                && channel == "zsh" =>
        {
            Some(DeadlineBudget::Diagnostic)
        }
        [_, command, verb, channel_flag, channel, operation_flag, operation, attempt_flag, attempt]
            if command == "__setup-activation"
                && verb == "broker"
                && channel_flag == "--channel"
                && channel == "zsh"
                && operation_flag == "--operation-id"
                && attempt_flag == "--attempt-id" =>
        {
            canonical_non_nil_uuid(operation.to_str()?)?;
            canonical_non_nil_uuid(attempt.to_str()?)?;
            Some(DeadlineBudget::Broker)
        }
        [_, command, verb, channel_flag, channel, action_flag, action, operation, attempt, reason_flag, reason]
            if command == "__setup-activation"
                && verb == "relay"
                && channel_flag == "--channel"
                && channel == "zsh"
                && action_flag == "--action"
                && reason_flag == "--reason" =>
        {
            if action.len() > 8 || operation.len() > 51 || attempt.len() > 49 || reason.len() > 24 {
                return None;
            }
            let action = action.to_str()?;
            let operation = operation.to_str()?.strip_prefix("--operation-id=")?;
            let attempt = attempt.to_str()?.strip_prefix("--attempt-id=")?;
            crate::cli::setup::activation_protocol::Request::parse(
                action,
                operation,
                attempt,
                reason.to_str()?,
            )
            .ok()?;
            Some(DeadlineBudget::Relay)
        }
        _ => None,
    }
}

/// Closed durations. Neither argv nor the environment can extend them. Each
/// process arms once at entry; no progress message renews its original limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeadlineBudget {
    Diagnostic,
    #[cfg_attr(not(test), allow(dead_code))] // Reserved for the private coordinator.
    Broker,
    #[cfg_attr(not(test), allow(dead_code))] // Reserved for the private coordinator.
    Relay,
}

impl DeadlineBudget {
    const fn nanos(self) -> u64 {
        match self {
            Self::Diagnostic | Self::Relay => NANOS_PER_SECOND,
            Self::Broker => 10 * NANOS_PER_SECOND,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeadlineError {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    UnsupportedPlatform,
    ClockUnavailable,
    InvalidClock,
    ClockOverflow,
    ThreadUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BootNanos(u64);

/// Only the single native backend captured by arm supplies these values.
/// No wall clock, Instant, persistent stamp, or process-start clock is accepted.
struct Deadline {
    last: BootNanos,
    end: BootNanos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Poll {
    Wait(Duration),
    Exit(i32),
}

impl Deadline {
    fn new(start: BootNanos, budget: DeadlineBudget) -> Result<Self, DeadlineError> {
        let end = start
            .0
            .checked_add(budget.nanos())
            .ok_or(DeadlineError::ClockOverflow)?;
        Ok(Self {
            last: start,
            end: BootNanos(end),
        })
    }

    fn poll(&mut self, sample: Result<BootNanos, DeadlineError>) -> Poll {
        let now = match sample {
            Ok(now) if now >= self.last => now,
            _ => return Poll::Exit(EXIT_CLOCK_FAILURE),
        };
        self.last = now;
        if now >= self.end {
            Poll::Exit(EXIT_DEADLINE)
        } else {
            Poll::Wait(Duration::from_nanos(self.end.0 - now.0).min(POLL_INTERVAL))
        }
    }
}

/// The cancellation/fire race has one atomic winner. Drop never waits for a
/// thread or locks an output stream. If firing already won, dropping the guard
/// cannot revoke termination. Do not drop until the admitted operation is done.
#[must_use = "retain the guard through all admitted diagnostic work"]
pub(crate) struct SelfDeadline {
    state: Arc<AtomicU8>,
}

impl SelfDeadline {
    pub(crate) fn arm(budget: DeadlineBudget) -> Result<Self, DeadlineError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let clock = NativeClock::capture()?;
            let mut deadline = Deadline::new(clock.now()?, budget)?;
            let state = Arc::new(AtomicU8::new(ACTIVE));
            let thread_state = Arc::clone(&state);
            let _watchdog = std::thread::Builder::new()
                .name("tirith-auto-deadline".to_owned())
                .spawn(move || loop {
                    if thread_state.load(Ordering::Acquire) != ACTIVE {
                        return;
                    }
                    match deadline.poll(clock.now()) {
                        Poll::Wait(wait) => std::thread::sleep(wait),
                        Poll::Exit(code) => {
                            if transition(&thread_state, FIRED) {
                                // libc's process-wide _exit, not Linux SYS_exit
                                // (which would exit only the watchdog thread).
                                // No log/stdio lock, destructor, PID or signal.
                                unsafe { libc::_exit(code) }
                            }
                            return;
                        }
                    }
                })
                .map_err(|_| DeadlineError::ThreadUnavailable)?;
            Ok(Self { state })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = budget;
            Err(DeadlineError::UnsupportedPlatform)
        }
    }
}

impl Drop for SelfDeadline {
    fn drop(&mut self) {
        transition(&self.state, CANCELLED);
    }
}

fn transition(state: &AtomicU8, terminal: u8) -> bool {
    state
        .compare_exchange(ACTIVE, terminal, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

// CLOCK_BOOTTIME includes suspend; CLOCK_MONOTONIC/Instant cannot substitute.
#[cfg(target_os = "linux")]
struct NativeClock;

#[cfg(target_os = "linux")]
impl NativeClock {
    fn capture() -> Result<Self, DeadlineError> {
        Ok(Self)
    }

    fn now(&self) -> Result<BootNanos, DeadlineError> {
        let mut sample = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: sample is initialized, writable, correctly sized, and local.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
            return Err(DeadlineError::ClockUnavailable);
        }
        timespec_nanos(i128::from(sample.tv_sec), i128::from(sample.tv_nsec))
    }
}

#[cfg(any(target_os = "linux", test))]
fn timespec_nanos(seconds: i128, nanos: i128) -> Result<BootNanos, DeadlineError> {
    if seconds < 0 || !(0..i128::from(NANOS_PER_SECOND)).contains(&nanos) {
        return Err(DeadlineError::InvalidClock);
    }
    let seconds = u64::try_from(seconds).map_err(|_| DeadlineError::ClockOverflow)?;
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanos as u64))
        .map(BootNanos)
        .ok_or(DeadlineError::ClockOverflow)
}

// mach_continuous_time includes sleep; mach_absolute_time cannot substitute.
#[cfg(target_os = "macos")]
struct NativeClock {
    numer: u32,
    denom: u32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    fn mach_continuous_time() -> u64;
}

#[cfg(target_os = "macos")]
impl NativeClock {
    fn capture() -> Result<Self, DeadlineError> {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: exact public mach_timebase_info_data_t ABI, writable local.
        if unsafe { mach_timebase_info(&mut info) } != 0 {
            return Err(DeadlineError::ClockUnavailable);
        }
        if info.numer == 0 || info.denom == 0 {
            return Err(DeadlineError::InvalidClock);
        }
        Ok(Self {
            numer: info.numer,
            denom: info.denom,
        })
    }

    fn now(&self) -> Result<BootNanos, DeadlineError> {
        // SAFETY: no inputs or pointers; read-only continuous clock query.
        mach_nanos(unsafe { mach_continuous_time() }, self.numer, self.denom)
    }
}

#[cfg(any(target_os = "macos", test))]
fn mach_nanos(ticks: u64, numer: u32, denom: u32) -> Result<BootNanos, DeadlineError> {
    if numer == 0 || denom == 0 {
        return Err(DeadlineError::InvalidClock);
    }
    // Widen before multiplication, retain one backend/timebase for arm and all
    // later samples, and floor consistently (conversion error below one ns).
    let nanos = u128::from(ticks) * u128::from(numer) / u128::from(denom);
    u64::try_from(nanos)
        .map(BootNanos)
        .map_err(|_| DeadlineError::ClockOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "12345678-9abc-4def-8123-456789abcdef";

    #[test]
    fn automatic_receipt_operations_require_exact_five_argument_zsh_routes() {
        for (verb, action) in [
            ("receipt-consume", ReceiptAction::Consume),
            ("receipt-reconcile", ReceiptAction::Reconcile),
            ("receipt-discard", ReceiptAction::Discard),
            ("receipt-acknowledge", ReceiptAction::Acknowledge),
        ] {
            let good: Vec<OsString> = ["tirith", "__setup-activation", verb, "--channel", "zsh"]
                .into_iter()
                .map(OsString::from)
                .collect();
            assert_eq!(
                match_zsh_automatic_diagnostic(&good),
                Some(DiagnosticInvocation::Receipt(action))
            );
            assert_eq!(match_zsh_automatic_coordinator(&good), None);
            for index in 1..good.len() {
                let mut changed = good.clone();
                changed[index] = "unrecognized".into();
                assert_eq!(match_zsh_automatic_diagnostic(&changed), None);
                let mut omitted = good.clone();
                omitted.remove(index);
                assert_eq!(match_zsh_automatic_diagnostic(&omitted), None);
                let mut inserted = good.clone();
                inserted.insert(index, "--offline".into());
                assert_eq!(match_zsh_automatic_diagnostic(&inserted), None);
                if index + 1 < good.len() {
                    let mut swapped = good.clone();
                    swapped.swap(index, index + 1);
                    assert_eq!(match_zsh_automatic_diagnostic(&swapped), None);
                }
            }
            let mut extra = good.clone();
            extra.push("--token=private".into());
            assert_eq!(match_zsh_automatic_diagnostic(&extra), None);
            let mut other_channel = good;
            other_channel[4] = "bash-enter".into();
            assert_eq!(match_zsh_automatic_diagnostic(&other_channel), None);
        }
        for verb in [
            "consume",
            "reconcile",
            "discard",
            "receipt-arm",
            "receipt-register",
        ] {
            let old: Vec<OsString> = ["tirith", "__execution-receipt", verb, "--channel", "zsh"]
                .into_iter()
                .map(OsString::from)
                .collect();
            assert_eq!(match_zsh_automatic_diagnostic(&old), None);
        }
    }

    #[test]
    fn coordinator_deadline_requires_closed_argv_and_canonical_ids() {
        let broker: Vec<OsString> = [
            "tirith",
            "__setup-activation",
            "broker",
            "--channel",
            "zsh",
            "--operation-id",
            ID,
            "--attempt-id",
            ID,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(
            match_zsh_automatic_coordinator(&broker),
            Some(DeadlineBudget::Broker)
        );
        for index in 1..broker.len() {
            let mut changed = broker.clone();
            changed[index] = "unrecognized".into();
            assert_eq!(match_zsh_automatic_coordinator(&changed), None);
        }
        let mut nil = broker;
        nil[8] = "00000000-0000-0000-0000-000000000000".into();
        assert_eq!(match_zsh_automatic_coordinator(&nil), None);
        for action in ["discover", "start", "next", "restored", "cancel"] {
            let discovery = action == "discover";
            let args: Vec<OsString> = vec![
                "tirith".into(),
                "__setup-activation".into(),
                "relay".into(),
                "--channel".into(),
                "zsh".into(),
                "--action".into(),
                action.into(),
                format!("--operation-id={}", if discovery { "-" } else { ID }).into(),
                format!("--attempt-id={}", if discovery { "-" } else { ID }).into(),
                "--reason".into(),
                if action == "cancel" {
                    "cancelled"
                } else {
                    "none"
                }
                .into(),
            ];
            assert_eq!(
                match_zsh_automatic_coordinator(&args),
                Some(DeadlineBudget::Relay)
            );
            let mut extra = args.clone();
            extra.push("--exec".into());
            assert_eq!(match_zsh_automatic_coordinator(&extra), None);
            let mut swapped = args;
            swapped.swap(7, 8);
            assert_eq!(match_zsh_automatic_coordinator(&swapped), None);
        }
    }

    fn body(action: &str) -> Vec<OsString> {
        [
            "tirith",
            "__setup-activation",
            "probe",
            action,
            "--channel",
            "zsh",
            "--id",
            ID,
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn receipt(action: &str) -> Vec<OsString> {
        let mut args: Vec<OsString> = [
            "tirith",
            "check",
            "--approval-check",
            "--non-interactive",
            "--interactive",
            "--shell",
            "posix",
            "--execution-receipt",
            "zsh",
            "--offline",
            "--",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.push(format!("_tirith_verification_probe {ID} {action}").into());
        args
    }

    #[test]
    fn exact_automatic_abi_accepts_all_three_actions_in_both_routes() {
        for (action, expected) in [
            ("allowed", ProbeAction::Allowed),
            ("blocked", ProbeAction::Blocked),
            ("status", ProbeAction::Status),
        ] {
            assert_eq!(
                match_zsh_automatic_diagnostic(&body(action)),
                Some(DiagnosticInvocation::Probe(expected))
            );
            assert_eq!(
                match_zsh_automatic_diagnostic(&receipt(action)),
                Some(DiagnosticInvocation::ReceiptCheck(expected))
            );
        }
    }

    #[test]
    fn omitted_reordered_added_and_replaced_fixed_operands_refuse() {
        for good in [body("allowed"), receipt("status")] {
            for index in 1..good.len() {
                let mut omitted = good.clone();
                omitted.remove(index);
                assert_eq!(match_zsh_automatic_diagnostic(&omitted), None);
                let mut replaced = good.clone();
                replaced[index] = "unrecognized".into();
                assert_eq!(match_zsh_automatic_diagnostic(&replaced), None);
                let mut added = good.clone();
                added.insert(index, "--help".into());
                assert_eq!(match_zsh_automatic_diagnostic(&added), None);
                if index + 1 < good.len() {
                    let mut swapped = good.clone();
                    swapped.swap(index, index + 1);
                    assert_eq!(match_zsh_automatic_diagnostic(&swapped), None);
                }
            }
            let mut appended = good;
            appended.push("--json".into());
            assert_eq!(match_zsh_automatic_diagnostic(&appended), None);
        }
    }

    #[test]
    fn manual_status_start_and_other_internal_routes_are_never_admitted() {
        for args in [
            vec![
                "tirith",
                "__shell-verification",
                "status",
                "--channel",
                "zsh",
                "--id",
                ID,
            ],
            vec![
                "tirith",
                "__shell-verification",
                "allowed",
                "--channel",
                "zsh",
                "--id",
                ID,
            ],
            vec![
                "tirith",
                "__setup-activation",
                "probe",
                "start",
                "--channel",
                "zsh",
                "--id",
                ID,
            ],
            vec!["tirith", "status", "--json"],
            vec!["tirith", "__capsule-child"],
            vec![
                "tirith",
                "__execution-receipt",
                "consume",
                "--channel",
                "zsh",
            ],
        ] {
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert_eq!(match_zsh_automatic_diagnostic(&args), None);
        }
        let mut manual_check = receipt("allowed");
        manual_check.remove(9); // Original manual check has no explicit --offline.
        assert_eq!(match_zsh_automatic_diagnostic(&manual_check), None);
    }

    #[test]
    fn native_module_import_has_only_the_fixed_child_free_deadline_route() {
        let good: Vec<OsString> = [
            "tirith",
            "__setup-activation",
            "modules",
            "--channel",
            "zsh",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(
            match_zsh_automatic_coordinator(&good),
            Some(DeadlineBudget::Diagnostic)
        );
        for index in 1..good.len() {
            let mut bad = good.clone();
            bad[index] = "unknown".into();
            assert_eq!(match_zsh_automatic_coordinator(&bad), None);
            let mut bad = good.clone();
            bad.remove(index);
            assert_eq!(match_zsh_automatic_coordinator(&bad), None);
        }
        let mut extra = good;
        extra.push("/tmp/module.so".into());
        assert_eq!(match_zsh_automatic_coordinator(&extra), None);
    }

    #[test]
    fn uuid_must_be_canonical_ascii_and_non_nil_in_both_routes() {
        for bad in [
            "",
            "123456789abc4def8123456789abcdef",
            "12345678-9ABC-4DEF-8123-456789ABCDEF",
            "00000000-0000-0000-0000-000000000000",
            "{12345678-9abc-4def-8123-456789abcdef}",
            "12345678-9abc-4def-8123-456789abcdeg",
            "12345678_9abc-4def-8123-456789abcdef",
            "12345678-9abc-4def-8123-456789abcdéf",
        ] {
            let mut args = body("allowed");
            args[7] = bad.into();
            assert_eq!(match_zsh_automatic_diagnostic(&args), None);
            let mut args = receipt("allowed");
            args[11] = format!("_tirith_verification_probe {bad} allowed").into();
            assert_eq!(match_zsh_automatic_diagnostic(&args), None);
        }
    }

    #[test]
    fn shell_syntax_extra_commands_and_similar_leaders_refuse() {
        for input in [
            format!("_tirith_verification_probe {ID} allowed; sleep 2"),
            format!("_tirith_verification_probe {ID} allowed\n"),
            format!("_tirith_verification_probe {ID} allowed "),
            format!("_tirith_verification_probe  {ID} allowed"),
            format!("_tirith_verification_probe\t{ID} allowed"),
            format!("'_tirith_verification_probe' {ID} allowed"),
            format!("_tirith_verification_probe {ID} 'allowed'"),
            format!("env _tirith_verification_probe {ID} allowed"),
            format!("/tmp/_tirith_verification_probe {ID} allowed"),
            format!("_tirith_verification_probe {ID} $(true)"),
        ] {
            let mut args = receipt("allowed");
            args[11] = input.into();
            assert_eq!(match_zsh_automatic_diagnostic(&args), None);
        }
    }

    #[test]
    fn overlong_variable_operands_refuse_before_utf8_or_command_parsing() {
        let oversized = "a".repeat(4096);
        let mut args = body("allowed");
        args[7] = oversized.clone().into();
        assert_eq!(match_zsh_automatic_diagnostic(&args), None);
        let mut args = body("allowed");
        args[3] = oversized.clone().into();
        assert_eq!(match_zsh_automatic_diagnostic(&args), None);
        let mut args = receipt("allowed");
        args[11] = oversized.into();
        assert_eq!(match_zsh_automatic_diagnostic(&args), None);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_operands_refuse_but_executable_name_is_not_authority() {
        use std::os::unix::ffi::OsStringExt;
        for good in [body("allowed"), receipt("allowed")] {
            for index in 1..good.len() {
                let mut args = good.clone();
                args[index] = OsString::from_vec(vec![0xff]);
                assert_eq!(match_zsh_automatic_diagnostic(&args), None);
            }
            let mut args = good.clone();
            args[0] = OsString::from_vec(vec![0xff]);
            assert_eq!(
                match_zsh_automatic_diagnostic(&args),
                match_zsh_automatic_diagnostic(&good)
            );
        }
    }

    #[test]
    fn inert_probe_stays_out_of_known_child_producing_engine_gates() {
        use tirith_core::{checkpoint, context_detect, repo_hooks, tokenize};
        for action in ["allowed", "blocked", "status"] {
            let command = format!("_tirith_verification_probe {ID} {action}");
            let segments = tokenize::tokenize(&command, tokenize::ShellType::Posix);
            assert_eq!(segments.len(), 1);
            let segment = &segments[0];
            assert_eq!(
                segment.command.as_deref(),
                Some("_tirith_verification_probe")
            );
            assert_eq!(segment.args, [ID.to_owned(), action.to_owned()]);
            assert!(!repo_hooks::is_hook_triggering_command(
                "_tirith_verification_probe",
                &segment.args
            ));
            assert!(context_detect::Provider::from_leader("_tirith_verification_probe").is_none());
            assert!(!checkpoint::should_auto_checkpoint(&command));
        }
    }

    #[test]
    fn deadline_expires_at_exact_boundary_without_renewal_on_progress() {
        let mut deadline = Deadline::new(BootNanos(100), DeadlineBudget::Diagnostic).unwrap();
        assert_eq!(deadline.poll(Ok(BootNanos(100))), Poll::Wait(POLL_INTERVAL));
        assert_eq!(
            deadline.poll(Ok(BootNanos(500_000_100))),
            Poll::Wait(POLL_INTERVAL)
        );
        assert_eq!(
            deadline.poll(Ok(BootNanos(1_000_000_099))),
            Poll::Wait(Duration::from_nanos(1))
        );
        assert_eq!(
            deadline.poll(Ok(BootNanos(1_000_000_100))),
            Poll::Exit(EXIT_DEADLINE)
        );
    }

    #[test]
    fn repeated_ticks_are_legal_but_clock_regression_and_failure_refuse() {
        let mut deadline = Deadline::new(BootNanos(100), DeadlineBudget::Relay).unwrap();
        assert_eq!(deadline.poll(Ok(BootNanos(101))), Poll::Wait(POLL_INTERVAL));
        assert_eq!(deadline.poll(Ok(BootNanos(101))), Poll::Wait(POLL_INTERVAL));
        assert_eq!(
            deadline.poll(Ok(BootNanos(100))),
            Poll::Exit(EXIT_CLOCK_FAILURE)
        );
        for error in [
            DeadlineError::ClockUnavailable,
            DeadlineError::InvalidClock,
            DeadlineError::ClockOverflow,
        ] {
            let mut deadline = Deadline::new(BootNanos(0), DeadlineBudget::Broker).unwrap();
            assert_eq!(deadline.poll(Err(error)), Poll::Exit(EXIT_CLOCK_FAILURE));
        }
    }

    #[test]
    fn continuous_clock_jump_after_suspend_expires_immediately_on_next_poll() {
        let mut deadline = Deadline::new(BootNanos(900), DeadlineBudget::Broker).unwrap();
        assert_eq!(
            deadline.poll(Ok(BootNanos(900 + 30 * NANOS_PER_SECOND))),
            Poll::Exit(EXIT_DEADLINE)
        );
    }

    #[test]
    fn fixed_budgets_and_overflow_are_checked() {
        assert_eq!(DeadlineBudget::Diagnostic.nanos(), NANOS_PER_SECOND);
        assert_eq!(DeadlineBudget::Relay.nanos(), NANOS_PER_SECOND);
        assert_eq!(DeadlineBudget::Broker.nanos(), 10 * NANOS_PER_SECOND);
        assert!(matches!(
            Deadline::new(BootNanos(u64::MAX), DeadlineBudget::Diagnostic),
            Err(DeadlineError::ClockOverflow)
        ));
    }

    #[test]
    fn native_clock_unit_conversion_rejects_invalid_or_overflowed_values() {
        assert_eq!(timespec_nanos(3, 42), Ok(BootNanos(3_000_000_042)));
        assert_eq!(timespec_nanos(-1, 0), Err(DeadlineError::InvalidClock));
        assert_eq!(timespec_nanos(0, -1), Err(DeadlineError::InvalidClock));
        assert_eq!(
            timespec_nanos(0, 1_000_000_000),
            Err(DeadlineError::InvalidClock)
        );
        assert_eq!(
            timespec_nanos(i128::MAX, 0),
            Err(DeadlineError::ClockOverflow)
        );
        assert_eq!(
            timespec_nanos(i128::from(u64::MAX), 0),
            Err(DeadlineError::ClockOverflow)
        );
        assert_eq!(mach_nanos(7, 125, 3), Ok(BootNanos(291)));
        assert_eq!(
            mach_nanos(u64::MAX, u32::MAX, u32::MAX),
            Ok(BootNanos(u64::MAX))
        );
        assert_eq!(
            mach_nanos(u64::MAX, 2, 1),
            Err(DeadlineError::ClockOverflow)
        );
        assert_eq!(mach_nanos(1, 0, 1), Err(DeadlineError::InvalidClock));
        assert_eq!(mach_nanos(1, 1, 0), Err(DeadlineError::InvalidClock));
    }

    #[test]
    fn cancellation_wins_once_and_prevents_firing() {
        let state = Arc::new(AtomicU8::new(ACTIVE));
        let guard = SelfDeadline {
            state: Arc::clone(&state),
        };
        drop(guard);
        assert_eq!(state.load(Ordering::Acquire), CANCELLED);
        assert!(!transition(&state, FIRED));
        assert!(!transition(&state, CANCELLED));
    }

    #[test]
    fn firing_wins_once_and_cannot_be_revoked_by_guard_drop() {
        let state = Arc::new(AtomicU8::new(ACTIVE));
        let guard = SelfDeadline {
            state: Arc::clone(&state),
        };
        assert!(transition(&state, FIRED));
        drop(guard);
        assert_eq!(state.load(Ordering::Acquire), FIRED);
        assert!(!transition(&state, FIRED));
    }
}
