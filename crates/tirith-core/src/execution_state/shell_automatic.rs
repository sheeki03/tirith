//! Private automatic challenge state. Scheduling acknowledgments do not stand
//! in for the authenticated hook/body transitions in the parent module.
use super::*;

const AUTOMATIC_TTL_NS: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticVerificationStage {
    Allowed,
    Blocked,
    Status,
    Restore,
}

/// Owns one automatic attempt in its authenticated broker process. It cannot
/// be serialized, cloned, sent to another thread, or reconstructed from a DTO.
pub struct AutomaticShellVerification<'shell> {
    context: &'shell AuthenticatedShellContext,
    id: String,
    operation_id: String,
    attempt_id: String,
    loaded: String,
    created: std::time::Instant,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AutomaticBinding {
    operation_id: String,
    attempt_id: String,
    pub(super) broker_pid: u32,
    broker_identity: ShellProcessIdentity,
    clock: DeadlineClock,
    issued: Option<AutomaticVerificationStage>,
    allowed_hooks: u8,
    blocked_hooks: u8,
    status_hooks: u8,
    pub(super) status_bodies: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeadlineClock {
    coordinate: String,
    started_ns: u64,
    deadline_ns: u64,
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

impl DeadlineClock {
    fn capture() -> Result<Self, String> {
        let (coordinate, started_ns) = monotonic_now()?;
        Ok(Self {
            coordinate,
            started_ns,
            deadline_ns: started_ns
                .checked_add(AUTOMATIC_TTL_NS)
                .ok_or("automatic deadline overflow")?,
        })
    }

    pub(super) fn live(&self) -> Result<(), String> {
        let (coordinate, now) = monotonic_now()?;
        if coordinate != self.coordinate
            || now < self.started_ns
            || now >= self.deadline_ns
            || self.started_ns.checked_add(AUTOMATIC_TTL_NS) != Some(self.deadline_ns)
        {
            return Err("automatic shell verification expired or its clock changed".into());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn monotonic_now() -> Result<(String, u64), String> {
    fn coordinate() -> Result<String, String> {
        let leader = std::fs::read_link("/proc/self/ns/time")
            .map_err(|_| "automatic time namespace unavailable")?;
        let thread = std::fs::read_link("/proc/thread-self/ns/time")
            .map_err(|_| "automatic thread time namespace unavailable")?;
        let value = leader.to_str().ok_or("invalid automatic time namespace")?;
        let number = value
            .strip_prefix("time:[")
            .and_then(|v| v.strip_suffix(']'))
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .ok_or("invalid automatic time namespace")?;
        if leader != thread || number.parse::<u64>().ok().filter(|n| *n > 0).is_none() {
            return Err("automatic time namespace differs across threads".into());
        }
        Ok(format!("linux-boottime:{value}"))
    }
    let before = coordinate()?;
    let mut value = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
        return Err("automatic monotonic clock unavailable".into());
    }
    let value = unsafe { value.assume_init() };
    if before != coordinate()? || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("automatic monotonic clock changed".into());
    }
    let nanos = (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64))
        .filter(|v| *v > 0)
        .ok_or("invalid automatic monotonic clock")?;
    Ok((before, nanos))
}

#[cfg(target_os = "macos")]
pub(super) fn monotonic_now() -> Result<(String, u64), String> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    #[link(name = "System")]
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
        fn mach_continuous_time() -> u64;
    }
    let mut base = Timebase { numer: 0, denom: 0 };
    if unsafe { mach_timebase_info(&mut base) } != 0 || base.numer == 0 || base.denom == 0 {
        return Err("automatic monotonic clock unavailable".into());
    }
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks) * u128::from(base.numer) / u128::from(base.denom);
    let nanos = u64::try_from(nanos)
        .ok()
        .filter(|n| *n > 0)
        .ok_or("invalid automatic monotonic clock")?;
    Ok((
        format!("macos-continuous:{}:{}", base.numer, base.denom),
        nanos,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn monotonic_now() -> Result<(String, u64), String> {
    Err("automatic native deadline is unsupported".into())
}

impl AutomaticBinding {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !canonical_id(&self.operation_id)
            || !canonical_id(&self.attempt_id)
            || self.broker_pid <= 1
            || self.broker_pid > i32::MAX as u32
            || self.clock.started_ns.checked_add(AUTOMATIC_TTL_NS) != Some(self.clock.deadline_ns)
            || self.clock.coordinate.is_empty()
            || self.clock.coordinate.len() > 128
            || self.allowed_hooks > 1
            || self.blocked_hooks > 1
            || self.status_hooks > 1
            || self.status_bodies > 1
        {
            return Err("automatic shell verification binding is invalid".into());
        }
        Ok(())
    }

    pub(super) fn live(&self) -> Result<(), String> {
        self.clock.live()?;
        if shell_process_identity(self.broker_pid).map_err(|_| "automatic broker is unavailable")?
            != self.broker_identity
        {
            return Err("automatic broker process changed".into());
        }
        self.clock.live()
    }

    pub(super) fn hook(
        &mut self,
        phase: &mut Phase,
        kind: ProbeCommand,
    ) -> ShellVerificationHookDecision {
        let accepted = match kind {
            ProbeCommand::Allowed
                if self.issued == Some(AutomaticVerificationStage::Allowed)
                    && *phase == Phase::Challenged
                    && self.allowed_hooks == 0 =>
            {
                self.allowed_hooks = 1;
                *phase = Phase::AllowChecked;
                true
            }
            ProbeCommand::Blocked
                if self.issued == Some(AutomaticVerificationStage::Blocked)
                    && *phase == Phase::AllowedExecuted
                    && self.blocked_hooks == 0 =>
            {
                self.blocked_hooks = 1;
                *phase = Phase::BlockChecked;
                true
            }
            ProbeCommand::Status
                if self.issued == Some(AutomaticVerificationStage::Status)
                    && *phase == Phase::BlockChecked
                    && self.status_hooks == 0 =>
            {
                self.status_hooks = 1;
                *phase = Phase::StatusChecked;
                true
            }
            _ => false,
        };
        if !accepted {
            *phase = Phase::Failed;
        }
        if accepted && matches!(kind, ProbeCommand::Blocked) {
            ShellVerificationHookDecision::ForceDiagnosticBlock
        } else {
            ShellVerificationHookDecision::ContinueProbe
        }
    }
}

/// Requires a completed setup lease and fresh-shell check in the CLI coordinator
/// before entry. This core capability proves only the observed shell sequence.
pub fn start_automatic_shell_verification<'shell>(
    context: &'shell AuthenticatedShellContext,
    operation_id: &str,
    attempt_id: &str,
    config_paths: &[PathBuf],
    loaded: &str,
) -> Result<AutomaticShellVerification<'shell>, String> {
    context.revalidate()?;
    if context.family != ShellHookFamily::Zsh
        || !canonical_id(operation_id)
        || !canonical_id(attempt_id)
        || !digest_is_valid(loaded)
    {
        return Err("automatic shell verification input is unsupported".into());
    }
    let clock = DeadlineClock::capture()?;
    let now = unix_time_ms()?;
    let configuration = capture_configuration(config_paths, &context.secret)?;
    let snapshot = current_policy()?;
    let mut record = VerificationRecord {
        schema_version: VERIFICATION_SCHEMA,
        id: attempt_id.into(),
        family: context.family,
        hook_binding: token_sha256(&context.secret),
        cwd_binding: current_cwd_binding_sha256(&context.secret)?,
        policy_guard: snapshot.private_replay_guard(),
        loaded_hook_state: loaded.into(),
        configuration,
        created_unix_ms: now,
        expires_unix_ms: now.saturating_add(VERIFICATION_TTL_MS),
        observed_unix_ms: None,
        phase: Phase::Challenged,
        allowed_executions: 0,
        blocked_executions: 0,
        automatic: Some(AutomaticBinding {
            operation_id: operation_id.into(),
            attempt_id: attempt_id.into(),
            broker_pid: std::process::id(),
            broker_identity: shell_process_identity(std::process::id())
                .map_err(|_| "cannot retain automatic broker identity")?,
            clock,
            issued: None,
            allowed_hooks: 0,
            blocked_hooks: 0,
            status_hooks: 0,
            status_bodies: 0,
        }),
        seal: String::new(),
    };
    let store = VerificationStore::open(&context.secret)?;
    if store.load(&context.secret, now)?.is_some() {
        return Err("this shell already has a verification attempt".into());
    }
    store.reserve_capacity(now)?;
    snapshot
        .revalidate_inputs()
        .map_err(|_| "policy changed during automatic verification")?;
    context.revalidate()?;
    record.automatic.as_ref().unwrap().live()?;
    store.publish(&mut record, &context.secret)?;
    Ok(AutomaticShellVerification {
        context,
        id: record.id,
        operation_id: operation_id.into(),
        attempt_id: attempt_id.into(),
        loaded: loaded.into(),
        created: std::time::Instant::now(),
    })
}

impl AutomaticShellVerification<'_> {
    fn load(&self) -> Result<(VerificationStore, VerificationRecord), String> {
        if self.created.elapsed() >= std::time::Duration::from_nanos(AUTOMATIC_TTL_NS) {
            return Err("automatic verification owner expired".into());
        }
        self.context.revalidate()?;
        let now = unix_time_ms()?;
        let store = VerificationStore::open(&self.context.secret)?;
        let record = store
            .load(&self.context.secret, now)?
            .ok_or("automatic challenge unavailable")?;
        let automatic = record
            .automatic
            .as_ref()
            .ok_or("automatic binding unavailable")?;
        if record.id != self.id
            || automatic.operation_id != self.operation_id
            || automatic.attempt_id != self.attempt_id
            || automatic.broker_pid != std::process::id()
            || record.family != self.context.family
            || record.hook_binding != token_sha256(&self.context.secret)
            || context_status(&record, &self.context.secret, Some(&self.loaded), now)?.is_some()
        {
            return Err("automatic verification owner or context changed".into());
        }
        self.context.revalidate()?;
        automatic.live()?;
        Ok((store, record))
    }

    /// Persist one stage before giving its closed scheduling value to the relay.
    /// A lost response cannot cause the inert command to be issued twice.
    pub fn issue_next(&mut self) -> Result<AutomaticVerificationStage, String> {
        let (store, mut record) = self.load()?;
        let automatic = record.automatic.as_mut().unwrap();
        let stage = match (automatic.issued, record.phase) {
            (None, Phase::Challenged) => AutomaticVerificationStage::Allowed,
            (Some(AutomaticVerificationStage::Allowed), Phase::AllowedExecuted) => {
                AutomaticVerificationStage::Blocked
            }
            (Some(AutomaticVerificationStage::Blocked), Phase::BlockChecked) => {
                AutomaticVerificationStage::Status
            }
            (Some(AutomaticVerificationStage::Status), Phase::AwaitingRestoration) => {
                AutomaticVerificationStage::Restore
            }
            _ => {
                record.phase = Phase::Failed;
                store.publish(&mut record, &self.context.secret)?;
                return Err(
                    "automatic stage was repeated or its execution was not observed".into(),
                );
            }
        };
        automatic.issued = Some(stage);
        automatic.live()?;
        store.publish(&mut record, &self.context.secret)?;
        Ok(stage)
    }

    /// The coordinator authenticates the restoration acknowledgment and checks
    /// its completed-file lease before and after this consumed observation.
    pub fn finish_restored(self, loaded: &str) -> Result<ShellVerificationObservation, String> {
        if loaded != self.loaded {
            return Err("restored loaded shell state changed".into());
        }
        let (store, mut record) = self.load()?;
        let automatic = record.automatic.as_ref().unwrap();
        if automatic.issued != Some(AutomaticVerificationStage::Restore)
            || record.phase != Phase::AwaitingRestoration
            || record.allowed_executions != 1
            || record.blocked_executions != 0
            || automatic.allowed_hooks != 1
            || automatic.blocked_hooks != 1
            || automatic.status_hooks != 1
            || automatic.status_bodies != 1
        {
            return Err("automatic shell sequence or restoration is incomplete".into());
        }
        automatic.live()?;
        record.phase = Phase::Verified;
        record.observed_unix_ms = Some(unix_time_ms()?);
        store.publish(&mut record, &self.context.secret)?;
        let proof = ShellVerificationProof {
            observation: record.observation(ShellVerificationStatus::ObservedBlocking),
            binding: ProjectionBinding {
                channel: ShellReceiptChannel::Zsh,
                loaded_hook_state: loaded.into(),
                record_seal: record.seal.clone(),
                issuer_pid: std::process::id(),
                issued_at: std::time::Instant::now(),
                automatic_record: true,
                automatic_owner: true,
            },
        };
        drop(store);
        let mut observation = proof.into_current_observation();
        if observation.status != ShellVerificationStatus::ObservedBlocking {
            return Err("automatic final observation expired or its authority changed".into());
        }
        observation.source = "fresh_terminal_activation";
        observation.scope = "completed_setup_shell_observation";
        Ok(observation)
    }

    pub fn cancel(self) -> Result<(), String> {
        let (store, mut record) = self.load()?;
        record.phase = Phase::Failed;
        store.publish(&mut record, &self.context.secret)
    }
}
