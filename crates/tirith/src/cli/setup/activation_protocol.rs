//! Closed scheduling messages. These contain no executable source, paths,
//! secrets or protection evidence. A Complete frame is never a shell proof.

const MAX_FRAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Id(uuid::Uuid);

impl Id {
    pub(super) fn parse(value: &str) -> Result<Self, &'static str> {
        let id = uuid::Uuid::parse_str(value).map_err(|_| "invalid activation identifier")?;
        if value != id.hyphenated().to_string() {
            return Err("activation identifier is not canonical");
        }
        Ok(Self(id))
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

macro_rules! closed_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum $name { $($variant),+ }
        impl $name {
            fn parse(value: &str) -> Option<Self> {
                match value { $($wire => Some(Self::$variant),)+ _ => None }
            }
            fn wire(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }
        }
    }
}

closed_enum!(Stage {
    Allowed => "allowed", Blocked => "blocked", Status => "status",
    Restore => "restore", Complete => "complete", Wait => "wait",
});
closed_enum!(Failure {
    Unavailable => "unavailable", Cancelled => "cancelled", Failed => "failed",
});
closed_enum!(Reason {
    UnsupportedEditor => "unsupported-editor", Callbacks => "callbacks",
    InputPresent => "input-present", HistoryContext => "history-context",
    Cancelled => "cancelled", Deadline => "deadline", ContextDrift => "context-drift",
    Busy => "busy", BackendUnavailable => "backend-unavailable",
    Protocol => "protocol", ProofRefused => "proof-refused",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    pub(super) operation: Id,
    pub(super) attempt: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Frame {
    None,
    Pending(Attempt),
    Stage {
        stage: Stage,
        attempt: Attempt,
        challenge: Id,
    },
    Failure {
        failure: Failure,
        attempt: Attempt,
        challenge: Option<Id>,
        reason: Reason,
    },
}

impl Frame {
    /// Decode exactly one complete wire frame, including its single newline.
    /// Socket reads and their absolute deadlines belong to the native owner.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("activation frame is over limit");
        }
        let line = bytes
            .strip_suffix(b"\n")
            .ok_or("activation frame is incomplete")?;
        if !line.iter().all(|byte| (b' '..=b'~').contains(byte)) {
            return Err("activation frame contains invalid bytes");
        }
        let line = std::str::from_utf8(line).map_err(|_| "activation frame is not ASCII")?;
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 6 || fields[0] != "TA1" {
            return Err("unsupported activation frame");
        }
        if fields[1] == "none" {
            return if fields[2..] == ["-", "-", "-", "none"] {
                Ok(Self::None)
            } else {
                Err("invalid no-intent activation frame")
            };
        }
        let attempt = Attempt {
            operation: Id::parse(fields[2])?,
            attempt: Id::parse(fields[3])?,
        };
        if fields[1] == "pending" {
            return if fields[4..] == ["-", "none"] {
                Ok(Self::Pending(attempt))
            } else {
                Err("invalid pending activation frame")
            };
        }
        if let Some(stage) = Stage::parse(fields[1]) {
            if fields[5] != "none" {
                return Err("unexpected activation stage reason");
            }
            return Ok(Self::Stage {
                stage,
                attempt,
                challenge: Id::parse(fields[4])?,
            });
        }
        let failure = Failure::parse(fields[1]).ok_or("unknown activation stage")?;
        let challenge = if fields[4] == "-" {
            None
        } else {
            Some(Id::parse(fields[4])?)
        };
        let reason = Reason::parse(fields[5]).ok_or("unknown activation refusal")?;
        Ok(Self::Failure {
            failure,
            attempt,
            challenge,
            reason,
        })
    }

    pub(super) fn encode(self) -> String {
        match self {
            Self::None => "TA1|none|-|-|-|none\n".into(),
            Self::Pending(ids) => format!("TA1|pending|{}|{}|-|none\n", ids.operation, ids.attempt),
            Self::Stage {
                stage,
                attempt: ids,
                challenge,
            } => format!(
                "TA1|{}|{}|{}|{}|none\n",
                stage.wire(),
                ids.operation,
                ids.attempt,
                challenge
            ),
            Self::Failure {
                failure,
                attempt: ids,
                challenge,
                reason,
            } => format!(
                "TA1|{}|{}|{}|{}|{}\n",
                failure.wire(),
                ids.operation,
                ids.attempt,
                challenge.map_or_else(|| "-".into(), |id| id.to_string()),
                reason.wire()
            ),
        }
    }
}

/// An accepted request describes metadata coordination only. Every transition
/// still requires the authenticated peer, completed setup lease and core proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Request {
    Discover,
    Start(Attempt),
    Next(Attempt),
    Restored(Attempt),
    Cancel { attempt: Attempt, reason: Reason },
}

impl Request {
    pub(super) fn parse(
        action: &str,
        operation: &str,
        attempt: &str,
        reason: &str,
    ) -> Result<Self, &'static str> {
        if action == "discover" {
            return if (operation, attempt, reason) == ("-", "-", "none") {
                Ok(Self::Discover)
            } else {
                Err("invalid activation discovery request")
            };
        }
        let ids = Attempt {
            operation: Id::parse(operation)?,
            attempt: Id::parse(attempt)?,
        };
        if action == "cancel" {
            return Ok(Self::Cancel {
                attempt: ids,
                reason: Reason::parse(reason).ok_or("unknown activation cancellation reason")?,
            });
        }
        if reason != "none" {
            return Err("unexpected activation request reason");
        }
        match action {
            "start" => Ok(Self::Start(ids)),
            "next" => Ok(Self::Next(ids)),
            "restored" => Ok(Self::Restored(ids)),
            _ => Err("unknown activation request"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const OP: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const ATTEMPT: &str = "11234567-89ab-cdef-0123-456789abcdef";
    const CHALLENGE: &str = "21234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn scheduler_contract_frames_are_exact_and_roundtrip() {
        let mut frames = vec![
            "TA1|none|-|-|-|none\n".to_string(),
            format!("TA1|pending|{OP}|{ATTEMPT}|-|none\n"),
        ];
        for stage in [
            "allowed", "blocked", "status", "restore", "complete", "wait",
        ] {
            frames.push(format!("TA1|{stage}|{OP}|{ATTEMPT}|{CHALLENGE}|none\n"));
        }
        for stage in ["unavailable", "cancelled", "failed"] {
            for reason in [
                "unsupported-editor",
                "callbacks",
                "input-present",
                "history-context",
                "cancelled",
                "deadline",
                "context-drift",
                "busy",
                "backend-unavailable",
                "protocol",
                "proof-refused",
            ] {
                for challenge in ["-", CHALLENGE] {
                    frames.push(format!("TA1|{stage}|{OP}|{ATTEMPT}|{challenge}|{reason}\n"));
                }
            }
        }
        for frame in frames {
            assert_eq!(Frame::decode(frame.as_bytes()).unwrap().encode(), frame);
        }
    }

    #[test]
    fn malformed_or_command_bearing_frames_cannot_become_stages() {
        for frame in [
            "TA1|none|-|-|-|none",
            "TA1|none|-|-|-|none\r\n",
            "TA1|none|-|-|-|none\n\n",
            "TA1|none|-|-|-|none\0\n",
            "TA1|none|-|-|-|none|extra\n",
            "TA2|none|-|-|-|none\n",
            "TA1|none|-|-|-|none\ncommand\n",
            "TA1|none|-|-|-|nöne\n",
        ] {
            assert!(Frame::decode(frame.as_bytes()).is_err(), "{frame:?}");
        }
        for stage in ["run", "eval", "allowed;id", "complete", "allowed"] {
            assert!(
                Frame::decode(format!("TA1|{stage}|{OP}|{ATTEMPT}|-|none\n").as_bytes()).is_err()
            );
        }
        assert!(Frame::decode(&[b'x'; MAX_FRAME_BYTES + 1]).is_err());
        assert!(Frame::decode(
            format!(
                "TA1|allowed|{}|{ATTEMPT}|{CHALLENGE}|none\n",
                OP.to_uppercase()
            )
            .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn actions_cannot_carry_paths_commands_or_extra_authority() {
        assert_eq!(
            Request::parse("discover", "-", "-", "none").unwrap(),
            Request::Discover
        );
        for action in ["start", "next", "restored"] {
            assert!(Request::parse(action, OP, ATTEMPT, "none").is_ok());
            assert!(Request::parse(action, OP, ATTEMPT, "deadline").is_err());
        }
        assert!(Request::parse("cancel", OP, ATTEMPT, "deadline").is_ok());
        assert!(Request::parse("cancel", OP, ATTEMPT, "none").is_err());
        for action in ["exec", "start sh", "start;id", "decline"] {
            assert!(Request::parse(action, OP, ATTEMPT, "none").is_err());
        }
        for id in ["/tmp/endpoint", "../operation", "$(id)", "invalid", ""] {
            assert!(Request::parse("start", id, ATTEMPT, "none").is_err());
        }
    }
}
