use super::*;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OPERATION: &str = "12345678-1234-4234-8234-123456789abc";
const ATTEMPT: &str = "abcdef01-1234-4234-8234-123456789abc";

fn binding() -> WireBinding {
    let id = ActivationExchangeId::parse(OPERATION, ATTEMPT).unwrap();
    WireBinding {
        operation: id.operation,
        attempt: id.attempt,
        context: [3; 32],
        client: [4; 32],
        server: [5; 32],
    }
}

fn transcript() -> [u8; TRANSCRIPT_LEN] {
    let hello = make_hello(KEY, &binding(), [6; 32]).unwrap();
    make_challenge(KEY, &hello, [7; 32]).unwrap().1
}

#[test]
fn rfc4231_hmac_sha256_known_answers() {
    // https://www.rfc-editor.org/rfc/rfc4231 sections 4.2 and 4.3.
    for (key, data, expected) in [
        (
            vec![0x0b; 20],
            b"Hi There".as_slice(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".as_slice(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
    ] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
        mac.update(data);
        mac.clone()
            .verify_slice(&hex::decode(expected).unwrap())
            .unwrap();
        assert_eq!(hex::encode(mac.finalize().into_bytes()), expected);
    }
}

#[test]
fn immutable_exchange_ids_require_canonical_non_nil_uuids() {
    assert!(ActivationExchangeId::parse(OPERATION, ATTEMPT).is_ok());
    for invalid in [
        "",
        "-",
        "00000000-0000-0000-0000-000000000000",
        "12345678123442348234123456789abc",
        "12345678-1234-4234-8234-123456789ABC",
        "{12345678-1234-4234-8234-123456789abc}",
        "12345678-1234-4234-8234-123456789abc\n",
    ] {
        assert!(matches!(
            ActivationExchangeId::parse(invalid, ATTEMPT),
            Err(ActivationTransportError::Frame)
        ));
        assert!(matches!(
            ActivationExchangeId::parse(OPERATION, invalid),
            Err(ActivationTransportError::Frame)
        ));
    }
}

#[test]
fn both_roles_agree_on_the_fixed_handshake() {
    let binding = binding();
    let hello = make_hello(KEY, &binding, [6; 32]).unwrap();
    accept_hello(KEY, &binding, &hello).unwrap();
    let (challenge, server) = make_challenge(KEY, &hello, [7; 32]).unwrap();
    let client = accept_challenge(KEY, &hello, &challenge).unwrap();
    assert_eq!(server, client);
    assert_eq!(&server[..HELLO_LEN], &hello);
    assert_eq!(&server[HELLO_LEN..], &[7; 32]);
}

#[test]
fn every_hello_byte_is_authenticated() {
    let hello = make_hello(KEY, &binding(), [6; 32]).unwrap();
    for position in 0..HELLO_LEN {
        let mut changed = hello;
        changed[position] ^= 1;
        assert!(
            accept_hello(KEY, &binding(), &changed).is_err(),
            "byte {position}"
        );
    }
}

#[test]
fn operation_attempt_context_and_role_order_must_match() {
    let original = binding();
    let hello = make_hello(KEY, &original, [6; 32]).unwrap();
    for field in 0..6 {
        let mut other = original.clone();
        match field {
            0 => other.operation[0] ^= 1,
            1 => other.attempt[0] ^= 1,
            2 => other.context[0] ^= 1,
            3 => other.client[0] ^= 1,
            4 => other.server[0] ^= 1,
            _ => std::mem::swap(&mut other.client, &mut other.server),
        }
        assert_eq!(
            accept_hello(KEY, &other, &hello),
            Err(ActivationTransportError::Authentication)
        );
    }
}

#[test]
fn wrong_capability_cannot_authenticate_either_role() {
    let hello = make_hello(KEY, &binding(), [6; 32]).unwrap();
    assert_eq!(
        accept_hello(b"wrong", &binding(), &hello),
        Err(ActivationTransportError::Authentication)
    );
    let (challenge, _) = make_challenge(KEY, &hello, [7; 32]).unwrap();
    assert_eq!(
        accept_challenge(b"wrong", &hello, &challenge),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn zero_and_reflected_nonces_refuse() {
    assert!(matches!(
        make_hello(KEY, &binding(), [0; 32]),
        Err(ActivationTransportError::Frame)
    ));
    let hello = make_hello(KEY, &binding(), [6; 32]).unwrap();
    for nonce in [[0; 32], [6; 32]] {
        assert!(matches!(
            make_challenge(KEY, &hello, nonce),
            Err(ActivationTransportError::Frame)
        ));
    }
}

#[test]
fn role_domains_and_field_lengths_reject_reflection_and_ambiguity() {
    let data = transcript();
    let roles: [&[u8]; 5] = [
        b"client-hello",
        b"server-challenge",
        b"client-request",
        b"server-reply",
        b"client-complete",
    ];
    for role in roles {
        let signature = tag(KEY, role, &data, b"payload");
        verify_tag(KEY, role, &data, b"payload", &signature).unwrap();
        for other in roles {
            if other != role {
                assert_eq!(
                    verify_tag(KEY, other, &data, b"payload", &signature),
                    Err(ActivationTransportError::Authentication)
                );
            }
        }
    }
    let signature = tag(KEY, b"role", b"ab", b"c");
    assert_eq!(
        verify_tag(KEY, b"role", b"a", b"bc", &signature),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn server_challenge_replay_fails_under_a_new_client_nonce_or_identity() {
    let original = binding();
    let hello = make_hello(KEY, &original, [6; 32]).unwrap();
    let (challenge, _) = make_challenge(KEY, &hello, [7; 32]).unwrap();
    let new_hello = make_hello(KEY, &original, [8; 32]).unwrap();
    assert_eq!(
        accept_challenge(KEY, &new_hello, &challenge),
        Err(ActivationTransportError::Authentication)
    );
    let mut new_binding = original;
    new_binding.server[0] ^= 1;
    let new_hello = make_hello(KEY, &new_binding, [6; 32]).unwrap();
    assert_eq!(
        accept_challenge(KEY, &new_hello, &challenge),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn hello_replay_cannot_replay_request_against_a_fresh_server_nonce() {
    let hello = make_hello(KEY, &binding(), [6; 32]).unwrap();
    let (_, old) = make_challenge(KEY, &hello, [7; 32]).unwrap();
    let (_, fresh) = make_challenge(KEY, &hello, [8; 32]).unwrap();
    let signature = tag(KEY, b"client-request", &old, b"fixed-request");
    assert_eq!(
        verify_tag(KEY, b"client-request", &fresh, b"fixed-request", &signature),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn reply_authentication_covers_the_exact_accepted_request() {
    let transcript = transcript();
    let accepted = bind_request(KEY, &transcript, b"action-one");
    let substituted = bind_request(KEY, &transcript, b"action-two");
    let signature = tag(KEY, b"server-reply", &accepted, b"closed-reply");
    verify_tag(KEY, b"server-reply", &accepted, b"closed-reply", &signature).unwrap();
    assert_eq!(
        verify_tag(
            KEY,
            b"server-reply",
            &substituted,
            b"closed-reply",
            &signature
        ),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn completion_ack_covers_the_exact_reply_and_cannot_reflect_it() {
    let bound = bind_request(KEY, &transcript(), b"fixed-request");
    let ack = tag(KEY, b"client-complete", &bound, b"accepted-reply");
    verify_tag(KEY, b"client-complete", &bound, b"accepted-reply", &ack).unwrap();
    assert_eq!(
        verify_tag(KEY, b"client-complete", &bound, b"different-reply", &ack),
        Err(ActivationTransportError::Authentication)
    );
    let response_tag = tag(KEY, b"server-reply", &bound, b"accepted-reply");
    assert_eq!(
        verify_tag(
            KEY,
            b"client-complete",
            &bound,
            b"accepted-reply",
            &response_tag
        ),
        Err(ActivationTransportError::Authentication)
    );
}

fn context() -> AuthenticatedShellContext {
    // Pure digest fixture only: no authenticator accepts this synthetic object.
    AuthenticatedShellContext {
        shell_pid: 100,
        issuer_pid: 101,
        family: ShellHookFamily::Zsh,
        session_id: "session-one".into(),
        session_environment: None,
        secret: KEY.iter().map(|byte| *byte as char).collect(),
        identity: process(100).birth,
        executable: TirithExecutableIdentity {
            device: 1,
            inode: 2,
            size: 3,
            owner_uid: 501,
            mode: 0o100755,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        },
        _same_thread: std::marker::PhantomData,
    }
}

#[test]
fn authenticated_context_binds_shell_family_session_birth_and_binary() {
    let expected = context_digest(&context()).unwrap();
    for field in 0..14 {
        let mut changed = context();
        match field {
            0 => changed.shell_pid += 1,
            1 => changed.family = ShellHookFamily::Fish,
            2 => changed.session_id.push('x'),
            3 => changed.identity.effective_uid += 1,
            4 => changed.identity.start_fingerprint.push('x'),
            5 => changed.executable.device += 1,
            6 => changed.executable.inode += 1,
            7 => changed.executable.size += 1,
            8 => changed.executable.owner_uid += 1,
            9 => changed.executable.mode ^= 1,
            10 => changed.executable.modified_seconds += 1,
            11 => changed.executable.modified_nanoseconds += 1,
            12 => changed.executable.changed_seconds += 1,
            _ => changed.executable.changed_nanoseconds += 1,
        }
        assert_ne!(context_digest(&changed).unwrap(), expected, "field {field}");
    }
}

#[test]
fn issuer_pid_is_role_bound_separately_and_not_part_of_shared_context() {
    let original = context();
    let mut sibling = context();
    sibling.issuer_pid += 1;
    assert_eq!(
        context_digest(&original).unwrap(),
        context_digest(&sibling).unwrap()
    );
    assert_ne!(
        process(original.issuer_pid).digest(),
        process(sibling.issuer_pid).digest()
    );
}

#[test]
fn context_session_work_is_bounded() {
    for session in [String::new(), "x".repeat(257)] {
        let mut context = context();
        context.session_id = session;
        assert_eq!(
            context_digest(&context),
            Err(ActivationTransportError::Identity)
        );
    }
}

fn process(pid: u32) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        parent: 100,
        birth: ShellProcessIdentity {
            effective_uid: 501,
            start_fingerprint: format!("native:boot:{pid}"),
        },
        image: [pid as u8; 32],
    }
}

#[test]
fn kernel_peer_must_be_a_distinct_same_uid_live_shell_child() {
    let own = process(101);
    let peer = process(102);
    let credentials = PeerCredentials { pid: 102, uid: 501 };
    validate_pair(100, 501, &credentials, &own, &peer).unwrap();
    for field in 0..7 {
        let mut changed_own = own.clone();
        let mut changed_peer = peer.clone();
        let mut changed_credentials = credentials.clone();
        match field {
            0 => changed_own.parent += 1,
            1 => changed_peer.parent += 1,
            2 => changed_own.birth.effective_uid += 1,
            3 => changed_peer.birth.effective_uid += 1,
            4 => changed_credentials.uid += 1,
            5 => changed_credentials.pid += 1,
            _ => {
                changed_peer.pid = own.pid;
                changed_credentials.pid = own.pid;
            }
        }
        assert_eq!(
            validate_pair(100, 501, &changed_credentials, &changed_own, &changed_peer),
            Err(ActivationTransportError::Identity)
        );
    }
}

#[test]
fn native_birth_parent_uid_and_observable_image_are_transcript_bound() {
    let original = process(102);
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.pid += 1,
            1 => changed.parent += 1,
            2 => changed.birth.start_fingerprint.push('x'),
            3 => changed.birth.effective_uid += 1,
            _ => changed.image[0] ^= 1,
        }
        assert_ne!(changed, original);
        assert_ne!(changed.digest(), original.digest());
    }
}

// These socket fixtures exercise the actual nonblocking frame engine with
// private pairs. They deliberately do not bypass ExchangeGuard or claim a
// production authenticated shell/broker journey; that needs native CLI coverage.
#[test]
fn payload_limits_allow_exact_bound_and_reject_the_next_byte() {
    for cap in [ACTIVATION_REQUEST_CAP, ACTIVATION_REPLY_CAP] {
        for length in [0, 1, cap - 1, cap] {
            check_payload(&vec![0; length], cap).unwrap();
        }
        assert_eq!(
            check_payload(&vec![0; cap + 1], cap),
            Err(ActivationTransportError::PayloadTooLarge)
        );
    }
}

#[test]
fn an_oversized_wire_length_refuses_without_waiting_for_payload() {
    let (receiver, mut sender) = UnixStream::pair().unwrap();
    sender
        .write_all(&((ACTIVATION_REQUEST_CAP + 1) as u16).to_be_bytes())
        .unwrap();
    let mut io = BoundedIo::new(receiver).unwrap();
    assert_eq!(
        read_payload(
            &mut io,
            KEY,
            b"client-request",
            &transcript(),
            ACTIVATION_REQUEST_CAP
        ),
        Err(ActivationTransportError::PayloadTooLarge)
    );
}

#[test]
fn truncated_payload_and_tag_refuse() {
    for prefix in [0, 1, 2, 3, 4, 20, 35] {
        let (receiver, mut sender) = UnixStream::pair().unwrap();
        let mut bytes = 3u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&tag(KEY, b"client-request", &transcript(), b"abc"));
        sender.write_all(&bytes[..prefix]).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        let mut io = BoundedIo::new(receiver).unwrap();
        assert_eq!(
            read_payload(
                &mut io,
                KEY,
                b"client-request",
                &transcript(),
                ACTIVATION_REQUEST_CAP
            ),
            Err(ActivationTransportError::Connection)
        );
    }
}

#[test]
fn wire_mac_tampering_never_delivers_payload() {
    let (receiver, mut sender) = UnixStream::pair().unwrap();
    let transcript = transcript();
    let mut signature = tag(KEY, b"client-request", &transcript, b"abc");
    signature[31] ^= 1;
    sender.write_all(&3u16.to_be_bytes()).unwrap();
    sender.write_all(b"abc").unwrap();
    sender.write_all(&signature).unwrap();
    let mut io = BoundedIo::new(receiver).unwrap();
    assert_eq!(
        read_payload(
            &mut io,
            KEY,
            b"client-request",
            &transcript,
            ACTIVATION_REQUEST_CAP
        ),
        Err(ActivationTransportError::Authentication)
    );
}

#[test]
fn terminal_ack_keeps_server_live_until_client_post_reply_validation() {
    let (client, server) = UnixStream::pair().unwrap();
    let mut client = BoundedIo::new(client).unwrap();
    let mut server = BoundedIo::new(server).unwrap();
    let transcript = transcript();
    let request = vec![1; ACTIVATION_REQUEST_CAP];
    write_payload(
        &mut client,
        KEY,
        b"client-request",
        &transcript,
        &request,
        ACTIVATION_REQUEST_CAP,
    )
    .unwrap();
    let received = read_payload(
        &mut server,
        KEY,
        b"client-request",
        &transcript,
        ACTIVATION_REQUEST_CAP,
    )
    .unwrap();
    assert_eq!(received, request);
    let bound = bind_request(KEY, &transcript, &received);
    let reply = vec![2; ACTIVATION_REPLY_CAP];
    write_payload(
        &mut server,
        KEY,
        b"server-reply",
        &bound,
        &reply,
        ACTIVATION_REPLY_CAP,
    )
    .unwrap();
    assert_eq!(
        read_payload(
            &mut client,
            KEY,
            b"server-reply",
            &bound,
            ACTIVATION_REPLY_CAP
        )
        .unwrap(),
        reply
    );
    // Production now revalidates the server/context before writing this ACK.
    let acknowledgment = tag(KEY, b"client-complete", &bound, &reply);
    client.write_all(&acknowledgment).unwrap();
    client.finish_writing().unwrap();
    let mut observed = [0; TAG_LEN];
    server.read_exact(&mut observed).unwrap();
    verify_tag(KEY, b"client-complete", &bound, &reply, &observed).unwrap();
    server.require_eof().unwrap();
    // Production revalidates the client/context while the client awaits EOF.
    server.finish_writing().unwrap();
    client.require_eof().unwrap();
}

#[test]
fn pipelined_bytes_are_not_a_second_request_or_ignored_suffix() {
    let (receiver, mut sender) = UnixStream::pair().unwrap();
    sender.write_all(b"extra").unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        BoundedIo::new(receiver).unwrap().require_eof(),
        Err(ActivationTransportError::Frame)
    );
}

#[test]
fn expired_budget_refuses_even_already_buffered_io() {
    let (receiver, mut sender) = UnixStream::pair().unwrap();
    sender.write_all(b"buffered").unwrap();
    let mut io = BoundedIo::new(receiver).unwrap();
    io.deadline = Instant::now();
    assert_eq!(
        io.read_exact(&mut [0]),
        Err(ActivationTransportError::Deadline)
    );
    assert_eq!(io.write_all(b"x"), Err(ActivationTransportError::Deadline));
    assert_eq!(io.finish_writing(), Err(ActivationTransportError::Deadline));
    assert_eq!(io.require_eof(), Err(ActivationTransportError::Deadline));
}

#[test]
fn a_silent_peer_expires_without_a_new_budget() {
    let (receiver, _held_sender) = UnixStream::pair().unwrap();
    let mut io = BoundedIo::new(receiver).unwrap();
    // Test-only shortening avoids a full second per fixture. Production has no
    // caller-configurable deadline and keeps its one original Instant.
    io.deadline = Instant::now() + Duration::from_millis(5);
    let original = io.deadline;
    assert_eq!(
        io.read_exact(&mut [0]),
        Err(ActivationTransportError::Deadline)
    );
    assert_eq!(io.deadline, original);
    assert_eq!(io.require_eof(), Err(ActivationTransportError::Deadline));
}

#[test]
fn stream_is_nonblocking_after_acquisition() {
    let (receiver, _held_sender) = UnixStream::pair().unwrap();
    let io = BoundedIo::new(receiver).unwrap();
    let flags = unsafe { libc::fcntl(io.stream.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::O_NONBLOCK, 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn real_socketpair_credentials_identify_the_creator_not_a_claimed_pid() {
    let (first, second) = UnixStream::pair().unwrap();
    for stream in [&first, &second] {
        let credentials = peer_credentials(stream).unwrap();
        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.uid, unsafe { libc::geteuid() });
    }
    // Production additionally rejects this same-process pair; ordinary frame
    // engine tests above do not masquerade as a sibling authentication proof.
}
