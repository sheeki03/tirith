use tirith_core::effects::{CommandEffects, Completeness, IncompleteReason, SourceSpan};
use tirith_core::rules::web3::{
    parse_web3_commands, parse_web3_commands_v2, NetworkEvidence, RpcReference, RpcReferenceV2,
    SelectorSource, SignerKind, SignerReferenceV2, Web3CommandFacts, Web3JsonDecodeError,
    Web3Operation, Web3ParseContext, Web3ParseContextV2, Web3ParseResult, Web3ParseResultV2,
    Web3ToolFamily, Web3WriteMode, MAX_CONTEXT_SELECTORS, MAX_WEB3_PARSE_RESULT_JSON_BYTES,
    WEB3_PARSE_RESULT_SCHEMA_V2,
};
use tirith_core::tokenize::ShellType;

fn exhaustive_v1_operation(operation: Web3Operation) -> u8 {
    match operation {
        Web3Operation::Send => 0,
        Web3Operation::Create => 1,
        Web3Operation::Call => 2,
        Web3Operation::Balance => 3,
        Web3Operation::Code => 4,
        Web3Operation::MakeTransaction => 5,
        Web3Operation::Script => 6,
        Web3Operation::IgnitionDeploy => 7,
        Web3Operation::PluginDeploy => 8,
        Web3Operation::RunScript => 9,
        Web3Operation::ProgramDeploy => 10,
        Web3Operation::ProgramShow => 11,
        Web3Operation::ProgramDump => 12,
        Web3Operation::Query => 13,
        Web3Operation::AnchorDeploy => 14,
        Web3Operation::Build => 15,
        Web3Operation::Test => 16,
        Web3Operation::Unknown => 17,
    }
}

fn exhaustive_v1_signer_kind(kind: SignerKind) -> u8 {
    match kind {
        SignerKind::RawPrivateKey => 0,
        SignerKind::RawKeypair => 1,
        SignerKind::Mnemonic => 2,
        SignerKind::KeypairFile => 3,
        SignerKind::Keystore => 4,
        SignerKind::Ledger => 5,
        SignerKind::Trezor => 6,
        SignerKind::AwsKms => 7,
        SignerKind::UnlockedNode => 8,
        SignerKind::AccountAlias => 9,
        SignerKind::Unknown => 10,
    }
}

fn exhaustive_v1_incomplete_reason(reason: IncompleteReason) -> u8 {
    match reason {
        IncompleteReason::SegmentBudgetExceeded => 0,
        IncompleteReason::WrapperDepthExceeded => 1,
        IncompleteReason::PackageRunnerDepthExceeded => 2,
        IncompleteReason::ArgumentCountExceeded => 3,
        IncompleteReason::ArgumentBytesExceeded => 4,
        IncompleteReason::ConfigBytesExceeded => 5,
        IncompleteReason::AliasResolutionBudgetExceeded => 6,
        IncompleteReason::ContextSelectorBudgetExceeded => 7,
        IncompleteReason::SelectorBytesExceeded => 8,
        IncompleteReason::MissingFlagValue => 9,
        IncompleteReason::ConflictingSelector => 10,
        IncompleteReason::UnknownOption => 11,
        IncompleteReason::AmbiguousSubcommand => 12,
        IncompleteReason::UnresolvedIndirection => 13,
        IncompleteReason::IncompleteQuoting => 14,
        IncompleteReason::DynamicConfigUnsupported => 15,
        IncompleteReason::ConfigMissing => 16,
        IncompleteReason::ConfigNotRegular => 17,
        IncompleteReason::ConfigMalformed => 18,
        IncompleteReason::ConfigIo => 19,
    }
}

#[test]
fn schema_v1_public_struct_literals_and_entry_point_remain_source_compatible() {
    let completeness = Completeness::complete();
    let rpc = RpcReference {
        scheme: Some("https".to_string()),
        host: Some("rpc.example".to_string()),
        port: Some(443),
        path: Some("/rpc".to_string()),
        alias: None,
        source: SelectorSource::ExplicitFlag,
        span: Some(SourceSpan::new(0, 4)),
    };
    let command = Web3CommandFacts {
        tool: Web3ToolFamily::Cast,
        operation: Web3Operation::Balance,
        write_mode: Web3WriteMode::ReadOnly,
        network: NetworkEvidence::default(),
        rpc: Some(rpc),
        signer: None,
        destination: None,
        artifact: None,
        safety_flags: Vec::new(),
        source_span: SourceSpan::new(0, 18),
        completeness: completeness.clone(),
    };
    let constructed = Web3ParseResult {
        commands: vec![command],
        effects: CommandEffects::default(),
        completeness,
    };
    assert_eq!(constructed.commands.len(), 1);

    let context = Web3ParseContext {
        cwd: None,
        environment: Default::default(),
        ambient_selectors: Default::default(),
        foundry_config_path: None,
        solana_config_path: None,
        anchor_config_path: None,
        static_config_enabled: false,
    };
    let parsed: Web3ParseResult =
        parse_web3_commands("cast balance 0xabc", ShellType::Posix, &context);
    assert_eq!(parsed.commands.len(), 1);
    assert_eq!(exhaustive_v1_operation(Web3Operation::Query), 13);
    assert_eq!(exhaustive_v1_signer_kind(SignerKind::Unknown), 10);
    assert_eq!(
        exhaustive_v1_incomplete_reason(IncompleteReason::ConfigIo),
        19
    );
    for wire in [
        "send",
        "create",
        "call",
        "balance",
        "code",
        "make_transaction",
        "script",
        "ignition_deploy",
        "plugin_deploy",
        "run_script",
        "program_deploy",
        "program_show",
        "program_dump",
        "query",
        "anchor_deploy",
        "build",
        "test",
        "unknown",
    ] {
        serde_json::from_value::<Web3Operation>(serde_json::json!(wire)).unwrap();
    }
    for wire in [
        "raw_private_key",
        "raw_keypair",
        "mnemonic",
        "keypair_file",
        "keystore",
        "ledger",
        "trezor",
        "aws_kms",
        "unlocked_node",
        "account_alias",
        "unknown",
    ] {
        serde_json::from_value::<SignerKind>(serde_json::json!(wire)).unwrap();
    }
    for wire in [
        "segment_budget_exceeded",
        "wrapper_depth_exceeded",
        "package_runner_depth_exceeded",
        "argument_count_exceeded",
        "argument_bytes_exceeded",
        "config_bytes_exceeded",
        "alias_resolution_budget_exceeded",
        "context_selector_budget_exceeded",
        "selector_bytes_exceeded",
        "missing_flag_value",
        "conflicting_selector",
        "unknown_option",
        "ambiguous_subcommand",
        "unresolved_indirection",
        "incomplete_quoting",
        "dynamic_config_unsupported",
        "config_missing",
        "config_not_regular",
        "config_malformed",
        "config_io",
    ] {
        serde_json::from_value::<IncompleteReason>(serde_json::json!(wire)).unwrap();
    }
    assert!(serde_json::from_value::<Web3Operation>(serde_json::json!("address")).is_err());
    assert!(serde_json::from_value::<SignerKind>(serde_json::json!("stdin")).is_err());
    assert!(serde_json::from_value::<SignerKind>(serde_json::json!("prompt")).is_err());
    assert!(
        serde_json::from_value::<IncompleteReason>(serde_json::json!("input_bytes_exceeded"))
            .is_err()
    );
    assert!(
        serde_json::from_value::<IncompleteReason>(serde_json::json!("effect_budget_exceeded"))
            .is_err()
    );

    let legacy_wire = serde_json::json!({
        "commands": [{
            "tool": "solana",
            "operation": "query",
            "write_mode": "read_only",
            "network": {"network": null, "chain": null},
            "rpc": null,
            "signer": {
                "kind": "keypair_file",
                "source": "static_config",
                "span": null,
                "reference": "wallet.json"
            },
            "destination": null,
            "artifact": null,
            "safety_flags": [],
            "source_span": {"start": 0, "end": 10},
            "completeness": {"gaps": []}
        }],
        "effects": {"effects": [], "completeness": {"gaps": []}},
        "completeness": {"gaps": []}
    });
    let legacy_wire = serde_json::to_vec(&legacy_wire).unwrap();
    let decoded = Web3ParseResult::from_json_slice_bounded(&legacy_wire).unwrap();
    assert_eq!(decoded.commands[0].operation, Web3Operation::Query);
    assert_eq!(
        decoded.commands[0].signer.as_ref().unwrap().kind(),
        SignerKind::KeypairFile
    );
}

#[test]
fn schema_v1_context_maps_and_values_are_bounded_before_projection() {
    let mut too_many = Web3ParseContext::without_filesystem();
    for index in 0..=MAX_CONTEXT_SELECTORS {
        too_many
            .environment
            .insert(format!("SELECTOR_{index}"), "value".to_string());
    }
    let capped = parse_web3_commands("cast balance 0xabc", ShellType::Posix, &too_many);
    assert!(capped
        .completeness
        .gaps()
        .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded));

    let oversized = format!("https://oversized.example/{}", "x".repeat(16 * 1024));
    let mut oversized_value = Web3ParseContext::without_filesystem();
    oversized_value
        .environment
        .insert("ETH_RPC_URL".to_string(), oversized.clone());
    let bounded = parse_web3_commands("cast balance 0xabc", ShellType::Posix, &oversized_value);
    assert!(bounded
        .completeness
        .gaps()
        .any(|gap| gap == IncompleteReason::SelectorBytesExceeded));
    assert!(!serde_json::to_string(&bounded)
        .unwrap()
        .contains(&oversized));
}

#[test]
fn schema_v2_is_discriminated_and_old_new_wire_shapes_negotiate() {
    let v2 = parse_web3_commands_v2(
        "cast balance 0xabc",
        ShellType::Posix,
        &Web3ParseContextV2::without_filesystem(),
    );
    let encoded = serde_json::to_value(&v2).unwrap();
    assert_eq!(
        encoded
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(WEB3_PARSE_RESULT_SCHEMA_V2))
    );

    let encoded_json = serde_json::to_vec(&encoded).unwrap();
    let decoded_v2 = Web3ParseResultV2::from_json_slice_bounded(&encoded_json).unwrap();
    let decoded_v1 = Web3ParseResult::from_json_slice_bounded(&encoded_json).unwrap();
    assert_eq!(decoded_v2.commands.len(), 1);
    assert_eq!(decoded_v1.commands.len(), 1);

    let schema_last = format!(
        "{{\"commands\":{},\"effects\":{},\"completeness\":{},\"schema_version\":2}}",
        serde_json::to_string(&decoded_v2.commands).unwrap(),
        serde_json::to_string(&decoded_v2.effects).unwrap(),
        serde_json::to_string(&decoded_v2.completeness).unwrap(),
    );
    let reordered = Web3ParseResultV2::from_json_slice_bounded(schema_last.as_bytes()).unwrap();
    assert_eq!(reordered.commands.len(), 1);

    let legacy_wire = serde_json::to_value(&decoded_v1).unwrap();
    assert!(legacy_wire.get("schema_version").is_none());
    let legacy_wire = serde_json::to_vec(&legacy_wire).unwrap();
    let upgraded = Web3ParseResultV2::from_json_slice_bounded(&legacy_wire).unwrap();
    assert_eq!(upgraded.commands.len(), 1);

    let mut explicit_v1 = serde_json::to_value(&decoded_v1).unwrap();
    explicit_v1["schema_version"] = serde_json::json!(1);
    let explicit_v1 = serde_json::to_vec(&explicit_v1).unwrap();
    assert_eq!(
        Web3ParseResultV2::from_json_slice_bounded(&explicit_v1)
            .unwrap()
            .commands
            .len(),
        1
    );

    let mut v2_as_v1 = encoded.clone();
    v2_as_v1["schema_version"] = serde_json::json!(1);
    assert!(
        Web3ParseResultV2::from_json_slice_bounded(&serde_json::to_vec(&v2_as_v1).unwrap())
            .is_err()
    );

    let mut v2_operation_as_v1 = serde_json::to_value(&decoded_v1).unwrap();
    v2_operation_as_v1["schema_version"] = serde_json::json!(1);
    v2_operation_as_v1["commands"][0]["operation"] = serde_json::json!("address");
    assert!(Web3ParseResultV2::from_json_slice_bounded(
        &serde_json::to_vec(&v2_operation_as_v1).unwrap()
    )
    .is_err());

    let mut unsupported = serde_json::to_value(v2).unwrap();
    unsupported["schema_version"] = serde_json::json!(99);
    let unsupported = serde_json::to_vec(&unsupported).unwrap();
    assert!(Web3ParseResultV2::from_json_slice_bounded(&unsupported).is_err());
}

#[test]
fn schema_v2_bounded_json_decode_rejects_limits_and_unsupported_versions_first() {
    let huge = "x".repeat(16 * 1024 + 1);
    assert!(serde_json::from_value::<RpcReferenceV2>(serde_json::json!({
        "scheme": null,
        "host": null,
        "port": null,
        "path": null,
        "path_class": "unknown",
        "path_match_outcomes": [],
        "alias": huge,
        "source": "unresolved",
        "span": null
    }))
    .is_err());
    let escaped_alias = "\\u0061".repeat(16 * 1024 + 1);
    let raw_rpc = format!(
        "{{\"scheme\":null,\"host\":null,\"port\":null,\"path\":null,\"path_class\":\"unknown\",\"path_match_outcomes\":[],\"alias\":\"{escaped_alias}\",\"source\":\"unresolved\",\"span\":null}}"
    );
    assert!(serde_json::from_str::<RpcReferenceV2>(&raw_rpc).is_err());
    assert!(
        serde_json::from_value::<SignerReferenceV2>(serde_json::json!({
            "kind": "keypair_file",
            "source": "static_config",
            "span": null,
            "reference": "x".repeat(16 * 1024 + 1)
        }))
        .is_err()
    );

    let parsed = parse_web3_commands_v2(
        "cast balance 0xabc",
        ShellType::Posix,
        &Web3ParseContextV2::without_filesystem(),
    );
    let encoded = serde_json::to_value(parsed).unwrap();
    let mut too_many_flags = encoded.clone();
    too_many_flags["commands"][0]["safety_flags"] =
        serde_json::Value::Array(vec![serde_json::json!("broadcast"); 65]);
    let too_many_flags = serde_json::to_vec(&too_many_flags).unwrap();
    assert!(Web3ParseResultV2::from_json_slice_bounded(&too_many_flags).is_err());

    let mut too_many_commands = encoded.clone();
    too_many_commands["commands"] =
        serde_json::Value::Array(vec![encoded["commands"][0].clone(); 257]);
    let too_many_commands = serde_json::to_vec(&too_many_commands).unwrap();
    assert!(Web3ParseResultV2::from_json_slice_bounded(&too_many_commands).is_err());

    let effect = serde_json::json!({
        "kind": "network_egress",
        "source": {"kind": "command_operation", "span": null},
        "enforceability": "observe_only",
        "completeness": {"gaps": []}
    });
    let mut too_many_effects = encoded;
    too_many_effects["effects"]["effects"] = serde_json::Value::Array(vec![effect; 513]);
    let too_many_effects = serde_json::to_vec(&too_many_effects).unwrap();
    assert!(Web3ParseResultV2::from_json_slice_bounded(&too_many_effects).is_err());

    let unsupported = format!(
        "{{\"commands\":\"{}\",\"schema_version\":99}}",
        "z".repeat(2 * 1024 * 1024)
    );
    let error = Web3ParseResultV2::from_json_slice_bounded(unsupported.as_bytes()).unwrap_err();
    assert!(matches!(
        &error,
        Web3JsonDecodeError::InvalidJson(category) if category == "unsupported_schema"
    ));
    assert!(!error.to_string().contains("99"));

    let escaped = "\\u0061".repeat(16 * 1024 + 1);
    let supported_oversized_string = format!(
        "{{\"schema_version\":2,\"commands\":[],\"effects\":{{\"effects\":[],\"completeness\":{{\"gaps\":[]}},\"ignored\":\"{escaped}\"}},\"completeness\":{{\"gaps\":[]}}}}"
    );
    let error = Web3ParseResultV2::from_json_slice_bounded(supported_oversized_string.as_bytes())
        .unwrap_err();
    assert!(matches!(
        &error,
        Web3JsonDecodeError::InvalidJson(category) if category == "string_budget_exceeded"
    ));

    for malformed in [
        r#"{"schema_version":2,"commands":[],"effects":{"effects":[],"completeness":{"gaps":[]}},"completeness":{"gaps":[]},"ignored":wat}"#,
        r#"{"schema_version":01,"commands":[],"effects":{"effects":[],"completeness":{"gaps":[]}},"completeness":{"gaps":[]}}"#,
    ] {
        let error = Web3ParseResultV2::from_json_slice_bounded(malformed.as_bytes()).unwrap_err();
        assert!(matches!(
            &error,
            Web3JsonDecodeError::InvalidJson(category) if category == "invalid_syntax"
        ));
    }

    let secret = "must-not-appear-in-errors";
    let secret_bearing_invalid = format!(
        r#"{{"schema_version":2,"commands":[{{"tool":"{secret}"}}],"effects":{{"effects":[],"completeness":{{"gaps":[]}}}},"completeness":{{"gaps":[]}}}}"#
    );
    let error =
        Web3ParseResultV2::from_json_slice_bounded(secret_bearing_invalid.as_bytes()).unwrap_err();
    assert!(matches!(
        &error,
        Web3JsonDecodeError::InvalidJson(category) if category == "invalid_schema_v2"
    ));
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));

    let valid_unknown = r#"{"schema_version":2,"commands":[],"effects":{"effects":[],"completeness":{"gaps":[]}},"completeness":{"gaps":[]},"ignored":{"future":[true,null,-1.2e3]}}"#;
    assert!(Web3ParseResultV2::from_json_slice_bounded(valid_unknown.as_bytes()).is_ok());

    let oversized_reader = std::io::Cursor::new(vec![b' '; MAX_WEB3_PARSE_RESULT_JSON_BYTES + 1]);
    let error = Web3ParseResultV2::from_json_reader_bounded(oversized_reader).unwrap_err();
    assert!(matches!(
        error,
        Web3JsonDecodeError::InputBytesExceeded {
            limit: MAX_WEB3_PARSE_RESULT_JSON_BYTES
        }
    ));
}
