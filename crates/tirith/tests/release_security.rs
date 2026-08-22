//! Release-profile security controls that must survive the CLI's default
//! feature graph. The release workflow runs this target with `--release` before
//! packaging so a feature-gated security regression cannot ship silently.

use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use tirith_core::artifact::{ArtifactIdentity, ArtifactInspection, InspectionSubject};
use tirith_core::threatdb::{
    Confidence, Ecosystem, ThreatDb, ThreatDbFormat, ThreatDbWriter, ThreatSource,
};
use tirith_core::verdict::{action_from_findings, Action, RuleId, Severity};

#[test]
fn default_cli_feature_graph_blocks_a_known_malicious_artifact_hash() {
    let malicious_sha = [0xA5; 32];
    let signing_key = SigningKey::from_bytes(&[0x17; 32]);
    let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
    writer.add_artifact_sha256(
        malicious_sha,
        ThreatSource::OssfMalicious,
        Confidence::Confirmed,
        true,
        Some("release-regression"),
    );
    let bytes = writer
        .build_format(ThreatDbFormat::V2, &signing_key)
        .expect("build signed v2 test database");
    let db = ThreatDb::from_bytes(bytes, 0).expect("load signed v2 test database");

    let inspection = ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
        ecosystem: Ecosystem::PyPI,
        name: "release-regression".to_string(),
        version: Some("1.0.0".to_string()),
        filename: "release_regression-1.0.0-py3-none-any.whl".to_string(),
        sha256: malicious_sha
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }));
    let findings = tirith_core::artifact::correlate::correlate_inspection_findings(
        &inspection,
        &[],
        Some(&db),
    );

    assert!(findings.iter().any(|finding| {
        finding.rule_id == RuleId::ArtifactKnownMalicious && finding.severity == Severity::Critical
    }));
    assert_eq!(action_from_findings(&findings), Action::Block);
}

fn yaml_key<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> &'a serde_yaml::Value {
    mapping
        .get(serde_yaml::Value::String(key.to_string()))
        .unwrap_or_else(|| panic!("YAML mapping is missing {key:?}"))
}

fn workflow_job<'a>(jobs: &'a serde_yaml::Mapping, name: &str) -> &'a serde_yaml::Mapping {
    yaml_key(jobs, name)
        .as_mapping()
        .unwrap_or_else(|| panic!("workflow job {name:?} must be a mapping"))
}

fn joined_run_scripts(job: &serde_yaml::Mapping) -> String {
    yaml_key(job, "steps")
        .as_sequence()
        .expect("workflow job steps sequence")
        .iter()
        .filter_map(|step| {
            step.as_mapping()?
                .get(serde_yaml::Value::String("run".to_string()))?
                .as_str()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn uses_is_immutably_pinned(uses: &str) -> bool {
    if uses.starts_with("./") {
        return true;
    }
    if let Some(image) = uses.strip_prefix("docker://") {
        let digest = image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .unwrap_or_default();
        return digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    let revision = uses
        .rsplit_once('@')
        .map(|(_, revision)| revision)
        .unwrap_or_default();
    revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn assert_immutable_action_reference(
    config_path: &std::path::Path,
    location: &str,
    value: &serde_yaml::Value,
) {
    let uses = value.as_str().unwrap_or_else(|| {
        panic!(
            "action reference at {}:{location} must be a string, got {value:?}",
            config_path.display()
        )
    });
    assert!(
        uses_is_immutably_pinned(uses),
        "action reference at {}:{location} ({uses:?}) must be a local path, a full commit SHA, or a sha256-digest container",
        config_path.display()
    );
}

fn assert_composite_action_uses_are_immutable(
    action_path: &std::path::Path,
    document: &serde_yaml::Value,
) {
    let root = document
        .as_mapping()
        .expect("composite action root mapping");
    let runs = yaml_key(root, "runs")
        .as_mapping()
        .expect("composite action runs mapping");
    let steps = yaml_key(runs, "steps")
        .as_sequence()
        .expect("composite action steps sequence");

    for (index, step) in steps.iter().enumerate() {
        let step = step.as_mapping().expect("composite action step mapping");
        // Skip only when the key is absent. Folding a non-string value into the
        // same `continue` would let `uses: 123` pass the pinning gate unchecked.
        let Some(value) = step.get(serde_yaml::Value::String("uses".to_string())) else {
            continue;
        };
        assert_immutable_action_reference(action_path, &format!("runs.steps[{index}].uses"), value);
    }
}

fn assert_workflow_uses_are_immutable(
    workflow_path: &std::path::Path,
    document: &serde_yaml::Value,
) {
    let root = document.as_mapping().expect("workflow root mapping");
    let jobs = yaml_key(root, "jobs")
        .as_mapping()
        .expect("workflow jobs mapping");

    for (job_name, job) in jobs {
        let job_name = job_name.as_str().expect("string workflow job name");
        let job = job.as_mapping().expect("workflow job mapping");

        // Reusable workflows are referenced directly from a job.
        if let Some(value) = job.get(serde_yaml::Value::String("uses".to_string())) {
            assert_immutable_action_reference(
                workflow_path,
                &format!("jobs.{job_name}.uses"),
                value,
            );
        }

        let Some(steps) = job.get(serde_yaml::Value::String("steps".to_string())) else {
            continue;
        };
        let steps = steps.as_sequence().unwrap_or_else(|| {
            panic!(
                "workflow steps at {}:jobs.{job_name}.steps must be a sequence, got {steps:?}",
                workflow_path.display()
            )
        });
        for (index, step) in steps.iter().enumerate() {
            let step = step.as_mapping().unwrap_or_else(|| {
                panic!(
                    "workflow step at {}:jobs.{job_name}.steps[{index}] must be a mapping, got {step:?}",
                    workflow_path.display()
                )
            });
            let Some(value) = step.get(serde_yaml::Value::String("uses".to_string())) else {
                continue;
            };
            assert_immutable_action_reference(
                workflow_path,
                &format!("jobs.{job_name}.steps[{index}].uses"),
                value,
            );
        }
    }
}

#[test]
fn github_automation_keeps_all_action_references_immutably_pinned() {
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let action_path = repository_root.join("action.yml");
    let action = std::fs::read_to_string(&action_path).expect("read composite action");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&action).expect("composite action must be valid YAML");
    assert_composite_action_uses_are_immutable(&action_path, &document);

    let workflows_path = repository_root.join(".github/workflows");
    let mut workflow_paths: Vec<_> = std::fs::read_dir(&workflows_path)
        .expect("read workflow directory")
        .map(|entry| entry.expect("read workflow directory entry").path())
        .filter(|path| {
            matches!(
                path.extension().and_then(std::ffi::OsStr::to_str),
                Some("yml" | "yaml")
            )
        })
        .collect();
    workflow_paths.sort();
    assert!(
        !workflow_paths.is_empty(),
        "no GitHub Actions workflows found under {}",
        workflows_path.display()
    );

    for workflow_path in workflow_paths {
        assert!(
            workflow_path.is_file(),
            "workflow path must be a regular file: {}",
            workflow_path.display()
        );
        let workflow = std::fs::read_to_string(&workflow_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", workflow_path.display()));
        let document: serde_yaml::Value = serde_yaml::from_str(&workflow)
            .unwrap_or_else(|error| panic!("parse {} as YAML: {error}", workflow_path.display()));
        assert_workflow_uses_are_immutable(&workflow_path, &document);
    }
}

#[test]
fn mutable_docker_tags_are_not_immutable_pins() {
    assert!(!uses_is_immutably_pinned(
        "docker://ghcr.io/example/tool:latest"
    ));
    assert!(uses_is_immutably_pinned(&format!(
        "docker://ghcr.io/example/tool@sha256:{}",
        "ab".repeat(32)
    )));
    assert!(uses_is_immutably_pinned(
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    ));
    assert!(uses_is_immutably_pinned(
        "github/codeql-action/upload-sarif@f3712979fa5f215279b101dd0a2e3bdfb4353324"
    ));
    assert!(!uses_is_immutably_pinned("actions/checkout@v7"));
    assert!(!uses_is_immutably_pinned("actions/checkout@main"));
    assert!(!uses_is_immutably_pinned("actions/checkout"));
}

#[test]
fn release_workflow_keeps_manual_dispatch_non_publishing() {
    let workflow_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(".github/workflows/release.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("read release workflow");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&workflow).expect("release workflow must be valid YAML");
    let root = document
        .as_mapping()
        .expect("release workflow root mapping");

    let triggers = yaml_key(root, "on")
        .as_mapping()
        .expect("release workflow trigger mapping");
    let push = yaml_key(triggers, "push")
        .as_mapping()
        .expect("release push trigger mapping");
    let tags = yaml_key(push, "tags")
        .as_sequence()
        .expect("release tag filter");
    assert_eq!(
        tags,
        &[serde_yaml::Value::String("v*".to_string())],
        "release pushes must remain version-tag-only"
    );

    let pull_request = yaml_key(triggers, "pull_request")
        .as_mapping()
        .expect("release pull-request trigger mapping");
    let pull_request_paths = yaml_key(pull_request, "paths")
        .as_sequence()
        .expect("release pull-request path filter");
    assert!(
        !pull_request_paths.is_empty(),
        "release pull requests must remain path-filtered"
    );
    for required_path in [
        ".github/workflows/release.yml",
        ".github/scripts/smoke-linux-release.sh",
        ".github/scripts/verify-glibc-compat.sh",
    ] {
        assert!(
            pull_request_paths
                .iter()
                .any(|path| path.as_str() == Some(required_path)),
            "release pull-request path filter must include {required_path:?}"
        );
    }

    // Manual dispatch must offer no inputs. Publication is gated on
    // `github.event_name == 'push'` below, so no dispatch option can turn it
    // on; a knob that looks like it might is worse than no knob, because a
    // release engineer reading it would believe the default is what protects
    // them rather than the event gate.
    let dispatch = yaml_key(triggers, "workflow_dispatch");
    assert!(
        dispatch.is_null()
            || dispatch
                .as_mapping()
                .is_some_and(|mapping| mapping.is_empty()),
        "manual dispatch must declare no inputs, got {dispatch:?}"
    );

    // These jobs only build or validate artifacts. Every other current or future
    // job is part of the fuzz, package-attestation, or publication boundary and
    // must require a real push event as well as a v* ref. This catches a manual
    // dispatch that selects an existing tag: `github.ref` alone is not an
    // adequate publication gate.
    const PUBLICATION_GATE: &str =
        "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')";

    let dry_run_jobs: HashSet<&str> = [
        "enforcement-check",
        "completions",
        "build",
        "smoke-test",
        "linux-runtime-compat",
        "build-deb",
        "build-rpm",
        "rpm-runtime-compat",
        "release-validation",
    ]
    .into_iter()
    .collect();
    let jobs = yaml_key(root, "jobs")
        .as_mapping()
        .expect("release workflow jobs mapping");
    for (job_name, job) in jobs {
        let job_name = job_name.as_str().expect("string release job name");
        if dry_run_jobs.contains(job_name) {
            continue;
        }
        let job = job.as_mapping().expect("release job mapping");
        let condition = yaml_key(job, "if")
            .as_str()
            .expect("publication job condition");
        // Exact match, not `contains`. A substring test passes for
        // `(push && tag) || workflow_dispatch`, which is precisely the shape
        // that would hand publication to anyone who can press Run workflow —
        // and it is already the shape the build-only jobs above use, so it is
        // one copy-paste away at all times.
        let normalized = condition.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            normalized, PUBLICATION_GATE,
            "release job {job_name:?} must carry exactly the pushed-v*-tag gate, got {condition:?}"
        );
    }
}

#[test]
fn linux_release_keeps_glibc_and_canonical_package_contracts() {
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow_path = repository_root.join(".github/workflows/release.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("read release workflow");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&workflow).expect("release workflow must be valid YAML");
    let root = document
        .as_mapping()
        .expect("release workflow root mapping");
    let jobs = yaml_key(root, "jobs")
        .as_mapping()
        .expect("release workflow jobs mapping");

    let build = workflow_job(jobs, "build");
    let build_matrix = yaml_key(
        yaml_key(build, "strategy")
            .as_mapping()
            .expect("build strategy mapping"),
        "matrix",
    )
    .as_mapping()
    .expect("build matrix mapping");
    let build_targets: HashSet<&str> = yaml_key(build_matrix, "include")
        .as_sequence()
        .expect("build matrix include sequence")
        .iter()
        .map(|row| {
            yaml_key(
                row.as_mapping().expect("build matrix row mapping"),
                "target",
            )
            .as_str()
            .expect("build target string")
        })
        .collect();
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        assert!(
            build_targets.contains(target),
            "GNU release matrix must keep {target}"
        );
    }

    let build_runs = joined_run_scripts(build);
    assert!(
        build_runs.contains("cargo zigbuild --release --locked --bins")
            && build_runs.contains("--target ${{ matrix.target }}.2.28"),
        "both GNU architectures must be linked through the explicit GLIBC 2.28 Zig target"
    );
    for verified_tool_contract in [
        "CARGO_ZIGBUILD_VERSION: \"0.19.8\"",
        "CARGO_ZIGBUILD_SHA256: 72cc1bd7d42819641db917977b0a7025c9e95e1cc7d19bab79af4a875b5eaa6e",
        "ZIG_VERSION: \"0.13.0\"",
        "ZIG_SHA256: d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea",
        "CARGO_DEB_VERSION: \"3.7.0\"",
        "CARGO_DEB_SHA256: a40a401a79fd1bd9d2cb41fd783d0c80f3504f657002bfae49dfd55049dce8f8",
    ] {
        assert!(
            workflow.contains(verified_tool_contract),
            "release tool acquisition must retain verified contract {verified_tool_contract:?}"
        );
    }
    assert!(
        !build_runs.contains(".2.17"),
        "the rejected GLIBC 2.17 link target must not return to an executable step"
    );
    assert!(
        build_runs.contains("verify-glibc-compat.sh \"$ARCH\" 2.28 staging"),
        "every staged GNU ELF must retain the GLIBC 2.28 scan"
    );
    for required in [
        "qemu-aarch64-static \"$BIN\" capsule run",
        "CAPSULE_RC",
        "REFUSED before launch (nothing was copied or spawned)",
        "missing: network_raw_denied",
        "TIRITH_CAPSULE_CHILD_MUST_NOT_RUN",
    ] {
        assert!(
            build_runs.contains(required),
            "aarch64 musl smoke must retain fail-closed contract fragment {required:?}"
        );
    }

    let runtime = workflow_job(jobs, "linux-runtime-compat");
    let runtime_matrix = yaml_key(
        yaml_key(runtime, "strategy")
            .as_mapping()
            .expect("runtime strategy mapping"),
        "matrix",
    )
    .as_mapping()
    .expect("runtime matrix mapping");
    let mut runtime_pairs = HashSet::new();
    for row in yaml_key(runtime_matrix, "include")
        .as_sequence()
        .expect("runtime matrix include sequence")
    {
        let row = row.as_mapping().expect("runtime matrix row mapping");
        let distro = yaml_key(row, "distro").as_str().expect("runtime distro");
        let arch = yaml_key(row, "arch").as_str().expect("runtime arch");
        let image = yaml_key(row, "image").as_str().expect("runtime image");
        let digest = image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .unwrap_or_default();
        assert!(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "runtime image for {distro}/{arch} must remain digest-pinned"
        );
        runtime_pairs.insert((distro, arch));
    }
    let expected_runtime_pairs: HashSet<_> = [
        ("almalinux-8", "x86_64"),
        ("almalinux-8", "aarch64"),
        ("amazonlinux-2023", "x86_64"),
        ("amazonlinux-2023", "aarch64"),
        ("rocky-9", "x86_64"),
        ("rocky-9", "aarch64"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        runtime_pairs, expected_runtime_pairs,
        "runtime proof must cover both GNU architectures on EL8, Amazon Linux 2023, and Rocky 9"
    );
    for qemu_contract in [
        "image: tonistiigi/binfmt:qemu-v9.2.0@sha256:ea2f0dd74e74f101df59f9a6b31d0960994060c7982a921cbceecee0f1841125",
        "platforms: arm64",
        "cache-image: false",
    ] {
        assert!(
            workflow.contains(qemu_contract),
            "aarch64 runtime proof must retain pinned QEMU contract {qemu_contract:?}"
        );
    }

    for (job_name, expected_paths) in [
        (
            "build-deb",
            [
                "deb-extract/usr/bin/tirith",
                "deb-extract/usr/libexec/tirith-package-approval-authority",
            ],
        ),
        (
            "build-rpm",
            [
                "usr/bin/tirith",
                "usr/libexec/tirith-package-approval-authority",
            ],
        ),
    ] {
        let runs = joined_run_scripts(workflow_job(jobs, job_name));
        assert!(
            runs.matches("cmp --silent").count() >= 2,
            "{job_name} must byte-compare both packaged executables"
        );
        for path in expected_paths {
            assert!(
                runs.contains(path),
                "{job_name} must verify canonical identity for {path}"
            );
        }
        assert!(
            runs.contains("verify-glibc-compat.sh") && runs.contains("2.28"),
            "{job_name} must scan every packaged ELF against GLIBC 2.28"
        );
    }
    let rpm_runs = joined_run_scripts(workflow_job(jobs, "build-rpm"));
    assert!(
        rpm_runs.contains("--define \"__strip /bin/true\"")
            && !rpm_runs.contains("cargo build")
            && !rpm_runs.contains("cargo zigbuild"),
        "RPM creation must package canonical bytes without stripping or a distro-native Rust relink"
    );
    assert!(
        rpm_runs.contains(r#"${GITHUB_WORKSPACE}:/workspace:ro"#)
            && rpm_runs.contains(r#"${rpm_output}:/output"#)
            && rpm_runs.contains(r#"rpm_output="${RUNNER_TEMP}/tirith-rpm-output""#),
        "the RPM tool container must receive a read-only checkout and a narrowly writable output mount"
    );

    let smoke_path = repository_root.join(".github/scripts/smoke-linux-release.sh");
    let smoke = std::fs::read_to_string(smoke_path).expect("read Linux release smoke script");
    for required in [
        "$(uname -m)\" == \"aarch64",
        "capsule run",
        "capsule_rc -ne 1",
        "REFUSED before launch (nothing was copied or spawned)",
        "missing: network_raw_denied",
        "TIRITH_CAPSULE_CHILD_MUST_NOT_RUN",
    ] {
        assert!(
            smoke.contains(required),
            "aarch64 runtime smoke must retain fail-closed contract fragment {required:?}"
        );
    }
}
