# Lab artifact fixtures

Synthetic, inert byte-level fixtures for `tirith lab` artifact scenarios (plan
unit G2). These exercise the wheel / `.pth` / native-`.so` inspection pipeline
(`tirith_core::artifact::inspect_artifact_set` plus `all_findings` and
`finalize_static_verdict`) the same way the package firewall does, but over
hand-built bytes that contain no real payload.

## What these are NOT

- Not real malware. No fixture downloads, executes, or contacts anything.
- Every network-shaped string uses the reserved `example.invalid` domain
  (RFC 6761), so even a copy-paste accident reaches nothing routable.
- Native `.so` fixtures are hand-rolled ELF object files with a constructor
  section and capability strings in `.rodata`. They are parsed by `object` for
  static facts only; they are never loaded or run.

## How the fixtures are materialized

`crates/tirith/src/cli/lab_artifacts.rs` reads the inert source members in this
directory and zips them into wheels (and synthesizes the `.so` bytes) into a
per-run temp directory at lab time. Nothing here is a prebuilt binary: the
checked-in bytes are the reviewable plain-text members, and the wheel/ELF
wrapping is mechanical and deterministic. The lab then inspects the resulting
`.whl` files through the real artifact pipeline.

## Members

| Source | Role |
| --- | --- |
| `pth_cross_runtime.pth` | a `.pth` whose import line launches a cross-runtime (node) payload via `os.system` (Critical `PythonStartupHookCrossRuntime`) |
| `pth_subprocess.pth` | a `.pth` whose import line spawns a subprocess + reaches a URL (High `PythonStartupHookSuspicious`) |
| `pth_benign_editable.pth` | a benign editable-install `.pth` (negative control, no finding) |
| `loader_cross_dist.pth` | a sys.path-searching loader `.pth` that names a payload member owned by a SEPARATE wheel (drives the cross-distribution split) |

The benign and malicious wheels, the cross-distribution loader/payload pair, and
the native-`.so` wheel are assembled in `lab_artifacts.rs` from these members
plus generated `METADATA` / `WHEEL` / `RECORD` and ELF bytes.
