# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-02-04

### Fixed

- Shell hooks now reliably display block/warn messages in all terminal contexts (zsh, bash, fish, PowerShell).
- Blocked commands show with `command>` prefix, blocked pastes show with `paste>` prefix.
- Fish hook now works with vi keybindings (`fish_vi_key_bindings`). Binds Enter in insert, default, and replace modes.
- Fish vi mode: Enter from normal mode now correctly returns to insert mode after execution.

## [0.1.4] - 2026-02-04

### Fixed

- Shell hooks (zsh, bash) now properly display block/warn messages. Previously, messages were silently swallowed in zle/bind-x contexts.

## [0.1.3] - 2026-02-03

### Changed

- Re-licensed under AGPL-3.0-only with a commercial licensing option.

## [0.1.0] - 2026-02-02

### Added

- Tiered analysis engine (Tier 0-3) with <2ms fast path for clean commands
- 30 detection rules across 7 categories: hostname, path, transport, terminal, command, ecosystem, environment
- Shell hooks: zsh, bash (enter + preexec modes), fish, PowerShell
- Self-contained install: hooks embedded in binary, materialized on first `tirith init`
- Policy engine: YAML config, allowlist/blocklist, severity overrides, fail_mode (open/closed)
- JSONL audit log with file locking and event correlation IDs
- Receipt system for script execution tracking with SHA-256 verification
- `doctor` diagnostic command for installation troubleshooting
- Shell completions (zsh, bash, fish, PowerShell) via hidden `completions` subcommand
- Man page via hidden `manpage` subcommand
- `diff` command for comparing URLs against known-good patterns
- `score` command for URL risk scoring
- `why` command to explain the last triggered rule
- `run` command for safe script download and execution (Unix only)
- 235 golden fixture tests across 10 categories
- Criterion performance benchmarks
