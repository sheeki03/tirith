# Bounded Python and Cargo task effects

The task gate now recognizes operation intent in two existing incomplete workflows: the `pip install` example in `docs/task-envelope.md` and the mixed pip command in `tests/task_provenance.rs`, plus the pip/Cargo installation workflows documented in `docs/cookbook.md`. Recognition adds effect evidence; these command families remain incomplete even with an authoritative shell, absolute working directory and captured policy identity.

The grammar consumes the shared shell tokenizer and wrapper resolver for the boundary-selected POSIX, Fish, PowerShell or Cmd dialect. Caller-claimed dialects produce diagnostic hints only. Parser fixtures for Windows are lexical coverage, not native Windows execution qualification.

| Family | Supported operation grammar | Potential effects | Remaining unknown behavior |
|---|---|---|---|
| Python packaging | `pip`, `pip3`, versioned `pip3.N`; `python[3[.N]]` or Windows `py` with a literal `-m pip`; followed by `install` | Package installation, network egress, filesystem writes, persistence changes | Build backends, package code, credentials/configuration, requirements files and dynamic values |
| Python artifact preparation | Same launchers, `download` or `wheel` | Network egress and filesystem writes | Build/metadata hooks and dependency resolution |
| Python removal | Same launchers, `uninstall` | Filesystem writes and persistence changes | Installed metadata, interpreter startup/configuration and dynamic values |
| Cargo installation | `cargo [+toolchain] install` | Package installation, network egress, filesystem writes, persistence changes | Build scripts, procedural macros, toolchain dispatch, registry/configuration and dynamic values |
| Cargo build or execution | `cargo [+toolchain] build`, `b`, `check`, `c`, `test`, `t`, `run`, `r`, `bench`, `rustc`, `rustdoc` or `doc` | Network egress and filesystem writes | Build scripts, procedural macros, tests, executable entrypoints and external tooling |
| Cargo dependency fetch | `cargo [+toolchain] fetch` | Network egress and filesystem writes | Registry/configuration, credential providers and dependency resolution |

Known prefix options consume their declared values. An unknown prefix option, a dynamic subcommand, an arbitrary Python script, `python -c`, or a Cargo custom subcommand cannot be reinterpreted by finding an operation word later in its arguments. Recognized but unsupported invocations remain unknown. A pip `--log` prefix adds a write hint even when its operation is unsupported; option values never become command verbs.

The effect sets describe possible operation capabilities, not proof that the command will perform every effect. `--offline`, `--no-index`, `--dry-run` and `--ignore-installed` do not grant completeness or establish that package/build code cannot use the network or write files. This parser executes nothing and reads no package metadata or configuration.

Limits are explicit: 1 MiB of command text, 256 retained executable segments, 512 retained words per segment and 16 KiB per word. Reaching any limit keeps the result incomplete. Effects from retained invocations survive a mixed command; no recognized occurrence can vouch for another segment or an additional runtime effect. Existing Web3 occurrence accounting and npm-family inference remain authoritative for their own grammars.

The integration has no new authorization path: the existing task gate receives the inferred effects and incomplete state, and existing owned boundaries apply policy. A claimed trusted origin, requested effect or shell name cannot supply provenance or a runtime permit.

Grammar references: [pip general options](https://pip.pypa.io/en/stable/cli/pip/), [pip install](https://pip.pypa.io/en/stable/cli/pip_install/), [Cargo build](https://doc.rust-lang.org/cargo/commands/cargo-build.html), and [Cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html). Parser coverage is deliberately narrower than these tools' full interfaces.
