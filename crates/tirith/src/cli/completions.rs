use clap::{Command, CommandFactory};
use clap_complete::Shell;
use std::io;

pub fn run(shell: Shell) -> i32 {
    let mut cmd = command_for_completions();
    clap_complete::generate(shell, &mut cmd, "tirith", &mut io::stdout());
    0
}

/// Build the command graph used only by static completion generators.
///
/// clap_complete's Bash generator encodes a subcommand path by replacing spaces
/// with `__`, then splits that encoded value on `__`. A literal `__` in a
/// subcommand name is therefore ambiguous and makes the generator panic while
/// resolving the path. Tirith intentionally has hidden internal receipt and
/// verification commands; rename those commands in this disposable clone only.
/// The actual parser graph and hidden command API remain unchanged.
fn command_for_completions() -> Command {
    sanitize_completion_subcommand_names(crate::Cli::command())
}

fn sanitize_completion_subcommand_names(command: Command) -> Command {
    command.mut_subcommands(|subcommand| {
        let completion_alias = match subcommand.get_name() {
            "__execution-receipt" => Some("_execution-receipt"),
            "__shell-verification" => Some("_shell-verification"),
            _ => None,
        };
        let contains_path_delimiter = subcommand.get_name().contains("__");
        let subcommand = if let Some(alias) = completion_alias {
            debug_assert!(subcommand.is_hide_set());
            subcommand.name(alias)
        } else {
            debug_assert!(
                !contains_path_delimiter,
                "new subcommands containing clap_complete's `__` path delimiter need a \
                 completion-only static alias"
            );
            subcommand
        };
        sanitize_completion_subcommand_names(subcommand)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_generation_handles_hidden_double_underscore_command() {
        // The generated graph is intentionally large; libtest worker threads
        // have a smaller stack than the CLI's main thread. Match the runtime
        // environment so this test asserts the generator contract rather than
        // libtest's default stack size.
        let output = std::thread::Builder::new()
            .name("bash-completion-regression".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut command = command_for_completions();
                let mut output = Vec::new();
                clap_complete::generate(Shell::Bash, &mut command, "tirith", &mut output);
                String::from_utf8(output).expect("Bash completion must be UTF-8")
            })
            .expect("completion test thread must start")
            .join()
            .expect("Bash completion generation must not panic");

        assert!(!output.is_empty());
        assert!(output.contains("_tirith"));
    }

    #[test]
    fn completion_clone_preserves_the_actual_hidden_command_api() {
        std::thread::Builder::new()
            .name("completion-clone-regression".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let parser_command = crate::Cli::command();
                let completion_command = command_for_completions();
                for (internal, alias) in [
                    ("__execution-receipt", "_execution-receipt"),
                    ("__shell-verification", "_shell-verification"),
                ] {
                    assert!(parser_command
                        .find_subcommand(internal)
                        .unwrap()
                        .is_hide_set());
                    assert!(parser_command.find_subcommand(alias).is_none());
                    assert!(completion_command.find_subcommand(internal).is_none());
                    assert!(completion_command
                        .find_subcommand(alias)
                        .unwrap()
                        .is_hide_set());
                }
            })
            .expect("completion clone test thread must start")
            .join()
            .expect("completion clone must preserve the parser API");
    }
}
