use clap::CommandFactory;
use clap_complete::Shell;
use std::io;

pub fn run(shell: Shell) -> i32 {
    let mut cmd = crate::Cli::command();
    clap_complete::generate(shell, &mut cmd, "tirith", &mut io::stdout());
    0
}
