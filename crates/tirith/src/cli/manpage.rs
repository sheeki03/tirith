use clap::CommandFactory;
use std::io;

pub fn run() -> i32 {
    let cmd = crate::Cli::command();
    let man = clap_mangen::Man::new(cmd);
    match man.render(&mut io::stdout()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("tirith: failed to generate man page: {e}");
            1
        }
    }
}
