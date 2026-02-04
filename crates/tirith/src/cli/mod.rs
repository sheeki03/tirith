pub mod check;
pub mod completions;
pub mod diff;
pub mod doctor;
pub mod init;
pub mod last_trigger;
pub mod manpage;
pub mod paste;
pub mod receipt;
pub mod score;
pub mod why;

#[cfg(unix)]
pub mod run;
