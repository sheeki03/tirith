pub mod audit;
pub mod check;
pub mod checkpoint;
pub mod completions;
pub mod diff;
pub mod doctor;
#[allow(dead_code)]
pub mod gateway;
pub mod init;
pub mod last_trigger;
pub mod license_cmd;
pub mod manpage;
pub mod mcp_server;
pub mod paste;
pub mod receipt;
pub mod scan;
pub mod score;
pub mod why;

#[cfg(unix)]
pub mod fetch;
#[cfg(unix)]
pub mod run;
#[allow(dead_code)]
pub mod setup;
