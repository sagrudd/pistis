//! Framework-neutral orchestration for terminal authentication.
//!
//! This crate owns command interpretation and safe terminal ceremony flow. It
//! deliberately delegates challenge creation, signing, response ingestion,
//! and single-use verification to one authoritative authentication adapter.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod ceremony;
mod command;
mod execution;
mod local_agent;
mod terminal_io;

pub use ceremony::{
    AuthenticationBackend, CeremonyError, ChallengePresentation, CliExit, CliIo, DirectStatus,
    PendingCeremony, run,
};
pub use command::{AuthCommand, OutputProfile, ParseError, parse};
pub use execution::{
    ActionExecutor, ActionInspector, ApprovalAuthority, ExecutionError, ExecutionGrant,
    execute_approved,
};
pub use local_agent::SocketAuthenticationBackend;
pub use terminal_io::TerminalIo;
