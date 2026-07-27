//! Durable, owner-only local agent building blocks.
//!
//! This crate stores single-use ceremony state, frames canonical messages for
//! a Unix-domain socket, and defines a non-exportable installation-signing
//! boundary. Platform daemon and key-store adapters remain separate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod completion;
mod daemon;
mod dispatch;
mod framing;
mod handler;
#[cfg(target_os = "macos")]
mod macos;
mod protocol;
mod repository;
mod signer;
mod socket;
mod verification;

pub use completion::{AuditTransfer, DurableAuditEvent, VerifiedCompletion, VerifiedSession};
pub use daemon::{DaemonControl, SameUserAuthorizer, serve_until};
pub use dispatch::{AgentHandler, DispatchError, PeerAuthorizer, dispatch_one};
pub use framing::{MAX_AGENT_MESSAGE_BYTES, SocketFrameError, read_frame, write_frame};
pub use handler::{AuthoritativeCeremonies, AuthoritativeError, AuthoritativeHandler};
#[cfg(target_os = "macos")]
pub use macos::MacOsKeychainBackend;
pub use protocol::{
    AgentFailure, AgentReference, AgentRequest, AgentResponse, AgentStatus, PendingChallenge,
    ProtocolError, decode_request, decode_response, encode_request, encode_response,
};
pub use repository::{
    CeremonyKind, CeremonyRecord, CeremonyRepository, CeremonyState, RepositoryError,
};
pub use signer::{
    InstallationSignature, InstallationSigner, KeychainBackend, KeychainSigner, SignerError,
};
pub use socket::{AgentSocket, SocketError, connect};
pub use verification::{
    CompletionCoordinator, CompletionError, OsSessionIds, SessionIdSource, StagedResponseVerifier,
    VerifiedPrincipal,
};
