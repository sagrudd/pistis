use crate::{AuthCommand, AuthenticationBackend, CeremonyError, DirectStatus, PendingCeremony};
use pistis_agent::{
    AgentFailure, AgentReference, AgentRequest, AgentResponse, AgentStatus, connect,
    decode_response, encode_request, read_frame, write_frame,
};
use std::path::{Path, PathBuf};

/// Authentication backend connected to the owner-only local-agent socket.
pub struct SocketAuthenticationBackend {
    socket_path: PathBuf,
}

impl SocketAuthenticationBackend {
    /// Constructs a client for an absolute socket path.
    ///
    /// # Errors
    ///
    /// Rejects relative, empty, or control-bearing paths before connection.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, CeremonyError> {
        let socket_path = path.into();
        let text = socket_path.to_string_lossy();
        if !socket_path.is_absolute() || text.is_empty() || text.chars().any(char::is_control) {
            return Err(CeremonyError::Unavailable);
        }
        Ok(Self { socket_path })
    }

    fn call(&self, request: &AgentRequest) -> Result<AgentResponse, CeremonyError> {
        let mut stream = connect(&self.socket_path).map_err(|_| CeremonyError::Unavailable)?;
        let request = encode_request(request).map_err(|_| CeremonyError::Rejected)?;
        write_frame(&mut stream, &request).map_err(|_| CeremonyError::Unavailable)?;
        let response = read_frame(&mut stream).map_err(|_| CeremonyError::Unavailable)?;
        decode_response(&response).map_err(|_| CeremonyError::Rejected)
    }

    /// Returns the configured socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl AuthenticationBackend for SocketAuthenticationBackend {
    fn begin(&mut self, command: &AuthCommand) -> Result<PendingCeremony, CeremonyError> {
        let request = match command {
            AuthCommand::Login { .. } => AgentRequest::BeginLogin,
            AuthCommand::Approve { command, .. } => AgentRequest::BeginAction {
                arguments: command.clone(),
            },
        };
        match self.call(&request)? {
            AgentResponse::Pending(pending) => Ok(PendingCeremony {
                reference: encode_reference(pending.reference),
                challenge_transfer: pending.challenge_transfer,
                installation_name: pending.installation_name,
                installation_fingerprint: pending.installation_fingerprint,
                purpose: pending.purpose,
                expires_at_millis: pending.expires_at_millis,
            }),
            AgentResponse::Failure(failure) => Err(map_failure(failure)),
            _ => Err(CeremonyError::Rejected),
        }
    }

    fn direct_status(&mut self, reference: &str) -> Result<DirectStatus, CeremonyError> {
        let reference = decode_reference(reference)?;
        match self.call(&AgentRequest::Status { reference })? {
            AgentResponse::Status(status) => Ok(map_status(status)),
            AgentResponse::Failure(failure) => Err(map_failure(failure)),
            _ => Err(CeremonyError::Rejected),
        }
    }

    fn submit_framed(
        &mut self,
        reference: &str,
        response: &str,
    ) -> Result<DirectStatus, CeremonyError> {
        let reference = decode_reference(reference)?;
        match self.call(&AgentRequest::Submit {
            reference,
            transfer: response.into(),
        })? {
            AgentResponse::Status(status) => Ok(map_status(status)),
            AgentResponse::Failure(failure) => Err(map_failure(failure)),
            _ => Err(CeremonyError::Rejected),
        }
    }

    fn cancel(&mut self, reference: &str) {
        if let Ok(reference) = decode_reference(reference) {
            let _ = self.call(&AgentRequest::Cancel { reference });
        }
    }
}

fn encode_reference(reference: AgentReference) -> String {
    let mut output = String::with_capacity(64);
    for byte in reference.as_bytes() {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_reference(value: &str) -> Result<AgentReference, CeremonyError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CeremonyError::Rejected);
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| CeremonyError::Rejected)?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| CeremonyError::Rejected)?;
    }
    Ok(AgentReference::from_bytes(bytes))
}

const fn map_status(status: AgentStatus) -> DirectStatus {
    match status {
        AgentStatus::Pending => DirectStatus::Pending,
        AgentStatus::Completed => DirectStatus::Completed,
        AgentStatus::Denied => DirectStatus::Denied,
        AgentStatus::Expired => DirectStatus::Expired,
    }
}

const fn map_failure(failure: AgentFailure) -> CeremonyError {
    match failure {
        AgentFailure::Unavailable => CeremonyError::Unavailable,
        AgentFailure::Rejected | AgentFailure::Conflict => CeremonyError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use pistis_agent::{
        AgentHandler, AgentSocket, DispatchError, PeerAuthorizer, PendingChallenge, dispatch_one,
    };
    use std::{
        fs,
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Allow;

    impl PeerAuthorizer for Allow {
        fn authorize(&self, _: &UnixStream) -> Result<(), DispatchError> {
            Ok(())
        }
    }

    struct Handler;

    impl AgentHandler for Handler {
        fn handle(&mut self, request: AgentRequest) -> Result<AgentResponse, DispatchError> {
            match request {
                AgentRequest::BeginLogin => Ok(AgentResponse::Pending(PendingChallenge {
                    reference: AgentReference::from_bytes([7; 32]),
                    challenge_transfer: "PISTIS1:challenge.checksum".into(),
                    installation_name: "Workstation".into(),
                    installation_fingerprint: "12:34".into(),
                    purpose: "authenticate terminal".into(),
                    expires_at_millis: 42,
                })),
                AgentRequest::Status { .. } => Ok(AgentResponse::Status(AgentStatus::Pending)),
                AgentRequest::Submit { .. } => Ok(AgentResponse::Status(AgentStatus::Completed)),
                AgentRequest::Cancel { .. } => Ok(AgentResponse::Acknowledged),
                AgentRequest::BeginAction { .. } => {
                    Ok(AgentResponse::Failure(AgentFailure::Unavailable))
                }
            }
        }
    }

    fn directory() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pistis-client-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn client_maps_closed_agent_ceremony() {
        let directory = directory();
        let path = directory.join("agent.sock");
        let socket = AgentSocket::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let mut handler = Handler;
            for _ in 0..3 {
                dispatch_one(socket.accept().unwrap(), &Allow, &mut handler).unwrap();
            }
        });
        let mut backend = SocketAuthenticationBackend::new(path).unwrap();
        let pending = backend.begin(&parse(["auth", "login"]).unwrap()).unwrap();
        assert_eq!(pending.reference, "07".repeat(32));
        assert_eq!(
            backend.direct_status(&pending.reference),
            Ok(DirectStatus::Pending)
        );
        assert_eq!(
            backend.submit_framed(&pending.reference, "PISTIS1:response.checksum"),
            Ok(DirectStatus::Completed)
        );
        server.join().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
