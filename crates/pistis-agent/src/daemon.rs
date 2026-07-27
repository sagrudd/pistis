use crate::{AgentHandler, AgentSocket, DispatchError, PeerAuthorizer, SocketError, dispatch_one};
use std::{os::unix::net::UnixStream, time::Duration};

const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Lifecycle boundary for a non-blocking local-agent service loop.
pub trait DaemonControl {
    /// Returns false when the service must stop accepting new work.
    fn continue_running(&self) -> bool;

    /// Waits or yields after a poll with no pending connection.
    fn idle(&self);
}

/// Authorizes only peers whose effective user ID matches the daemon.
pub struct SameUserAuthorizer {
    expected_uid: u32,
}

impl SameUserAuthorizer {
    /// Captures the daemon effective user ID as the required peer identity.
    #[must_use]
    pub fn current() -> Self {
        Self {
            expected_uid: nix::unistd::geteuid().as_raw(),
        }
    }

    /// Constructs an explicit policy, primarily for platform-policy tests.
    #[must_use]
    pub const fn requiring(expected_uid: u32) -> Self {
        Self { expected_uid }
    }
}

impl PeerAuthorizer for SameUserAuthorizer {
    fn authorize(&self, stream: &UnixStream) -> Result<(), DispatchError> {
        peer_uid(stream)
            .filter(|uid| *uid == self.expected_uid)
            .map(|_| ())
            .ok_or(DispatchError::Unauthorized)
    }
}

/// Runs the non-blocking service until the lifecycle controller stops it.
///
/// Each connection is independently peer-authorized and dispatched. Rejected
/// or malformed clients cannot terminate the service. Listener failures do.
///
/// # Errors
///
/// Returns unavailable when listener configuration or acceptance fails.
pub fn serve_until(
    socket: &AgentSocket,
    authorizer: &impl PeerAuthorizer,
    handler: &mut impl AgentHandler,
    control: &impl DaemonControl,
) -> Result<(), SocketError> {
    socket.set_nonblocking(true)?;
    while control.continue_running() {
        match socket.accept() {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
                    .and_then(|()| stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT)))
                    .map_err(|_| SocketError::Unavailable)?;
                let _ = dispatch_one(stream, authorizer, handler);
            }
            Err(SocketError::NoConnection) => control.idle(),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    nix::unistd::getpeereid(stream)
        .ok()
        .map(|(uid, _)| uid.as_raw())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .ok()
        .map(|credentials| credentials.uid())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "android"
)))]
fn peer_uid(_: &UnixStream) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRequest, AgentResponse, AgentStatus, connect, encode_request, write_frame};
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Control(AtomicUsize);

    impl DaemonControl for Control {
        fn continue_running(&self) -> bool {
            self.0.load(Ordering::Relaxed) < 2
        }

        fn idle(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Handler(usize);

    impl AgentHandler for Handler {
        fn handle(&mut self, _: AgentRequest) -> Result<AgentResponse, DispatchError> {
            self.0 += 1;
            Ok(AgentResponse::Status(AgentStatus::Pending))
        }
    }

    fn directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("pistis-daemon-{}-{suffix}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn same_user_is_authorized_and_loop_stops_cleanly() {
        let directory = directory();
        let path = directory.join("agent.sock");
        let socket = AgentSocket::bind(&path).unwrap();
        let mut client = connect(&path).unwrap();
        write_frame(
            &mut client,
            &encode_request(&AgentRequest::BeginLogin).unwrap(),
        )
        .unwrap();
        let mut handler = Handler(0);
        serve_until(
            &socket,
            &SameUserAuthorizer::current(),
            &mut handler,
            &Control(AtomicUsize::new(0)),
        )
        .unwrap();
        assert_eq!(handler.0, 1);
        drop(client);
        drop(socket);
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn wrong_user_is_rejected_before_protocol_dispatch() {
        let (server, _) = UnixStream::pair().unwrap();
        let wrong_uid = nix::unistd::geteuid().as_raw().wrapping_add(1);
        assert!(matches!(
            SameUserAuthorizer::requiring(wrong_uid).authorize(&server),
            Err(DispatchError::Unauthorized)
        ));
    }
}
