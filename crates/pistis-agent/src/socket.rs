use std::{
    error::Error,
    fmt, fs, io,
    os::unix::{
        fs::{FileTypeExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

/// Bound owner-only local-agent socket.
pub struct AgentSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl AgentSocket {
    /// Binds a new owner-only Unix-domain socket.
    ///
    /// The parent must already exist with mode `0700` or stricter. Existing
    /// paths are never removed implicitly. The resulting socket is mode `0600`.
    ///
    /// # Errors
    ///
    /// Rejects permissive or symlinked parents, existing paths, non-socket
    /// results, permission-setting failures, and bind errors.
    pub fn bind(path: &Path) -> Result<Self, SocketError> {
        let parent = path.parent().ok_or(SocketError::Permissions)?;
        let metadata = fs::symlink_metadata(parent).map_err(map_io)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
            || path.exists()
        {
            return Err(SocketError::Permissions);
        }
        let listener = UnixListener::bind(path).map_err(map_io)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(map_io)?;
        let socket_metadata = fs::symlink_metadata(path).map_err(map_io)?;
        if !socket_metadata.file_type().is_socket()
            || socket_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(SocketError::Permissions);
        }
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Accepts one local client.
    ///
    /// Platform daemon adapters must additionally verify peer credentials
    /// before reading a request.
    ///
    /// # Errors
    ///
    /// Returns a coarse unavailable failure when accept fails.
    pub fn accept(&self) -> Result<UnixStream, SocketError> {
        self.listener
            .accept()
            .map(|(stream, _)| stream)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    SocketError::NoConnection
                } else {
                    map_io(error)
                }
            })
    }

    /// Selects blocking or non-blocking acceptance for a reviewed lifecycle.
    ///
    /// # Errors
    ///
    /// Returns unavailable when the listener mode cannot be changed.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), SocketError> {
        self.listener.set_nonblocking(nonblocking).map_err(map_io)
    }

    /// Returns the bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AgentSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Connects to an existing local-agent socket.
///
/// The target must be a socket with no group or world permissions.
///
/// # Errors
///
/// Rejects symlinks, non-sockets, permissive modes, and connection failures.
pub fn connect(path: &Path) -> Result<UnixStream, SocketError> {
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SocketError::Permissions);
    }
    UnixStream::connect(path).map_err(map_io)
}

/// Coarse local-agent socket failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketError {
    /// Filesystem ownership or mode policy failed.
    Permissions,
    /// A non-blocking listener currently has no connection.
    NoConnection,
    /// Socket creation, connection, or I/O failed.
    Unavailable,
}

impl fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Permissions => "local agent socket permissions rejected",
            Self::NoConnection => "local agent has no pending connection",
            Self::Unavailable => "local agent socket unavailable",
        })
    }
}

impl Error for SocketError {}

fn map_io(_: io::Error) -> SocketError {
    SocketError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read as _, Write as _},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn directory() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pistis-socket-{}-{suffix}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn socket_is_owner_only_and_carries_local_bytes() {
        let directory = directory();
        let path = directory.join("agent.sock");
        let socket = AgentSocket::bind(&path).unwrap();
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let client_path = path.clone();
        let client = thread::spawn(move || {
            let mut stream = connect(&client_path).unwrap();
            stream.write_all(b"request").unwrap();
        });
        let mut stream = socket.accept().unwrap();
        let mut request = [0; 7];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"request");
        client.join().unwrap();
        drop(socket);
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn permissive_parent_and_existing_path_are_rejected() {
        let directory = directory();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AgentSocket::bind(&directory.join("agent.sock")),
            Err(SocketError::Permissions)
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("agent.sock");
        fs::write(&path, b"do not replace").unwrap();
        assert!(matches!(
            AgentSocket::bind(&path),
            Err(SocketError::Permissions)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
