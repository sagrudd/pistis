use pistis_cli::{
    AuthCommand, CliExit, EnrolmentPresentationOptions, SocketAuthenticationBackend, TerminalIo,
    parse, present_first_device, run,
};
use pistis_protocol::MAX_FIRST_DEVICE_FRAME_BYTES;
use std::{
    fs::File,
    io::{self, BufReader, Cursor, IsTerminal, Read},
    os::unix::fs::FileTypeExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const REVIEWED_GITHUB_APP_DIGEST: [u8; 32] = [
    0xbf, 0x79, 0x68, 0x03, 0x0a, 0xbd, 0xf7, 0xd3, 0xda, 0xbb, 0x38, 0x9f, 0x32, 0xcd, 0x4c, 0x53,
    0x10, 0xc1, 0xec, 0x4c, 0x9c, 0x62, 0x5d, 0x38, 0xd1, 0x3b, 0xe6, 0xef, 0xae, 0x23, 0x06, 0x63,
];

fn main() {
    let exit = match parse(std::env::args().skip(1)) {
        Ok(command) => run_command(&command),
        Err(error) => {
            eprintln!("pistis: {error}");
            CliExit::Usage
        }
    };
    std::process::exit(exit as i32);
}

fn run_command(command: &pistis_cli::AuthCommand) -> CliExit {
    if let AuthCommand::EnrolmentPresent { profile, inverted } = command {
        return run_enrolment_present(*profile, *inverted);
    }
    if matches!(command, AuthCommand::Exec { .. }) {
        eprintln!("pistis: supervised command execution is unavailable");
        return CliExit::Unavailable;
    }
    let Some(socket_path) = socket_path() else {
        eprintln!("pistis: authoritative local authentication agent is unavailable");
        return CliExit::Unavailable;
    };
    let Ok(mut backend) = SocketAuthenticationBackend::new(socket_path) else {
        eprintln!("pistis: authoritative local authentication agent is unavailable");
        return CliExit::Unavailable;
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let protected_input = !stdin.is_terminal();
    let mut terminal = TerminalIo::new(
        stdin.lock(),
        stdout.lock(),
        terminal_columns(),
        locale_is_utf8(),
        protected_input,
    );
    let exit = run(command, &mut backend, &mut terminal);
    if exit != CliExit::Success {
        eprintln!("pistis: authentication did not complete ({exit:?})");
    }
    exit
}

fn run_enrolment_present(profile: pistis_cli::OutputProfile, inverted: bool) -> CliExit {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    if !protected_stdin_is_pipe() {
        eprintln!("pistis: first-device presentation rejected");
        return CliExit::Rejected;
    }
    let Some((frame, now_ms)) = read_frame_then_timestamp(stdin.lock(), system_time_millis) else {
        eprintln!("pistis: first-device presentation rejected");
        return CliExit::Rejected;
    };
    let Ok(terminal) = File::open("/dev/tty") else {
        eprintln!("pistis: attended enrolment terminal is unavailable");
        return CliExit::Unavailable;
    };
    let mut acknowledgement = BufReader::new(terminal);
    let output_is_terminal = stdout.is_terminal();
    if present_first_device(
        Cursor::new(frame),
        &mut stdout,
        &mut acknowledgement,
        EnrolmentPresentationOptions {
            input_is_pipe: true,
            output_is_terminal,
            profile,
            inverted,
            columns: terminal_columns(),
            rows: terminal_rows(),
            expected_app_configuration_digest: REVIEWED_GITHUB_APP_DIGEST,
            now_ms,
        },
    )
    .is_ok()
    {
        CliExit::Success
    } else {
        eprintln!("pistis: first-device presentation rejected");
        CliExit::Rejected
    }
}

fn read_frame_then_timestamp(
    reader: impl Read,
    timestamp: impl FnOnce() -> Option<u64>,
) -> Option<(Vec<u8>, u64)> {
    let mut bounded = reader.take((MAX_FIRST_DEVICE_FRAME_BYTES + 1) as u64);
    let mut frame = Vec::new();
    bounded.read_to_end(&mut frame).ok()?;
    if frame.is_empty() || frame.len() > MAX_FIRST_DEVICE_FRAME_BYTES {
        return None;
    }
    Some((frame, timestamp()?))
}

fn system_time_millis() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

fn protected_stdin_is_pipe() -> bool {
    descriptor_path_is_fifo("/dev/fd/0")
}

fn descriptor_path_is_fifo(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_fifo())
}

fn socket_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PISTIS_AGENT_SOCKET") {
        return Some(PathBuf::from(path));
    }
    let runtime = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    runtime
        .is_absolute()
        .then(|| runtime.join("pistis/agent.sock"))
}

fn terminal_columns() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|columns| (40..=1_000).contains(columns))
        .unwrap_or(80)
}

fn terminal_rows() -> usize {
    std::env::var("LINES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|rows| (10..=1_000).contains(rows))
        .unwrap_or(24)
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].into_iter().any(|name| {
        std::env::var(name).is_ok_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_FIRST_DEVICE_FRAME_BYTES, descriptor_path_is_fifo, read_frame_then_timestamp};
    use std::{
        cell::Cell,
        io::{Cursor, Read},
        rc::Rc,
    };

    struct CompletionReader {
        inner: Cursor<Vec<u8>>,
        complete: Rc<Cell<bool>>,
    }

    impl Read for CompletionReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.inner.read(buffer)?;
            if count == 0 {
                self.complete.set(true);
            }
            Ok(count)
        }
    }

    #[test]
    fn regular_descriptor_cannot_impersonate_protected_pipe() {
        assert!(!descriptor_path_is_fifo("/dev/null"));
    }

    #[test]
    fn enrolment_clock_is_sampled_only_after_the_complete_pipe_frame() {
        let complete = Rc::new(Cell::new(false));
        let reader = CompletionReader {
            inner: Cursor::new(vec![7_u8; 32]),
            complete: Rc::clone(&complete),
        };
        let (_, timestamp) = read_frame_then_timestamp(reader, || {
            assert!(complete.get());
            Some(1_800_000_000_000)
        })
        .unwrap();
        assert_eq!(timestamp, 1_800_000_000_000);
    }

    #[test]
    fn oversized_pipe_frame_is_rejected_before_clock_sampling() {
        let sampled = Cell::new(false);
        let result = read_frame_then_timestamp(
            Cursor::new(vec![0_u8; MAX_FIRST_DEVICE_FRAME_BYTES + 1]),
            || {
                sampled.set(true);
                Some(1)
            },
        );
        assert!(result.is_none());
        assert!(!sampled.get());
    }
}
