use pistis_cli::{
    AuthCommand, CliExit, EnrolmentPresentationOptions, SocketAuthenticationBackend, TerminalIo,
    parse, present_first_device, run,
};
use std::{
    fs::File,
    io::{self, BufReader, IsTerminal},
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
    let Ok(terminal) = File::open("/dev/tty") else {
        eprintln!("pistis: attended enrolment terminal is unavailable");
        return CliExit::Unavailable;
    };
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        eprintln!("pistis: first-device presentation rejected");
        return CliExit::Rejected;
    };
    let Ok(now_ms) = u64::try_from(elapsed.as_millis()) else {
        eprintln!("pistis: first-device presentation rejected");
        return CliExit::Rejected;
    };
    let mut acknowledgement = BufReader::new(terminal);
    let output_is_terminal = stdout.is_terminal();
    if present_first_device(
        stdin.lock(),
        &mut stdout,
        &mut acknowledgement,
        EnrolmentPresentationOptions {
            input_is_pipe: !stdin.is_terminal(),
            output_is_terminal,
            profile,
            inverted,
            columns: terminal_columns(),
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

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"].into_iter().any(|name| {
        std::env::var(name).is_ok_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
    })
}
