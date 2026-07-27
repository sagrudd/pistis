use pistis_cli::{CliExit, SocketAuthenticationBackend, TerminalIo, parse, run};
use std::{
    io::{self, IsTerminal},
    path::PathBuf,
};

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
    if matches!(command, pistis_cli::AuthCommand::Exec { .. }) {
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
