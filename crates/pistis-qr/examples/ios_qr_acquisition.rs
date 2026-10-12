use std::{
    fs::File,
    io::{IsTerminal, Write},
    process::ExitCode,
};
#[path = "regression_support/mod.rs"]
mod acquisition;

use acquisition::{
    AcquisitionError, MAX_IMAGE_BYTES, MAX_TEXT_BYTES, acquire_png, acquire_text, bounded_read,
};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (source, emit_payload) = match args.as_slice() {
        [mode] if mode == "--stdin" => (None, false),
        [mode, emit] if mode == "--stdin" && emit == "--emit-payload" => (None, true),
        [mode, path] if mode == "--image" => (Some(path.as_str()), false),
        [mode, path, emit] if mode == "--image" && emit == "--emit-payload" => {
            (Some(path.as_str()), true)
        }
        _ => {
            println!("{}", diagnostic("failed", Some("invalid_arguments"), None));
            return ExitCode::FAILURE;
        }
    };
    let result = match source {
        Some(path) => File::open(path)
            .map_err(|_| AcquisitionError::InputRead)
            .and_then(|file| bounded_read(file, MAX_IMAGE_BYTES))
            .and_then(|bytes| acquire_png(&bytes)),
        None => bounded_read(std::io::stdin().lock(), MAX_TEXT_BYTES)
            .and_then(|bytes| acquire_text(&bytes)),
    };
    match result {
        Ok(acquired) => {
            if emit_payload {
                if std::io::stdout().is_terminal() {
                    eprintln!("{}", diagnostic("failed", Some("pipe_required"), None));
                    return ExitCode::FAILURE;
                }
                if std::io::stdout()
                    .lock()
                    .write_all(acquired.text().as_bytes())
                    .is_err()
                {
                    return ExitCode::FAILURE;
                }
            } else {
                println!(
                    "{}",
                    diagnostic("acquired", None, Some(acquired.text().len()))
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Diagnostics go to stderr in transport mode, never into the QR pipe.
            let diagnostic = diagnostic("failed", Some(error.code()), None);
            if emit_payload {
                eprintln!("{diagnostic}");
            } else {
                println!("{diagnostic}");
            }
            ExitCode::FAILURE
        }
    }
}

fn diagnostic(
    outcome: &str,
    failure: Option<&str>,
    text_bytes: Option<usize>,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "pistis.internal-ios-regression.acquisition.v1",
        "phase": "qr_acquisition",
        "outcome": outcome,
        "failure": failure,
        "text_bytes": text_bytes,
        "trust": "unverified",
    })
}
