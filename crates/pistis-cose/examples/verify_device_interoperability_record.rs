//! Verify one redacted EPIC-18 physical-device `XCTest` attachment locally.
//!
//! This operator tool deliberately accepts one file and prints only a
//! verification result and the derived public key identifier. It never emits
//! the attachment contents, signature, public key, or filesystem path.

use pistis_cose::verify_device_interoperability_record;
use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(record_path) = arguments.next() else {
        return reject();
    };
    if arguments.next().is_some() {
        return reject();
    }

    let Ok(record) = fs::read(record_path) else {
        return reject();
    };
    let Ok(verified) = verify_device_interoperability_record(&record) else {
        return reject();
    };

    println!("verified key_id={}", verified.key_id());
    ExitCode::SUCCESS
}

fn reject() -> ExitCode {
    eprintln!("verification failed");
    ExitCode::FAILURE
}
