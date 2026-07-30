use pistis_cli::{
    EnrolmentPresentationError, EnrolmentPresentationOptions, OutputProfile, present_first_device,
};
use std::io::Cursor;

const FIXTURE: &str =
    include_str!("../../../fixtures/protocol-v3/first-device/presentation-positive.json");
const APP_DIGEST: [u8; 32] = [
    0xbf, 0x79, 0x68, 0x03, 0x0a, 0xbd, 0xf7, 0xd3, 0xda, 0xbb, 0x38, 0x9f, 0x32, 0xcd, 0x4c, 0x53,
    0x10, 0xc1, 0xec, 0x4c, 0x9c, 0x62, 0x5d, 0x38, 0xd1, 0x3b, 0xe6, 0xef, 0xae, 0x23, 0x06, 0x63,
];

fn frame() -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["frame_hex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn options(
    input_is_pipe: bool,
    output_is_terminal: bool,
    profile: OutputProfile,
) -> EnrolmentPresentationOptions {
    EnrolmentPresentationOptions {
        input_is_pipe,
        output_is_terminal,
        profile,
        inverted: false,
        columns: 400,
        expected_app_configuration_digest: APP_DIGEST,
        now_ms: 1_700_000_060_000,
    }
}

#[test]
fn protected_pipe_uses_alternate_screen_and_never_prints_transfer() {
    let mut output = Vec::new();
    present_first_device(
        Cursor::new(frame()),
        &mut output,
        &mut Cursor::new(b"\n"),
        options(true, true, OutputProfile::Unicode),
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.starts_with("\u{1b}[?1049h\u{1b}[?25l"));
    assert!(output.ends_with("\u{1b}[?25h\u{1b}[?1049l"));
    assert!(output.contains("SENSITIVE FIRST-DEVICE INVITATION"));
    assert!(output.contains("Mnemosyne evaluation"));
    assert!(output.contains("https://pistis.example.test:8443"));
    assert!(!output.contains("PISTIS1:"));
    assert!(!output.contains("555555555555"));
}

#[test]
fn rejects_interactive_input_nonterminal_output_trailing_data_and_bad_acknowledgement() {
    let mut output = Vec::new();
    assert_eq!(
        present_first_device(
            Cursor::new(frame()),
            &mut output,
            &mut Cursor::new(b"\n"),
            options(false, true, OutputProfile::Ascii),
        ),
        Err(EnrolmentPresentationError::UnprotectedInput)
    );
    assert_eq!(
        present_first_device(
            Cursor::new(frame()),
            &mut output,
            &mut Cursor::new(b"\n"),
            options(true, false, OutputProfile::Ascii),
        ),
        Err(EnrolmentPresentationError::NoAttendedTerminal)
    );
    let mut trailing = frame();
    trailing.push(0);
    assert_eq!(
        present_first_device(
            Cursor::new(trailing),
            &mut output,
            &mut Cursor::new(b"\n"),
            options(true, true, OutputProfile::Ascii),
        ),
        Err(EnrolmentPresentationError::Rejected)
    );
    let mut failed_output = Vec::new();
    assert_eq!(
        present_first_device(
            Cursor::new(frame()),
            &mut failed_output,
            &mut Cursor::new(b"not-enter\n"),
            options(true, true, OutputProfile::Unicode),
        ),
        Err(EnrolmentPresentationError::Presentation)
    );
    assert!(
        String::from_utf8(failed_output)
            .unwrap()
            .ends_with("\u{1b}[?25h\u{1b}[?1049l")
    );
}
