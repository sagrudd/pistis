use std::process::Command;

#[test]
fn valid_auth_command_refuses_unavailable_agent() {
    let output = Command::new(env!("CARGO_BIN_EXE_pistis"))
        .args(["auth", "login"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(69));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("authoritative local authentication agent is unavailable"));
    assert!(!stderr.contains("PISTIS1:"));
}

#[test]
fn malformed_command_has_stable_usage_exit() {
    let output = Command::new(env!("CARGO_BIN_EXE_pistis"))
        .arg("login")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("usage: pistis auth")
    );
}
