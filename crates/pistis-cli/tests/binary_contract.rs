use std::process::Command;

#[test]
fn valid_auth_command_refuses_unavailable_agent() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pistis"));
    command
        .args(["auth", "login"])
        .env_remove("PISTIS_AGENT_SOCKET")
        .env_remove("XDG_RUNTIME_DIR");
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(69));
    assert!(
        output.stdout.is_empty(),
        "unavailable authority must not render a QR or any standard output"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PISTIS1:"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("authoritative local authentication agent is unavailable"));
    assert!(!stderr.contains("PISTIS1:"));
}

#[test]
fn login_rejects_a_relative_authority_socket_without_presenting_a_qr() {
    let output = Command::new(env!("CARGO_BIN_EXE_pistis"))
        .args(["auth", "login"])
        .env("PISTIS_AGENT_SOCKET", "agent.sock")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(69));
    assert!(
        output.stdout.is_empty(),
        "an invalid authority socket must not render a QR or any standard output"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PISTIS1:"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("authoritative local authentication agent is unavailable"));
    assert!(!stderr.contains("PISTIS1:"));
    assert!(!stderr.contains("agent.sock"));
}

#[test]
fn supervised_execution_remains_fail_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_pistis"))
        .args(["auth", "exec", "--", "tool", "argument"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(69));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("supervised command execution is unavailable"));
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
