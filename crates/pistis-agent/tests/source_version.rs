//! Keep the selected Kanon version witness, workspace and lock coherent.

#[test]
fn agent_source_version_matches_workspace_and_lock() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.1");
    let workspace = include_str!("../../../Cargo.toml");
    assert!(
        workspace
            .contains("pistis-agent = { version = \"0.1.1\", path = \"crates/pistis-agent\" }")
    );
    let lock = include_str!("../../../Cargo.lock");
    let agent_entries = lock
        .split("[[package]]")
        .filter(|entry| entry.lines().any(|line| line == "name = \"pistis-agent\""))
        .collect::<Vec<_>>();
    assert_eq!(agent_entries.len(), 1);
    assert!(
        agent_entries[0]
            .lines()
            .any(|line| line == "version = \"0.1.1\"")
    );
}
