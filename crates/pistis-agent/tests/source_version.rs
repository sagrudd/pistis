//! Keep the selected Kanon version witness, workspace and lock coherent.

#[test]
fn agent_source_version_matches_workspace_and_lock() {
    let version = env!("CARGO_PKG_VERSION");
    let version_assignment = format!("version = \"{version}\"");
    let manifest = include_str!("../Cargo.toml");
    let package_section = manifest
        .strip_prefix("[package]\n")
        .expect("agent manifest starts with its package section")
        .split("\n[")
        .next()
        .expect("package section");
    assert!(
        package_section
            .lines()
            .any(|line| line == version_assignment)
    );
    let workspace = include_str!("../../../Cargo.toml");
    let agent_declarations = workspace
        .lines()
        .filter(|line| line.starts_with("pistis-agent = "))
        .collect::<Vec<_>>();
    assert_eq!(agent_declarations.len(), 1);
    assert!(agent_declarations[0].contains(&format!("version = \"{version}\",")));
    assert!(agent_declarations[0].contains("path = \"crates/pistis-agent\""));
    let lock = include_str!("../../../Cargo.lock");
    let agent_entries = lock
        .split("[[package]]")
        .filter(|entry| entry.lines().any(|line| line == "name = \"pistis-agent\""))
        .collect::<Vec<_>>();
    assert_eq!(agent_entries.len(), 1);
    assert!(
        agent_entries[0]
            .lines()
            .any(|line| line == version_assignment)
    );
}
