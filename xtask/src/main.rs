//! Repository maintenance commands.

mod language;

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

const MAX_RUST_LINES: usize = 1_000;
const EXCEPTIONS_FILE: &str = "architecture-exceptions.txt";

fn main() {
    let result = match env::args().nth(1).as_deref() {
        Some("architecture") => check_architecture(),
        Some("language") => language::check(),
        Some("language-fix") => language::fix(),
        _ => Err("usage: cargo run --locked -p xtask -- architecture\n\
             supported commands: architecture, language, language-fix"
            .to_owned()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn check_architecture() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask must be located directly below the repository root".to_owned())?;
    let exceptions = read_exceptions(root)?;
    let mut rust_files = Vec::new();
    collect_rust_files(root, root, &mut rust_files)?;
    let mut failures = Vec::new();
    for path in rust_files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("source path escaped repository: {}", path.display()))?;
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", relative.display()))?;
        if let Err(error) = validate_rust_file(relative, &contents, &exceptions) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        println!(
            "architecture guardrails passed: Rust sources use package hierarchy and no file exceeds {MAX_RUST_LINES} lines"
        );
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn collect_rust_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect directory entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("source path escaped repository: {}", path.display()))?;
        if entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", relative.display()))?
            .is_dir()
        {
            if !matches!(
                relative
                    .components()
                    .next()
                    .and_then(|part| part.as_os_str().to_str()),
                Some(".git" | "target")
            ) && !relative
                .components()
                .any(|part| part.as_os_str() == "target")
            {
                collect_rust_files(root, &path, output)?;
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn read_exceptions(root: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let path = root.join(EXCEPTIONS_FILE);
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {EXCEPTIONS_FILE}: {error}"))?;
    let mut exceptions = BTreeMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (file, rationale) = line.split_once('|').ok_or_else(|| {
            format!(
                "{EXCEPTIONS_FILE}:{} must use `relative/path.rs | rationale`",
                index + 1
            )
        })?;
        let file = PathBuf::from(file.trim());
        let rationale = rationale.trim();
        if file.is_absolute()
            || file.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || file.extension().is_none_or(|extension| extension != "rs")
            || rationale.len() < 20
            || exceptions
                .insert(file.clone(), rationale.to_owned())
                .is_some()
        {
            return Err(format!(
                "{EXCEPTIONS_FILE}:{} contains an unsafe, duplicate, or unexplained exception",
                index + 1
            ));
        }
    }
    Ok(exceptions)
}

fn validate_rust_file(
    relative: &Path,
    contents: &str,
    exceptions: &BTreeMap<PathBuf, String>,
) -> Result<(), String> {
    if !valid_rust_location(relative) {
        return Err(format!(
            "{}: Rust source must live in a reviewed crate, xtask, integration, example, benchmark, or fuzz-target hierarchy",
            relative.display()
        ));
    }
    let lines = contents.lines().count();
    if lines > MAX_RUST_LINES && !exceptions.contains_key(relative) {
        return Err(format!(
            "{}: {lines} lines exceeds the {MAX_RUST_LINES}-line limit; split the module or add a reviewed exception with a concrete rationale",
            relative.display()
        ));
    }
    Ok(())
}

fn valid_rust_location(path: &Path) -> bool {
    let components = path
        .iter()
        .filter_map(|component| component.to_str())
        .collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        ["xtask", "src", ..]
            | ["crates", _, "src" | "tests" | "benches" | "examples", ..]
            | ["tests" | "benches" | "examples", ..]
            | ["fuzz", "fuzz_targets", ..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    const GITHUB_APP_CONFIGURATION: &[u8] =
        include_bytes!("../../fixtures/github-app-configuration-v1.json");
    const IOS_INFO_PLIST: &str = include_str!("../../ios/PistisApp/Info.plist");
    const IOS_GITHUB_CONFIGURATION: &str =
        include_str!("../../ios/PistisApp/Sources/App/GitHubEnrolmentReadiness.swift");

    #[test]
    fn accepts_hierarchical_source_below_limit() {
        assert!(
            validate_rust_file(
                Path::new("crates/pistis-domain/src/identity/user.rs"),
                "fn user() {}\n",
                &BTreeMap::new()
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_misplaced_rust_source() {
        let error = validate_rust_file(
            Path::new("scripts/protocol.rs"),
            "fn main() {}\n",
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.contains("must live"));
    }

    #[test]
    fn accepts_cargo_fuzz_target_hierarchy() {
        assert!(
            validate_rust_file(
                Path::new("fuzz/fuzz_targets/canonical_parser.rs"),
                "fn target() {}\n",
                &BTreeMap::new()
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_oversized_source_without_exception() {
        let source = "line\n".repeat(MAX_RUST_LINES + 1);
        let error = validate_rust_file(
            Path::new("crates/pistis-domain/src/lib.rs"),
            &source,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn accepts_reviewed_oversized_exception() {
        let path = PathBuf::from("crates/pistis-domain/src/lib.rs");
        let source = "line\n".repeat(MAX_RUST_LINES + 1);
        let exceptions = BTreeMap::from([(
            path.clone(),
            "Protocol table is generated atomically.".to_owned(),
        )]);
        assert!(validate_rust_file(&path, &source, &exceptions).is_ok());
    }

    #[test]
    fn reviewed_github_app_digest_matches_fixture_plist_and_swift() {
        let digest = Sha256::digest(GITHUB_APP_CONFIGURATION);
        let mut digest_hex = String::with_capacity(64);
        for byte in digest {
            write!(&mut digest_hex, "{byte:02x}").unwrap();
        }
        assert!(
            IOS_INFO_PLIST.contains(&format!("<string>{digest_hex}</string>")),
            "Info.plist must embed the canonical GitHub App fixture digest"
        );

        let byte_list = IOS_GITHUB_CONFIGURATION
            .split_once("static let reviewedAppConfigurationDigest = Data([")
            .expect("reviewed Swift digest declaration")
            .1
            .split_once("])")
            .expect("closed Swift digest declaration")
            .0;
        let swift_digest = byte_list
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| {
                u8::from_str_radix(
                    token
                        .strip_prefix("0x")
                        .expect("Swift digest bytes use hexadecimal"),
                    16,
                )
                .expect("Swift digest byte")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            swift_digest,
            &digest[..],
            "Swift must enforce the canonical GitHub App fixture digest"
        );
    }
}
