//! British-English guard for maintained user-facing text.

use std::{
    fs,
    path::{Path, PathBuf},
};

const DOCUMENT_EXTENSIONS: &[&str] = &["md", "rst"];
const MOBILE_SOURCE_EXTENSIONS: &[&str] = &["swift", "kt"];
const FIXED_THIRD_PARTY_TERMS: &[&str] = &["Device Authorization Grant", "Mozilla Public License"];
const AMERICAN_WORDS: &[(&str, &str)] = &[
    ("analyze", "analyse"),
    ("analyzed", "analysed"),
    ("analyzes", "analyses"),
    ("analyzing", "analysing"),
    ("artifact", "artefact"),
    ("artifacts", "artefacts"),
    ("authorization", "authorisation"),
    ("authorizations", "authorisations"),
    ("authorize", "authorise"),
    ("authorized", "authorised"),
    ("authorizes", "authorises"),
    ("authorizing", "authorising"),
    ("behavior", "behaviour"),
    ("behaviors", "behaviours"),
    ("catalog", "catalogue"),
    ("catalogs", "catalogues"),
    ("center", "centre"),
    ("centered", "centred"),
    ("centering", "centring"),
    ("centers", "centres"),
    ("color", "colour"),
    ("colored", "coloured"),
    ("colors", "colours"),
    ("customize", "customise"),
    ("customized", "customised"),
    ("customizes", "customises"),
    ("customizing", "customising"),
    ("dialog", "dialogue"),
    ("dialogs", "dialogues"),
    ("enrollment", "enrolment"),
    ("enrollments", "enrolments"),
    ("finalize", "finalise"),
    ("finalized", "finalised"),
    ("finalizes", "finalises"),
    ("finalizing", "finalising"),
    ("labeled", "labelled"),
    ("labeling", "labelling"),
    ("license", "licence"),
    ("licenses", "licences"),
    ("normalization", "normalisation"),
    ("normalize", "normalise"),
    ("normalized", "normalised"),
    ("normalizes", "normalises"),
    ("normalizing", "normalising"),
    ("organization", "organisation"),
    ("organizational", "organisational"),
    ("organizations", "organisations"),
    ("recognize", "recognise"),
    ("recognized", "recognised"),
    ("recognizes", "recognises"),
    ("recognizing", "recognising"),
];

pub(crate) fn check() -> Result<(), String> {
    let root = repository_root()?;
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    let mut failures = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("text path escaped repository: {}", path.display()))?;
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", relative.display()))?;
        let extension = path.extension().and_then(|value| value.to_str());
        let findings = if extension.is_some_and(|value| DOCUMENT_EXTENSIONS.contains(&value)) {
            inspect_document(&contents)
        } else {
            inspect_mobile_strings(&contents)
        };
        failures.extend(findings.into_iter().map(|finding| {
            format!(
                "{}:{}:{}: use `{}` instead of `{}` in user-facing text",
                relative.display(),
                finding.line,
                finding.column,
                finding.preferred,
                finding.found
            )
        }));
    }
    if failures.is_empty() {
        println!("language guard passed: maintained user-facing text uses British English");
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

pub(crate) fn fix() -> Result<(), String> {
    let root = repository_root()?;
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    let mut changed = 0;
    for path in files {
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let extension = path.extension().and_then(|value| value.to_str());
        let rewritten = if extension.is_some_and(|value| DOCUMENT_EXTENSIONS.contains(&value)) {
            rewrite_document(&contents)
        } else {
            rewrite_mobile_strings(&contents)
        };
        if rewritten != contents {
            fs::write(&path, rewritten)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
            changed += 1;
        }
    }
    println!("updated {changed} files to British English");
    Ok(())
}

fn repository_root() -> Result<&'static Path, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask must be directly below the repository root".to_owned())
}

#[derive(Debug, Eq, PartialEq)]
struct Finding {
    line: usize,
    column: usize,
    found: String,
    preferred: &'static str,
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect directory entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("text path escaped repository: {}", path.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", relative.display()))?;
        if file_type.is_dir() {
            let first = relative
                .components()
                .next()
                .and_then(|part| part.as_os_str().to_str());
            if !matches!(first, Some(".git" | "target" | "fixtures"))
                && !relative
                    .components()
                    .any(|part| part.as_os_str() == "target")
            {
                collect_files(root, &path, output)?;
            }
            continue;
        }
        let extension = path.extension().and_then(|value| value.to_str());
        let document = extension.is_some_and(|value| DOCUMENT_EXTENSIONS.contains(&value));
        let mobile_source = extension
            .is_some_and(|value| MOBILE_SOURCE_EXTENSIONS.contains(&value))
            && (relative.starts_with("ios/PistisApp/Sources/App")
                || relative == Path::new("ios/PistisApp/Sources/Platform/PlatformFailure.swift")
                || relative.starts_with(
                    "android/app/src/main/java/org/mnemosynebiosciences/pistis/presentation",
                ));
        if document || mobile_source {
            output.push(path);
        }
    }
    output.sort();
    Ok(())
}

fn inspect_document(contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut fenced = false;
    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced || indented_literal_line(line) {
            continue;
        }
        inspect_text_segments(line, index + 1, true, &mut findings);
    }
    findings
}

fn indented_literal_line(line: &str) -> bool {
    line.starts_with("   $ ")
        || line.starts_with("   # ")
        || line.starts_with("   cargo ")
        || line.starts_with("   docker ")
        || line.starts_with("   xcodebuild ")
        || line.starts_with("   ./")
        || line.starts_with("   /")
}

fn inspect_mobile_strings(contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        inspect_text_segments(line, index + 1, false, &mut findings);
    }
    findings
}

fn rewrite_document(contents: &str) -> String {
    let mut output = String::with_capacity(contents.len());
    let mut fenced = false;
    for line in contents.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let newline = if line.ends_with('\n') { "\n" } else { "" };
        let trimmed = body.trim_start();
        if trimmed.starts_with("```") {
            fenced = !fenced;
            output.push_str(line);
        } else if fenced || indented_literal_line(body) {
            output.push_str(line);
        } else {
            output.push_str(&rewrite_line(body, true));
            output.push_str(newline);
        }
    }
    output
}

fn rewrite_mobile_strings(contents: &str) -> String {
    let mut output = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        output.push_str(&rewrite_line(body, false));
        if line.ends_with('\n') {
            output.push('\n');
        }
    }
    output
}

fn rewrite_line(line: &str, document: bool) -> String {
    let mut findings = Vec::new();
    inspect_text_segments(line, 1, document, &mut findings);
    let mut output = line.to_owned();
    for finding in findings.into_iter().rev() {
        let start = finding.column - 1;
        let end = start + finding.found.len();
        let replacement = if finding
            .found
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_uppercase)
        {
            let mut preferred = finding.preferred.to_owned();
            preferred[0..1].make_ascii_uppercase();
            preferred
        } else {
            finding.preferred.to_owned()
        };
        output.replace_range(start..end, &replacement);
    }
    output
}

fn inspect_text_segments(
    line: &str,
    line_number: usize,
    document: bool,
    output: &mut Vec<Finding>,
) {
    let delimiter = if document { '`' } else { '"' };
    let mut start = 0;
    let mut inside = document;
    for (offset, character) in line.char_indices() {
        if character != delimiter || escaped(line, offset) {
            continue;
        }
        if inside && start < offset {
            inspect_words(&line[start..offset], line_number, start, output);
        }
        inside = !inside;
        start = offset + character.len_utf8();
    }
    if inside && start < line.len() {
        inspect_words(&line[start..], line_number, start, output);
    }
}

fn escaped(line: &str, offset: usize) -> bool {
    offset > 0 && line.as_bytes()[offset - 1] == b'\\'
}

fn inspect_words(text: &str, line: usize, base_column: usize, output: &mut Vec<Finding>) {
    for (offset, word) in words(text) {
        if word.bytes().all(|byte| !byte.is_ascii_lowercase()) {
            continue;
        }
        if FIXED_THIRD_PARTY_TERMS.iter().any(|phrase| {
            text.match_indices(phrase)
                .any(|(start, value)| start <= offset && offset < start + value.len())
        }) {
            continue;
        }
        if let Some((_, preferred)) = AMERICAN_WORDS
            .iter()
            .find(|(american, _)| word.eq_ignore_ascii_case(american))
        {
            output.push(Finding {
                line,
                column: base_column + offset + 1,
                found: word.to_owned(),
                preferred,
            });
        }
    }
}

fn words(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut start = None;
    text.char_indices()
        .chain(std::iter::once((text.len(), ' ')))
        .filter_map(move |(offset, character)| {
            if character.is_ascii_alphabetic() {
                start.get_or_insert(offset);
                None
            } else {
                start.take().map(|begin| (begin, &text[begin..offset]))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_american_document_prose_but_skips_inline_and_fenced_code() {
        let text = "Authorization behavior and color.\n\
                    `authorization behavior color`\n\
                    ```text\n\
                    authorization behavior color\n\
                    ```\n";
        let findings = inspect_document(text);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.found.to_ascii_lowercase())
                .collect::<Vec<_>>(),
            ["authorization", "behavior", "color"]
        );
    }

    #[test]
    fn scans_only_mobile_string_literals() {
        let findings = inspect_mobile_strings(
            "let authorizationState = true\n\
             Text(\"Authorization behavior\")\n",
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.found.to_ascii_lowercase())
                .collect::<Vec<_>>(),
            ["authorization", "behavior"]
        );
    }

    #[test]
    fn accepts_british_user_facing_text() {
        assert!(inspect_document("Authorisation behaviour and colour.").is_empty());
        assert!(inspect_mobile_strings("Text(\"Authorised organisation\")").is_empty());
        assert!(
            inspect_document("OAuth Device Authorization Grant; Mozilla Public License 2.0.")
                .is_empty()
        );
    }

    #[test]
    fn rewrites_prose_and_mobile_strings_without_changing_code() {
        assert_eq!(
            rewrite_document("Authorization `authorization` behavior.\n"),
            "Authorisation `authorization` behaviour.\n"
        );
        assert_eq!(
            rewrite_mobile_strings("let authorization = \"Authorization behavior\"\n"),
            "let authorization = \"Authorisation behaviour\"\n"
        );
    }
}
