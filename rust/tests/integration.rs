use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_unicode-safety-check"))
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}

fn run_check(fixture: &str, extra_args: &[&str]) -> std::process::Output {
    Command::new(binary_path())
        .arg("--no-color")
        .args(extra_args)
        .arg(fixture_path(fixture))
        .output()
        .expect("failed to execute binary")
}

/// Extract the finding count from stdout (e.g., "3 finding(s)")
fn finding_count(stdout: &str) -> Option<usize> {
    for line in stdout.lines() {
        if let Some(pos) = line.find(" finding(s)") {
            let prefix = line[..pos].trim();
            // Take last word before "finding(s)"
            if let Some(num_str) = prefix.rsplit_once(' ') {
                return num_str.1.parse().ok();
            }
            return prefix.parse().ok();
        }
    }
    None
}

#[test]
fn test_clean_file() {
    let output = run_check("clean.py", &[]);
    assert_eq!(output.status.code(), Some(0), "clean.py should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0 finding(s)"),
        "clean.py should have no findings, got: {stdout}"
    );
}

#[test]
fn test_bidi_detection() {
    let output = run_check("bidi.py", &[]);
    assert_eq!(output.status.code(), Some(1), "bidi.py should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC001"),
        "bidi.py should trigger USC001, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "bidi.py should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_invisible_detection() {
    let output = run_check("invisible.py", &[]);
    assert_eq!(output.status.code(), Some(1), "invisible.py should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC002"),
        "invisible.py should trigger USC002, got: {stdout}"
    );
}

#[test]
fn test_confusable_detection() {
    let output = run_check("confusable.py", &[]);
    assert_eq!(output.status.code(), Some(1), "confusable.py should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC004"),
        "confusable.py should trigger USC004, got: {stdout}"
    );
    assert!(
        stdout.contains("USC017"),
        "confusable.py should trigger USC017, got: {stdout}"
    );
    assert!(
        stdout.contains("USC003"),
        "confusable.py should trigger USC003 (mixed-script), got: {stdout}"
    );
    assert!(
        stdout.contains("USC019"),
        "confusable.py should trigger USC019 (non-ascii-identifier), got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 4,
        "confusable.py should have at least 4 findings, got: {:?}",
        count
    );
}

#[test]
fn test_mixed_script_detection() {
    let output = run_check("mixed_script.py", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "mixed_script.py should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC003"),
        "mixed_script.py should trigger USC003, got: {stdout}"
    );
    assert!(
        stdout.contains("USC017"),
        "mixed_script.py should trigger USC017 (homoglyph), got: {stdout}"
    );
    assert!(
        stdout.contains("USC019"),
        "mixed_script.py should trigger USC019 (non-ascii-identifier), got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 3,
        "mixed_script.py should have at least 3 findings, got: {:?}",
        count
    );
}

#[test]
fn test_nbsp_detection() {
    let output = run_check("nbsp.js", &["--fail-on-warn"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "nbsp.js should exit 1 with --fail-on-warn"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC005"),
        "nbsp.js should trigger USC005, got: {stdout}"
    );
}

#[test]
fn test_nbsp_exit_zero_without_fail_on_warn() {
    let output = run_check("nbsp.js", &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "nbsp.js should exit 0 without --fail-on-warn (medium severity, high risk file)"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC005"),
        "nbsp.js should still detect USC005, got: {stdout}"
    );
}

#[test]
fn test_control_detection() {
    let output = run_check("control.txt", &[]);
    assert_eq!(output.status.code(), Some(1), "control.txt should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC007"),
        "control.txt should trigger USC007, got: {stdout}"
    );
}

#[test]
fn test_sarif_output() {
    let sarif_path =
        std::env::temp_dir().join(format!("usc-test-sarif-{}.json", std::process::id()));
    let sarif_str = sarif_path.to_str().unwrap();

    let output = Command::new(binary_path())
        .arg("--no-color")
        .arg("--sarif-file")
        .arg(sarif_str)
        .arg(fixture_path("bidi.py"))
        .output()
        .expect("failed to execute binary");

    let status = output.status.code().unwrap_or(-1);
    assert!(
        status == 0 || status == 1,
        "Unexpected exit code: {}",
        status
    );

    assert!(
        sarif_path.exists(),
        "SARIF file should be created at {sarif_str}"
    );

    let contents = std::fs::read_to_string(&sarif_path).expect("failed to read SARIF file");
    let json: serde_json::Value =
        serde_json::from_str(&contents).expect("SARIF output should be valid JSON");

    assert_eq!(
        json.get("version").and_then(|v| v.as_str()),
        Some("2.1.0"),
        "SARIF version should be 2.1.0"
    );
    let runs = json.get("runs").and_then(|r| r.as_array());
    assert!(runs.is_some(), "SARIF should contain runs array");

    // Verify results are non-empty and contain expected rule
    let results = runs
        .unwrap()
        .first()
        .and_then(|r| r.get("results"))
        .and_then(|r| r.as_array());
    assert!(
        results.is_some() && !results.unwrap().is_empty(),
        "SARIF results should be non-empty"
    );
    let has_usc001 = results
        .unwrap()
        .iter()
        .any(|r| r.get("ruleId").and_then(|v| v.as_str()) == Some("USC001"));
    assert!(has_usc001, "SARIF results should contain USC001");

    // Cleanup
    let _ = std::fs::remove_file(&sarif_path);
}

#[test]
fn test_normalization_drift() {
    let output = run_check("normalization.py", &["--fail-on-warn"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "normalization.py should exit 1 with --fail-on-warn"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC006"),
        "normalization.py should trigger USC006, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "normalization.py should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_invalid_encoding() {
    let output = run_check("invalid_utf8.bin", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "invalid_utf8.bin should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC008"),
        "invalid_utf8.bin should trigger USC008, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert_eq!(
        count,
        Some(1),
        "invalid_utf8.bin should have exactly 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_misplaced_bom() {
    let output = run_check("misplaced_bom.py", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "misplaced_bom.py should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC009"),
        "misplaced_bom.py should trigger USC009, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert_eq!(
        count,
        Some(1),
        "misplaced_bom.py should have exactly 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_variation_selector() {
    let output = run_check("variation_sel.txt", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "variation_sel.txt should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC010"),
        "variation_sel.txt should trigger USC010, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "variation_sel.txt should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_private_use() {
    let output = run_check("private_use.txt", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "private_use.txt should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC011"),
        "private_use.txt should trigger USC011, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "private_use.txt should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_tag_character() {
    let output = run_check("tag_char.txt", &[]);
    assert_eq!(output.status.code(), Some(1), "tag_char.txt should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC012"),
        "tag_char.txt should trigger USC012, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "tag_char.txt should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_deprecated_format() {
    let output = run_check("deprecated_fmt.txt", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "deprecated_fmt.txt should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC013"),
        "deprecated_fmt.txt should trigger USC013, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "deprecated_fmt.txt should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_annotation_anchor() {
    let output = run_check("annotation.txt", &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "annotation.txt should exit 1"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC014"),
        "annotation.txt should trigger USC014, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 3,
        "annotation.txt should have at least 3 findings (3 annotation chars), got: {:?}",
        count
    );
}

#[test]
fn test_bidi_pairing() {
    let output = run_check("bidi_pair.py", &[]);
    assert_eq!(output.status.code(), Some(1), "bidi_pair.py should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC015"),
        "bidi_pair.py should trigger USC015, got: {stdout}"
    );
    assert!(
        stdout.contains("USC001"),
        "bidi_pair.py should also trigger USC001 (bidi control), got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 2,
        "bidi_pair.py should have at least 2 findings, got: {:?}",
        count
    );
}

#[test]
fn test_default_ignorable() {
    let output = run_check("ignorable.txt", &["--fail-on-warn"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "ignorable.txt should exit 1 with --fail-on-warn"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC016"),
        "ignorable.txt should trigger USC016, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert!(
        count.is_some() && count.unwrap() >= 1,
        "ignorable.txt should have at least 1 finding, got: {:?}",
        count
    );
}

#[test]
fn test_mixed_line_endings() {
    let output = run_check("mixed_endings.txt", &["--fail-on-warn"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "mixed_endings.txt should exit 1 with --fail-on-warn"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC018"),
        "mixed_endings.txt should trigger USC018, got: {stdout}"
    );
    let count = finding_count(&stdout);
    assert_eq!(
        count,
        Some(1),
        "mixed_endings.txt should have exactly 1 finding, got: {:?}",
        count
    );
}
