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
}

#[test]
fn test_nbsp_detection() {
    let output = run_check("nbsp.js", &["--fail-on-warn"]);
    assert_eq!(output.status.code(), Some(1), "nbsp.js should exit 1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("USC005"),
        "nbsp.js should trigger USC005, got: {stdout}"
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
    assert!(
        json.get("runs").and_then(|r| r.as_array()).is_some(),
        "SARIF should contain runs array"
    );

    // Cleanup
    let _ = std::fs::remove_file(&sarif_path);
}
