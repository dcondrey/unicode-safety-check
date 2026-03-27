//! Output: SARIF, annotations, diagnostics, summaries.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;

use anyhow::Result;
use serde_json::json;

use crate::models::{get_rule, Finding, Severity, RULE_IDS};
use crate::unicode_data::classify_char;

const COLOR_CRITICAL: &str = "\x1b[1;31m";
const COLOR_HIGH: &str = "\x1b[0;31m";
const COLOR_MEDIUM: &str = "\x1b[0;33m";
const COLOR_LOW: &str = "\x1b[0;36m";
const RESET: &str = "\x1b[0m";

fn severity_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => COLOR_CRITICAL,
        Severity::High => COLOR_HIGH,
        Severity::Medium => COLOR_MEDIUM,
        Severity::Low => COLOR_LOW,
    }
}

fn severity_upper(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

/// Check if a codepoint is invisible/non-printing and should be escaped for
/// display. Delegates to `classify_char` so every character the checker flags
/// is also escaped in user-visible output.
fn is_invisible(cp: u32) -> bool {
    let (rule, is_vs) = classify_char(cp);
    rule.is_some() || is_vs
}

/// Replace invisible Unicode chars with `\u{XXXX}` notation for display.
pub fn escape_invisible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let cp = ch as u32;
        if cp > 0x7F && is_invisible(cp) {
            out.push_str(&format!("\\u{{{:04X}}}", cp));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Format a finding for terminal output.
pub fn format_finding(f: &Finding, color: bool) -> String {
    let sev_label = if color {
        format!(
            "{}{}{}",
            severity_color(f.severity),
            severity_upper(f.severity),
            RESET
        )
    } else {
        severity_upper(f.severity).to_string()
    };
    let mut lines = vec![
        format!(
            "  {} [{} {}] {}:{}:{}",
            sev_label, f.rule_id, f.rule_name, f.file, f.line, f.col
        ),
        format!("    {}", f.char_info),
        format!("    {}", f.message),
    ];
    if !f.snippet.is_empty() {
        lines.push(format!("    near: \"{}\"", escape_invisible(&f.snippet)));
    }
    lines.join("\n")
}

/// Print GitHub workflow annotation commands.
pub fn emit_annotations(findings: &[Finding]) {
    for f in findings {
        let lvl = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium | Severity::Low => "warning",
        };
        println!(
            "::{} file={},line={},col={},title=Unicode Safety [{}]::{} -- {}",
            lvl,
            f.file,
            f.line,
            f.col + 1,
            f.rule_name,
            f.char_info,
            f.message
        );
    }
}

/// Format a summary of findings.
pub fn format_summary(findings: &[Finding], files_scanned: usize) -> String {
    let mut lines = vec![
        format!(
            "Unicode Safety Check: {} files scanned, {} finding(s)",
            files_scanned,
            findings.len()
        ),
        String::new(),
    ];
    for &sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let items: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if !items.is_empty() {
            lines.push(format!("  {} ({}):", severity_upper(sev), items.len()));
            for f in items.iter().take(10) {
                lines.push(format!(
                    "    {} {}:{} {}",
                    f.rule_id, f.file, f.line, f.rule_name
                ));
            }
            if items.len() > 10 {
                lines.push(format!("    ... and {} more", items.len() - 10));
            }
            lines.push(String::new());
        }
    }
    if findings.is_empty() {
        lines.push("  No adversarial Unicode detected.".to_string());
    }
    lines.join("\n")
}

/// Write markdown table to `$GITHUB_STEP_SUMMARY`. No-op if env var not set.
pub fn write_step_summary(findings: &[Finding], files_scanned: usize) {
    let path = match env::var("GITHUB_STEP_SUMMARY") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let count = |sev: Severity| findings.iter().filter(|f| f.severity == sev).count();
    let mut lines = vec![
        "### Unicode Safety Check".to_string(),
        String::new(),
        "| Metric | Count |".to_string(),
        "|--------|-------|".to_string(),
        format!("| Files scanned | {} |", files_scanned),
        format!("| Critical | {} |", count(Severity::Critical)),
        format!("| High | {} |", count(Severity::High)),
        format!("| Medium | {} |", count(Severity::Medium)),
        format!("| Low | {} |", count(Severity::Low)),
        String::new(),
    ];
    if !findings.is_empty() {
        lines.push("#### Top findings".to_string());
        lines.push(String::new());
        lines.push("| Severity | Rule | File | Line | Description |".to_string());
        lines.push("|----------|------|------|------|-------------|".to_string());
        for f in findings.iter().take(20) {
            let msg: String = f.message.chars().take(80).collect();
            let msg = msg.replace('|', "\\|");
            lines.push(format!(
                "| {} | {} {} | `{}` | {} | {} |",
                f.severity, f.rule_id, f.rule_name, f.file, f.line, msg
            ));
        }
        if findings.len() > 20 {
            lines.push(format!("| | | | | ... and {} more |", findings.len() - 20));
        }
    } else {
        lines.push("No adversarial Unicode detected.".to_string());
    }
    let content = lines.join("\n") + "\n";
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()));
}

/// Write SARIF 2.1.0 JSON to the given path.
pub fn write_sarif(findings: &[Finding], sarif_path: &str) -> Result<()> {
    let rules: Vec<serde_json::Value> = RULE_IDS
        .iter()
        .filter_map(|&rid| {
            let info = get_rule(rid)?;
            let level = match info.default_severity {
                Severity::Low => "note",
                Severity::Medium => "warning",
                _ => "error",
            };
            Some(json!({
                "id": rid,
                "name": info.name,
                "shortDescription": { "text": info.description },
                "defaultConfiguration": { "level": level },
                "helpUri": "https://github.com/dcondrey/unicode-safety-check#what-it-detects",
                "properties": { "tags": ["security", "unicode", "supply-chain"] }
            }))
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Low => "note",
                Severity::Medium => "warning",
                _ => "error",
            };
            let uri = f.file.trim_start_matches("./");
            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": format!("{} -- {}", f.char_info, f.message) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" },
                        "region": { "startLine": f.line, "startColumn": f.col + 1 }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "unicode-safety-check",
                    "informationUri": "https://github.com/dcondrey/unicode-safety-check",
                    "version": "3.0.0",
                    "semanticVersion": "3.0.0",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    let content = serde_json::to_string_pretty(&sarif)?;
    fs::write(sarif_path, content)?;
    Ok(())
}

/// Append key=value pairs to `$GITHUB_OUTPUT`. No-op if env var not set.
pub fn write_github_outputs(findings: &[Finding], files_scanned: usize, sarif_path: Option<&str>) {
    let path = match env::var("GITHUB_OUTPUT") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let mut content = format!(
        "findings={}\nfiles_scanned={}\ncritical={}\nhigh={}\n",
        findings.len(),
        files_scanned,
        critical,
        high
    );
    if let Some(sp) = sarif_path {
        content.push_str(&format!("sarif_file={}\n", sp));
    }
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Context;

    fn make_finding() -> Finding {
        Finding {
            rule_id: "USC001",
            rule_name: "bidi-control",
            severity: Severity::Critical,
            file: "src/main.rs".to_string(),
            line: 42,
            col: 5,
            message: "Bidirectional override detected".to_string(),
            char_info: "U+202E RIGHT-TO-LEFT OVERRIDE".to_string(),
            context: Context::Identifier,
            snippet: "let x\u{202E} = 1;".to_string(),
        }
    }

    #[test]
    fn test_format_finding_no_color() {
        let f = make_finding();
        let output = format_finding(&f, false);
        assert!(output.contains("CRITICAL [USC001 bidi-control] src/main.rs:42:5"));
        assert!(output.contains("U+202E RIGHT-TO-LEFT OVERRIDE"));
        assert!(output.contains("Bidirectional override detected"));
        assert!(output.contains("near: \"let x\\u{202E} = 1;\""));
    }

    #[test]
    fn test_format_finding_with_color() {
        let f = make_finding();
        let output = format_finding(&f, true);
        assert!(output.contains("\x1b[1;31mCRITICAL\x1b[0m"));
    }

    #[test]
    fn test_format_finding_no_snippet() {
        let mut f = make_finding();
        f.snippet = String::new();
        let output = format_finding(&f, false);
        assert!(!output.contains("near:"));
    }

    #[test]
    fn test_escape_invisible() {
        // ZWS (U+200B)
        let input = "hello\u{200B}world";
        let escaped = escape_invisible(input);
        assert_eq!(escaped, "hello\\u{200B}world");

        // FEFF (BOM)
        let input2 = "\u{FEFF}text";
        assert_eq!(escape_invisible(input2), "\\u{FEFF}text");

        // Regular ASCII stays unchanged
        assert_eq!(escape_invisible("hello"), "hello");

        // Non-invisible high codepoint stays unchanged
        let input3 = "caf\u{00E9}";
        assert_eq!(escape_invisible(input3), "caf\u{00E9}");

        // Soft hyphen
        let input4 = "a\u{00AD}b";
        assert_eq!(escape_invisible(input4), "a\\u{00AD}b");
    }

    #[test]
    fn test_format_summary_no_findings() {
        let summary = format_summary(&[], 10);
        assert!(summary.contains("10 files scanned, 0 finding(s)"));
        assert!(summary.contains("No adversarial Unicode detected."));
    }

    #[test]
    fn test_format_summary_with_findings() {
        let findings = vec![make_finding()];
        let summary = format_summary(&findings, 5);
        assert!(summary.contains("5 files scanned, 1 finding(s)"));
        assert!(summary.contains("CRITICAL (1):"));
        assert!(summary.contains("USC001 src/main.rs:42 bidi-control"));
    }
}
