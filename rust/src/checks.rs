//! Detection rules: single-pass character classification + token-level checks.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

use crate::config::Policy;
use crate::models::{get_rule, Context, Finding, Severity, Token};
use crate::unicode_data::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn context_value(ctx: Context) -> &'static str {
    match ctx {
        Context::Identifier => "identifier",
        Context::Comment => "comment",
        Context::String => "string",
        Context::Other => "other",
    }
}

/// Get severity from policy overrides or rule default.
pub fn sev(rule_id: &str, policy: Option<&Policy>) -> Severity {
    let rule = match get_rule(rule_id) {
        Some(r) => r,
        None => return Severity::Critical,
    };
    if let Some(p) = policy {
        if let Some(&s) = p.severity_overrides.get(rule.name) {
            return s;
        }
    }
    rule.default_severity
}

/// Construct a Finding with the correct severity.
#[allow(clippy::too_many_arguments)]
pub fn make_finding(
    rule_id: &'static str,
    file: &str,
    line: usize,
    col: usize,
    msg: String,
    info: String,
    ctx: Context,
    snip: String,
    policy: Option<&Policy>,
) -> Finding {
    let (rule_name, severity) = match get_rule(rule_id) {
        Some(r) => (r.name, sev(rule_id, policy)),
        None => ("unknown", Severity::Critical),
    };
    Finding {
        rule_id,
        rule_name,
        severity,
        file: file.to_string(),
        line,
        col,
        message: msg,
        char_info: info,
        context: ctx,
        snippet: snip,
    }
}

/// Extract ~width chars centered on col, with "..." prefix/suffix if truncated.
pub fn snippet(text: &str, col: usize, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let half = width / 2;
    let clamped_col = std::cmp::min(col, chars.len().saturating_sub(1));
    let s = clamped_col.saturating_sub(half);
    let e = std::cmp::min(chars.len(), clamped_col + half);
    let mut r: String = chars[s..e].iter().collect();
    // strip trailing \r\n
    while r.ends_with('\r') || r.ends_with('\n') {
        r.pop();
    }
    if s > 0 {
        r = format!("...{}", r);
    }
    if e < chars.len() {
        r = format!("{}...", r);
    }
    r
}

// ---------------------------------------------------------------------------
// Line-level character scan
// ---------------------------------------------------------------------------

/// Single-pass character scan. Appends findings in-place.
pub fn scan_line_chars(
    line: &str,
    line_num: usize,
    file: &str,
    ctx: Context,
    policy: &Policy,
    is_critical_only: bool,
    findings: &mut Vec<Finding>,
) {
    let mut vs_count: usize = 0;
    let mut embed_depth: i32 = 0;
    let mut isolate_depth: i32 = 0;

    for (col, ch) in line.chars().enumerate() {
        let cp = ch as u32;

        // Bidi pairing tracking (always)
        if BIDI_OPENERS.contains(&cp) {
            embed_depth += 1;
        } else if cp == BIDI_CLOSER_PDF {
            embed_depth -= 1;
        } else if BIDI_ISOLATE_OPENERS.contains(&cp) {
            isolate_depth += 1;
        } else if cp == BIDI_ISOLATE_CLOSER {
            isolate_depth -= 1;
        }

        // BOM check
        if cp == 0xFEFF {
            if !(line_num == 1 && col == 0) {
                findings.push(make_finding(
                    "USC009",
                    file,
                    line_num,
                    col,
                    "Misplaced byte-order mark".to_string(),
                    char_info(ch),
                    Context::Other,
                    snippet(line, col, 40),
                    Some(policy),
                ));
            }
            continue;
        }

        let (rule_id, is_vs) = classify_char(cp);
        if is_vs {
            vs_count += 1;
            continue;
        }

        let rule_id = match rule_id {
            Some(r) => r,
            None => continue,
        };

        // Critical rules always run; non-critical only on changed lines
        let is_critical = matches!(rule_id, "USC001" | "USC011" | "USC012");
        if is_critical_only && !is_critical {
            continue;
        }

        if policy.is_allowed(file, cp, ctx) {
            continue;
        }

        let description = get_rule(rule_id)
            .map(|r| r.description)
            .unwrap_or("Unknown rule");
        let info = char_info(ch);
        findings.push(make_finding(
            rule_id,
            file,
            line_num,
            col,
            format!("{} {} in {}", description, info, context_value(ctx)),
            info,
            ctx,
            snippet(line, col, 40),
            Some(policy),
        ));
    }

    // Variation selector density
    if vs_count >= 3 && !is_critical_only {
        let line_preview: String = line.chars().take(80).collect();
        findings.push(make_finding(
            "USC010",
            file,
            line_num,
            0,
            format!("{} variation selectors on one line", vs_count),
            format!("{} variation selectors", vs_count),
            ctx,
            line_preview,
            Some(policy),
        ));
    }

    // Bidi pairing
    if embed_depth != 0 {
        let line_preview: String = line.chars().take(80).collect();
        findings.push(make_finding(
            "USC015",
            file,
            line_num,
            0,
            format!(
                "Unbalanced bidi embedding/override controls (depth: {})",
                embed_depth
            ),
            format!("embed imbalance: {}", embed_depth),
            Context::Other,
            line_preview,
            Some(policy),
        ));
    }
    if isolate_depth != 0 {
        let line_preview: String = line.chars().take(80).collect();
        findings.push(make_finding(
            "USC015",
            file,
            line_num,
            0,
            format!(
                "Unbalanced bidi isolate controls (depth: {})",
                isolate_depth
            ),
            format!("isolate imbalance: {}", isolate_depth),
            Context::Other,
            line_preview,
            Some(policy),
        ));
    }
}

// ---------------------------------------------------------------------------
// Confusable tracker
// ---------------------------------------------------------------------------

/// Tracks identifier skeletons to detect confusable collisions across a file.
///
/// Capped at 100_000 entries to prevent unbounded memory growth from
/// adversarial inputs with many unique identifiers.
pub struct ConfusableTracker {
    seen: HashMap<String, (String, usize, usize)>,
}

const CONFUSABLE_TRACKER_CAP: usize = 100_000;

impl ConfusableTracker {
    pub fn new() -> Self {
        ConfusableTracker {
            seen: HashMap::new(),
        }
    }

    /// Check an identifier for confusable collision. Only applies to Identifier context.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &mut self,
        text: &str,
        line: usize,
        col: usize,
        file: &str,
        ctx: Context,
        policy: &Policy,
        findings: &mut Vec<Finding>,
    ) {
        if ctx != Context::Identifier {
            return;
        }
        let skel = skeleton(text);
        if let Some((orig_text, orig_line, orig_col)) = self.seen.get(&skel) {
            if orig_text != text {
                findings.push(make_finding(
                    "USC004",
                    file,
                    line,
                    col,
                    format!(
                        "'{}' has same skeleton as '{}' (line {}:{})",
                        text, orig_text, orig_line, orig_col
                    ),
                    format!("confusable with '{}'", orig_text),
                    ctx,
                    text.to_string(),
                    Some(policy),
                ));
            }
        } else {
            if self.seen.len() >= CONFUSABLE_TRACKER_CAP {
                self.seen.clear();
            }
            self.seen.insert(skel, (text.to_string(), line, col));
        }
    }
}

// ---------------------------------------------------------------------------
// Token-level checks
// ---------------------------------------------------------------------------

/// Run token-level checks: mixed-script, homoglyph, normalization, non-ASCII.
pub fn check_token(tok: &Token, file: &str, policy: &Policy, findings: &mut Vec<Finding>) {
    let text = &tok.text;
    let ctx = tok.context;
    let line = tok.line;
    let col = tok.col;

    if ctx == Context::Identifier {
        // Mixed-script (USC003)
        let mut scripts = std::collections::HashSet::new();
        for ch in text.chars() {
            let s = get_script(ch);
            if s != "Common" && s != "Inherited" && s != "Unknown" {
                scripts.insert(s);
            }
        }
        if scripts.len() > 1 && policy.context_action("mixed-script", ctx) != "ignore" {
            let mut sorted: Vec<&str> = scripts.into_iter().collect();
            sorted.sort();
            let info = sorted.join(", ");
            findings.push(make_finding(
                "USC003",
                file,
                line,
                col,
                format!("Mixed-script identifier '{}' ({})", text, info),
                format!("scripts: {}", info),
                ctx,
                text.clone(),
                Some(policy),
            ));
        }

        // Non-ASCII identifier policy (USC019)
        if policy.identifier_policy == "ascii-only" {
            for (i, ch) in text.chars().enumerate() {
                if ch as u32 > 0x7F {
                    findings.push(make_finding(
                        "USC019",
                        file,
                        line,
                        col + i,
                        format!(
                            "Non-ASCII {} in identifier '{}' (policy: ascii-only)",
                            char_info(ch),
                            text
                        ),
                        char_info(ch),
                        ctx,
                        text.clone(),
                        Some(policy),
                    ));
                    break;
                }
            }
        } else if policy.identifier_policy == "permitted-scripts" {
            for ch in text.chars() {
                let s = get_script(ch);
                if s != "Common" && s != "Inherited" && !policy.permitted_scripts.contains(s) {
                    findings.push(make_finding(
                        "USC019",
                        file,
                        line,
                        col,
                        format!(
                            "Identifier '{}' uses script '{}' not in permitted set",
                            text, s
                        ),
                        format!("script {}", s),
                        ctx,
                        text.clone(),
                        Some(policy),
                    ));
                    break;
                }
            }
        }
    }

    // Homoglyphs (skip strings)
    if ctx != Context::String {
        for (i, ch) in text.chars().enumerate() {
            let cp = ch as u32;
            if let Some(target) = confusable_target(cp) {
                // Skip ASCII chars themselves
                if !(0x41..=0x5A).contains(&cp) && !(0x61..=0x7A).contains(&cp) {
                    findings.push(make_finding(
                        "USC017",
                        file,
                        line,
                        col + i,
                        format!(
                            "Homoglyph {} looks like '{}' in {}",
                            char_info(ch),
                            target,
                            context_value(ctx)
                        ),
                        char_info(ch),
                        ctx,
                        text.clone(),
                        Some(policy),
                    ));
                }
            }
        }
    }

    // Normalization drift (USC006)
    let nfc: String = text.nfc().collect();
    if nfc != *text {
        let nfkc: String = text.nfkc().collect();
        let info = if nfkc != nfc {
            format!("NFC: '{}', NFKC: '{}'", nfc, nfkc)
        } else {
            format!("NFC: '{}'", nfc)
        };
        findings.push(make_finding(
            "USC006",
            file,
            line,
            col,
            format!("'{}' changes under NFC ({})", text, info),
            info,
            ctx,
            text.clone(),
            Some(policy),
        ));
    }
}

// ---------------------------------------------------------------------------
// Encoding check
// ---------------------------------------------------------------------------

/// Check if raw bytes are valid UTF-8. Returns a finding on error.
pub fn check_encoding(raw: &[u8], file: &str, policy: &Policy) -> Option<Finding> {
    match std::str::from_utf8(raw) {
        Ok(_) => None,
        Err(e) => {
            let info = format!("byte {}: {}", e.valid_up_to(), e);
            Some(Finding {
                rule_id: "USC008",
                rule_name: "invalid-encoding",
                severity: sev("USC008", Some(policy)),
                file: file.to_string(),
                line: 1,
                col: e.valid_up_to(),
                message: format!("Not valid UTF-8: {}", info),
                char_info: info,
                context: Context::Other,
                snippet: String::new(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Mixed line endings
// ---------------------------------------------------------------------------

/// Check for mixed CRLF/LF/CR line endings. Returns a finding if >1 style present.
pub fn check_mixed_line_endings(content: &str, file: &str, policy: &Policy) -> Option<Finding> {
    let has_crlf = content.contains("\r\n");
    let mut has_cr = false;
    let mut has_lf = false;

    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
            } else {
                has_cr = true;
                i += 1;
            }
        } else if bytes[i] == b'\n' {
            has_lf = true;
            i += 1;
        } else {
            i += 1;
        }
    }

    let count = has_crlf as u8 + has_cr as u8 + has_lf as u8;
    if count > 1 {
        let mut styles = Vec::new();
        if has_crlf {
            styles.push("CRLF");
        }
        if has_lf {
            styles.push("LF");
        }
        if has_cr {
            styles.push("CR");
        }
        let joined = styles.join(", ");
        Some(Finding {
            rule_id: "USC018",
            rule_name: "mixed-line-endings",
            severity: sev("USC018", Some(policy)),
            file: file.to_string(),
            line: 1,
            col: 0,
            message: format!("Mixed line endings: {}", joined),
            char_info: format!("mixed: {}", joined),
            context: Context::Other,
            snippet: String::new(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;

    fn default_policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn test_scan_line_chars_bidi() {
        let policy = default_policy();
        let mut findings = Vec::new();
        // U+202A is LEFT-TO-RIGHT EMBEDDING (a bidi opener)
        let line = "x\u{202A}y";
        scan_line_chars(
            line,
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        // Should find USC001 for the bidi control and USC015 for unbalanced pairing
        let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rule_ids.contains(&"USC001"),
            "expected USC001 for bidi control, got {:?}",
            rule_ids
        );
        assert!(
            rule_ids.contains(&"USC015"),
            "expected USC015 for unbalanced bidi, got {:?}",
            rule_ids
        );
    }

    #[test]
    fn test_scan_line_chars_balanced_bidi() {
        let policy = default_policy();
        let mut findings = Vec::new();
        // U+202A open + U+202C close = balanced
        let line = "\u{202A}\u{202C}";
        scan_line_chars(
            line,
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        // Should have USC001 findings but no USC015
        assert!(
            !rule_ids.iter().any(|&r| r == "USC015"),
            "expected no USC015 for balanced bidi, got {:?}",
            rule_ids
        );
    }

    #[test]
    fn test_scan_line_chars_bom_line1_col0() {
        let policy = default_policy();
        let mut findings = Vec::new();
        let line = "\u{FEFF}hello";
        scan_line_chars(
            line,
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        // BOM at line 1, col 0 should NOT be reported
        assert!(
            !findings.iter().any(|f| f.rule_id == "USC009"),
            "BOM at line 1 col 0 should not be reported"
        );
    }

    #[test]
    fn test_scan_line_chars_bom_misplaced() {
        let policy = default_policy();
        let mut findings = Vec::new();
        let line = "hello\u{FEFF}world";
        scan_line_chars(
            line,
            2,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "USC009"),
            "misplaced BOM should be reported as USC009"
        );
    }

    #[test]
    fn test_check_encoding_valid() {
        let raw = b"hello world";
        assert!(check_encoding(raw, "test.py").is_none());
    }

    #[test]
    fn test_check_encoding_invalid() {
        let raw: &[u8] = &[0x68, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0xFE];
        let finding = check_encoding(raw, "test.py");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "USC008");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_check_mixed_line_endings_clean_lf() {
        assert!(check_mixed_line_endings("hello\nworld\n", "test.py").is_none());
    }

    #[test]
    fn test_check_mixed_line_endings_clean_crlf() {
        assert!(check_mixed_line_endings("hello\r\nworld\r\n", "test.py").is_none());
    }

    #[test]
    fn test_check_mixed_line_endings_mixed() {
        let content = "line1\r\nline2\nline3\n";
        let finding = check_mixed_line_endings(content, "test.py");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "USC018");
        assert!(f.message.contains("CRLF"));
        assert!(f.message.contains("LF"));
    }

    #[test]
    fn test_confusable_tracker_collision() {
        let policy = default_policy();
        let mut tracker = ConfusableTracker::new();
        let mut findings = Vec::new();

        // "scope" in Latin
        tracker.check(
            "scope",
            1,
            0,
            "test.py",
            Context::Identifier,
            &policy,
            &mut findings,
        );
        assert!(findings.is_empty());

        // "scope" with Cyrillic 'o' (U+043E) and Cyrillic 'c' (U+0441)
        // These map to ASCII 'o' and 'c' via confusable_target, producing the same skeleton
        tracker.check(
            "s\u{0441}\u{043E}pe",
            2,
            0,
            "test.py",
            Context::Identifier,
            &policy,
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "USC004"),
            "expected USC004 confusable collision, got {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_confusable_tracker_non_identifier_ignored() {
        let policy = default_policy();
        let mut tracker = ConfusableTracker::new();
        let mut findings = Vec::new();

        tracker.check(
            "scope",
            1,
            0,
            "test.py",
            Context::Comment,
            &policy,
            &mut findings,
        );
        tracker.check(
            "s\u{0441}\u{043E}pe",
            2,
            0,
            "test.py",
            Context::Comment,
            &policy,
            &mut findings,
        );
        assert!(
            findings.is_empty(),
            "non-Identifier context should be ignored"
        );
    }

    #[test]
    fn test_snippet_no_truncation() {
        assert_eq!(snippet("hello", 2, 40), "hello");
    }

    #[test]
    fn test_snippet_with_truncation() {
        let long = "a".repeat(100);
        let s = snippet(&long, 50, 40);
        assert!(s.starts_with("..."));
        assert!(s.ends_with("..."));
    }

    #[test]
    fn test_snippet_empty_text() {
        assert_eq!(snippet("", 0, 40), "");
        assert_eq!(snippet("", 5, 40), "");
    }

    #[test]
    fn test_snippet_col_past_end() {
        // col far beyond text length should not panic
        let s = snippet("abc", 100, 40);
        assert!(s.contains('c'));
    }

    #[test]
    fn test_snippet_col_zero() {
        let s = snippet("hello world", 0, 10);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_snippet_very_short_text() {
        assert_eq!(snippet("x", 0, 40), "x");
    }

    #[test]
    fn test_sev_default() {
        assert_eq!(sev("USC001", None), Severity::Critical);
        assert_eq!(sev("USC005", None), Severity::Medium);
    }

    #[test]
    fn test_scan_line_chars_empty_line() {
        let policy = default_policy();
        let mut findings = Vec::new();
        scan_line_chars(
            "",
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_line_chars_only_bom_line1() {
        let policy = default_policy();
        let mut findings = Vec::new();
        scan_line_chars(
            "\u{FEFF}",
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        // BOM at line 1 col 0 is allowed
        assert!(!findings.iter().any(|f| f.rule_id == "USC009"));
    }

    #[test]
    fn test_scan_line_chars_bom_col_gt_0_line1() {
        let policy = default_policy();
        let mut findings = Vec::new();
        scan_line_chars(
            "x\u{FEFF}",
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        // BOM at line 1, col 1 should be flagged
        assert!(
            findings.iter().any(|f| f.rule_id == "USC009"),
            "BOM at col>0 on line 1 should be flagged"
        );
    }

    #[test]
    fn test_scan_line_chars_negative_embed_depth() {
        let policy = default_policy();
        let mut findings = Vec::new();
        // PDF without prior opener
        scan_line_chars(
            "\u{202C}",
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "USC015"),
            "orphan PDF should trigger USC015"
        );
    }

    #[test]
    fn test_scan_line_chars_exactly_3_variation_selectors() {
        let policy = default_policy();
        let mut findings = Vec::new();
        let line = "a\u{FE00}b\u{FE01}c\u{FE02}d";
        scan_line_chars(
            line,
            2,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "USC010"),
            "exactly 3 variation selectors should trigger USC010"
        );
    }

    #[test]
    fn test_scan_line_chars_whitespace_only() {
        let policy = default_policy();
        let mut findings = Vec::new();
        scan_line_chars(
            "   \t  ",
            1,
            "test.py",
            Context::Other,
            &policy,
            false,
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_token_empty() {
        let policy = default_policy();
        let mut findings = Vec::new();
        let tok = Token {
            text: String::new(),
            context: Context::Identifier,
            line: 1,
            col: 0,
        };
        check_token(&tok, "test.py", &policy, &mut findings);
        // Should not panic; no findings expected for empty token
    }

    #[test]
    fn test_check_token_single_ascii_char() {
        let policy = default_policy();
        let mut findings = Vec::new();
        let tok = Token {
            text: "x".to_string(),
            context: Context::Identifier,
            line: 1,
            col: 0,
        };
        check_token(&tok, "test.py", &policy, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_mixed_line_endings_only_cr() {
        assert!(check_mixed_line_endings("hello\rworld\r", "test.py").is_none());
    }

    #[test]
    fn test_sev_unknown_rule_returns_critical() {
        assert_eq!(sev("USCXXX", None), Severity::Critical);
    }

    #[test]
    fn test_make_finding_unknown_rule() {
        let f = make_finding(
            "USCXXX",
            "test.py",
            1,
            0,
            "test message".to_string(),
            "info".to_string(),
            Context::Other,
            "snippet".to_string(),
            None,
        );
        assert_eq!(f.rule_name, "unknown");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_check_token_normalization_drift() {
        let policy = default_policy();
        let mut findings = Vec::new();
        // U+00E9 is NFC for 'e' + combining acute, but "e\u{0301}" is NFD
        let tok = Token {
            text: "e\u{0301}".to_string(),
            context: Context::Other,
            line: 1,
            col: 0,
        };
        check_token(&tok, "test.py", &policy, &mut findings);
        assert!(
            findings.iter().any(|f| f.rule_id == "USC006"),
            "expected USC006 normalization drift"
        );
    }
}
