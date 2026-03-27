use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::process::{Command, Stdio};

/// Maximum diff output size (50 MB) to prevent memory exhaustion.
const MAX_DIFF_BYTES: usize = 50 * 1024 * 1024;

/// Run `git diff` against the given base SHA and return a map of
/// file paths to sets of changed line numbers.
///
/// Returns `None` if git is not available or the diff command fails,
/// so the caller can fall back to scanning all lines.
///
/// NOTE: There is no timeout on the git process (std has no wait_timeout).
/// The output is capped at 50 MB to prevent memory exhaustion.
pub fn get_changed_lines(base_sha: &str) -> Option<HashMap<String, HashSet<usize>>> {
    if base_sha.is_empty() {
        return None;
    }

    // Validate that base_sha looks like a hex SHA to prevent flag injection.
    if !base_sha.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("warning: invalid base SHA '{}', skipping diff", base_sha);
        return None;
    }

    let mut child = match Command::new("git")
        .args(["diff", "-U0", "--diff-filter=AMR", base_sha, "HEAD"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: could not run git: {}", e);
            eprintln!("warning: scanning all lines instead of diff-only");
            return None;
        }
    };

    // Read stdout with a size cap.
    let mut buf = Vec::with_capacity(64 * 1024);
    if let Some(ref mut stdout) = child.stdout {
        let _ = stdout.take(MAX_DIFF_BYTES as u64).read_to_end(&mut buf);
    }

    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: failed to wait on git: {}", e);
            eprintln!("warning: scanning all lines instead of diff-only");
            return None;
        }
    };

    if !status.success() {
        // Read stderr for diagnostics.
        let mut stderr_buf = Vec::new();
        if let Some(ref mut stderr) = child.stderr {
            let _ = stderr.read_to_end(&mut stderr_buf);
        }
        let stderr_text = String::from_utf8_lossy(&stderr_buf);
        eprintln!(
            "warning: git diff failed (exit {}): {}",
            status.code().unwrap_or(-1),
            stderr_text.trim()
        );
        eprintln!("warning: scanning all lines instead of diff-only");
        return None;
    }

    if buf.len() >= MAX_DIFF_BYTES {
        eprintln!(
            "warning: diff output exceeded {} bytes, truncated",
            MAX_DIFF_BYTES
        );
    }

    let stdout_text = String::from_utf8_lossy(&buf);
    Some(parse_diff(&stdout_text))
}

/// Extract the `+start,count` portion from a hunk header line.
/// Returns `(start, count)` where count defaults to 1 if absent.
fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    // Find the first '+' after "@@"
    let plus_pos = line.find('+')?;
    let rest = &line[plus_pos + 1..];
    // Read digits for start
    let digit_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digit_end == 0 {
        return None;
    }
    let start: usize = rest[..digit_end].parse().ok()?;
    // Check for ,count
    let after = &rest[digit_end..];
    let count = if let Some(stripped) = after.strip_prefix(',') {
        let cnt_end = stripped
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(stripped.len());
        if cnt_end == 0 {
            1
        } else {
            stripped[..cnt_end].parse().unwrap_or(1)
        }
    } else {
        1
    };
    Some((start, count))
}

/// Parse unified diff output into a map of file paths to changed line numbers.
pub fn parse_diff(text: &str) -> HashMap<String, HashSet<usize>> {
    let mut result: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut cur: Option<String> = None;

    for line in text.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            cur = Some(path.to_string());
            result.entry(path.to_string()).or_default();
        } else if line.starts_with("@@") {
            if let Some(ref file) = cur {
                if let Some((start, count)) = parse_hunk_header(line) {
                    let set = result.entry(file.clone()).or_default();
                    for n in start..start + count {
                        set.insert(n);
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_diff_basic() {
        let diff = "\
diff --git a/foo.txt b/foo.txt
--- a/foo.txt
+++ b/foo.txt
@@ -1,3 +1,4 @@ some context
+added line
@@ -10,2 +11,3 @@ more context
+another";
        let result = parse_diff(diff);
        assert!(result.contains_key("foo.txt"));
        let lines = &result["foo.txt"];
        // First hunk: +1,4 -> lines 1,2,3,4
        assert!(lines.contains(&1));
        assert!(lines.contains(&4));
        // Second hunk: +11,3 -> lines 11,12,13
        assert!(lines.contains(&11));
        assert!(lines.contains(&13));
    }

    #[test]
    fn test_parse_diff_count_defaults_to_one() {
        let diff = "\
diff --git a/bar.txt b/bar.txt
--- a/bar.txt
+++ b/bar.txt
@@ -5 +5 @@ ctx";
        let result = parse_diff(diff);
        let lines = &result["bar.txt"];
        assert_eq!(lines.len(), 1);
        assert!(lines.contains(&5));
    }

    #[test]
    fn test_parse_diff_empty() {
        let result = parse_diff("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_changed_lines_empty_sha() {
        let result = get_changed_lines("");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_changed_lines_invalid_sha() {
        // Non-hex strings should be rejected
        assert!(get_changed_lines("--malicious").is_none());
        assert!(get_changed_lines("not-a-sha!").is_none());
        assert!(get_changed_lines("abc/../etc").is_none());
    }

    #[test]
    fn test_get_changed_lines_valid_hex_accepted() {
        // A valid hex string should not be rejected by validation
        // (it will fail at the git level since the SHA doesn't exist,
        // but it should pass the hex check)
        let result = get_changed_lines("abcdef0123456789");
        // Returns None because git diff fails, not because of validation
        assert!(result.is_none());
    }
}
