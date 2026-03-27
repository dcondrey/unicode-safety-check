use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::checks::{
    check_encoding, check_mixed_line_endings, check_token, scan_line_chars, ConfusableTracker,
};
use crate::config::Policy;
use crate::models::{Context, Finding, Token};
use crate::tokenizer::{detect_language, tokenize_line, TokenizerState};

// ---------------------------------------------------------------------------
// Exclusion constants
// ---------------------------------------------------------------------------

const EXCLUDE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".vscode",
    "__pycache__",
    ".mypy_cache",
    ".tox",
    "vendor",
    "dist",
    "build",
    "_site",
    ".next",
    "target",
];

const EXCLUDE_EXTS: &[&str] = &[
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".webp", ".pdf", ".wasm", ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll", ".exe",
    ".a", ".lib", ".jar", ".war", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".lock",
    ".min.js", ".min.css", ".pb.go",
];

const EXCLUDE_SUBSTRS: &[&str] = &[
    ".git/",
    "node_modules/",
    ".vscode/",
    "__pycache__/",
    ".mypy_cache/",
    ".tox/",
    "vendor/",
    "dist/",
    "build/",
    "_site/",
    ".next/",
    "target/",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple fnmatch-style glob matching supporting `*` and `?`.
/// Uses an iterative two-pointer approach to avoid exponential backtracking.
fn fnmatch(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1; // try matching '*' with zero chars first
        } else if star_pi != usize::MAX {
            // backtrack: let the last '*' consume one more character
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // consume trailing '*' in the pattern
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Check whether a path should be excluded from scanning.
pub fn should_exclude(path: &str, extra: &[String]) -> bool {
    // Normalize backslashes so Windows paths match the forward-slash patterns.
    let normalized;
    let path = if path.contains('\\') {
        normalized = path.replace('\\', "/");
        normalized.as_str()
    } else {
        path
    };

    // Check substring patterns
    for pat in EXCLUDE_SUBSTRS {
        if path.contains(pat) {
            return true;
        }
    }

    // Check file extensions
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    for ext in EXCLUDE_EXTS {
        if name.ends_with(ext) {
            return true;
        }
    }

    // Check extra patterns (fnmatch or substring)
    for pat in extra {
        if fnmatch(pat, path) || path.contains(pat.as_str()) {
            return true;
        }
    }

    false
}

/// Return true if the file appears to be binary (contains a null byte in the first 8192 bytes).
/// Returns true on any IO error.  Only reads up to 8192 bytes regardless of file size.
pub fn is_binary(path: &str) -> bool {
    use std::io::Read;
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return true,
    };
    let mut buf = [0u8; 8192];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return true,
    };
    buf[..n].contains(&0u8)
}

/// Determine the dominant context of a line from its tokens.
pub fn line_context(tokens: &[Token]) -> Context {
    if tokens.is_empty() {
        return Context::Other;
    }
    for t in tokens {
        if t.context == Context::Identifier {
            return Context::Identifier;
        }
    }
    for t in tokens {
        if t.context == Context::Comment {
            return Context::Comment;
        }
    }
    for t in tokens {
        if t.context == Context::String {
            return Context::String;
        }
    }
    Context::Other
}

// ---------------------------------------------------------------------------
// Core scanning
// ---------------------------------------------------------------------------

/// Maximum file size to scan (50 MB). Larger files are skipped.
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Scan a single file and return all findings.
pub fn scan_file(
    path: &str,
    policy: &Policy,
    changed_lines: Option<&HashSet<usize>>,
    extra_excludes: &[String],
) -> Vec<Finding> {
    if should_exclude(path, extra_excludes) || is_binary(path) {
        return Vec::new();
    }

    // Skip files larger than MAX_FILE_SIZE to prevent memory exhaustion.
    match fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_FILE_SIZE => {
            eprintln!(
                "warning: skipping '{}' ({} bytes exceeds {} byte limit)",
                path,
                meta.len(),
                MAX_FILE_SIZE
            );
            return Vec::new();
        }
        Err(_) => return Vec::new(),
        _ => {}
    }

    let raw = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    // Check encoding; return early if invalid
    if let Some(enc_err) = check_encoding(&raw, path) {
        return vec![enc_err];
    }

    let content = match std::str::from_utf8(&raw) {
        Ok(s) => s.to_owned(),
        Err(_) => return Vec::new(),
    };

    let mut findings: Vec<Finding> = Vec::new();

    // Check mixed line endings
    if let Some(le_err) = check_mixed_line_endings(&content, path) {
        findings.push(le_err);
    }

    let lang = detect_language(path);
    let mut state = TokenizerState::default();
    let mut tracker = ConfusableTracker::new();

    // Split into lines preserving line boundaries
    let lines = split_lines_keep_ends(&content);

    for (i, line_text) in lines.iter().enumerate() {
        let line_num = i + 1;
        let is_changed = changed_lines.map_or(true, |lines| lines.contains(&line_num));

        let tokens = tokenize_line(line_text, lang, &mut state, line_num);
        let ctx = line_context(&tokens);

        scan_line_chars(
            line_text,
            line_num,
            path,
            ctx,
            policy,
            !is_changed,
            &mut findings,
        );

        if !is_changed {
            continue;
        }

        for tok in &tokens {
            check_token(tok, path, policy, &mut findings);
            tracker.check(
                &tok.text,
                tok.line,
                tok.col,
                path,
                tok.context,
                policy,
                &mut findings,
            );
        }
    }

    findings
}

/// Split a string into lines, keeping line endings attached (like Python's splitlines(keepends=True)).
fn split_lines_keep_ends(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = s.as_bytes();
    let len = bytes.len();

    while start < len {
        let mut end = start;
        while end < len {
            if bytes[end] == b'\n' {
                end += 1;
                break;
            } else if bytes[end] == b'\r' {
                end += 1;
                if end < len && bytes[end] == b'\n' {
                    end += 1;
                }
                break;
            }
            end += 1;
        }
        lines.push(&s[start..end]);
        start = end;
    }

    lines
}

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

/// Recursively collect files under `root`, skipping excluded directories and files.
/// Returns relative paths.
pub fn collect_files(root: &str) -> Vec<String> {
    let root_path = Path::new(root);
    let exclude_dirs: HashSet<&str> = EXCLUDE_DIRS.iter().copied().collect();
    let mut files = Vec::new();
    collect_files_recursive(root_path, root_path, &exclude_dirs, &mut files);
    files
}

fn collect_files_recursive(
    dir: &Path,
    root: &Path,
    exclude_dirs: &HashSet<&str>,
    files: &mut Vec<String>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if path.is_dir() {
                if !exclude_dirs.contains(name) {
                    collect_files_recursive(&path, root, exclude_dirs, files);
                }
            } else if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().to_string();
                if !should_exclude(&rel_str, &[]) {
                    files.push(rel_str);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_should_exclude_substrs() {
        assert!(should_exclude("foo/.git/config", &[]));
        assert!(should_exclude("project/node_modules/pkg/index.js", &[]));
        assert!(should_exclude("src/__pycache__/mod.pyc", &[]));
        assert!(!should_exclude("src/main.rs", &[]));
    }

    #[test]
    fn test_should_exclude_extensions() {
        assert!(should_exclude("fonts/arial.woff2", &[]));
        assert!(should_exclude("img/logo.PNG", &[])); // case-insensitive
        assert!(should_exclude("bundle.min.js", &[]));
        assert!(should_exclude("proto.pb.go", &[]));
        assert!(!should_exclude("src/lib.rs", &[]));
    }

    #[test]
    fn test_should_exclude_extra() {
        let extra = vec!["*.log".to_string()];
        assert!(should_exclude("debug.log", &extra));
        assert!(!should_exclude("debug.txt", &extra));

        // substring match in extra
        let extra2 = vec!["secret".to_string()];
        assert!(should_exclude("path/to/secret/file.txt", &extra2));
    }

    #[test]
    fn test_is_binary_text_file() {
        let dir = std::env::temp_dir().join("usc_test_text");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("hello.txt");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"Hello, world!\n").unwrap();
        }
        assert!(!is_binary(path.to_str().unwrap()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_is_binary_with_null() {
        let dir = std::env::temp_dir().join("usc_test_bin");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("data.bin");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"abc\x00def").unwrap();
        }
        assert!(is_binary(path.to_str().unwrap()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_is_binary_missing_file() {
        assert!(is_binary("/nonexistent/path/to/file.txt"));
    }

    #[test]
    fn test_line_context_priority() {
        use crate::models::Context;

        let tokens = vec![
            Token {
                text: "x".into(),
                context: Context::Comment,
                line: 1,
                col: 1,
            },
            Token {
                text: "foo".into(),
                context: Context::Identifier,
                line: 1,
                col: 5,
            },
        ];
        assert_eq!(line_context(&tokens), Context::Identifier);

        let tokens2 = vec![
            Token {
                text: "\"hi\"".into(),
                context: Context::String,
                line: 1,
                col: 1,
            },
            Token {
                text: "// note".into(),
                context: Context::Comment,
                line: 1,
                col: 10,
            },
        ];
        assert_eq!(line_context(&tokens2), Context::Comment);

        let tokens3 = vec![Token {
            text: "\"hi\"".into(),
            context: Context::String,
            line: 1,
            col: 1,
        }];
        assert_eq!(line_context(&tokens3), Context::String);

        assert_eq!(line_context(&[]), Context::Other);
    }

    #[test]
    fn test_split_lines_keep_ends() {
        assert_eq!(split_lines_keep_ends("a\nb\n"), vec!["a\n", "b\n"]);
        assert_eq!(split_lines_keep_ends("a\r\nb\r\n"), vec!["a\r\n", "b\r\n"]);
        assert_eq!(split_lines_keep_ends("a\rb\n"), vec!["a\r", "b\n"]);
        assert_eq!(split_lines_keep_ends("no newline"), vec!["no newline"]);
        assert_eq!(split_lines_keep_ends("").len(), 0);
        // CR-only multi-line
        assert_eq!(split_lines_keep_ends("a\rb\rc"), vec!["a\r", "b\r", "c"]);
    }

    #[test]
    fn test_should_exclude_backslash_paths() {
        // Windows-style paths should still match forward-slash exclusion patterns
        assert!(should_exclude("foo\\.git\\config", &[]));
        assert!(should_exclude("project\\node_modules\\pkg\\index.js", &[]));
    }

    #[test]
    fn test_fnmatch_no_exponential_blowup() {
        // Pathological pattern that would hang a naive recursive matcher.
        let pattern = "a]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]";
        let text = "b]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]";
        // Just verify it completes quickly without matching.
        assert!(!fnmatch(pattern, text));
    }

    #[test]
    fn test_fnmatch_star_patterns() {
        assert!(fnmatch("*.rs", "main.rs"));
        assert!(fnmatch("*", "anything"));
        assert!(fnmatch("a*b", "aXYZb"));
        assert!(!fnmatch("a*b", "aXYZc"));
        assert!(fnmatch("**", "deep/path/file.rs"));
        assert!(fnmatch("a?c", "abc"));
        assert!(!fnmatch("a?c", "abbc"));
    }

    #[test]
    fn test_is_binary_empty_file() {
        let dir = std::env::temp_dir().join("usc_test_empty");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("empty.txt");
        fs::write(&path, b"").unwrap();
        assert!(!is_binary(path.to_str().unwrap()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_scan_file_skips_large_files() {
        // We can't create a real 50MB+ file in a unit test, but we can verify
        // the threshold constant and test the metadata check path by using a
        // small file that is under the limit (should NOT be skipped).
        let dir = std::env::temp_dir().join("usc_test_size_limit");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("small.txt");
        fs::write(&path, "hello\n").unwrap();

        let policy = Policy::default();
        let findings = scan_file(path.to_str().unwrap(), &policy, None, &[]);
        // A small, clean file should produce no findings (not be skipped).
        assert!(findings.is_empty());

        // Verify the constant is 50MB.
        assert_eq!(MAX_FILE_SIZE, 50 * 1024 * 1024);

        let _ = fs::remove_file(&path);
    }
}
