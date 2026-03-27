//! Policy configuration.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context as _, Result};
use fnmatch_regex::glob_to_regex;
use serde::Deserialize;

use crate::models::{Context, FileRisk, Severity};

// ---------------------------------------------------------------------------
// Extension sets
// ---------------------------------------------------------------------------

const HIGH_RISK_EXTS: &[&str] = &[
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".scala",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".pl",
    ".pm",
    ".sh",
    ".bash",
    ".zsh",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".env",
    ".tf",
    ".hcl",
    ".sql",
    ".r",
    ".R",
    ".swift",
    ".m",
    ".mm",
    ".lua",
    ".zig",
    ".nim",
    ".v",
    ".dockerfile",
];

const MEDIUM_RISK_EXTS: &[&str] = &[
    ".md",
    ".rst",
    ".txt",
    ".adoc",
    ".asciidoc",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".less",
    ".xml",
    ".xsl",
    ".xslt",
    ".csv",
    ".tsv",
];

// ---------------------------------------------------------------------------
// Named character sets
// ---------------------------------------------------------------------------

pub fn named_chars(name: &str) -> Option<HashSet<u32>> {
    match name {
        "ZWJ" => Some([0x200D].into_iter().collect()),
        "ZWNJ" => Some([0x200C].into_iter().collect()),
        "NBSP" => Some([0x00A0].into_iter().collect()),
        "SOFT_HYPHEN" => Some([0x00AD].into_iter().collect()),
        "BOM" => Some([0xFEFF].into_iter().collect()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// AllowEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AllowEntry {
    pub paths: Vec<String>,
    pub codepoints: HashSet<u32>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Policy {
    pub encoding: String,
    pub identifier_policy: String,
    pub permitted_scripts: HashSet<String>,
    pub severity_overrides: HashMap<String, Severity>,
    pub file_policies: HashMap<FileRisk, Vec<String>>,
    pub allowlist: Vec<AllowEntry>,
    pub context_rules: HashMap<String, HashMap<String, String>>,
    pub diff_only: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            encoding: "utf-8-only".into(),
            identifier_policy: "ascii-only".into(),
            permitted_scripts: ["Latin", "Common", "Inherited"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            severity_overrides: HashMap::new(),
            file_policies: HashMap::new(),
            allowlist: Vec::new(),
            context_rules: HashMap::new(),
            diff_only: true,
        }
    }
}

impl Policy {
    /// Determine the risk level for a file path by checking configured
    /// glob patterns first, then falling back to extension-based lookup.
    pub fn get_file_risk(&self, path: &str) -> FileRisk {
        let basename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path);

        for (risk, patterns) in &self.file_policies {
            for pat in patterns {
                if matches_glob(pat, path) || matches_glob(pat, basename) {
                    return *risk;
                }
            }
        }

        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();

        // Extension comparison: most are lowercase, but ".R" is case-sensitive.
        if HIGH_RISK_EXTS
            .iter()
            .any(|e| *e == ext || *e == ext.to_lowercase())
        {
            return FileRisk::High;
        }
        if MEDIUM_RISK_EXTS
            .iter()
            .any(|e| *e == ext || *e == ext.to_lowercase())
        {
            return FileRisk::Medium;
        }
        FileRisk::High
    }

    /// Check whether a codepoint is explicitly allowed for the given path.
    pub fn is_allowed(&self, path: &str, cp: u32, _context: Context) -> bool {
        if self.allowlist.is_empty() {
            return false;
        }
        let basename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path);

        for entry in &self.allowlist {
            let path_match = entry
                .paths
                .iter()
                .any(|p| matches_glob(p, path) || matches_glob(p, basename));
            if path_match && entry.codepoints.contains(&cp) {
                return true;
            }
        }
        false
    }

    /// Return the action for a rule in a given context.
    /// Returns "fail", "warn", or "ignore".
    pub fn context_action(&self, rule_name: &str, context: Context) -> &str {
        let ctx_key = match context {
            Context::Identifier => "identifier",
            Context::Comment => "comment",
            Context::String => "string",
            Context::Other => "other",
        };
        if let Some(ctx_map) = self.context_rules.get(ctx_key) {
            if let Some(action) = ctx_map.get(rule_name) {
                return action.as_str();
            }
        }
        match context {
            Context::Identifier => "fail",
            Context::Comment | Context::String => "warn",
            Context::Other => "fail",
        }
    }
}

// ---------------------------------------------------------------------------
// Glob helper
// ---------------------------------------------------------------------------

fn matches_glob(pattern: &str, text: &str) -> bool {
    glob_to_regex(pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Serde deserialization structs
// ---------------------------------------------------------------------------

/// Deserialize a severity map, silently skipping entries with unknown severity
/// values (matching Python behavior where `except ValueError: pass`).
fn deserialize_severity_map<'de, D>(deserializer: D) -> Result<HashMap<String, Severity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (name, level) in raw {
        match level.to_ascii_lowercase().as_str() {
            "critical" => {
                result.insert(name, Severity::Critical);
            }
            "high" => {
                result.insert(name, Severity::High);
            }
            "medium" => {
                result.insert(name, Severity::Medium);
            }
            "low" => {
                result.insert(name, Severity::Low);
            }
            _ => {} // silently skip unknown severity values
        }
    }
    Ok(result)
}

#[derive(Deserialize, Debug, Default)]
struct PolicyFile {
    #[serde(default = "default_encoding")]
    encoding: String,
    #[serde(default = "default_identifier_policy")]
    identifier_policy: String,
    #[serde(default = "default_permitted_scripts")]
    permitted_scripts: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_severity_map")]
    severity: HashMap<String, Severity>,
    #[serde(default)]
    file_policies: HashMap<String, FilePolicyEntry>,
    #[serde(default, rename = "allow")]
    allowlist: Vec<AllowEntryRaw>,
    #[serde(default, rename = "contexts")]
    context_rules: HashMap<String, HashMap<String, String>>,
    #[serde(default = "default_diff_only")]
    diff_only: bool,
}

fn default_encoding() -> String {
    "utf-8-only".into()
}
fn default_identifier_policy() -> String {
    "ascii-only".into()
}
fn default_permitted_scripts() -> Vec<String> {
    vec!["Latin".into(), "Common".into(), "Inherited".into()]
}
fn default_diff_only() -> bool {
    true
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum FilePolicyEntry {
    Patterns(Vec<String>),
    Map { patterns: Vec<String> },
}

impl FilePolicyEntry {
    fn into_patterns(self) -> Vec<String> {
        match self {
            FilePolicyEntry::Patterns(v) => v,
            FilePolicyEntry::Map { patterns } => patterns,
        }
    }
}

#[derive(Deserialize, Debug)]
struct AllowEntryRaw {
    #[serde(default = "default_allow_paths")]
    paths: Vec<String>,
    #[serde(default)]
    characters: Vec<CharSpec>,
    #[serde(default)]
    contexts: Option<Vec<String>>,
    #[serde(default)]
    reason: String,
}

fn default_allow_paths() -> Vec<String> {
    vec!["**".into()]
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum CharSpec {
    Named(String),
    Codepoint(u32),
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn parse_file_risk(key: &str) -> Option<FileRisk> {
    let normalized = key.replace('-', "_").replace("_risk", "");
    match normalized.as_str() {
        "high" => Some(FileRisk::High),
        "medium" => Some(FileRisk::Medium),
        "low" => Some(FileRisk::Low),
        _ => None,
    }
}

fn parse_char_spec(spec: &CharSpec) -> HashSet<u32> {
    match spec {
        CharSpec::Named(name) => {
            if let Some(set) = named_chars(name) {
                return set;
            }
            if let Some(hex) = name.strip_prefix("U+") {
                if let Ok(cp) = u32::from_str_radix(hex, 16) {
                    return [cp].into_iter().collect();
                }
            }
            HashSet::new()
        }
        CharSpec::Codepoint(cp) => [*cp].into_iter().collect(),
    }
}

fn convert_policy_file(pf: PolicyFile) -> Policy {
    let mut file_policies = HashMap::new();
    for (key, entry) in pf.file_policies {
        if let Some(risk) = parse_file_risk(&key) {
            file_policies.insert(risk, entry.into_patterns());
        }
    }

    let allowlist = pf
        .allowlist
        .into_iter()
        .map(|raw| {
            let mut cps = HashSet::new();
            for spec in &raw.characters {
                cps.extend(parse_char_spec(spec));
            }
            AllowEntry {
                paths: raw.paths,
                codepoints: cps,
                reason: raw.reason,
            }
        })
        .collect();

    Policy {
        encoding: pf.encoding,
        identifier_policy: pf.identifier_policy,
        permitted_scripts: pf.permitted_scripts.into_iter().collect(),
        severity_overrides: pf.severity,
        file_policies,
        allowlist,
        context_rules: pf.context_rules,
        diff_only: pf.diff_only,
    }
}

// ---------------------------------------------------------------------------
// Public loader
// ---------------------------------------------------------------------------

/// Load a policy from a YAML or JSON file.
/// Returns the default policy if `path` is `None` or the file does not exist.
pub fn load_policy(path: Option<&str>) -> Result<Policy> {
    let path = match path {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(Policy::default()),
    };

    let p = Path::new(path);
    if !p.exists() || p.is_dir() {
        return Ok(Policy::default());
    }

    let text =
        std::fs::read_to_string(p).with_context(|| format!("reading policy file: {}", path))?;

    // An empty or whitespace-only file is treated as default policy.
    if text.trim().is_empty() {
        return Ok(Policy::default());
    }

    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");

    let pf: PolicyFile =
        match ext {
            "yml" | "yaml" => serde_yaml::from_str(&text)
                .with_context(|| format!("parsing YAML policy: {}", path))?,
            "json" => serde_json::from_str(&text)
                .with_context(|| format!("parsing JSON policy: {}", path))?,
            other => {
                anyhow::bail!("Unsupported policy format: .{}", other);
            }
        };

    Ok(convert_policy_file(pf))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_fields() {
        let p = Policy::default();
        assert_eq!(p.encoding, "utf-8-only");
        assert_eq!(p.identifier_policy, "ascii-only");
        assert!(p.permitted_scripts.contains("Latin"));
        assert!(p.permitted_scripts.contains("Common"));
        assert!(p.permitted_scripts.contains("Inherited"));
        assert_eq!(p.permitted_scripts.len(), 3);
        assert!(p.severity_overrides.is_empty());
        assert!(p.file_policies.is_empty());
        assert!(p.allowlist.is_empty());
        assert!(p.context_rules.is_empty());
        assert!(p.diff_only);
    }

    #[test]
    fn file_risk_high_by_extension() {
        let p = Policy::default();
        assert_eq!(p.get_file_risk("main.py"), FileRisk::High);
        assert_eq!(p.get_file_risk("app.js"), FileRisk::High);
        assert_eq!(p.get_file_risk("lib.rs"), FileRisk::High);
        assert_eq!(p.get_file_risk("config.yml"), FileRisk::High);
        assert_eq!(p.get_file_risk("deploy.tf"), FileRisk::High);
    }

    #[test]
    fn file_risk_medium_by_extension() {
        let p = Policy::default();
        assert_eq!(p.get_file_risk("README.md"), FileRisk::Medium);
        assert_eq!(p.get_file_risk("index.html"), FileRisk::Medium);
        assert_eq!(p.get_file_risk("style.css"), FileRisk::Medium);
        assert_eq!(p.get_file_risk("data.csv"), FileRisk::Medium);
    }

    #[test]
    fn file_risk_unknown_defaults_high() {
        let p = Policy::default();
        assert_eq!(p.get_file_risk("mystery.xyz"), FileRisk::High);
        assert_eq!(p.get_file_risk("noext"), FileRisk::High);
    }

    #[test]
    fn file_risk_policy_override() {
        let mut p = Policy::default();
        p.file_policies
            .insert(FileRisk::Low, vec!["*.test.js".into()]);
        assert_eq!(p.get_file_risk("foo.test.js"), FileRisk::Low);
    }

    #[test]
    fn is_allowed_empty() {
        let p = Policy::default();
        assert!(!p.is_allowed("foo.py", 0x200D, Context::Other));
    }

    #[test]
    fn is_allowed_matching() {
        let mut p = Policy::default();
        p.allowlist.push(AllowEntry {
            paths: vec!["*.py".into()],
            codepoints: [0x200D].into_iter().collect(),
            reason: "test".into(),
        });
        assert!(p.is_allowed("foo.py", 0x200D, Context::Other));
        assert!(!p.is_allowed("foo.py", 0x200C, Context::Other));
        assert!(!p.is_allowed("foo.js", 0x200D, Context::Other));
    }

    #[test]
    fn context_action_defaults() {
        let p = Policy::default();
        assert_eq!(
            p.context_action("bidi-control", Context::Identifier),
            "fail"
        );
        assert_eq!(p.context_action("bidi-control", Context::Comment), "warn");
        assert_eq!(p.context_action("bidi-control", Context::String), "warn");
        assert_eq!(p.context_action("bidi-control", Context::Other), "fail");
    }

    #[test]
    fn context_action_override() {
        let mut p = Policy::default();
        let mut comment_rules = HashMap::new();
        comment_rules.insert("bidi-control".into(), "ignore".into());
        p.context_rules.insert("comment".into(), comment_rules);
        assert_eq!(p.context_action("bidi-control", Context::Comment), "ignore");
        assert_eq!(
            p.context_action("bidi-control", Context::Identifier),
            "fail"
        );
    }

    #[test]
    fn load_policy_none_returns_default() {
        let p = load_policy(None).unwrap();
        assert_eq!(p.encoding, "utf-8-only");
        assert!(p.diff_only);
    }

    #[test]
    fn load_policy_missing_file_returns_default() {
        let p = load_policy(Some("/nonexistent/policy.yml")).unwrap();
        assert_eq!(p.encoding, "utf-8-only");
    }

    #[test]
    fn named_chars_lookup() {
        assert_eq!(named_chars("ZWJ"), Some([0x200D].into_iter().collect()));
        assert_eq!(named_chars("ZWNJ"), Some([0x200C].into_iter().collect()));
        assert_eq!(named_chars("NBSP"), Some([0x00A0].into_iter().collect()));
        assert_eq!(
            named_chars("SOFT_HYPHEN"),
            Some([0x00AD].into_iter().collect())
        );
        assert_eq!(named_chars("BOM"), Some([0xFEFF].into_iter().collect()));
        assert!(named_chars("UNKNOWN").is_none());
    }

    #[test]
    fn parse_file_risk_variants() {
        assert_eq!(parse_file_risk("high"), Some(FileRisk::High));
        assert_eq!(parse_file_risk("high-risk"), Some(FileRisk::High));
        assert_eq!(parse_file_risk("high_risk"), Some(FileRisk::High));
        assert_eq!(parse_file_risk("medium"), Some(FileRisk::Medium));
        assert_eq!(parse_file_risk("low"), Some(FileRisk::Low));
        assert_eq!(parse_file_risk("unknown"), None);
    }

    #[test]
    fn parse_char_spec_named() {
        let spec = CharSpec::Named("ZWJ".into());
        let result = parse_char_spec(&spec);
        assert!(result.contains(&0x200D));
    }

    #[test]
    fn parse_char_spec_u_plus() {
        let spec = CharSpec::Named("U+FEFF".into());
        let result = parse_char_spec(&spec);
        assert!(result.contains(&0xFEFF));
    }

    #[test]
    fn parse_char_spec_codepoint() {
        let spec = CharSpec::Codepoint(0x200C);
        let result = parse_char_spec(&spec);
        assert!(result.contains(&0x200C));
    }

    #[test]
    fn load_policy_empty_file_returns_default() {
        let dir = std::env::temp_dir().join("usc_test_policy");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.yml");
        std::fs::write(&path, "").unwrap();
        let p = load_policy(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(p.encoding, "utf-8-only");
        assert!(p.diff_only);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_policy_unknown_keys_ignored() {
        let dir = std::env::temp_dir().join("usc_test_policy_unk");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("extra_keys.yml");
        std::fs::write(&path, "encoding: utf-8-only\nunknown_key: value\n").unwrap();
        // serde(default) + deny_unknown_fields is NOT set, so extra keys are silently ignored
        let p = load_policy(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(p.encoding, "utf-8-only");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_risk_no_extension() {
        let p = Policy::default();
        // Files with no extension default to High risk
        assert_eq!(p.get_file_risk("Makefile"), FileRisk::High);
        assert_eq!(p.get_file_risk("Dockerfile"), FileRisk::High);
    }

    #[test]
    fn file_risk_double_extension() {
        let p = Policy::default();
        // .tar.gz: Path::extension() returns "gz", which is not in any risk list
        assert_eq!(p.get_file_risk("archive.tar.gz"), FileRisk::High);
    }
}
