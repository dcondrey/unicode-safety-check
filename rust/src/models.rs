use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 3,
            Severity::High => 2,
            Severity::Medium => 1,
            Severity::Low => 0,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
        }
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            _ => Err(serde::de::Error::unknown_variant(
                &s,
                &["critical", "high", "medium", "low"],
            )),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Context {
    Identifier,
    Comment,
    String,
    Other,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Context::Identifier => write!(f, "identifier"),
            Context::Comment => write!(f, "comment"),
            Context::String => write!(f, "string"),
            Context::Other => write!(f, "other"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FileRisk {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub message: String,
    pub char_info: String,
    #[allow(dead_code)]
    pub context: Context,
    pub snippet: String,
}

#[derive(Debug)]
pub struct Token {
    pub text: String,
    pub context: Context,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug)]
pub struct RuleInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub default_severity: Severity,
}

pub fn get_rule(id: &str) -> Option<&'static RuleInfo> {
    match id {
        "USC001" => Some(&RuleInfo {
            name: "bidi-control",
            description: "Bidirectional control character",
            default_severity: Severity::Critical,
        }),
        "USC002" => Some(&RuleInfo {
            name: "invisible-format",
            description: "Invisible formatting character",
            default_severity: Severity::Critical,
        }),
        "USC003" => Some(&RuleInfo {
            name: "mixed-script",
            description: "Mixed-script identifier",
            default_severity: Severity::High,
        }),
        "USC004" => Some(&RuleInfo {
            name: "confusable-collision",
            description: "Confusable identifier collision",
            default_severity: Severity::High,
        }),
        "USC005" => Some(&RuleInfo {
            name: "suspicious-spacing",
            description: "Suspicious spacing character",
            default_severity: Severity::Medium,
        }),
        "USC006" => Some(&RuleInfo {
            name: "normalization-drift",
            description: "Normalization-unstable text",
            default_severity: Severity::Medium,
        }),
        "USC007" => Some(&RuleInfo {
            name: "control-character",
            description: "Disallowed control character",
            default_severity: Severity::Critical,
        }),
        "USC008" => Some(&RuleInfo {
            name: "invalid-encoding",
            description: "Invalid UTF-8 encoding",
            default_severity: Severity::Critical,
        }),
        "USC009" => Some(&RuleInfo {
            name: "misplaced-bom",
            description: "Misplaced byte-order mark",
            default_severity: Severity::Critical,
        }),
        "USC010" => Some(&RuleInfo {
            name: "variation-selector",
            description: "Suspicious variation selector sequence",
            default_severity: Severity::Critical,
        }),
        "USC011" => Some(&RuleInfo {
            name: "private-use",
            description: "Private Use Area code point",
            default_severity: Severity::Critical,
        }),
        "USC012" => Some(&RuleInfo {
            name: "tag-character",
            description: "Tag character (payload encoding)",
            default_severity: Severity::Critical,
        }),
        "USC013" => Some(&RuleInfo {
            name: "deprecated-format",
            description: "Deprecated format character",
            default_severity: Severity::Critical,
        }),
        "USC014" => Some(&RuleInfo {
            name: "annotation-anchor",
            description: "Interlinear annotation anchor",
            default_severity: Severity::Critical,
        }),
        "USC015" => Some(&RuleInfo {
            name: "bidi-pairing",
            description: "Unbalanced bidi control pairing",
            default_severity: Severity::Critical,
        }),
        "USC016" => Some(&RuleInfo {
            name: "default-ignorable",
            description: "Default-ignorable code point",
            default_severity: Severity::High,
        }),
        "USC017" => Some(&RuleInfo {
            name: "homoglyph",
            description: "Homoglyph character",
            default_severity: Severity::High,
        }),
        "USC018" => Some(&RuleInfo {
            name: "mixed-line-endings",
            description: "Mixed line endings",
            default_severity: Severity::Medium,
        }),
        "USC019" => Some(&RuleInfo {
            name: "non-ascii-identifier",
            description: "Non-ASCII in identifier (policy violation)",
            default_severity: Severity::Medium,
        }),
        _ => None,
    }
}

pub const RULE_IDS: &[&str] = &[
    "USC001", "USC002", "USC003", "USC004", "USC005", "USC006", "USC007", "USC008", "USC009",
    "USC010", "USC011", "USC012", "USC013", "USC014", "USC015", "USC016", "USC017", "USC018",
    "USC019",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_ids_match_get_rule() {
        for id in RULE_IDS {
            assert!(
                get_rule(id).is_some(),
                "RULE_IDS contains {} but get_rule returns None",
                id
            );
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Critical > Severity::Low);
    }

    #[test]
    fn severity_sort() {
        let mut v = vec![
            Severity::Low,
            Severity::Critical,
            Severity::Medium,
            Severity::High,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
    }

    #[test]
    fn severity_equal() {
        assert_eq!(
            Severity::Critical.cmp(&Severity::Critical),
            std::cmp::Ordering::Equal
        );
    }
}
