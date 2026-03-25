"""Policy configuration for unicode safety checking."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from models import Severity, Context, FileRisk


class Policy:
    """Scanning policy loaded from a config file or defaults."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        data = data or {}

        # Encoding enforcement
        self.encoding = data.get("encoding", "utf-8-only")

        # Identifier policy: ascii-only, latin-extended, permitted-scripts
        self.identifier_policy = data.get("identifier_policy", "ascii-only")
        self.permitted_scripts = set(data.get("permitted_scripts", ["Latin", "Common", "Inherited"]))

        # Severity overrides (rule_name -> Severity)
        self.severity_overrides: Dict[str, Severity] = {}
        for rule_name, level in data.get("severity", {}).items():
            try:
                self.severity_overrides[rule_name] = Severity(level)
            except ValueError:
                pass

        # File risk policies
        self.file_policies = _parse_file_policies(data.get("file_policies", {}))

        # Allowlist entries
        self.allowlist = _parse_allowlist(data.get("allow", []))

        # Context rules
        self.context_rules = _parse_context_rules(data.get("contexts", {}))

        # Diff-only mode
        self.diff_only = data.get("diff_only", True)

    def get_file_risk(self, path: str) -> FileRisk:
        """Determine risk level for a file based on its path."""
        import fnmatch
        for risk_level, patterns in self.file_policies.items():
            for pattern in patterns:
                if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
                    return risk_level
        # Default: high risk for code, medium for everything else
        ext = Path(path).suffix.lower()
        if ext in _HIGH_RISK_EXTENSIONS:
            return FileRisk.HIGH
        if ext in _MEDIUM_RISK_EXTENSIONS:
            return FileRisk.MEDIUM
        return FileRisk.HIGH  # default to strict

    def should_fail(self, severity: Severity, file_risk: FileRisk) -> bool:
        """Determine if a finding at this severity should fail the check."""
        if file_risk == FileRisk.HIGH:
            return severity in (Severity.CRITICAL, Severity.HIGH)
        if file_risk == FileRisk.MEDIUM:
            return severity == Severity.CRITICAL
        # LOW risk: only critical fails
        return severity == Severity.CRITICAL

    def is_allowed(self, path: str, cp: int, context: Context) -> bool:
        """Check if a code point is allowed at this path and context."""
        import fnmatch
        for entry in self.allowlist:
            path_match = any(
                fnmatch.fnmatch(path, p) or fnmatch.fnmatch(os.path.basename(path), p)
                for p in entry["paths"]
            )
            if not path_match:
                continue
            if cp in entry["codepoints"]:
                return True
            if entry.get("context") and context.value not in entry["context"]:
                continue
        return False

    def context_action(self, rule_name: str, context: Context) -> str:
        """Get action for a rule in a given context: 'fail', 'warn', or 'ignore'."""
        if context.value in self.context_rules:
            rules = self.context_rules[context.value]
            if rule_name in rules:
                return rules[rule_name]
        # Defaults by context
        if context == Context.IDENTIFIER:
            return "fail"
        if context == Context.COMMENT:
            return "warn"
        if context == Context.STRING:
            return "warn"
        return "fail"


# High-risk file extensions (code, config, CI)
_HIGH_RISK_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".scala", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".rb", ".php", ".pl", ".pm", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".toml", ".cfg", ".ini", ".env",
    ".tf", ".hcl",  # terraform
    ".sql",
    ".r", ".R",
    ".swift", ".m", ".mm",
    ".lua", ".zig", ".nim", ".v",
    ".dockerfile",
}

# Medium-risk file extensions (docs, config-ish)
_MEDIUM_RISK_EXTENSIONS = {
    ".md", ".rst", ".txt", ".adoc", ".asciidoc",
    ".html", ".htm", ".css", ".scss", ".less",
    ".xml", ".xsl", ".xslt",
    ".csv", ".tsv",
}

# Named character sets for allowlist
_NAMED_CHARS = {
    "ZWJ": {0x200D},
    "ZWNJ": {0x200C},
    "NBSP": {0x00A0},
    "SOFT_HYPHEN": {0x00AD},
    "BOM": {0xFEFF},
}


def _parse_file_policies(data: Dict) -> Dict[FileRisk, List[str]]:
    result = {}
    for key, value in data.items():
        try:
            risk = FileRisk(key.replace("-", "_").replace("_risk", ""))
        except ValueError:
            continue
        patterns = value.get("patterns", []) if isinstance(value, dict) else value
        result[risk] = patterns
    return result


def _parse_allowlist(data: list) -> list:
    entries = []
    for item in data:
        codepoints = set()
        for char_spec in item.get("characters", []):
            if isinstance(char_spec, str) and char_spec in _NAMED_CHARS:
                codepoints.update(_NAMED_CHARS[char_spec])
            elif isinstance(char_spec, int):
                codepoints.add(char_spec)
            elif isinstance(char_spec, str) and char_spec.startswith("U+"):
                try:
                    codepoints.add(int(char_spec[2:], 16))
                except ValueError:
                    pass
        entries.append({
            "paths": item.get("paths", ["**"]),
            "codepoints": codepoints,
            "context": item.get("contexts"),
            "reason": item.get("reason", ""),
        })
    return entries


def _parse_context_rules(data: Dict) -> Dict[str, Dict[str, str]]:
    return {ctx: rules for ctx, rules in data.items()}


def load_policy(path: Optional[str] = None) -> Policy:
    """Load policy from a file, or return defaults."""
    if not path:
        return Policy()

    p = Path(path)
    if not p.exists() or p.is_dir():
        return Policy()

    text = p.read_text(encoding="utf-8")

    if p.suffix in (".yml", ".yaml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise RuntimeError(
                f"PyYAML required to load {path}. Install with: pip install pyyaml\n"
                "Alternatively, use a .json policy file."
            )
    elif p.suffix == ".json":
        data = json.loads(text)
    elif p.suffix == ".toml":
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                raise RuntimeError(f"Python 3.11+ or tomli required to load {path}.")
        data = tomllib.loads(text)
    else:
        raise RuntimeError(f"Unsupported policy file format: {p.suffix}")

    return Policy(data)
