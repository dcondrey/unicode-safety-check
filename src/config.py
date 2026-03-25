"""Policy configuration."""
import json
import os
from pathlib import Path

from models import Severity, Context, FileRisk


class Policy:
    def __init__(self, data=None):
        data = data or {}
        self.encoding = data.get("encoding", "utf-8-only")
        self.identifier_policy = data.get("identifier_policy", "ascii-only")
        self.permitted_scripts = set(data.get("permitted_scripts", ["Latin", "Common", "Inherited"]))
        self.severity_overrides = {}
        for name, level in data.get("severity", {}).items():
            try: self.severity_overrides[name] = Severity(level)
            except ValueError: pass
        self.file_policies = _parse_file_policies(data.get("file_policies", {}))
        self.allowlist = _parse_allowlist(data.get("allow", []))
        self.context_rules = data.get("contexts", {})
        self.diff_only = data.get("diff_only", True)

    def get_file_risk(self, path):
        import fnmatch
        for risk, patterns in self.file_policies.items():
            for pat in patterns:
                if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(os.path.basename(path), pat):
                    return risk
        ext = Path(path).suffix.lower()
        if ext in _HIGH_RISK_EXTS: return FileRisk.HIGH
        if ext in _MEDIUM_RISK_EXTS: return FileRisk.MEDIUM
        return FileRisk.HIGH

    def should_fail(self, severity, file_risk):
        if file_risk == FileRisk.HIGH:
            return severity in (Severity.CRITICAL, Severity.HIGH)
        if file_risk == FileRisk.MEDIUM:
            return severity == Severity.CRITICAL
        return severity == Severity.CRITICAL

    def is_allowed(self, path, cp, context):
        if not self.allowlist:
            return False
        import fnmatch
        for e in self.allowlist:
            if not any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(os.path.basename(path), p) for p in e["paths"]):
                continue
            if cp in e["codepoints"]:
                return True
        return False

    def context_action(self, rule_name, context):
        ctx_key = context.value
        if ctx_key in self.context_rules and rule_name in self.context_rules[ctx_key]:
            return self.context_rules[ctx_key][rule_name]
        if context == Context.IDENTIFIER: return "fail"
        if context in (Context.COMMENT, Context.STRING): return "warn"
        return "fail"


_HIGH_RISK_EXTS = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".scala", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".rb", ".php", ".pl", ".pm", ".sh", ".bash", ".zsh",
    ".yml", ".yaml", ".toml", ".cfg", ".ini", ".env",
    ".tf", ".hcl", ".sql", ".r", ".R",
    ".swift", ".m", ".mm", ".lua", ".zig", ".nim", ".v", ".dockerfile",
})
_MEDIUM_RISK_EXTS = frozenset({
    ".md", ".rst", ".txt", ".adoc", ".asciidoc",
    ".html", ".htm", ".css", ".scss", ".less",
    ".xml", ".xsl", ".xslt", ".csv", ".tsv",
})
_NAMED_CHARS = {"ZWJ": {0x200D}, "ZWNJ": {0x200C}, "NBSP": {0x00A0}, "SOFT_HYPHEN": {0x00AD}, "BOM": {0xFEFF}}


def _parse_file_policies(data):
    result = {}
    for key, value in data.items():
        try: risk = FileRisk(key.replace("-", "_").replace("_risk", ""))
        except ValueError: continue
        result[risk] = value.get("patterns", []) if isinstance(value, dict) else value
    return result


def _parse_allowlist(data):
    entries = []
    for item in data:
        cps = set()
        for spec in item.get("characters", []):
            if isinstance(spec, str) and spec in _NAMED_CHARS:
                cps.update(_NAMED_CHARS[spec])
            elif isinstance(spec, int):
                cps.add(spec)
            elif isinstance(spec, str) and spec.startswith("U+"):
                try: cps.add(int(spec[2:], 16))
                except ValueError: pass
        entries.append({"paths": item.get("paths", ["**"]), "codepoints": cps,
                        "context": item.get("contexts"), "reason": item.get("reason", "")})
    return entries


def load_policy(path=None):
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
            raise RuntimeError(f"PyYAML required for {path}. pip install pyyaml")
    elif p.suffix == ".json":
        data = json.loads(text)
    elif p.suffix == ".toml":
        try: import tomllib
        except ImportError:
            try: import tomli as tomllib
            except ImportError: raise RuntimeError(f"Python 3.11+ or tomli required for {path}.")
        data = tomllib.loads(text)
    else:
        raise RuntimeError(f"Unsupported policy format: {p.suffix}")
    return Policy(data)
