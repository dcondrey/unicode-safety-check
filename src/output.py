"""Output formatting: SARIF, GitHub annotations, rich diagnostics, summaries."""

import json
import os
from typing import Dict, List, Optional

from models import Context, Finding, Severity, RULES


# ---------------------------------------------------------------------------
# Rich diagnostic formatting (item #11)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[0;31m",      # red
    Severity.MEDIUM: "\033[0;33m",    # yellow
    Severity.LOW: "\033[0;36m",       # cyan
}
_NC = "\033[0m"


def format_finding(f: Finding, color: bool = True) -> str:
    """Format a finding as a rich diagnostic string.

    Example:
      CRITICAL [USC001 bidi-control] src/auth.py:118:5
        U+202E RIGHT-TO-LEFT OVERRIDE found in identifier
        near: "isAdmin\u202e \u2066// check later\u2069"
    """
    sev = f.severity.value.upper()
    if color:
        c = _SEVERITY_COLORS.get(f.severity, "")
        sev = f"{c}{sev}{_NC}"

    lines = [
        f"  {sev} [{f.rule_id} {f.rule_name}] {f.file}:{f.line}:{f.col}",
        f"    {f.char_info}",
        f"    {f.message}",
    ]
    if f.snippet:
        # Escape invisible characters in snippet for display
        escaped = _escape_invisible(f.snippet)
        lines.append(f"    near: \"{escaped}\"")
    return "\n".join(lines)


def _escape_invisible(text: str) -> str:
    """Replace invisible Unicode with escaped representations for display."""
    result = []
    for ch in text:
        cp = ord(ch)
        if cp > 0x7F and (cp < 0x20 or _is_invisible(cp)):
            result.append(f"\\u{{{cp:04X}}}")
        else:
            result.append(ch)
    return "".join(result)


def _is_invisible(cp: int) -> bool:
    """Quick check for invisible characters."""
    return (
        (0x200B <= cp <= 0x200F)
        or (0x202A <= cp <= 0x202E)
        or (0x2060 <= cp <= 0x206F)
        or (0x2066 <= cp <= 0x2069)
        or cp == 0xFEFF
        or cp == 0x00AD
        or cp == 0x061C
    )


# ---------------------------------------------------------------------------
# GitHub Actions annotations
# ---------------------------------------------------------------------------

def emit_annotations(findings: List[Finding]):
    """Emit GitHub Actions workflow annotations."""
    for f in findings:
        level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
        title = f"Unicode Safety [{f.rule_name}]"
        msg = f"{f.char_info} -- {f.message}"
        print(f"::{level} file={f.file},line={f.line},col={f.col},title={title}::{msg}")


# ---------------------------------------------------------------------------
# Severity-bucketed summary (item #19)
# ---------------------------------------------------------------------------

def format_summary(findings: List[Finding], files_scanned: int) -> str:
    """Format a severity-bucketed summary."""
    buckets: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
    for f in findings:
        buckets[f.severity].append(f)

    lines = [
        f"Unicode Safety Check: {files_scanned} files scanned, {len(findings)} finding(s)",
        "",
    ]

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        items = buckets[sev]
        if items:
            lines.append(f"  {sev.value.upper()} ({len(items)}):")
            for f in items[:10]:  # cap at 10 per bucket
                lines.append(f"    {f.rule_id} {f.file}:{f.line} {f.rule_name}")
            if len(items) > 10:
                lines.append(f"    ... and {len(items) - 10} more")
            lines.append("")

    if not findings:
        lines.append("  No adversarial Unicode detected.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GitHub Step Summary (Markdown)
# ---------------------------------------------------------------------------

def write_step_summary(findings: List[Finding], files_scanned: int):
    """Write a Markdown summary to GITHUB_STEP_SUMMARY."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    buckets: Dict[str, int] = {}
    for f in findings:
        buckets[f.severity.value] = buckets.get(f.severity.value, 0) + 1

    lines = [
        "### Unicode Safety Check",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Files scanned | {files_scanned} |",
        f"| Critical | {buckets.get('critical', 0)} |",
        f"| High | {buckets.get('high', 0)} |",
        f"| Medium | {buckets.get('medium', 0)} |",
        f"| Low | {buckets.get('low', 0)} |",
        "",
    ]

    if findings:
        lines.append("#### Top findings")
        lines.append("")
        lines.append("| Severity | Rule | File | Line | Description |")
        lines.append("|----------|------|------|------|-------------|")
        for f in findings[:20]:
            lines.append(
                f"| {f.severity.value} | {f.rule_id} {f.rule_name} | "
                f"`{f.file}` | {f.line} | {f.message[:80]} |"
            )
        if len(findings) > 20:
            lines.append(f"| | | | | ... and {len(findings) - 20} more |")
    else:
        lines.append("No adversarial Unicode detected.")

    with open(summary_path, "a") as fp:
        fp.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

def write_sarif(findings: List[Finding], sarif_path: str):
    """Write findings in SARIF 2.1.0 format for GitHub Code Scanning."""
    rules = []
    for rule_id, (name, desc, default_sev) in RULES.items():
        sarif_level = "error" if default_sev in (Severity.CRITICAL, Severity.HIGH) else "warning"
        if default_sev == Severity.LOW:
            sarif_level = "note"
        rules.append({
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": desc},
            "defaultConfiguration": {"level": sarif_level},
            "helpUri": "https://github.com/dcondrey/unicode-safety-check#what-it-detects",
            "properties": {"tags": ["security", "unicode", "supply-chain"]},
        })

    results = []
    for f in findings:
        sarif_level = "error"
        if f.severity == Severity.MEDIUM:
            sarif_level = "warning"
        elif f.severity == Severity.LOW:
            sarif_level = "note"

        uri = f.file.lstrip("./")
        results.append({
            "ruleId": f.rule_id,
            "level": sarif_level,
            "message": {"text": f"{f.char_info} -- {f.message}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.col + 1},
                },
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "unicode-safety-check",
                    "informationUri": "https://github.com/dcondrey/unicode-safety-check",
                    "version": "2.0.0",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }

    with open(sarif_path, "w") as fp:
        json.dump(sarif, fp, indent=2)


# ---------------------------------------------------------------------------
# GitHub outputs
# ---------------------------------------------------------------------------

def write_github_outputs(findings: List[Finding], files_scanned: int, sarif_path: Optional[str] = None):
    """Write to GITHUB_OUTPUT for downstream steps."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return

    with open(output_path, "a") as fp:
        fp.write(f"findings={len(findings)}\n")
        fp.write(f"files_scanned={files_scanned}\n")
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        fp.write(f"critical={critical}\n")
        fp.write(f"high={high}\n")
        if sarif_path:
            fp.write(f"sarif_file={sarif_path}\n")
