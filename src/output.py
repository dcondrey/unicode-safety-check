"""Output: SARIF, annotations, diagnostics, summaries."""
import json
import os

from models import Finding, Severity, RULES

_SEV_COLORS = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[0;31m",
    Severity.MEDIUM: "\033[0;33m", Severity.LOW: "\033[0;36m",
}
_NC = "\033[0m"


def format_finding(f, color=True):
    sev = f.severity.value.upper()
    if color:
        sev = f"{_SEV_COLORS.get(f.severity, '')}{sev}{_NC}"
    lines = [
        f"  {sev} [{f.rule_id} {f.rule_name}] {f.file}:{f.line}:{f.col}",
        f"    {f.char_info}",
        f"    {f.message}",
    ]
    if f.snippet:
        lines.append(f'    near: "{_escape(f.snippet)}"')
    return "\n".join(lines)


def _escape(text):
    out = []
    for ch in text:
        cp = ord(ch)
        if cp > 0x7F and _invisible(cp):
            out.append(f"\\u{{{cp:04X}}}")
        else:
            out.append(ch)
    return "".join(out)


def _invisible(cp):
    return ((0x200B <= cp <= 0x200F) or (0x202A <= cp <= 0x202E) or
            (0x2060 <= cp <= 0x206F) or (0x2066 <= cp <= 0x2069) or
            cp in (0xFEFF, 0x00AD, 0x061C))


def emit_annotations(findings):
    for f in findings:
        lvl = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
        print(f"::{lvl} file={f.file},line={f.line},col={f.col},"
              f"title=Unicode Safety [{f.rule_name}]::{f.char_info} -- {f.message}")


def format_summary(findings, files_scanned):
    buckets = {s: [] for s in Severity}
    for f in findings:
        buckets[f.severity].append(f)
    lines = [f"Unicode Safety Check: {files_scanned} files scanned, {len(findings)} finding(s)", ""]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        items = buckets[sev]
        if items:
            lines.append(f"  {sev.value.upper()} ({len(items)}):")
            for f in items[:10]:
                lines.append(f"    {f.rule_id} {f.file}:{f.line} {f.rule_name}")
            if len(items) > 10:
                lines.append(f"    ... and {len(items) - 10} more")
            lines.append("")
    if not findings:
        lines.append("  No adversarial Unicode detected.")
    return "\n".join(lines)


def write_step_summary(findings, files_scanned):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    buckets = {}
    for f in findings:
        buckets[f.severity.value] = buckets.get(f.severity.value, 0) + 1
    lines = [
        "### Unicode Safety Check", "",
        "| Metric | Count |", "|--------|-------|",
        f"| Files scanned | {files_scanned} |",
        f"| Critical | {buckets.get('critical', 0)} |",
        f"| High | {buckets.get('high', 0)} |",
        f"| Medium | {buckets.get('medium', 0)} |",
        f"| Low | {buckets.get('low', 0)} |", "",
    ]
    if findings:
        lines += ["#### Top findings", "",
                   "| Severity | Rule | File | Line | Description |",
                   "|----------|------|------|------|-------------|"]
        for f in findings[:20]:
            lines.append(f"| {f.severity.value} | {f.rule_id} {f.rule_name} | `{f.file}` | {f.line} | {f.message[:80]} |")
        if len(findings) > 20:
            lines.append(f"| | | | | ... and {len(findings) - 20} more |")
    else:
        lines.append("No adversarial Unicode detected.")
    with open(path, "a") as fp:
        fp.write("\n".join(lines) + "\n")


def write_sarif(findings, sarif_path):
    rules = []
    for rid, (name, desc, sev) in RULES.items():
        lvl = "note" if sev == Severity.LOW else ("warning" if sev == Severity.MEDIUM else "error")
        rules.append({"id": rid, "name": name, "shortDescription": {"text": desc},
                       "defaultConfiguration": {"level": lvl},
                       "helpUri": "https://github.com/dcondrey/unicode-safety-check#what-it-detects",
                       "properties": {"tags": ["security", "unicode", "supply-chain"]}})
    results = []
    for f in findings:
        lvl = "note" if f.severity == Severity.LOW else ("warning" if f.severity == Severity.MEDIUM else "error")
        results.append({"ruleId": f.rule_id, "level": lvl,
                         "message": {"text": f"{f.char_info} -- {f.message}"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": f.file.lstrip("./"), "uriBaseId": "%SRCROOT%"},
                             "region": {"startLine": f.line, "startColumn": f.col + 1}}}]})
    with open(sarif_path, "w") as fp:
        json.dump({"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "unicode-safety-check",
                        "informationUri": "https://github.com/dcondrey/unicode-safety-check",
                        "version": "2.0.0", "rules": rules}}, "results": results}]}, fp, indent=2)


def write_github_outputs(findings, files_scanned, sarif_path=None):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    with open(path, "a") as fp:
        fp.write(f"findings={len(findings)}\nfiles_scanned={files_scanned}\n"
                 f"critical={critical}\nhigh={high}\n")
        if sarif_path:
            fp.write(f"sarif_file={sarif_path}\n")
