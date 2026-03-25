#!/usr/bin/env python3
"""Unicode Safety Check -- entry point.

Detects adversarial Unicode in source files: invisible characters, bidi
attacks, homoglyphs, confusable collisions, encoding issues, and more.
"""

import argparse
import os
import sys

# Allow imports from the src directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import Severity
from config import load_policy
from diff import get_changed_lines
from scanner import collect_files_recursive, scan_file, scan_files, should_exclude
from output import (
    emit_annotations,
    format_finding,
    format_summary,
    write_github_outputs,
    write_sarif,
    write_step_summary,
)


def main():
    parser = argparse.ArgumentParser(
        description="Detect adversarial Unicode in source files."
    )
    parser.add_argument(
        "files", nargs="*",
        help="Files to scan. If empty, reads from --file-list or scans all.",
    )
    parser.add_argument(
        "--file-list",
        help="Path to a file containing one path per line to scan.",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Scan all files in the current directory recursively.",
    )
    parser.add_argument(
        "--policy",
        help="Path to policy file (.yml, .yaml, .json, or .toml).",
    )
    parser.add_argument(
        "--base-sha",
        help="Base SHA for diff-only mode (only check new/modified lines).",
    )
    parser.add_argument(
        "--sarif-file",
        help="Path to write SARIF output.",
    )
    parser.add_argument(
        "--no-annotations", action="store_true",
        help="Suppress GitHub Actions annotations.",
    )
    parser.add_argument(
        "--fail-on-warn", action="store_true",
        help="Exit non-zero on warnings (medium/low severity).",
    )
    parser.add_argument(
        "--exclude", action="append", default=[],
        help="Additional path patterns to exclude (can be repeated).",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output.",
    )

    args = parser.parse_args()

    # Load policy
    policy_path = args.policy or os.environ.get("INPUT_POLICY_FILE") or None
    policy = load_policy(policy_path)

    # Merge env-based config (from action.yml)
    if os.environ.get("INPUT_FAIL_ON_WARN", "").lower() == "true":
        args.fail_on_warn = True
    if os.environ.get("INPUT_DISABLE_ANNOTATIONS", "").lower() == "true":
        args.no_annotations = True
    sarif_file = args.sarif_file or os.environ.get("INPUT_SARIF_FILE") or None
    base_sha = args.base_sha or os.environ.get("INPUT_BASE_SHA") or None
    scan_all = args.all or os.environ.get("INPUT_SCAN_MODE") == "all"

    # Collect exclude patterns
    extra_excludes = args.exclude[:]
    env_excludes = os.environ.get("INPUT_EXCLUDE_PATTERNS", "")
    if env_excludes:
        extra_excludes.extend(p.strip() for p in env_excludes.splitlines() if p.strip())

    # Determine files to scan
    if scan_all:
        file_list = collect_files_recursive(".")
    elif args.file_list:
        with open(args.file_list) as f:
            file_list = [line.strip() for line in f if line.strip()]
    elif args.files:
        file_list = args.files
    else:
        # Default: scan all
        file_list = collect_files_recursive(".")

    # Filter excluded files
    file_list = [f for f in file_list if not should_exclude(f, extra_excludes)]

    # Get diff data for diff-only scanning
    changed_lines_map = None
    if base_sha:
        changed_lines_map = get_changed_lines(base_sha)

    # Scan
    all_findings = []
    files_scanned = 0
    for path in file_list:
        if not os.path.isfile(path):
            continue
        changed = changed_lines_map.get(path) if changed_lines_map else None
        findings = scan_file(path, policy, changed, extra_excludes)
        all_findings.extend(findings)
        files_scanned += 1

    # Output findings
    use_color = not args.no_color and sys.stdout.isatty()
    for f in all_findings:
        print(format_finding(f, color=use_color))
        print()

    # Print summary
    print(format_summary(all_findings, files_scanned))

    # GitHub annotations
    if not args.no_annotations:
        emit_annotations(all_findings)

    # SARIF output
    if sarif_file:
        write_sarif(all_findings, sarif_file)
        print(f"SARIF report written to: {sarif_file}")

    # GitHub step summary
    write_step_summary(all_findings, files_scanned)

    # GitHub outputs
    write_github_outputs(all_findings, files_scanned, sarif_file)

    # Determine exit code based on severity and file risk
    has_critical = any(f.severity == Severity.CRITICAL for f in all_findings)
    has_high = any(f.severity == Severity.HIGH for f in all_findings)
    has_medium_or_low = any(
        f.severity in (Severity.MEDIUM, Severity.LOW) for f in all_findings
    )

    if has_critical or has_high:
        sys.exit(1)
    elif args.fail_on_warn and has_medium_or_low:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
