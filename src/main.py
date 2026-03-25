#!/usr/bin/env python3
"""Unicode Safety Check entry point."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import Severity
from config import load_policy
from diff import get_changed_lines
from scanner import collect_files, scan_file, should_exclude
from output import (emit_annotations, format_finding, format_summary,
                    write_github_outputs, write_sarif, write_step_summary)


def main():
    p = argparse.ArgumentParser(description="Detect adversarial Unicode in source files.")
    p.add_argument("files", nargs="*")
    p.add_argument("--file-list")
    p.add_argument("--all", action="store_true")
    p.add_argument("--policy")
    p.add_argument("--base-sha")
    p.add_argument("--sarif-file")
    p.add_argument("--no-annotations", action="store_true")
    p.add_argument("--fail-on-warn", action="store_true")
    p.add_argument("--exclude", action="append", default=[])
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()

    policy = load_policy(args.policy or os.environ.get("INPUT_POLICY_FILE") or None)

    if os.environ.get("INPUT_FAIL_ON_WARN", "").lower() == "true":
        args.fail_on_warn = True
    if os.environ.get("INPUT_DISABLE_ANNOTATIONS", "").lower() == "true":
        args.no_annotations = True
    sarif_file = args.sarif_file or os.environ.get("INPUT_SARIF_FILE") or None
    base_sha = args.base_sha or os.environ.get("INPUT_BASE_SHA") or None
    scan_all = args.all or os.environ.get("INPUT_SCAN_MODE") == "all"

    excludes = args.exclude[:]
    env_exc = os.environ.get("INPUT_EXCLUDE_PATTERNS", "")
    if env_exc:
        excludes.extend(l.strip() for l in env_exc.splitlines() if l.strip())

    if scan_all:
        files = collect_files(".")
    elif args.file_list:
        with open(args.file_list) as f:
            files = [l.strip() for l in f if l.strip()]
    elif args.files:
        files = args.files
    else:
        files = collect_files(".")

    files = [f for f in files if not should_exclude(f, excludes)]

    changed = get_changed_lines(base_sha) if base_sha else None

    all_findings = []
    scanned = 0
    for path in files:
        if not os.path.isfile(path):
            continue
        all_findings.extend(scan_file(path, policy, changed.get(path) if changed else None, excludes))
        scanned += 1

    color = not args.no_color and sys.stdout.isatty()
    for f in all_findings:
        print(format_finding(f, color=color))
        print()
    print(format_summary(all_findings, scanned))

    if not args.no_annotations:
        emit_annotations(all_findings)
    if sarif_file:
        write_sarif(all_findings, sarif_file)
        print(f"SARIF report written to: {sarif_file}")

    write_step_summary(all_findings, scanned)
    write_github_outputs(all_findings, scanned, sarif_file)

    has_fail = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in all_findings)
    has_warn = any(f.severity in (Severity.MEDIUM, Severity.LOW) for f in all_findings)
    sys.exit(1 if has_fail or (args.fail_on_warn and has_warn) else 0)


if __name__ == "__main__":
    main()
