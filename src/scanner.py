"""Core scanner that orchestrates checks across files."""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set

from models import Context, FileRisk, Finding, Severity, Token
from config import Policy
from tokenizer import TokenizerState, detect_language, tokenize_line
from checks import (
    ConfusableTracker,
    check_annotation_anchors,
    check_bidi_controls,
    check_bidi_pairing,
    check_bom,
    check_control_chars,
    check_default_ignorable,
    check_deprecated_format,
    check_encoding,
    check_homoglyphs,
    check_invisible_format,
    check_mixed_line_endings,
    check_mixed_script,
    check_non_ascii_identifier,
    check_normalization,
    check_pua,
    check_suspicious_spacing,
    check_tag_chars,
    check_variation_selectors,
)


# Paths excluded by default (binary, deps, build output)
DEFAULT_EXCLUDE_PATTERNS = [
    '.git/', 'node_modules/', '.vscode/', '__pycache__/', '.mypy_cache/',
    '.tox/', 'vendor/', 'dist/', 'build/', '_site/', '.next/', 'target/',
]

DEFAULT_EXCLUDE_EXTENSIONS = {
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.pdf', '.wasm', '.pyc', '.pyo', '.class',
    '.o', '.so', '.dylib', '.dll', '.exe', '.a', '.lib',
    '.jar', '.war', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.lock', '.min.js', '.min.css',
    '.pb.go',
}


def should_exclude(path: str, extra_patterns: Optional[List[str]] = None) -> bool:
    """Check if a path should be excluded from scanning."""
    for pattern in DEFAULT_EXCLUDE_PATTERNS:
        if pattern in path:
            return True
    ext = Path(path).suffix.lower()
    if ext in DEFAULT_EXCLUDE_EXTENSIONS:
        return True
    # Check two-part extensions like .min.js
    name = Path(path).name.lower()
    for exc_ext in DEFAULT_EXCLUDE_EXTENSIONS:
        if name.endswith(exc_ext):
            return True
    if extra_patterns:
        import fnmatch
        for pat in extra_patterns:
            if fnmatch.fnmatch(path, pat) or pat in path:
                return True
    return False


def is_binary(path: str) -> bool:
    """Heuristic binary detection: check first 8KB for null bytes."""
    try:
        with open(path, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except (IOError, OSError):
        return True


def scan_file(
    path: str,
    policy: Policy,
    changed_lines: Optional[Set[int]] = None,
    extra_excludes: Optional[List[str]] = None,
) -> List[Finding]:
    """Scan a single file and return all findings."""
    if should_exclude(path, extra_excludes):
        return []
    if is_binary(path):
        return []

    findings = []

    # Read raw bytes for encoding check
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except (IOError, OSError):
        return []

    # USC008: Encoding check
    encoding_findings = check_encoding(raw, path)
    if encoding_findings:
        return encoding_findings  # Can't proceed if not valid UTF-8

    content = raw.decode('utf-8')

    # USC018: Mixed line endings
    findings.extend(check_mixed_line_endings(content, path))

    # Determine language and file risk
    lang = detect_language(path)
    file_risk = policy.get_file_risk(path)

    # Set up tokenizer and confusable tracker
    state = TokenizerState()
    confusable_tracker = ConfusableTracker()
    lines = content.splitlines(keepends=True)

    for line_num_0, line_text in enumerate(lines):
        line_num = line_num_0 + 1

        # Diff-only mode: skip unchanged lines for most checks
        # But always run critical checks (bidi, tag chars) on all lines
        is_changed = changed_lines is None or line_num in changed_lines
        is_critical_only = not is_changed

        # Tokenize the line
        tokens, state = tokenize_line(line_text, lang, state, line_num)

        # Determine dominant context for the line
        line_context = _dominant_context(tokens)

        # --- Character-level checks (run on every character) ---

        # USC001: Bidi controls (ALWAYS check, even on unchanged lines)
        findings.extend(check_bidi_controls(line_text, line_num, path, line_context, policy))

        # USC015: Bidi pairing (ALWAYS check)
        findings.extend(check_bidi_pairing(line_text, line_num, path, policy))

        # USC012: Tag characters (ALWAYS check)
        findings.extend(check_tag_chars(line_text, line_num, path, line_context, policy))

        # USC011: Private Use Area (ALWAYS check)
        findings.extend(check_pua(line_text, line_num, path, line_context, policy))

        if is_critical_only:
            continue  # Skip non-critical checks on unchanged lines

        # USC002: Invisible format chars
        findings.extend(check_invisible_format(line_text, line_num, path, line_context, policy))

        # USC005: Suspicious spacing
        findings.extend(check_suspicious_spacing(line_text, line_num, path, line_context, policy))

        # USC007: Control characters
        findings.extend(check_control_chars(line_text, line_num, path, line_context, policy))

        # USC009: Misplaced BOM
        findings.extend(check_bom(line_text, line_num, path, line_num == 1, policy))

        # USC010: Variation selectors
        findings.extend(check_variation_selectors(line_text, line_num, path, line_context, policy))

        # USC013: Deprecated format chars
        findings.extend(check_deprecated_format(line_text, line_num, path, line_context, policy))

        # USC014: Annotation anchors
        findings.extend(check_annotation_anchors(line_text, line_num, path, line_context, policy))

        # USC016: Default-ignorable chars
        findings.extend(check_default_ignorable(line_text, line_num, path, line_context, policy))

        # --- Token-level checks ---
        for token in tokens:
            # USC003: Mixed-script identifiers
            findings.extend(check_mixed_script(
                token.text, token.line, token.col, path, token.context, policy,
            ))

            # USC004: Confusable collisions
            findings.extend(confusable_tracker.check(
                token.text, token.line, token.col, path, token.context, policy,
            ))

            # USC006: Normalization drift
            findings.extend(check_normalization(
                token.text, token.line, token.col, path, token.context, policy,
            ))

            # USC017: Homoglyphs
            findings.extend(check_homoglyphs(
                token.text, token.line, token.col, path, token.context, policy,
            ))

            # USC019: Non-ASCII identifier policy
            findings.extend(check_non_ascii_identifier(
                token.text, token.line, token.col, path, token.context, policy,
            ))

    return findings


def scan_files(
    paths: List[str],
    policy: Policy,
    changed_lines_map: Optional[Dict[str, Set[int]]] = None,
    extra_excludes: Optional[List[str]] = None,
) -> List[Finding]:
    """Scan multiple files and return all findings."""
    all_findings = []
    for path in paths:
        changed = changed_lines_map.get(path) if changed_lines_map else None
        all_findings.extend(scan_file(path, policy, changed, extra_excludes))
    return all_findings


def collect_files_recursive(root: str = ".") -> List[str]:
    """Collect all files under root, excluding defaults."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories
        dirnames[:] = [
            d for d in dirnames
            if not any(pat.rstrip('/') == d for pat in DEFAULT_EXCLUDE_PATTERNS)
        ]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            # Normalize to relative path
            rel = os.path.relpath(full, root)
            if not should_exclude(rel):
                files.append(rel)
    return files


def _dominant_context(tokens: List[Token]) -> Context:
    """Determine the dominant context from a line's tokens."""
    if not tokens:
        return Context.OTHER
    # If any token is an identifier, the line has code
    contexts = {t.context for t in tokens}
    if Context.IDENTIFIER in contexts:
        return Context.IDENTIFIER
    if Context.COMMENT in contexts:
        return Context.COMMENT
    if Context.STRING in contexts:
        return Context.STRING
    return Context.OTHER
