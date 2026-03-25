"""Core scanner: orchestrates checks across files."""
import os
from pathlib import Path

from models import Context, Finding, Token
from config import Policy
from tokenizer import TokenizerState, detect_language, tokenize_line
from checks import (
    ConfusableTracker, check_encoding, check_mixed_line_endings,
    check_token, scan_line_chars,
)

_EXCLUDE_DIRS = frozenset({
    '.git', 'node_modules', '.vscode', '__pycache__', '.mypy_cache',
    '.tox', 'vendor', 'dist', 'build', '_site', '.next', 'target',
})

_EXCLUDE_EXTS = frozenset({
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
    '.pdf', '.wasm', '.pyc', '.pyo', '.class',
    '.o', '.so', '.dylib', '.dll', '.exe', '.a', '.lib',
    '.jar', '.war', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.lock', '.min.js', '.min.css', '.pb.go',
})

_EXCLUDE_SUBSTRS = ['.git/', 'node_modules/', '.vscode/', '__pycache__/',
    '.mypy_cache/', '.tox/', 'vendor/', 'dist/', 'build/', '_site/', '.next/', 'target/']


def should_exclude(path, extra=None):
    for pat in _EXCLUDE_SUBSTRS:
        if pat in path:
            return True
    name = Path(path).name.lower()
    for ext in _EXCLUDE_EXTS:
        if name.endswith(ext):
            return True
    if extra:
        import fnmatch
        for pat in extra:
            if fnmatch.fnmatch(path, pat) or pat in path:
                return True
    return False


def _is_binary(path):
    try:
        with open(path, 'rb') as f:
            return b'\x00' in f.read(8192)
    except (IOError, OSError):
        return True


def scan_file(path, policy, changed_lines=None, extra_excludes=None):
    if should_exclude(path, extra_excludes) or _is_binary(path):
        return []

    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except (IOError, OSError):
        return []

    enc_err = check_encoding(raw, path)
    if enc_err:
        return [enc_err]

    content = raw.decode('utf-8')
    findings = []

    le_err = check_mixed_line_endings(content, path)
    if le_err:
        findings.append(le_err)

    lang = detect_language(path)
    state = TokenizerState()
    tracker = ConfusableTracker()
    lines = content.splitlines(keepends=True)

    for i, line_text in enumerate(lines):
        line_num = i + 1
        is_changed = changed_lines is None or line_num in changed_lines
        tokens, state = tokenize_line(line_text, lang, state, line_num)
        ctx = _line_context(tokens)

        scan_line_chars(line_text, line_num, path, ctx, policy, not is_changed, findings)

        if not is_changed:
            continue

        for tok in tokens:
            check_token(tok, path, policy, findings)
            tracker.check(tok.text, tok.line, tok.col, path, tok.context, policy, findings)

    return findings


def collect_files(root="."):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS]
        for fname in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fname), root)
            if not should_exclude(rel):
                files.append(rel)
    return files


def _line_context(tokens):
    if not tokens:
        return Context.OTHER
    for t in tokens:
        if t.context == Context.IDENTIFIER:
            return Context.IDENTIFIER
    for t in tokens:
        if t.context == Context.COMMENT:
            return Context.COMMENT
    for t in tokens:
        if t.context == Context.STRING:
            return Context.STRING
    return Context.OTHER
