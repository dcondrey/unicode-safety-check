"""Language-aware tokenization for context-sensitive checking.

Classifies text on each line into identifier, comment, string, or other
contexts. Uses regex-based heuristics, not a full parser.
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple

from models import Context, Token

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_TO_LANG = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".pl": "perl", ".pm": "perl",
    ".r": "r", ".R": "r",
    ".swift": "swift",
    ".lua": "lua",
    ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml",
    ".md": "markdown", ".rst": "rst",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss",
    ".sql": "sql",
    ".zig": "zig",
    ".nim": "nim",
    ".json": "json",
    ".xml": "xml",
}

_FILENAME_TO_LANG = {
    "Dockerfile": "dockerfile",
    "Makefile": "makefile",
    "Gemfile": "ruby",
    "Rakefile": "ruby",
    "Vagrantfile": "ruby",
}


def detect_language(path: str) -> str:
    """Detect programming language from file path."""
    name = Path(path).name
    if name in _FILENAME_TO_LANG:
        return _FILENAME_TO_LANG[name]
    ext = Path(path).suffix.lower()
    return _EXT_TO_LANG.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Tokenization state machine
# ---------------------------------------------------------------------------

class TokenizerState:
    """Tracks multi-line comment/string state across lines."""

    def __init__(self):
        self.in_block_comment = False
        self.in_multiline_string = False
        self.string_delimiter = None  # for triple-quoted strings


# Comment patterns by language family
_HASH_COMMENT = {"python", "ruby", "perl", "shell", "yaml", "toml", "makefile", "dockerfile", "r"}
_SLASHSLASH_COMMENT = {
    "javascript", "typescript", "go", "rust", "java", "kotlin", "scala",
    "c", "cpp", "csharp", "swift", "zig", "nim", "php", "css", "scss", "sql",
}
_BLOCK_COMMENT_LANGS = {
    "javascript", "typescript", "go", "rust", "java", "kotlin", "scala",
    "c", "cpp", "csharp", "swift", "css", "scss", "php", "sql",
}
_TRIPLE_QUOTE_LANGS = {"python"}

# Word/identifier pattern
_IDENT_RE = re.compile(r'[A-Za-z_\u0080-\U0010FFFF][A-Za-z0-9_\u0080-\U0010FFFF]*')


def tokenize_line(
    line: str,
    lang: str,
    state: TokenizerState,
    line_num: int,
) -> Tuple[List[Token], TokenizerState]:
    """Tokenize a single line into classified tokens.

    Returns (tokens, updated_state).
    """
    tokens = []
    pos = 0
    n = len(line)

    # Handle continuation of block comment
    if state.in_block_comment:
        end = line.find("*/")
        if end == -1:
            # Entire line is still in block comment
            _extract_words(line, Context.COMMENT, line_num, 0, tokens)
            return tokens, state
        else:
            _extract_words(line[:end + 2], Context.COMMENT, line_num, 0, tokens)
            pos = end + 2
            state.in_block_comment = False

    # Handle continuation of triple-quoted string
    if state.in_multiline_string and state.string_delimiter:
        end = line.find(state.string_delimiter, pos)
        if end == -1:
            _extract_words(line[pos:], Context.STRING, line_num, pos, tokens)
            return tokens, state
        else:
            _extract_words(line[pos:end + 3], Context.STRING, line_num, pos, tokens)
            pos = end + 3
            state.in_multiline_string = False
            state.string_delimiter = None

    while pos < n:
        ch = line[pos]

        # Triple-quoted strings (Python)
        if lang in _TRIPLE_QUOTE_LANGS and pos + 2 < n:
            triple = line[pos:pos + 3]
            if triple in ('"""', "'''"):
                end = line.find(triple, pos + 3)
                if end == -1:
                    _extract_words(line[pos:], Context.STRING, line_num, pos, tokens)
                    state.in_multiline_string = True
                    state.string_delimiter = triple
                    return tokens, state
                else:
                    _extract_words(line[pos:end + 3], Context.STRING, line_num, pos, tokens)
                    pos = end + 3
                    continue

        # Line comments
        if lang in _HASH_COMMENT and ch == '#':
            _extract_words(line[pos:], Context.COMMENT, line_num, pos, tokens)
            return tokens, state

        if lang in _SLASHSLASH_COMMENT and ch == '/' and pos + 1 < n and line[pos + 1] == '/':
            _extract_words(line[pos:], Context.COMMENT, line_num, pos, tokens)
            return tokens, state

        # Block comments
        if lang in _BLOCK_COMMENT_LANGS and ch == '/' and pos + 1 < n and line[pos + 1] == '*':
            end = line.find("*/", pos + 2)
            if end == -1:
                _extract_words(line[pos:], Context.COMMENT, line_num, pos, tokens)
                state.in_block_comment = True
                return tokens, state
            else:
                _extract_words(line[pos:end + 2], Context.COMMENT, line_num, pos, tokens)
                pos = end + 2
                continue

        # String literals
        if ch in ('"', "'", '`'):
            end = _find_string_end(line, pos, ch)
            if end == -1:
                _extract_words(line[pos:], Context.STRING, line_num, pos, tokens)
                return tokens, state
            else:
                _extract_words(line[pos:end + 1], Context.STRING, line_num, pos, tokens)
                pos = end + 1
                continue

        # Identifier
        m = _IDENT_RE.match(line, pos)
        if m:
            tokens.append(Token(m.group(), Context.IDENTIFIER, line_num, pos))
            pos = m.end()
            continue

        # Other (operators, whitespace, etc.)
        pos += 1

    return tokens, state


def _find_string_end(line: str, start: int, quote: str) -> int:
    """Find the end of a string literal, handling escapes."""
    pos = start + 1
    while pos < len(line):
        if line[pos] == '\\':
            pos += 2  # skip escaped char
            continue
        if line[pos] == quote:
            return pos
        pos += 1
    return -1  # unterminated


def _extract_words(
    text: str,
    context: Context,
    line_num: int,
    offset: int,
    tokens: List[Token],
):
    """Extract word-like tokens from a text span."""
    for m in _IDENT_RE.finditer(text):
        tokens.append(Token(m.group(), context, line_num, offset + m.start()))
