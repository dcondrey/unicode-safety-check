"""Language-aware tokenization: classifies line content as identifier/comment/string."""
import re
from pathlib import Path

from models import Context, Token

_EXT_TO_LANG = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".go": "go", ".rs": "rust",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
    ".cs": "csharp", ".rb": "ruby", ".php": "php",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".pl": "perl", ".pm": "perl", ".r": "r", ".R": "r",
    ".swift": "swift", ".lua": "lua",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".md": "markdown", ".rst": "rst",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss", ".sql": "sql",
    ".zig": "zig", ".nim": "nim", ".json": "json", ".xml": "xml",
}
_FILENAME_TO_LANG = {
    "Dockerfile": "dockerfile", "Makefile": "makefile",
    "Gemfile": "ruby", "Rakefile": "ruby", "Vagrantfile": "ruby",
}
_HASH_LANGS = frozenset({"python", "ruby", "perl", "shell", "yaml", "toml", "makefile", "dockerfile", "r"})
_SLASH_LANGS = frozenset({
    "javascript", "typescript", "go", "rust", "java", "kotlin", "scala",
    "c", "cpp", "csharp", "swift", "zig", "nim", "php", "css", "scss", "sql",
})
_BLOCK_LANGS = frozenset({
    "javascript", "typescript", "go", "rust", "java", "kotlin", "scala",
    "c", "cpp", "csharp", "swift", "css", "scss", "php", "sql",
})
_TRIPLE_LANGS = frozenset({"python"})
_IDENT_RE = re.compile(r'[A-Za-z_\u0080-\U0010FFFF][A-Za-z0-9_\u0080-\U0010FFFF]*')


def detect_language(path):
    name = Path(path).name
    if name in _FILENAME_TO_LANG:
        return _FILENAME_TO_LANG[name]
    return _EXT_TO_LANG.get(Path(path).suffix.lower(), "unknown")


class TokenizerState:
    __slots__ = ('in_block_comment', 'in_multiline_string', 'string_delimiter')
    def __init__(self):
        self.in_block_comment = False
        self.in_multiline_string = False
        self.string_delimiter = None


def tokenize_line(line, lang, state, line_num):
    tokens = []
    pos = 0
    n = len(line)

    if state.in_block_comment:
        end = line.find("*/")
        if end == -1:
            _words(line, Context.COMMENT, line_num, 0, tokens)
            return tokens, state
        _words(line[:end + 2], Context.COMMENT, line_num, 0, tokens)
        pos = end + 2
        state.in_block_comment = False

    if state.in_multiline_string and state.string_delimiter:
        end = line.find(state.string_delimiter, pos)
        if end == -1:
            _words(line[pos:], Context.STRING, line_num, pos, tokens)
            return tokens, state
        _words(line[pos:end + 3], Context.STRING, line_num, pos, tokens)
        pos = end + 3
        state.in_multiline_string = False
        state.string_delimiter = None

    while pos < n:
        ch = line[pos]

        if lang in _TRIPLE_LANGS and pos + 2 < n:
            tri = line[pos:pos + 3]
            if tri in ('"""', "'''"):
                end = line.find(tri, pos + 3)
                if end == -1:
                    _words(line[pos:], Context.STRING, line_num, pos, tokens)
                    state.in_multiline_string = True
                    state.string_delimiter = tri
                    return tokens, state
                _words(line[pos:end + 3], Context.STRING, line_num, pos, tokens)
                pos = end + 3
                continue

        if lang in _HASH_LANGS and ch == '#':
            _words(line[pos:], Context.COMMENT, line_num, pos, tokens)
            return tokens, state

        if lang in _SLASH_LANGS and ch == '/' and pos + 1 < n and line[pos + 1] == '/':
            _words(line[pos:], Context.COMMENT, line_num, pos, tokens)
            return tokens, state

        if lang in _BLOCK_LANGS and ch == '/' and pos + 1 < n and line[pos + 1] == '*':
            end = line.find("*/", pos + 2)
            if end == -1:
                _words(line[pos:], Context.COMMENT, line_num, pos, tokens)
                state.in_block_comment = True
                return tokens, state
            _words(line[pos:end + 2], Context.COMMENT, line_num, pos, tokens)
            pos = end + 2
            continue

        if ch in ('"', "'", '`'):
            end = _str_end(line, pos, ch)
            if end == -1:
                _words(line[pos:], Context.STRING, line_num, pos, tokens)
                return tokens, state
            _words(line[pos:end + 1], Context.STRING, line_num, pos, tokens)
            pos = end + 1
            continue

        m = _IDENT_RE.match(line, pos)
        if m:
            tokens.append(Token(m.group(), Context.IDENTIFIER, line_num, pos))
            pos = m.end()
            continue

        pos += 1

    return tokens, state


def _str_end(line, start, q):
    pos = start + 1
    while pos < len(line):
        if line[pos] == '\\':
            pos += 2
            continue
        if line[pos] == q:
            return pos
        pos += 1
    return -1


def _words(text, ctx, line_num, offset, tokens):
    for m in _IDENT_RE.finditer(text):
        tokens.append(Token(m.group(), ctx, line_num, offset + m.start()))
