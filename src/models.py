"""Shared types."""
from enum import Enum
from typing import NamedTuple


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Context(Enum):
    IDENTIFIER = "identifier"
    COMMENT = "comment"
    STRING = "string"
    OTHER = "other"


class FileRisk(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(NamedTuple):
    rule_id: str
    rule_name: str
    severity: Severity
    file: str
    line: int
    col: int
    message: str
    char_info: str
    context: Context
    snippet: str


class Token(NamedTuple):
    text: str
    context: Context
    line: int
    col: int


RULES = {
    "USC001": ("bidi-control", "Bidirectional control character", Severity.CRITICAL),
    "USC002": ("invisible-format", "Invisible formatting character", Severity.CRITICAL),
    "USC003": ("mixed-script", "Mixed-script identifier", Severity.HIGH),
    "USC004": ("confusable-collision", "Confusable identifier collision", Severity.HIGH),
    "USC005": ("suspicious-spacing", "Suspicious spacing character", Severity.MEDIUM),
    "USC006": ("normalization-drift", "Normalization-unstable text", Severity.MEDIUM),
    "USC007": ("control-character", "Disallowed control character", Severity.CRITICAL),
    "USC008": ("invalid-encoding", "Invalid UTF-8 encoding", Severity.CRITICAL),
    "USC009": ("misplaced-bom", "Misplaced byte-order mark", Severity.CRITICAL),
    "USC010": ("variation-selector", "Suspicious variation selector sequence", Severity.CRITICAL),
    "USC011": ("private-use", "Private Use Area code point", Severity.CRITICAL),
    "USC012": ("tag-character", "Tag character (payload encoding)", Severity.CRITICAL),
    "USC013": ("deprecated-format", "Deprecated format character", Severity.CRITICAL),
    "USC014": ("annotation-anchor", "Interlinear annotation anchor", Severity.CRITICAL),
    "USC015": ("bidi-pairing", "Unbalanced bidi control pairing", Severity.CRITICAL),
    "USC016": ("default-ignorable", "Default-ignorable code point", Severity.HIGH),
    "USC017": ("homoglyph", "Homoglyph character", Severity.HIGH),
    "USC018": ("mixed-line-endings", "Mixed line endings", Severity.MEDIUM),
    "USC019": ("non-ascii-identifier", "Non-ASCII in identifier (policy violation)", Severity.MEDIUM),
}
