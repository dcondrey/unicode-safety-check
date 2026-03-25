"""Detection rules for adversarial Unicode.

Each check function takes file context and returns a list of Finding objects.
"""

import unicodedata
from typing import Dict, List, Optional, Set, Tuple

from models import Context, Finding, Severity, RULES
from unicode_data import (
    BIDI_CONTROLS, BIDI_OPENERS, BIDI_CLOSER_PDF,
    BIDI_ISOLATE_OPENERS, BIDI_ISOLATE_CLOSER,
    CONFUSABLES, INVISIBLE_FORMAT_CHARS, SUSPICIOUS_SPACES,
    char_info, get_script, is_default_ignorable, is_pua,
    is_tag_character, is_variation_selector, skeleton,
)
from config import Policy


def _finding(rule_id: str, file: str, line: int, col: int,
             message: str, ch_info: str, context: Context,
             snippet: str, policy: Optional[Policy] = None) -> Finding:
    """Create a Finding with the rule's default severity (or policy override)."""
    rule_name, _, default_sev = RULES[rule_id]
    sev = default_sev
    if policy and rule_name in policy.severity_overrides:
        sev = policy.severity_overrides[rule_name]
    return Finding(rule_id, rule_name, sev, file, line, col, message, ch_info, context, snippet)


# ---------------------------------------------------------------------------
# USC001: Bidirectional control characters
# ---------------------------------------------------------------------------

def check_bidi_controls(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if cp in BIDI_CONTROLS:
            if policy.is_allowed(file, cp, context):
                continue
            info = char_info(ch)
            snippet = _snippet(line_text, col)
            findings.append(_finding(
                "USC001", file, line_num, col,
                f"Bidirectional control character {info} in {context.value}",
                info, context, snippet, policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC002: Invisible formatting characters
# ---------------------------------------------------------------------------

def check_invisible_format(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if cp in INVISIBLE_FORMAT_CHARS:
            # BOM at file start is handled separately (USC009)
            if cp == 0xFEFF:
                continue
            if policy.is_allowed(file, cp, context):
                continue
            info = char_info(ch)
            snippet = _snippet(line_text, col)
            findings.append(_finding(
                "USC002", file, line_num, col,
                f"Invisible format character {info} in {context.value}",
                info, context, snippet, policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC003: Mixed-script identifiers
# ---------------------------------------------------------------------------

def check_mixed_script(
    token_text: str, line_num: int, col: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    if context != Context.IDENTIFIER:
        return []

    scripts = set()
    for ch in token_text:
        s = get_script(ch)
        if s not in ("Common", "Inherited", "Unknown"):
            scripts.add(s)

    if len(scripts) > 1:
        info = f"scripts: {', '.join(sorted(scripts))}"
        snippet = token_text
        action = policy.context_action("mixed-script", context)
        if action == "ignore":
            return []
        return [_finding(
            "USC003", file, line_num, col,
            f"Mixed-script identifier '{token_text}' combines {info}",
            info, context, snippet, policy,
        )]
    return []


# ---------------------------------------------------------------------------
# USC004: Confusable identifier collisions
# ---------------------------------------------------------------------------

class ConfusableTracker:
    """Track identifiers and detect skeleton collisions within a file."""

    def __init__(self):
        # skeleton -> (original_text, line, col)
        self.seen: Dict[str, Tuple[str, int, int]] = {}

    def check(
        self, token_text: str, line_num: int, col: int, file: str,
        context: Context, policy: Policy,
    ) -> List[Finding]:
        if context != Context.IDENTIFIER:
            return []

        skel = skeleton(token_text)
        if skel in self.seen:
            orig_text, orig_line, orig_col = self.seen[skel]
            if orig_text != token_text:
                info = f"'{token_text}' confusable with '{orig_text}' (line {orig_line})"
                return [_finding(
                    "USC004", file, line_num, col,
                    f"Confusable collision: '{token_text}' has same skeleton as "
                    f"'{orig_text}' (first seen at line {orig_line}:{orig_col})",
                    info, context, token_text, policy,
                )]
        else:
            self.seen[skel] = (token_text, line_num, col)
        return []


# ---------------------------------------------------------------------------
# USC005: Suspicious spacing characters
# ---------------------------------------------------------------------------

def check_suspicious_spacing(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if cp in SUSPICIOUS_SPACES:
            if policy.is_allowed(file, cp, context):
                continue
            info = char_info(ch)
            name = SUSPICIOUS_SPACES[cp]
            snippet = _snippet(line_text, col)
            findings.append(_finding(
                "USC005", file, line_num, col,
                f"Suspicious spacing character {info} ({name}) in {context.value}",
                info, context, snippet, policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC006: Normalization drift
# ---------------------------------------------------------------------------

def check_normalization(
    token_text: str, line_num: int, col: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    nfc = unicodedata.normalize("NFC", token_text)
    if nfc != token_text:
        nfkc = unicodedata.normalize("NFKC", token_text)
        severity_hint = "identifier" if context == Context.IDENTIFIER else "text"
        info = f"NFC: '{nfc}'" + (f", NFKC: '{nfkc}'" if nfkc != nfc else "")
        return [_finding(
            "USC006", file, line_num, col,
            f"Normalization-unstable {severity_hint} '{token_text}' changes under NFC ({info})",
            info, context, token_text, policy,
        )]
    return []


# ---------------------------------------------------------------------------
# USC007: Control characters (non-tab, non-newline, non-CR)
# ---------------------------------------------------------------------------

_ALLOWED_CONTROLS = {0x09, 0x0A, 0x0D}  # tab, newline, carriage return


def check_control_chars(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cat == "Cc" and cp not in _ALLOWED_CONTROLS:
            if policy.is_allowed(file, cp, context):
                continue
            info = char_info(ch)
            snippet = _snippet(line_text, col)
            findings.append(_finding(
                "USC007", file, line_num, col,
                f"Control character {info} in {context.value}",
                info, context, snippet, policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC008: Invalid UTF-8 encoding (checked at file level, not per-line)
# ---------------------------------------------------------------------------

def check_encoding(file_bytes: bytes, file: str) -> List[Finding]:
    try:
        file_bytes.decode("utf-8")
        return []
    except UnicodeDecodeError as e:
        info = f"byte offset {e.start}: {e.reason}"
        return [Finding(
            "USC008", "invalid-encoding", Severity.CRITICAL, file,
            1, 0, f"File is not valid UTF-8: {info}",
            info, Context.OTHER, "",
        )]


# ---------------------------------------------------------------------------
# USC009: Misplaced BOM
# ---------------------------------------------------------------------------

def check_bom(
    line_text: str, line_num: int, file: str, is_first_line: bool,
    policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        if ord(ch) == 0xFEFF:
            if is_first_line and col == 0:
                continue  # BOM at file start is allowed (though discouraged)
            info = char_info(ch)
            findings.append(_finding(
                "USC009", file, line_num, col,
                f"Misplaced byte-order mark {info} (not at start of file)",
                info, Context.OTHER, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC010: Variation selector abuse
# ---------------------------------------------------------------------------

def check_variation_selectors(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    count = sum(1 for ch in line_text if is_variation_selector(ord(ch)))
    if count >= 3:
        info = f"{count} variation selectors on one line"
        return [_finding(
            "USC010", file, line_num, 0,
            f"Suspicious variation selector density: {info} (potential payload encoding)",
            info, context, line_text[:80], policy,
        )]
    return []


# ---------------------------------------------------------------------------
# USC011: Private Use Area
# ---------------------------------------------------------------------------

def check_pua(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        if is_pua(ord(ch)):
            if policy.is_allowed(file, ord(ch), context):
                continue
            info = char_info(ch)
            findings.append(_finding(
                "USC011", file, line_num, col,
                f"Private Use Area code point {info}",
                info, context, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC012: Tag characters
# ---------------------------------------------------------------------------

def check_tag_chars(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        if is_tag_character(ord(ch)):
            info = char_info(ch)
            findings.append(_finding(
                "USC012", file, line_num, col,
                f"Tag character {info} (Glassworm-style payload encoding)",
                info, context, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC013: Deprecated format characters
# ---------------------------------------------------------------------------

def check_deprecated_format(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if (0x206A <= cp <= 0x206F) or (0xFFF0 <= cp <= 0xFFF8):
            info = char_info(ch)
            findings.append(_finding(
                "USC013", file, line_num, col,
                f"Deprecated format character {info}",
                info, context, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC014: Interlinear annotation anchors
# ---------------------------------------------------------------------------

def check_annotation_anchors(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if 0xFFF9 <= cp <= 0xFFFB:
            info = char_info(ch)
            findings.append(_finding(
                "USC014", file, line_num, col,
                f"Interlinear annotation anchor {info}",
                info, context, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC015: Bidi pairing validation
# ---------------------------------------------------------------------------

def check_bidi_pairing(
    line_text: str, line_num: int, file: str,
    policy: Policy,
) -> List[Finding]:
    """Validate that bidi embedding/override/isolate controls are properly paired."""
    embed_stack = 0
    isolate_stack = 0

    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if cp in BIDI_OPENERS:
            embed_stack += 1
        elif cp == BIDI_CLOSER_PDF:
            embed_stack -= 1
        elif cp in BIDI_ISOLATE_OPENERS:
            isolate_stack += 1
        elif cp == BIDI_ISOLATE_CLOSER:
            isolate_stack -= 1

    findings = []
    if embed_stack != 0:
        info = f"embedding depth imbalance: {embed_stack}"
        findings.append(_finding(
            "USC015", file, line_num, 0,
            f"Unbalanced bidi embedding/override controls ({info})",
            info, Context.OTHER, line_text[:80], policy,
        ))
    if isolate_stack != 0:
        info = f"isolate depth imbalance: {isolate_stack}"
        findings.append(_finding(
            "USC015", file, line_num, 0,
            f"Unbalanced bidi isolate controls ({info})",
            info, Context.OTHER, line_text[:80], policy,
        ))
    return findings


# ---------------------------------------------------------------------------
# USC016: Default-ignorable code points (outside known categories)
# ---------------------------------------------------------------------------

def check_default_ignorable(
    line_text: str, line_num: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    findings = []
    for col, ch in enumerate(line_text):
        cp = ord(ch)
        if is_default_ignorable(cp):
            # Skip characters already caught by more specific rules
            if (cp in BIDI_CONTROLS or cp in INVISIBLE_FORMAT_CHARS
                    or is_variation_selector(cp) or is_tag_character(cp)
                    or cp == 0xFEFF):
                continue
            if policy.is_allowed(file, cp, context):
                continue
            info = char_info(ch)
            findings.append(_finding(
                "USC016", file, line_num, col,
                f"Default-ignorable code point {info} in {context.value}",
                info, context, _snippet(line_text, col), policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC017: Homoglyph detection (single character level)
# ---------------------------------------------------------------------------

def check_homoglyphs(
    token_text: str, line_num: int, col: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    """Flag individual characters that are confusable with ASCII letters."""
    if context == Context.STRING:
        return []  # Too noisy in strings

    findings = []
    for i, ch in enumerate(token_text):
        cp = ord(ch)
        if cp in CONFUSABLES and not (0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A):
            info = char_info(ch)
            latin_equiv = CONFUSABLES[cp]
            findings.append(_finding(
                "USC017", file, line_num, col + i,
                f"Homoglyph {info} looks like Latin '{latin_equiv}' in {context.value}",
                info, context, token_text, policy,
            ))
    return findings


# ---------------------------------------------------------------------------
# USC018: Mixed line endings
# ---------------------------------------------------------------------------

def check_mixed_line_endings(content: str, file: str) -> List[Finding]:
    """Check for mixed line ending styles in a file."""
    has_crlf = "\r\n" in content
    # Check for lone CR (old Mac style) or lone LF mixed with CRLF
    has_lone_cr = False
    has_lone_lf = False

    i = 0
    while i < len(content):
        if content[i] == '\r':
            if i + 1 < len(content) and content[i + 1] == '\n':
                i += 2  # CRLF
                continue
            else:
                has_lone_cr = True
                i += 1
        elif content[i] == '\n':
            has_lone_lf = True
            i += 1
        else:
            i += 1

    mixed = sum([has_crlf, has_lone_cr, has_lone_lf]) > 1
    if mixed:
        styles = []
        if has_crlf:
            styles.append("CRLF")
        if has_lone_lf:
            styles.append("LF")
        if has_lone_cr:
            styles.append("CR")
        info = f"mixed: {', '.join(styles)}"
        return [Finding(
            "USC018", "mixed-line-endings", Severity.MEDIUM, file,
            1, 0, f"Mixed line endings detected: {info}",
            info, Context.OTHER, "",
        )]
    return []


# ---------------------------------------------------------------------------
# USC019: Non-ASCII identifier policy violation
# ---------------------------------------------------------------------------

def check_non_ascii_identifier(
    token_text: str, line_num: int, col: int, file: str,
    context: Context, policy: Policy,
) -> List[Finding]:
    if context != Context.IDENTIFIER:
        return []
    if policy.identifier_policy == "ascii-only":
        for i, ch in enumerate(token_text):
            if ord(ch) > 0x7F:
                info = char_info(ch)
                return [_finding(
                    "USC019", file, line_num, col + i,
                    f"Non-ASCII character {info} in identifier '{token_text}' "
                    f"(policy: ascii-only)",
                    info, context, token_text, policy,
                )]
    elif policy.identifier_policy == "permitted-scripts":
        for ch in token_text:
            s = get_script(ch)
            if s not in policy.permitted_scripts and s not in ("Common", "Inherited"):
                info = f"script {s} not in permitted set"
                return [_finding(
                    "USC019", file, line_num, col,
                    f"Identifier '{token_text}' uses script '{s}' "
                    f"not in permitted set: {policy.permitted_scripts}",
                    info, context, token_text, policy,
                )]
    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snippet(line_text: str, col: int, width: int = 40) -> str:
    """Extract a snippet around a column position."""
    start = max(0, col - width // 2)
    end = min(len(line_text), col + width // 2)
    s = line_text[start:end].rstrip('\n').rstrip('\r')
    if start > 0:
        s = "..." + s
    if end < len(line_text):
        s = s + "..."
    return s
