"""Detection rules -- single-pass character classification + token-level checks."""
import unicodedata

from models import Context, Finding, Severity, RULES
from unicode_data import (
    BIDI_CONTROLS, BIDI_OPENERS, BIDI_CLOSER_PDF,
    BIDI_ISOLATE_OPENERS, BIDI_ISOLATE_CLOSER,
    CONFUSABLES, char_info, classify_char, get_script, skeleton,
)
from config import Policy

_RULE_CACHE = {}

def _sev(rule_id, policy):
    name, _, default = RULES[rule_id]
    if policy and name in policy.severity_overrides:
        return policy.severity_overrides[name]
    return default


def _finding(rule_id, file, line, col, msg, info, ctx, snip, policy=None):
    name = RULES[rule_id][0]
    return Finding(rule_id, name, _sev(rule_id, policy), file, line, col, msg, info, ctx, snip)


def _snippet(text, col, w=40):
    s = max(0, col - w // 2)
    e = min(len(text), col + w // 2)
    r = text[s:e].rstrip('\r\n')
    if s > 0: r = "..." + r
    if e < len(text): r = r + "..."
    return r


def scan_line_chars(line, line_num, file, ctx, policy, is_critical_only, findings):
    """Single-pass character scan. Appends findings in-place."""
    vs_count = 0
    embed_depth = 0
    isolate_depth = 0

    for col, ch in enumerate(line):
        cp = ord(ch)

        # Bidi pairing tracking (always)
        if cp in BIDI_OPENERS:
            embed_depth += 1
        elif cp == BIDI_CLOSER_PDF:
            embed_depth -= 1
        elif cp in BIDI_ISOLATE_OPENERS:
            isolate_depth += 1
        elif cp == BIDI_ISOLATE_CLOSER:
            isolate_depth -= 1

        # BOM check
        if cp == 0xFEFF:
            if not (line_num == 1 and col == 0):
                findings.append(_finding(
                    "USC009", file, line_num, col,
                    "Misplaced byte-order mark", char_info(ch),
                    Context.OTHER, _snippet(line, col), policy))
            continue

        rule_id, is_vs = classify_char(cp)
        if is_vs:
            vs_count += 1
            continue

        if rule_id is None:
            continue

        # Critical rules always run; non-critical only on changed lines
        is_critical = rule_id in ("USC001", "USC011", "USC012")
        if is_critical_only and not is_critical:
            continue

        if policy.is_allowed(file, cp, ctx):
            continue

        info = char_info(ch)
        findings.append(_finding(
            rule_id, file, line_num, col,
            f"{RULES[rule_id][1]} {info} in {ctx.value}",
            info, ctx, _snippet(line, col), policy))

    # Variation selector density
    if vs_count >= 3 and not is_critical_only:
        findings.append(_finding(
            "USC010", file, line_num, 0,
            f"{vs_count} variation selectors on one line",
            f"{vs_count} variation selectors", ctx, line[:80], policy))

    # Bidi pairing
    if embed_depth != 0:
        findings.append(_finding(
            "USC015", file, line_num, 0,
            f"Unbalanced bidi embedding/override controls (depth: {embed_depth})",
            f"embed imbalance: {embed_depth}", Context.OTHER, line[:80], policy))
    if isolate_depth != 0:
        findings.append(_finding(
            "USC015", file, line_num, 0,
            f"Unbalanced bidi isolate controls (depth: {isolate_depth})",
            f"isolate imbalance: {isolate_depth}", Context.OTHER, line[:80], policy))


class ConfusableTracker:
    __slots__ = ('seen',)
    def __init__(self):
        self.seen = {}

    def check(self, text, line, col, file, ctx, policy, findings):
        if ctx != Context.IDENTIFIER:
            return
        skel = skeleton(text)
        prev = self.seen.get(skel)
        if prev is not None:
            orig_text, orig_line, orig_col = prev
            if orig_text != text:
                findings.append(_finding(
                    "USC004", file, line, col,
                    f"'{text}' has same skeleton as '{orig_text}' (line {orig_line}:{orig_col})",
                    f"confusable with '{orig_text}'", ctx, text, policy))
        else:
            self.seen[skel] = (text, line, col)


def check_token(tok, file, policy, findings):
    """Run token-level checks: mixed-script, homoglyph, normalization, non-ASCII."""
    text, ctx, line, col = tok

    if ctx == Context.IDENTIFIER:
        # Mixed-script
        scripts = set()
        for ch in text:
            s = get_script(ch)
            if s not in ("Common", "Inherited", "Unknown"):
                scripts.add(s)
        if len(scripts) > 1:
            if policy.context_action("mixed-script", ctx) != "ignore":
                info = ", ".join(sorted(scripts))
                findings.append(_finding(
                    "USC003", file, line, col,
                    f"Mixed-script identifier '{text}' ({info})",
                    f"scripts: {info}", ctx, text, policy))

        # Non-ASCII identifier policy
        if policy.identifier_policy == "ascii-only":
            for i, ch in enumerate(text):
                if ord(ch) > 0x7F:
                    findings.append(_finding(
                        "USC019", file, line, col + i,
                        f"Non-ASCII {char_info(ch)} in identifier '{text}' (policy: ascii-only)",
                        char_info(ch), ctx, text, policy))
                    break
        elif policy.identifier_policy == "permitted-scripts":
            for ch in text:
                s = get_script(ch)
                if s not in policy.permitted_scripts and s not in ("Common", "Inherited"):
                    findings.append(_finding(
                        "USC019", file, line, col,
                        f"Identifier '{text}' uses script '{s}' not in permitted set",
                        f"script {s}", ctx, text, policy))
                    break

    # Homoglyphs (skip strings)
    if ctx != Context.STRING:
        for i, ch in enumerate(text):
            cp = ord(ch)
            if cp in CONFUSABLES and not (0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A):
                findings.append(_finding(
                    "USC017", file, line, col + i,
                    f"Homoglyph {char_info(ch)} looks like '{CONFUSABLES[cp]}' in {ctx.value}",
                    char_info(ch), ctx, text, policy))

    # Normalization drift
    nfc = unicodedata.normalize("NFC", text)
    if nfc != text:
        nfkc = unicodedata.normalize("NFKC", text)
        info = f"NFC: '{nfc}'" + (f", NFKC: '{nfkc}'" if nfkc != nfc else "")
        findings.append(_finding(
            "USC006", file, line, col,
            f"'{text}' changes under NFC ({info})",
            info, ctx, text, policy))


def check_encoding(raw, file):
    try:
        raw.decode("utf-8")
        return None
    except UnicodeDecodeError as e:
        info = f"byte {e.start}: {e.reason}"
        return Finding("USC008", "invalid-encoding", Severity.CRITICAL, file,
                       1, 0, f"Not valid UTF-8: {info}", info, Context.OTHER, "")


def check_mixed_line_endings(content, file):
    has_crlf = "\r\n" in content
    has_cr = has_lf = False
    i = 0
    while i < len(content):
        if content[i] == '\r':
            if i + 1 < len(content) and content[i + 1] == '\n':
                i += 2
            else:
                has_cr = True; i += 1
        elif content[i] == '\n':
            has_lf = True; i += 1
        else:
            i += 1
    if sum([has_crlf, has_cr, has_lf]) > 1:
        styles = [s for s, v in [("CRLF", has_crlf), ("LF", has_lf), ("CR", has_cr)] if v]
        return Finding("USC018", "mixed-line-endings", Severity.MEDIUM, file,
                       1, 0, f"Mixed line endings: {', '.join(styles)}",
                       f"mixed: {', '.join(styles)}", Context.OTHER, "")
    return None
