"""Unicode character data: scripts, confusables, classification."""
import unicodedata

_SCRIPT_RANGES = sorted([
    (0x0041, 0x005A, "Latin"), (0x0061, 0x007A, "Latin"),
    (0x00C0, 0x00D6, "Latin"), (0x00D8, 0x00F6, "Latin"),
    (0x00F8, 0x024F, "Latin"), (0x0250, 0x02AF, "Latin"),
    (0x1D00, 0x1D7F, "Latin"), (0x1D80, 0x1DBF, "Latin"),
    (0x1E00, 0x1EFF, "Latin"), (0x2C60, 0x2C7F, "Latin"),
    (0xA720, 0xA7FF, "Latin"), (0xAB30, 0xAB6F, "Latin"),
    (0xFB00, 0xFB06, "Latin"),
    (0x0370, 0x0377, "Greek"), (0x037A, 0x037F, "Greek"),
    (0x0384, 0x038A, "Greek"), (0x038C, 0x038C, "Greek"),
    (0x038E, 0x03A1, "Greek"), (0x03A3, 0x03FF, "Greek"),
    (0x1F00, 0x1FFF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"), (0x0500, 0x052F, "Cyrillic"),
    (0x2DE0, 0x2DFF, "Cyrillic"), (0xA640, 0xA69F, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"), (0xFB13, 0xFB17, "Armenian"),
    (0x10A0, 0x10FF, "Georgian"),
    (0x0600, 0x06FF, "Arabic"), (0x0750, 0x077F, "Arabic"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0900, 0x097F, "Devanagari"), (0x0980, 0x09FF, "Bengali"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x3040, 0x309F, "Hiragana"), (0x30A0, 0x30FF, "Katakana"),
    (0x4E00, 0x9FFF, "Han"), (0x3400, 0x4DBF, "Han"),
    (0xAC00, 0xD7AF, "Hangul"),
], key=lambda x: x[0])

_SCRIPT_STARTS = [r[0] for r in _SCRIPT_RANGES]


def get_script(char):
    cp = ord(char)
    cat = unicodedata.category(char)
    if cat[0] in 'NPSZ':
        return "Common"
    if cat[0] == 'M':
        return "Inherited"
    import bisect
    i = bisect.bisect_right(_SCRIPT_STARTS, cp) - 1
    if i >= 0:
        s, e, name = _SCRIPT_RANGES[i]
        if s <= cp <= e:
            return name
    return "Unknown"


CONFUSABLES = {
    0x0410: "A", 0x0430: "a", 0x0412: "B",
    0x0421: "C", 0x0441: "c", 0x0415: "E", 0x0435: "e",
    0x041D: "H", 0x041A: "K", 0x041C: "M",
    0x041E: "O", 0x043E: "o", 0x0420: "P", 0x0440: "p",
    0x0422: "T", 0x0425: "X", 0x0445: "x",
    0x0423: "Y", 0x0443: "y", 0x0405: "S", 0x0455: "s",
    0x0406: "I", 0x0456: "i", 0x0408: "J", 0x0458: "j",
    0x042C: "b", 0x044C: "b", 0x040C: "K", 0x0401: "E",
    0x04AE: "Y", 0x04AF: "y", 0x04BA: "h", 0x04BB: "h", 0x04C0: "I",
    0x0391: "A", 0x03B1: "a", 0x0392: "B", 0x03B2: "B",
    0x0395: "E", 0x03B5: "e", 0x0396: "Z",
    0x0397: "H", 0x03B7: "n", 0x0399: "I", 0x03B9: "i",
    0x039A: "K", 0x03BA: "k", 0x039C: "M",
    0x039D: "N", 0x03BD: "v", 0x039F: "O", 0x03BF: "o",
    0x03A1: "P", 0x03C1: "p", 0x03A4: "T", 0x03C4: "t",
    0x03A5: "Y", 0x03C5: "u", 0x03A7: "X", 0x03C7: "x", 0x03C9: "w",
    0x0555: "O", 0x0585: "o", 0x054D: "S", 0x057D: "s",
    0x054C: "L", 0x0570: "h", 0x0578: "n", 0x057C: "n", 0x0566: "q",
    0x2126: "O", 0x212A: "K", 0x212B: "A",
    0x2160: "I", 0x2164: "V", 0x2169: "X",
    0x216C: "L", 0x216D: "C", 0x216E: "D", 0x216F: "M",
    **{0xFF21 + i: chr(0x41 + i) for i in range(26)},
    **{0xFF41 + i: chr(0x61 + i) for i in range(26)},
    0x0251: "a", 0x0261: "g", 0x026A: "i", 0x1D00: "a",
}


def skeleton(s):
    s = unicodedata.normalize("NFD", s)
    return unicodedata.normalize("NFD",
        "".join(CONFUSABLES.get(ord(c), c) for c in s))


BIDI_CONTROLS = frozenset({
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C,
})
BIDI_OPENERS = frozenset({0x202A, 0x202B, 0x202D, 0x202E})
BIDI_CLOSER_PDF = 0x202C
BIDI_ISOLATE_OPENERS = frozenset({0x2066, 0x2067, 0x2068})
BIDI_ISOLATE_CLOSER = 0x2069

INVISIBLE_FORMAT_CHARS = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0x180E, 0x00AD, 0xFEFF})

SUSPICIOUS_SPACES = frozenset({
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
    0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x202F, 0x205F, 0x3000,
})

_ALLOWED_CONTROLS = frozenset({0x09, 0x0A, 0x0D})

# Pre-built lookup: cp -> rule_id for O(1) character classification.
# Range-based checks (PUA, tags, etc.) handled inline.
_CHAR_RULE_MAP = {}
for _cp in BIDI_CONTROLS:
    _CHAR_RULE_MAP[_cp] = "USC001"
for _cp in INVISIBLE_FORMAT_CHARS:
    _CHAR_RULE_MAP.setdefault(_cp, "USC002")
for _cp in SUSPICIOUS_SPACES:
    _CHAR_RULE_MAP.setdefault(_cp, "USC005")


def classify_char(cp):
    """Return (rule_id, is_vs) for a suspicious code point, or (None, False)."""
    r = _CHAR_RULE_MAP.get(cp)
    if r:
        return r, False
    cat = unicodedata.category(chr(cp)) if cp < 0x110000 else "Cn"
    if cat == "Cc" and cp not in _ALLOWED_CONTROLS:
        return "USC007", False
    if 0x206A <= cp <= 0x206F or 0xFFF0 <= cp <= 0xFFF8:
        return "USC013", False
    if 0xFFF9 <= cp <= 0xFFFB:
        return "USC014", False
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return None, True
    if 0xE0001 <= cp <= 0xE007F:
        return "USC012", False
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD:
        return "USC011", False
    # Default-ignorable catch-all (ranges not covered by specific rules above)
    if _is_default_ignorable(cp) and cp not in BIDI_CONTROLS and cp not in INVISIBLE_FORMAT_CHARS and cp != 0xFEFF:
        return "USC016", False
    return None, False


_DEFAULT_IGNORABLE_RANGES = [
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C),
    (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
    (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
]


def _is_default_ignorable(cp):
    for s, e in _DEFAULT_IGNORABLE_RANGES:
        if s <= cp <= e:
            return True
    return False


def char_info(char):
    cp = ord(char)
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = f"<unnamed U+{cp:04X}>"
    return f"U+{cp:04X} {name}"
