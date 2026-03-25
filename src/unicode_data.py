"""Unicode character data: scripts, confusables, character classification."""

import unicodedata

# ---------------------------------------------------------------------------
# Script detection (covers attack-relevant scripts)
# ---------------------------------------------------------------------------

_SCRIPT_RANGES = [
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
    (0x0900, 0x097F, "Devanagari"),
    (0x0980, 0x09FF, "Bengali"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x4E00, 0x9FFF, "Han"), (0x3400, 0x4DBF, "Han"),
    (0xAC00, 0xD7AF, "Hangul"),
]

# Build a sorted list for binary search
_SCRIPT_RANGES.sort(key=lambda x: x[0])


def get_script(char: str) -> str:
    """Return the script name for a character."""
    cp = ord(char)

    # Common: digits, punctuation, symbols
    cat = unicodedata.category(char)
    if cat.startswith('N') or cat.startswith('P') or cat.startswith('S') or cat.startswith('Z'):
        return "Common"
    if cat.startswith('M'):
        return "Inherited"

    # Binary search through ranges
    lo, hi = 0, len(_SCRIPT_RANGES) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, script = _SCRIPT_RANGES[mid]
        if cp < start:
            hi = mid - 1
        elif cp > end:
            lo = mid + 1
        else:
            return script

    return "Unknown"


# ---------------------------------------------------------------------------
# Confusable skeleton mapping (Unicode TR39)
# Maps code points to their Latin "skeleton" equivalents.
# Two strings are confusable if skeleton(a) == skeleton(b).
# ---------------------------------------------------------------------------

CONFUSABLES = {
    # Cyrillic -> Latin
    0x0410: "A", 0x0430: "a",   # U+0410/U+0430
    0x0412: "B",                  # U+0412
    0x0421: "C", 0x0441: "c",   # U+0421/U+0441
    0x0415: "E", 0x0435: "e",   # U+0415/U+0435
    0x041D: "H",                  # U+041D
    0x041A: "K",                  # U+041A
    0x041C: "M",                  # U+041C
    0x041E: "O", 0x043E: "o",   # U+041E/U+043E
    0x0420: "P", 0x0440: "p",   # U+0420/U+0440
    0x0422: "T",                  # U+0422
    0x0425: "X", 0x0445: "x",   # U+0425/U+0445
    0x0423: "Y", 0x0443: "y",   # U+0423/U+0443 (visual similarity)
    0x0405: "S", 0x0455: "s",   # U+0405/U+0455
    0x0406: "I", 0x0456: "i",   # U+0406/U+0456
    0x0408: "J", 0x0458: "j",   # U+0408/U+0458
    0x042C: "b", 0x044C: "b",   # U+042C/U+044C (soft sign, looks like b)
    0x040C: "K",                  # U+040C
    0x0401: "E",                  # U+0401 (looks like E with diaeresis)
    0x04AE: "Y", 0x04AF: "y",   # U+04AE/U+04AF
    0x04BA: "h", 0x04BB: "h",   # U+04BA/U+04BB
    0x04C0: "I",                  # U+04C0 (palochka)

    # Greek -> Latin
    0x0391: "A", 0x03B1: "a",   # U+0391/U+03B1 (alpha, close to a)
    0x0392: "B", 0x03B2: "B",   # U+0392/U+03B2
    0x0395: "E", 0x03B5: "e",   # U+0395/U+03B5
    0x0396: "Z",                  # U+0396
    0x0397: "H", 0x03B7: "n",   # U+0397/U+03B7
    0x0399: "I", 0x03B9: "i",   # U+0399/U+03B9
    0x039A: "K", 0x03BA: "k",   # U+039A/U+03BA
    0x039C: "M",                  # U+039C
    0x039D: "N", 0x03BD: "v",   # U+039D/U+03BD
    0x039F: "O", 0x03BF: "o",   # U+039F/U+03BF
    0x03A1: "P", 0x03C1: "p",   # U+03A1/U+03C1
    0x03A4: "T", 0x03C4: "t",   # U+03A4/U+03C4
    0x03A5: "Y", 0x03C5: "u",   # U+03A5/U+03C5
    0x03A7: "X", 0x03C7: "x",   # U+03A7/U+03C7
    0x03C9: "w",                  # U+03C9

    # Armenian -> Latin
    0x0555: "O", 0x0585: "o",   # U+0555/U+0585
    0x054D: "S", 0x057D: "s",   # U+054D/U+057D
    0x054C: "L",                  # U+054C
    0x0570: "h",                  # U+0570
    0x0578: "n",                  # U+0578
    0x057C: "n",                  # U+057C
    0x0566: "q",                  # U+0566 (visual similarity)

    # Mathematical/symbol confusables
    0x2126: "O",                  # U+2126 (ohm sign -> O in some fonts)
    0x212A: "K",                  # K (kelvin sign)
    0x212B: "A",                  # U+212B (angstrom)
    0x2160: "I",                  # U+2160 (roman numeral one)
    0x2164: "V",                  # U+2164
    0x2169: "X",                  # U+2169
    0x216C: "L",                  # U+216C
    0x216D: "C",                  # U+216D
    0x216E: "D",                  # U+216E
    0x216F: "M",                  # U+216F
    0xFF21: "A", 0xFF41: "a",   # U+FF21/U+FF41 (fullwidth)
    0xFF22: "B", 0xFF42: "b",
    0xFF23: "C", 0xFF43: "c",
    0xFF24: "D", 0xFF44: "d",
    0xFF25: "E", 0xFF45: "e",
    0xFF26: "F", 0xFF46: "f",
    0xFF27: "G", 0xFF47: "g",
    0xFF28: "H", 0xFF48: "h",
    0xFF29: "I", 0xFF49: "i",
    0xFF2A: "J", 0xFF4A: "j",
    0xFF2B: "K", 0xFF4B: "k",
    0xFF2C: "L", 0xFF4C: "l",
    0xFF2D: "M", 0xFF4D: "m",
    0xFF2E: "N", 0xFF4E: "n",
    0xFF2F: "O", 0xFF4F: "o",
    0xFF30: "P", 0xFF50: "p",
    0xFF31: "Q", 0xFF51: "q",
    0xFF32: "R", 0xFF52: "r",
    0xFF33: "S", 0xFF53: "s",
    0xFF34: "T", 0xFF54: "t",
    0xFF35: "U", 0xFF55: "u",
    0xFF36: "V", 0xFF56: "v",
    0xFF37: "W", 0xFF57: "w",
    0xFF38: "X", 0xFF58: "x",
    0xFF39: "Y", 0xFF59: "y",
    0xFF3A: "Z", 0xFF5A: "z",

    # Latin-like from other blocks
    0x0251: "a",   # U+0251 (Latin small alpha)
    0x0261: "g",   # U+0261 (Latin small script g)
    0x026A: "i",   # U+026A (Latin small capital I)
    0x1D00: "a",   # U+1D00 (Latin letter small capital A)
}


def skeleton(s: str) -> str:
    """Compute the confusable skeleton of a string per UTS#39."""
    s = unicodedata.normalize("NFD", s)
    result = []
    for ch in s:
        cp = ord(ch)
        if cp in CONFUSABLES:
            result.append(CONFUSABLES[cp])
        else:
            result.append(ch)
    return unicodedata.normalize("NFD", "".join(result))


# ---------------------------------------------------------------------------
# Character classification sets
# ---------------------------------------------------------------------------

# Bidirectional control characters (Trojan Source primitives)
BIDI_CONTROLS = {
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0x061C,  # ARABIC LETTER MARK
}

# Bidi controls that must be paired
BIDI_OPENERS = {0x202A, 0x202B, 0x202D, 0x202E}  # embeddings/overrides
BIDI_CLOSER_PDF = 0x202C  # POP DIRECTIONAL FORMATTING
BIDI_ISOLATE_OPENERS = {0x2066, 0x2067, 0x2068}
BIDI_ISOLATE_CLOSER = 0x2069  # POP DIRECTIONAL ISOLATE

# Invisible formatting characters (zero-width, etc.)
INVISIBLE_FORMAT_CHARS = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x00AD: "SOFT HYPHEN",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",  # BOM when not at position 0
}

# Suspicious spacing characters (not normal space/tab)
SUSPICIOUS_SPACES = {
    0x00A0: "NO-BREAK SPACE",
    0x1680: "OGHAM SPACE MARK",
    0x2000: "EN QUAD",
    0x2001: "EM QUAD",
    0x2002: "EN SPACE",
    0x2003: "EM SPACE",
    0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE",
    0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE",
    0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE",
    0x200A: "HAIR SPACE",
    0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE",
    0x3000: "IDEOGRAPHIC SPACE",
}

# Default-ignorable code points (render as nothing in most contexts)
DEFAULT_IGNORABLE_RANGES = [
    (0x00AD, 0x00AD),    # SOFT HYPHEN
    (0x034F, 0x034F),    # COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),    # ARABIC LETTER MARK
    (0x115F, 0x1160),    # HANGUL CHO/JUNGSEONG FILLER
    (0x17B4, 0x17B5),    # KHMER VOWEL INHERENT
    (0x180B, 0x180F),    # MONGOLIAN FREE VARIATION SELECTORS
    (0x200B, 0x200F),    # ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),    # BIDI CONTROLS
    (0x2060, 0x206F),    # WORD JOINER .. NOMINAL DIGIT SHAPES
    (0x3164, 0x3164),    # HANGUL FILLER
    (0xFE00, 0xFE0F),    # VARIATION SELECTORS
    (0xFEFF, 0xFEFF),    # ZERO WIDTH NO-BREAK SPACE
    (0xFFA0, 0xFFA0),    # HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),    # SPECIALS
    (0x1BCA0, 0x1BCA3),  # SHORTHAND FORMAT CONTROLS
    (0x1D173, 0x1D17A),  # MUSICAL SYMBOL FORMATTING
    (0xE0000, 0xE0FFF),  # TAGS + VARIATION SELECTORS SUPPLEMENT
]

# Variation selector ranges
VARIATION_SELECTOR_RANGES = [
    (0xFE00, 0xFE0F),      # Variation Selectors
    (0xE0100, 0xE01EF),    # Variation Selectors Supplement
]

# Tag character range (Glassworm payload encoding)
TAG_RANGE = (0xE0001, 0xE007F)

# Private Use Area ranges
PUA_RANGES = [
    (0xE000, 0xF8FF),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
]


def is_default_ignorable(cp: int) -> bool:
    """Check if a code point is default-ignorable."""
    for start, end in DEFAULT_IGNORABLE_RANGES:
        if start <= cp <= end:
            return True
    return False


def is_variation_selector(cp: int) -> bool:
    """Check if a code point is a variation selector."""
    for start, end in VARIATION_SELECTOR_RANGES:
        if start <= cp <= end:
            return True
    return False


def is_tag_character(cp: int) -> bool:
    """Check if a code point is a tag character."""
    return TAG_RANGE[0] <= cp <= TAG_RANGE[1]


def is_pua(cp: int) -> bool:
    """Check if a code point is in the Private Use Area."""
    for start, end in PUA_RANGES:
        if start <= cp <= end:
            return True
    return False


def char_info(char: str) -> str:
    """Return a diagnostic string like 'U+202E RIGHT-TO-LEFT OVERRIDE'."""
    cp = ord(char)
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = f"<unnamed U+{cp:04X}>"
    return f"U+{cp:04X} {name}"


def is_ascii_letter(char: str) -> bool:
    """Check if a character is an ASCII letter."""
    cp = ord(char)
    return (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A)
