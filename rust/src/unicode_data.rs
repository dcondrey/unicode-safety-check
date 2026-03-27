//! Unicode character data: scripts, confusables, classification.

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Script ranges (sorted by start codepoint)
// ---------------------------------------------------------------------------

/// Sorted array of (start, end, script_name) for script identification.
pub const SCRIPT_RANGES: &[(u32, u32, &str)] = &[
    // Sorted by start codepoint (required for binary search)
    (0x0041, 0x005A, "Latin"),
    (0x0061, 0x007A, "Latin"),
    (0x00C0, 0x00D6, "Latin"),
    (0x00D8, 0x00F6, "Latin"),
    (0x00F8, 0x024F, "Latin"),
    (0x0250, 0x02AF, "Latin"),
    (0x0370, 0x0377, "Greek"),
    (0x037A, 0x037F, "Greek"),
    (0x0384, 0x038A, "Greek"),
    (0x038C, 0x038C, "Greek"),
    (0x038E, 0x03A1, "Greek"),
    (0x03A3, 0x03FF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0500, 0x052F, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0700, 0x074F, "Syriac"),
    (0x0750, 0x077F, "Arabic"),
    (0x0780, 0x07BF, "Thaana"),
    (0x0870, 0x089F, "Arabic"),
    (0x08A0, 0x08FF, "Arabic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x0980, 0x09FF, "Bengali"),
    (0x0A00, 0x0A7F, "Gurmukhi"),
    (0x0A80, 0x0AFF, "Gujarati"),
    (0x0B00, 0x0B7F, "Oriya"),
    (0x0B80, 0x0BFF, "Tamil"),
    (0x0C00, 0x0C7F, "Telugu"),
    (0x0C80, 0x0CFF, "Kannada"),
    (0x0D00, 0x0D7F, "Malayalam"),
    (0x0D80, 0x0DFF, "Sinhala"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x0E80, 0x0EFF, "Lao"),
    (0x0F00, 0x0FFF, "Tibetan"),
    (0x1000, 0x109F, "Myanmar"),
    (0x10A0, 0x10FF, "Georgian"),
    (0x1100, 0x11FF, "Hangul"),
    (0x1200, 0x137F, "Ethiopic"),
    (0x1380, 0x139F, "Ethiopic"),
    (0x13A0, 0x13FF, "Cherokee"),
    (0x1400, 0x167F, "Canadian_Aboriginal"),
    (0x1780, 0x17FF, "Khmer"),
    (0x19E0, 0x19FF, "Khmer"),
    (0x1D00, 0x1D7F, "Latin"),
    (0x1D80, 0x1DBF, "Latin"),
    (0x1E00, 0x1EFF, "Latin"),
    (0x1F00, 0x1FFF, "Greek"),
    (0x2C60, 0x2C7F, "Latin"),
    (0x2D00, 0x2D2F, "Georgian"),
    (0x2D80, 0x2DDF, "Ethiopic"),
    (0x2DE0, 0x2DFF, "Cyrillic"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x3130, 0x318F, "Hangul"),
    (0x31F0, 0x31FF, "Katakana"),
    (0x3400, 0x4DBF, "Han"),
    (0x4E00, 0x9FFF, "Han"),
    (0xA640, 0xA69F, "Cyrillic"),
    (0xA720, 0xA7FF, "Latin"),
    (0xA8E0, 0xA8FF, "Devanagari"),
    (0xAB30, 0xAB6F, "Latin"),
    (0xAB70, 0xABBF, "Cherokee"),
    (0xAC00, 0xD7AF, "Hangul"),
    (0xF900, 0xFAFF, "Han"),
    (0xFB00, 0xFB06, "Latin"),
    (0xFB13, 0xFB17, "Armenian"),
    (0xFB1D, 0xFB4F, "Hebrew"),
    (0xFB50, 0xFDFF, "Arabic"),
    (0xFE70, 0xFEFF, "Arabic"),
    (0x20000, 0x2A6DF, "Han"),
];

/// Determine the script of a character.
///
/// Returns "Common" for numbers, punctuation, symbols, and separators.
/// Returns "Inherited" for marks. Otherwise binary-searches `SCRIPT_RANGES`.
pub fn get_script(ch: char) -> &'static str {
    let cat = get_general_category(ch);
    match cat {
        GeneralCategory::DecimalNumber
        | GeneralCategory::LetterNumber
        | GeneralCategory::OtherNumber
        | GeneralCategory::ConnectorPunctuation
        | GeneralCategory::DashPunctuation
        | GeneralCategory::OpenPunctuation
        | GeneralCategory::ClosePunctuation
        | GeneralCategory::InitialPunctuation
        | GeneralCategory::FinalPunctuation
        | GeneralCategory::OtherPunctuation
        | GeneralCategory::MathSymbol
        | GeneralCategory::CurrencySymbol
        | GeneralCategory::ModifierSymbol
        | GeneralCategory::OtherSymbol
        | GeneralCategory::SpaceSeparator
        | GeneralCategory::LineSeparator
        | GeneralCategory::ParagraphSeparator => return "Common",
        GeneralCategory::NonspacingMark
        | GeneralCategory::SpacingMark
        | GeneralCategory::EnclosingMark => return "Inherited",
        _ => {}
    }
    let cp = ch as u32;
    // Binary search: find rightmost range whose start <= cp
    let mut lo: usize = 0;
    let mut hi: usize = SCRIPT_RANGES.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if SCRIPT_RANGES[mid].0 <= cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo > 0 {
        let (s, e, name) = SCRIPT_RANGES[lo - 1];
        if cp >= s && cp <= e {
            return name;
        }
    }
    "Unknown"
}

// ---------------------------------------------------------------------------
// Confusables (sorted by codepoint)
// ---------------------------------------------------------------------------

/// Sorted array of (codepoint, target_ascii_char) for confusable detection.
pub const CONFUSABLES: &[(u32, char)] = &[
    // IPA
    (0x0251, 'a'),
    (0x0261, 'g'),
    (0x026A, 'i'),
    // Greek lowercase/uppercase
    (0x0391, 'A'),
    (0x0392, 'B'),
    (0x0395, 'E'),
    (0x0396, 'Z'),
    (0x0397, 'H'),
    (0x0399, 'I'),
    (0x039A, 'K'),
    (0x039C, 'M'),
    (0x039D, 'N'),
    (0x039F, 'O'),
    (0x03A1, 'P'),
    (0x03A4, 'T'),
    (0x03A5, 'Y'),
    (0x03A7, 'X'),
    (0x03B1, 'a'),
    (0x03B2, 'B'),
    (0x03B5, 'e'),
    (0x03B7, 'n'),
    (0x03B9, 'i'),
    (0x03BA, 'k'),
    (0x03BD, 'v'),
    (0x03BF, 'o'),
    (0x03C1, 'p'),
    (0x03C4, 't'),
    (0x03C5, 'u'),
    (0x03C7, 'x'),
    (0x03C9, 'w'),
    // Cyrillic
    (0x0401, 'E'),
    (0x0405, 'S'),
    (0x0406, 'I'),
    (0x0408, 'J'),
    (0x040C, 'K'),
    (0x0410, 'A'),
    (0x0412, 'B'),
    (0x0415, 'E'),
    (0x041A, 'K'),
    (0x041C, 'M'),
    (0x041D, 'H'),
    (0x041E, 'O'),
    (0x0420, 'P'),
    (0x0421, 'C'),
    (0x0422, 'T'),
    (0x0423, 'Y'),
    (0x0425, 'X'),
    (0x042C, 'b'),
    (0x0430, 'a'),
    (0x0435, 'e'),
    (0x043E, 'o'),
    (0x0440, 'p'),
    (0x0441, 'c'),
    (0x0443, 'y'),
    (0x0445, 'x'),
    (0x044C, 'b'),
    (0x0455, 's'),
    (0x0456, 'i'),
    (0x0458, 'j'),
    (0x04AE, 'Y'),
    (0x04AF, 'y'),
    (0x04BA, 'h'),
    (0x04BB, 'h'),
    (0x04C0, 'I'),
    // Armenian
    (0x054C, 'L'),
    (0x054D, 'S'),
    (0x0555, 'O'),
    (0x0566, 'q'),
    (0x0570, 'h'),
    (0x0578, 'n'),
    (0x057C, 'n'),
    (0x057D, 's'),
    (0x0585, 'o'),
    // Cherokee (visually similar to Latin)
    (0x13A0, 'D'), // Cherokee Letter A
    (0x13A1, 'R'), // Cherokee Letter E
    (0x13A2, 'T'), // Cherokee Letter I
    (0x13A9, 'Y'), // Cherokee Letter GI
    (0x13AA, 'A'), // Cherokee Letter GO
    (0x13AB, 'J'), // Cherokee Letter GU
    (0x13AC, 'E'), // Cherokee Letter GV
    (0x13B1, 'G'), // Cherokee Letter HU
    (0x13B3, 'W'), // Cherokee Letter LA
    (0x13B7, 'M'), // Cherokee Letter LU
    (0x13BB, 'H'), // Cherokee Letter MI
    (0x13BE, 'S'), // Cherokee Letter NO
    (0x13C0, 'P'), // Cherokee Letter QU
    (0x13C2, 'Z'), // Cherokee Letter SV
    (0x13C3, 'B'), // Cherokee Letter DA
    (0x13CB, 'V'), // Cherokee Letter TLI
    (0x13CF, 'K'), // Cherokee Letter TSO
    (0x13D2, 'L'), // Cherokee Letter WA
    (0x13DA, 'C'), // Cherokee Letter YA
    // Latin Extended (IPA)
    (0x1D00, 'a'),
    // Special symbols (must come before Math at U+1D400+)
    (0x2126, 'O'), // OHM SIGN
    (0x212A, 'K'), // KELVIN SIGN
    (0x212B, 'A'), // ANGSTROM SIGN
    // Roman numerals
    (0x2160, 'I'),
    (0x2164, 'V'),
    (0x2169, 'X'),
    (0x216C, 'L'),
    (0x216D, 'C'),
    (0x216E, 'D'),
    (0x216F, 'M'),
    // Mathematical Bold A-z (U+1D400-U+1D433)
    (0x1D400, 'A'),
    (0x1D401, 'B'),
    (0x1D402, 'C'),
    (0x1D403, 'D'),
    (0x1D404, 'E'),
    (0x1D405, 'F'),
    (0x1D406, 'G'),
    (0x1D407, 'H'),
    (0x1D408, 'I'),
    (0x1D409, 'J'),
    (0x1D40A, 'K'),
    (0x1D40B, 'L'),
    (0x1D40C, 'M'),
    (0x1D40D, 'N'),
    (0x1D40E, 'O'),
    (0x1D40F, 'P'),
    (0x1D410, 'Q'),
    (0x1D411, 'R'),
    (0x1D412, 'S'),
    (0x1D413, 'T'),
    (0x1D414, 'U'),
    (0x1D415, 'V'),
    (0x1D416, 'W'),
    (0x1D417, 'X'),
    (0x1D418, 'Y'),
    (0x1D419, 'Z'),
    (0x1D41A, 'a'),
    (0x1D41B, 'b'),
    (0x1D41C, 'c'),
    (0x1D41D, 'd'),
    (0x1D41E, 'e'),
    (0x1D41F, 'f'),
    (0x1D420, 'g'),
    (0x1D421, 'h'),
    (0x1D422, 'i'),
    (0x1D423, 'j'),
    (0x1D424, 'k'),
    (0x1D425, 'l'),
    (0x1D426, 'm'),
    (0x1D427, 'n'),
    (0x1D428, 'o'),
    (0x1D429, 'p'),
    (0x1D42A, 'q'),
    (0x1D42B, 'r'),
    (0x1D42C, 's'),
    (0x1D42D, 't'),
    (0x1D42E, 'u'),
    (0x1D42F, 'v'),
    (0x1D430, 'w'),
    (0x1D431, 'x'),
    (0x1D432, 'y'),
    (0x1D433, 'z'),
    // Mathematical Italic A-z
    (0x1D434, 'A'),
    (0x1D435, 'B'),
    (0x1D436, 'C'),
    (0x1D437, 'D'),
    (0x1D438, 'E'),
    (0x1D439, 'F'),
    (0x1D43A, 'G'),
    (0x1D43B, 'H'),
    (0x1D43C, 'I'),
    (0x1D43D, 'J'),
    (0x1D43E, 'K'),
    (0x1D43F, 'L'),
    (0x1D440, 'M'),
    (0x1D441, 'N'),
    (0x1D442, 'O'),
    (0x1D443, 'P'),
    (0x1D444, 'Q'),
    (0x1D445, 'R'),
    (0x1D446, 'S'),
    (0x1D447, 'T'),
    (0x1D448, 'U'),
    (0x1D449, 'V'),
    (0x1D44A, 'W'),
    (0x1D44B, 'X'),
    (0x1D44C, 'Y'),
    (0x1D44D, 'Z'),
    (0x1D44E, 'a'),
    (0x1D44F, 'b'),
    (0x1D450, 'c'),
    (0x1D451, 'd'),
    (0x1D452, 'e'),
    (0x1D453, 'f'),
    (0x1D454, 'g'),
    (0x1D456, 'i'),
    (0x1D457, 'j'),
    (0x1D458, 'k'),
    (0x1D459, 'l'),
    (0x1D45A, 'm'),
    (0x1D45B, 'n'),
    (0x1D45C, 'o'),
    (0x1D45D, 'p'),
    (0x1D45E, 'q'),
    (0x1D45F, 'r'),
    (0x1D460, 's'),
    (0x1D461, 't'),
    (0x1D462, 'u'),
    (0x1D463, 'v'),
    (0x1D464, 'w'),
    (0x1D465, 'x'),
    (0x1D466, 'y'),
    (0x1D467, 'z'),
    // Fullwidth A-Z and a-z (0xFF21-0xFF3A, 0xFF41-0xFF5A) handled
    // programmatically in confusable_target() to avoid 52 table entries.
];

/// Look up the confusable target for a codepoint via binary search.
/// Fullwidth Latin letters are handled programmatically to keep the table small.
pub fn confusable_target(cp: u32) -> Option<char> {
    // Fullwidth uppercase A-Z
    if (0xFF21..=0xFF3A).contains(&cp) {
        return Some((b'A' + (cp - 0xFF21) as u8) as char);
    }
    // Fullwidth lowercase a-z
    if (0xFF41..=0xFF5A).contains(&cp) {
        return Some((b'a' + (cp - 0xFF41) as u8) as char);
    }
    match CONFUSABLES.binary_search_by_key(&cp, |&(k, _)| k) {
        Ok(i) => Some(CONFUSABLES[i].1),
        Err(_) => None,
    }
}

/// Compute the "skeleton" of a string for confusable comparison.
///
/// NFD normalize, map each char through confusable_target, NFD normalize again.
/// Short-circuits for pure ASCII input (no allocations needed beyond the return).
pub fn skeleton(s: &str) -> String {
    // Fast path: pure ASCII is already NFD and has no confusable mappings.
    if s.is_ascii() {
        return s.to_owned();
    }
    let mapped: String = s
        .nfd()
        .map(|c| confusable_target(c as u32).unwrap_or(c))
        .collect();
    // Second NFD pass only needed if mapping produced decomposable chars.
    // All current confusable targets are ASCII, so skip if result is ASCII.
    if mapped.is_ascii() {
        mapped
    } else {
        mapped.nfd().collect()
    }
}

// ---------------------------------------------------------------------------
// Bidi constants
// ---------------------------------------------------------------------------

pub const BIDI_CONTROLS: &[u32] = &[
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
];

pub const BIDI_OPENERS: &[u32] = &[0x202A, 0x202B, 0x202D, 0x202E];

pub const BIDI_CLOSER_PDF: u32 = 0x202C;

pub const BIDI_ISOLATE_OPENERS: &[u32] = &[0x2066, 0x2067, 0x2068];

pub const BIDI_ISOLATE_CLOSER: u32 = 0x2069;

// ---------------------------------------------------------------------------
// Invisible / spacing / control character sets
// ---------------------------------------------------------------------------

pub const INVISIBLE_FORMAT_CHARS: &[u32] =
    &[0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF];

pub const SUSPICIOUS_SPACES: &[u32] = &[
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009,
    0x200A, 0x202F, 0x205F, 0x3000,
];

pub const ALLOWED_CONTROLS: &[u32] = &[0x09, 0x0A, 0x0D];

// ---------------------------------------------------------------------------
// Default-ignorable ranges
// ---------------------------------------------------------------------------

pub const DEFAULT_IGNORABLE_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// Check if a codepoint is default-ignorable (binary search on sorted ranges).
pub fn is_default_ignorable(cp: u32) -> bool {
    let idx = DEFAULT_IGNORABLE_RANGES.partition_point(|&(s, _)| s <= cp);
    if idx > 0 {
        let (s, e) = DEFAULT_IGNORABLE_RANGES[idx - 1];
        cp >= s && cp <= e
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Character classification
// ---------------------------------------------------------------------------

fn is_in_sorted(arr: &[u32], cp: u32) -> bool {
    arr.binary_search(&cp).is_ok()
}

/// Classify a codepoint, returning (rule_id, is_variation_selector).
///
/// Returns `(None, false)` if the codepoint is not suspicious.
pub fn classify_char(cp: u32) -> (Option<&'static str>, bool) {
    // Reject codepoints beyond the Unicode maximum
    if cp > 0x10FFFF {
        return (None, false);
    }

    // Fast lookups for known sets
    if is_in_sorted(BIDI_CONTROLS, cp) {
        return (Some("USC001"), false);
    }
    if is_in_sorted(INVISIBLE_FORMAT_CHARS, cp) {
        return (Some("USC002"), false);
    }
    if is_in_sorted(SUSPICIOUS_SPACES, cp) {
        return (Some("USC005"), false);
    }

    // General category check for control characters
    if let Some(ch) = char::from_u32(cp) {
        let cat = get_general_category(ch);
        if cat == GeneralCategory::Control && !is_in_sorted(ALLOWED_CONTROLS, cp) {
            return (Some("USC007"), false);
        }
    }

    // Range-based checks
    if (0x206A..=0x206F).contains(&cp) || (0xFFF0..=0xFFF8).contains(&cp) {
        return (Some("USC013"), false);
    }
    if (0xFFF9..=0xFFFB).contains(&cp) {
        return (Some("USC014"), false);
    }
    if (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp) {
        return (None, true);
    }
    if (0xE0001..=0xE007F).contains(&cp) {
        return (Some("USC012"), false);
    }
    if (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
    {
        return (Some("USC011"), false);
    }

    // Default-ignorable catch-all (earlier branches already returned for
    // BIDI_CONTROLS, INVISIBLE_FORMAT_CHARS, and FEFF, so no need to re-check)
    if is_default_ignorable(cp) {
        return (Some("USC016"), false);
    }

    (None, false)
}

// ---------------------------------------------------------------------------
// Character names
// ---------------------------------------------------------------------------

/// Sorted array of (codepoint, official_unicode_name) for chars the checker reports on.
pub const CHAR_NAMES: &[(u32, &str)] = &[
    (0x0009, "CHARACTER TABULATION"),
    (0x000A, "LINE FEED"),
    (0x000D, "CARRIAGE RETURN"),
    (0x00A0, "NO-BREAK SPACE"),
    (0x00AD, "SOFT HYPHEN"),
    (0x0251, "LATIN SMALL LETTER ALPHA"),
    (0x0261, "LATIN SMALL LETTER SCRIPT G"),
    (0x026A, "LATIN LETTER SMALL CAPITAL I"),
    (0x0391, "GREEK CAPITAL LETTER ALPHA"),
    (0x0392, "GREEK CAPITAL LETTER BETA"),
    (0x0395, "GREEK CAPITAL LETTER EPSILON"),
    (0x0396, "GREEK CAPITAL LETTER ZETA"),
    (0x0397, "GREEK CAPITAL LETTER ETA"),
    (0x0399, "GREEK CAPITAL LETTER IOTA"),
    (0x039A, "GREEK CAPITAL LETTER KAPPA"),
    (0x039C, "GREEK CAPITAL LETTER MU"),
    (0x039D, "GREEK CAPITAL LETTER NU"),
    (0x039F, "GREEK CAPITAL LETTER OMICRON"),
    (0x03A1, "GREEK CAPITAL LETTER RHO"),
    (0x03A4, "GREEK CAPITAL LETTER TAU"),
    (0x03A5, "GREEK CAPITAL LETTER UPSILON"),
    (0x03A7, "GREEK CAPITAL LETTER CHI"),
    (0x03B1, "GREEK SMALL LETTER ALPHA"),
    (0x03B2, "GREEK SMALL LETTER BETA"),
    (0x03B5, "GREEK SMALL LETTER EPSILON"),
    (0x03B7, "GREEK SMALL LETTER ETA"),
    (0x03B9, "GREEK SMALL LETTER IOTA"),
    (0x03BA, "GREEK SMALL LETTER KAPPA"),
    (0x03BD, "GREEK SMALL LETTER NU"),
    (0x03BF, "GREEK SMALL LETTER OMICRON"),
    (0x03C1, "GREEK SMALL LETTER RHO"),
    (0x03C4, "GREEK SMALL LETTER TAU"),
    (0x03C5, "GREEK SMALL LETTER UPSILON"),
    (0x03C7, "GREEK SMALL LETTER CHI"),
    (0x03C9, "GREEK SMALL LETTER OMEGA"),
    (0x0401, "CYRILLIC CAPITAL LETTER IO"),
    (0x0405, "CYRILLIC CAPITAL LETTER DZE"),
    (0x0406, "CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I"),
    (0x0408, "CYRILLIC CAPITAL LETTER JE"),
    (0x040C, "CYRILLIC CAPITAL LETTER KJE"),
    (0x0410, "CYRILLIC CAPITAL LETTER A"),
    (0x0412, "CYRILLIC CAPITAL LETTER VE"),
    (0x0415, "CYRILLIC CAPITAL LETTER IE"),
    (0x041A, "CYRILLIC CAPITAL LETTER KA"),
    (0x041C, "CYRILLIC CAPITAL LETTER EM"),
    (0x041D, "CYRILLIC CAPITAL LETTER EN"),
    (0x041E, "CYRILLIC CAPITAL LETTER O"),
    (0x0420, "CYRILLIC CAPITAL LETTER ER"),
    (0x0421, "CYRILLIC CAPITAL LETTER ES"),
    (0x0422, "CYRILLIC CAPITAL LETTER TE"),
    (0x0423, "CYRILLIC CAPITAL LETTER U"),
    (0x0425, "CYRILLIC CAPITAL LETTER HA"),
    (0x042C, "CYRILLIC CAPITAL LETTER SOFT SIGN"),
    (0x0430, "CYRILLIC SMALL LETTER A"),
    (0x0435, "CYRILLIC SMALL LETTER IE"),
    (0x043E, "CYRILLIC SMALL LETTER O"),
    (0x0440, "CYRILLIC SMALL LETTER ER"),
    (0x0441, "CYRILLIC SMALL LETTER ES"),
    (0x0443, "CYRILLIC SMALL LETTER U"),
    (0x0445, "CYRILLIC SMALL LETTER HA"),
    (0x044C, "CYRILLIC SMALL LETTER SOFT SIGN"),
    (0x0455, "CYRILLIC SMALL LETTER DZE"),
    (0x0456, "CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I"),
    (0x0458, "CYRILLIC SMALL LETTER JE"),
    (0x04AE, "CYRILLIC CAPITAL LETTER STRAIGHT U"),
    (0x04AF, "CYRILLIC SMALL LETTER STRAIGHT U"),
    (0x04BA, "CYRILLIC CAPITAL LETTER SHHA"),
    (0x04BB, "CYRILLIC SMALL LETTER SHHA"),
    (0x04C0, "CYRILLIC LETTER PALOCHKA"),
    (0x054C, "ARMENIAN CAPITAL LETTER RA"),
    (0x054D, "ARMENIAN CAPITAL LETTER SEH"),
    (0x0555, "ARMENIAN CAPITAL LETTER OH"),
    (0x0566, "ARMENIAN SMALL LETTER ZA"),
    (0x0570, "ARMENIAN SMALL LETTER HO"),
    (0x0578, "ARMENIAN SMALL LETTER VO"),
    (0x057C, "ARMENIAN SMALL LETTER RA"),
    (0x057D, "ARMENIAN SMALL LETTER SEH"),
    (0x0585, "ARMENIAN SMALL LETTER OH"),
    (0x061C, "ARABIC LETTER MARK"),
    (0x1680, "OGHAM SPACE MARK"),
    (0x180E, "MONGOLIAN VOWEL SEPARATOR"),
    (0x1D00, "LATIN LETTER SMALL CAPITAL A"),
    (0x2000, "EN QUAD"),
    (0x2001, "EM QUAD"),
    (0x2002, "EN SPACE"),
    (0x2003, "EM SPACE"),
    (0x2004, "THREE-PER-EM SPACE"),
    (0x2005, "FOUR-PER-EM SPACE"),
    (0x2006, "SIX-PER-EM SPACE"),
    (0x2007, "FIGURE SPACE"),
    (0x2008, "PUNCTUATION SPACE"),
    (0x2009, "THIN SPACE"),
    (0x200A, "HAIR SPACE"),
    (0x200B, "ZERO WIDTH SPACE"),
    (0x200C, "ZERO WIDTH NON-JOINER"),
    (0x200D, "ZERO WIDTH JOINER"),
    (0x200E, "LEFT-TO-RIGHT MARK"),
    (0x200F, "RIGHT-TO-LEFT MARK"),
    (0x202A, "LEFT-TO-RIGHT EMBEDDING"),
    (0x202B, "RIGHT-TO-LEFT EMBEDDING"),
    (0x202C, "POP DIRECTIONAL FORMATTING"),
    (0x202D, "LEFT-TO-RIGHT OVERRIDE"),
    (0x202E, "RIGHT-TO-LEFT OVERRIDE"),
    (0x202F, "NARROW NO-BREAK SPACE"),
    (0x205F, "MEDIUM MATHEMATICAL SPACE"),
    (0x2060, "WORD JOINER"),
    (0x2066, "LEFT-TO-RIGHT ISOLATE"),
    (0x2067, "RIGHT-TO-LEFT ISOLATE"),
    (0x2068, "FIRST STRONG ISOLATE"),
    (0x2069, "POP DIRECTIONAL ISOLATE"),
    (0x2126, "OHM SIGN"),
    (0x212A, "KELVIN SIGN"),
    (0x212B, "ANGSTROM SIGN"),
    (0x2160, "ROMAN NUMERAL ONE"),
    (0x2164, "ROMAN NUMERAL FIVE"),
    (0x2169, "ROMAN NUMERAL TEN"),
    (0x216C, "ROMAN NUMERAL FIFTY"),
    (0x216D, "ROMAN NUMERAL ONE HUNDRED"),
    (0x216E, "ROMAN NUMERAL FIVE HUNDRED"),
    (0x216F, "ROMAN NUMERAL ONE THOUSAND"),
    (0x3000, "IDEOGRAPHIC SPACE"),
    (0xFE00, "VARIATION SELECTOR-1"),
    (0xFE01, "VARIATION SELECTOR-2"),
    (0xFE02, "VARIATION SELECTOR-3"),
    (0xFE03, "VARIATION SELECTOR-4"),
    (0xFE04, "VARIATION SELECTOR-5"),
    (0xFE05, "VARIATION SELECTOR-6"),
    (0xFE06, "VARIATION SELECTOR-7"),
    (0xFE07, "VARIATION SELECTOR-8"),
    (0xFE08, "VARIATION SELECTOR-9"),
    (0xFE09, "VARIATION SELECTOR-10"),
    (0xFE0A, "VARIATION SELECTOR-11"),
    (0xFE0B, "VARIATION SELECTOR-12"),
    (0xFE0C, "VARIATION SELECTOR-13"),
    (0xFE0D, "VARIATION SELECTOR-14"),
    (0xFE0E, "VARIATION SELECTOR-15"),
    (0xFE0F, "VARIATION SELECTOR-16"),
    (0xFEFF, "ZERO WIDTH NO-BREAK SPACE"),
    (0xFF21, "FULLWIDTH LATIN CAPITAL LETTER A"),
    (0xFF22, "FULLWIDTH LATIN CAPITAL LETTER B"),
    (0xFF23, "FULLWIDTH LATIN CAPITAL LETTER C"),
    (0xFF24, "FULLWIDTH LATIN CAPITAL LETTER D"),
    (0xFF25, "FULLWIDTH LATIN CAPITAL LETTER E"),
    (0xFF26, "FULLWIDTH LATIN CAPITAL LETTER F"),
    (0xFF27, "FULLWIDTH LATIN CAPITAL LETTER G"),
    (0xFF28, "FULLWIDTH LATIN CAPITAL LETTER H"),
    (0xFF29, "FULLWIDTH LATIN CAPITAL LETTER I"),
    (0xFF2A, "FULLWIDTH LATIN CAPITAL LETTER J"),
    (0xFF2B, "FULLWIDTH LATIN CAPITAL LETTER K"),
    (0xFF2C, "FULLWIDTH LATIN CAPITAL LETTER L"),
    (0xFF2D, "FULLWIDTH LATIN CAPITAL LETTER M"),
    (0xFF2E, "FULLWIDTH LATIN CAPITAL LETTER N"),
    (0xFF2F, "FULLWIDTH LATIN CAPITAL LETTER O"),
    (0xFF30, "FULLWIDTH LATIN CAPITAL LETTER P"),
    (0xFF31, "FULLWIDTH LATIN CAPITAL LETTER Q"),
    (0xFF32, "FULLWIDTH LATIN CAPITAL LETTER R"),
    (0xFF33, "FULLWIDTH LATIN CAPITAL LETTER S"),
    (0xFF34, "FULLWIDTH LATIN CAPITAL LETTER T"),
    (0xFF35, "FULLWIDTH LATIN CAPITAL LETTER U"),
    (0xFF36, "FULLWIDTH LATIN CAPITAL LETTER V"),
    (0xFF37, "FULLWIDTH LATIN CAPITAL LETTER W"),
    (0xFF38, "FULLWIDTH LATIN CAPITAL LETTER X"),
    (0xFF39, "FULLWIDTH LATIN CAPITAL LETTER Y"),
    (0xFF3A, "FULLWIDTH LATIN CAPITAL LETTER Z"),
    (0xFF41, "FULLWIDTH LATIN SMALL LETTER A"),
    (0xFF42, "FULLWIDTH LATIN SMALL LETTER B"),
    (0xFF43, "FULLWIDTH LATIN SMALL LETTER C"),
    (0xFF44, "FULLWIDTH LATIN SMALL LETTER D"),
    (0xFF45, "FULLWIDTH LATIN SMALL LETTER E"),
    (0xFF46, "FULLWIDTH LATIN SMALL LETTER F"),
    (0xFF47, "FULLWIDTH LATIN SMALL LETTER G"),
    (0xFF48, "FULLWIDTH LATIN SMALL LETTER H"),
    (0xFF49, "FULLWIDTH LATIN SMALL LETTER I"),
    (0xFF4A, "FULLWIDTH LATIN SMALL LETTER J"),
    (0xFF4B, "FULLWIDTH LATIN SMALL LETTER K"),
    (0xFF4C, "FULLWIDTH LATIN SMALL LETTER L"),
    (0xFF4D, "FULLWIDTH LATIN SMALL LETTER M"),
    (0xFF4E, "FULLWIDTH LATIN SMALL LETTER N"),
    (0xFF4F, "FULLWIDTH LATIN SMALL LETTER O"),
    (0xFF50, "FULLWIDTH LATIN SMALL LETTER P"),
    (0xFF51, "FULLWIDTH LATIN SMALL LETTER Q"),
    (0xFF52, "FULLWIDTH LATIN SMALL LETTER R"),
    (0xFF53, "FULLWIDTH LATIN SMALL LETTER S"),
    (0xFF54, "FULLWIDTH LATIN SMALL LETTER T"),
    (0xFF55, "FULLWIDTH LATIN SMALL LETTER U"),
    (0xFF56, "FULLWIDTH LATIN SMALL LETTER V"),
    (0xFF57, "FULLWIDTH LATIN SMALL LETTER W"),
    (0xFF58, "FULLWIDTH LATIN SMALL LETTER X"),
    (0xFF59, "FULLWIDTH LATIN SMALL LETTER Y"),
    (0xFF5A, "FULLWIDTH LATIN SMALL LETTER Z"),
];

/// Format character info as "U+XXXX NAME".
pub fn char_info(ch: char) -> String {
    let cp = ch as u32;
    match CHAR_NAMES.binary_search_by_key(&cp, |&(k, _)| k) {
        Ok(i) => format!("U+{:04X} {}", cp, CHAR_NAMES[i].1),
        Err(_) => format!("U+{:04X} <unnamed U+{:04X}>", cp, cp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_script_latin() {
        assert_eq!(get_script('A'), "Latin");
        assert_eq!(get_script('z'), "Latin");
    }

    #[test]
    fn test_get_script_common() {
        assert_eq!(get_script('1'), "Common");
        assert_eq!(get_script('.'), "Common");
        assert_eq!(get_script(' '), "Common");
    }

    #[test]
    fn test_get_script_cyrillic() {
        assert_eq!(get_script('\u{0410}'), "Cyrillic");
    }

    #[test]
    fn test_confusable_target() {
        assert_eq!(confusable_target(0x0410), Some('A'));
        assert_eq!(confusable_target(0xFF21), Some('A'));
        assert_eq!(confusable_target(0x0041), None);
    }

    #[test]
    fn test_skeleton() {
        assert_eq!(skeleton("hello"), "hello");
    }

    #[test]
    fn test_classify_bidi() {
        assert_eq!(classify_char(0x202A), (Some("USC001"), false));
    }

    #[test]
    fn test_classify_invisible() {
        assert_eq!(classify_char(0x200B), (Some("USC002"), false));
    }

    #[test]
    fn test_classify_space() {
        assert_eq!(classify_char(0x00A0), (Some("USC005"), false));
    }

    #[test]
    fn test_classify_variation_selector() {
        assert_eq!(classify_char(0xFE00), (None, true));
    }

    #[test]
    fn test_classify_pua() {
        assert_eq!(classify_char(0xE000), (Some("USC011"), false));
    }

    #[test]
    fn test_classify_normal() {
        assert_eq!(classify_char(0x0041), (None, false));
    }

    #[test]
    fn test_char_info_known() {
        assert_eq!(char_info('\u{200B}'), "U+200B ZERO WIDTH SPACE");
    }

    #[test]
    fn test_char_info_unknown() {
        assert_eq!(char_info('A'), "U+0041 <unnamed U+0041>");
    }

    #[test]
    fn test_is_default_ignorable() {
        assert!(is_default_ignorable(0x200B));
        assert!(is_default_ignorable(0xFEFF));
        assert!(!is_default_ignorable(0x0041));
    }

    #[test]
    fn test_script_ranges_sorted() {
        for i in 1..SCRIPT_RANGES.len() {
            assert!(
                SCRIPT_RANGES[i].0 > SCRIPT_RANGES[i - 1].0,
                "SCRIPT_RANGES not sorted at index {}",
                i
            );
        }
    }

    #[test]
    fn test_confusables_sorted() {
        for i in 1..CONFUSABLES.len() {
            assert!(
                CONFUSABLES[i].0 > CONFUSABLES[i - 1].0,
                "CONFUSABLES not sorted at index {}",
                i
            );
        }
    }

    #[test]
    fn test_char_names_sorted() {
        for i in 1..CHAR_NAMES.len() {
            assert!(
                CHAR_NAMES[i].0 > CHAR_NAMES[i - 1].0,
                "CHAR_NAMES not sorted at index {}",
                i
            );
        }
    }

    #[test]
    fn test_default_ignorable_ranges_sorted() {
        for i in 1..DEFAULT_IGNORABLE_RANGES.len() {
            assert!(
                DEFAULT_IGNORABLE_RANGES[i].0 > DEFAULT_IGNORABLE_RANGES[i - 1].1,
                "DEFAULT_IGNORABLE_RANGES not sorted/overlapping at index {}",
                i
            );
        }
    }

    #[test]
    fn test_classify_null() {
        // U+0000 is a control character, not in ALLOWED_CONTROLS
        assert_eq!(classify_char(0x0000), (Some("USC007"), false));
    }

    #[test]
    fn test_classify_ffff() {
        // U+FFFF is a noncharacter; not flagged by current rules
        assert_eq!(classify_char(0xFFFF), (None, false));
    }

    #[test]
    fn test_classify_max_codepoint() {
        // U+10FFFF is the maximum valid codepoint
        assert_eq!(classify_char(0x10FFFF), (None, false));
    }

    #[test]
    fn test_classify_tag_chars() {
        // U+E0001 TAG LATIN CAPITAL LETTER A - should be USC012
        assert_eq!(classify_char(0xE0001), (Some("USC012"), false));
        assert_eq!(classify_char(0xE007F), (Some("USC012"), false));
    }

    #[test]
    fn test_classify_supplementary_variation_selectors() {
        // U+E0100..U+E01EF are variation selectors in SMP
        assert_eq!(classify_char(0xE0100), (None, true));
        assert_eq!(classify_char(0xE01EF), (None, true));
    }

    #[test]
    fn test_get_script_unknown() {
        // A codepoint not in any script range and not common/inherited
        // U+0250 is "Latin" (in 0x0250-0x02AF range)
        assert_eq!(get_script('\u{0250}'), "Latin");
        // U+0300 is a combining mark -> Inherited
        assert_eq!(get_script('\u{0300}'), "Inherited");
    }

    #[test]
    fn test_skeleton_ascii_fast_path() {
        // Pure ASCII should return identical string
        assert_eq!(skeleton("hello world"), "hello world");
    }

    #[test]
    fn test_skeleton_confusable() {
        // Cyrillic 'a' (U+0430) maps to Latin 'a'
        assert_eq!(skeleton("\u{0430}"), "a");
    }

    #[test]
    fn test_is_default_ignorable_boundaries() {
        // Test range boundaries
        assert!(is_default_ignorable(0x200B)); // start of 200B-200F
        assert!(is_default_ignorable(0x200F)); // end of 200B-200F
        assert!(!is_default_ignorable(0x200A)); // just before range
        assert!(!is_default_ignorable(0x2010)); // just after range
    }
}
