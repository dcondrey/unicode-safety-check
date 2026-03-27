use std::path::Path;

use crate::models::{Context, Token};

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

pub fn detect_language(path: &str) -> &'static str {
    let p = Path::new(path);
    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
        if let Some(lang) = filename_to_lang(name) {
            return lang;
        }
    }
    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        // Python's suffix.lower() includes the dot; we match on the bare extension.
        let ext_lower: String = ext.to_ascii_lowercase();
        if let Some(lang) = ext_to_lang(&ext_lower) {
            return lang;
        }
    }
    "unknown"
}

fn ext_to_lang(ext: &str) -> Option<&'static str> {
    match ext {
        "py" | "pyw" | "pyi" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        "kt" => Some("kotlin"),
        "scala" => Some("scala"),
        "c" | "h" => Some("c"),
        "cpp" | "hpp" | "cc" => Some("cpp"),
        "cs" => Some("csharp"),
        "rb" => Some("ruby"),
        "php" => Some("php"),
        "sh" | "bash" | "zsh" => Some("shell"),
        "pl" | "pm" => Some("perl"),
        "r" => Some("r"),
        "swift" => Some("swift"),
        "lua" => Some("lua"),
        "yml" | "yaml" => Some("yaml"),
        "toml" => Some("toml"),
        "md" => Some("markdown"),
        "rst" => Some("rst"),
        "html" | "htm" => Some("html"),
        "css" => Some("css"),
        "scss" => Some("scss"),
        "sql" => Some("sql"),
        "zig" => Some("zig"),
        "nim" => Some("nim"),
        "json" => Some("json"),
        "xml" => Some("xml"),
        _ => None,
    }
}

fn filename_to_lang(name: &str) -> Option<&'static str> {
    match name {
        "Dockerfile" => Some("dockerfile"),
        "Makefile" => Some("makefile"),
        "Gemfile" | "Rakefile" | "Vagrantfile" => Some("ruby"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Language feature sets
// ---------------------------------------------------------------------------

fn is_hash_lang(lang: &str) -> bool {
    matches!(
        lang,
        "python" | "ruby" | "perl" | "shell" | "yaml" | "toml" | "makefile" | "dockerfile" | "r"
    )
}

fn is_slash_lang(lang: &str) -> bool {
    matches!(
        lang,
        "javascript"
            | "typescript"
            | "go"
            | "rust"
            | "java"
            | "kotlin"
            | "scala"
            | "c"
            | "cpp"
            | "csharp"
            | "swift"
            | "zig"
            | "nim"
            | "php"
            | "css"
            | "scss"
            | "sql"
    )
}

fn is_block_lang(lang: &str) -> bool {
    matches!(
        lang,
        "javascript"
            | "typescript"
            | "go"
            | "rust"
            | "java"
            | "kotlin"
            | "scala"
            | "c"
            | "cpp"
            | "csharp"
            | "swift"
            | "css"
            | "scss"
            | "php"
            | "sql"
    )
}

fn is_triple_lang(lang: &str) -> bool {
    lang == "python"
}

// ---------------------------------------------------------------------------
// Tokenizer state
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TokenizerState {
    pub in_block_comment: bool,
    pub in_multiline_string: bool,
    pub string_delimiter: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a character can start an identifier.
fn is_ident_start(ch: char) -> bool {
    ch.is_alphabetic() || ch == '_' || ch > '\x7f'
}

/// Check if a character can continue an identifier.
fn is_ident_cont(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_' || ch > '\x7f'
}

/// Find the end of a string literal starting at byte offset `start` (on the
/// opening quote). Returns `Some(byte_offset)` of the closing quote, or `None`
/// if the string is unterminated on this line.
pub fn find_str_end(line: &str, start: usize, quote: char) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut pos = start + quote.len_utf8();
    while pos < bytes.len() {
        let ch = line[pos..].chars().next().unwrap();
        if ch == '\\' {
            pos += 1; // skip backslash
                      // skip the escaped character
            if pos < bytes.len() {
                let esc = line[pos..].chars().next().unwrap();
                pos += esc.len_utf8();
            }
            continue;
        }
        if ch == quote {
            return Some(pos);
        }
        pos += ch.len_utf8();
    }
    None
}

/// Extract all identifier-like words from `text` and produce tokens with the
/// given context. `offset` is the byte offset of `text` within the original
/// line (used to compute column positions as character indices).
pub fn extract_words(text: &str, ctx: Context, line_num: usize, offset: usize) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();
    // We need to translate byte offsets back to character columns relative to
    // the full line. `offset` is itself a byte offset into the line, so we
    // compute the column the same way Python does: character index within the
    // line. However, the Python code just passes `offset + m.start()` which
    // are both character-index based (Python strings are char-indexed). Since
    // Rust strings are byte-indexed we replicate the same semantics by
    // tracking the character index within `text` and adding the *character
    // count* up to `offset` in the original line. But callers pass byte
    // offsets here, and the Python version uses character offsets throughout.
    // For simplicity (and consistency with the Python port where ASCII is
    // dominant), we pass byte offsets directly; this matches Python behaviour
    // when the preceding text is ASCII.
    while let Some(&(byte_idx, ch)) = chars.peek() {
        if is_ident_start(ch) {
            let start = byte_idx;
            let mut end = byte_idx + ch.len_utf8();
            chars.next();
            while let Some(&(bi, c)) = chars.peek() {
                if is_ident_cont(c) {
                    end = bi + c.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token {
                text: text[start..end].to_string(),
                context: ctx,
                line: line_num,
                col: offset + start,
            });
        } else {
            chars.next();
        }
    }
    tokens
}

// ---------------------------------------------------------------------------
// Main tokenizer
// ---------------------------------------------------------------------------

pub fn tokenize_line(
    line: &str,
    lang: &str,
    state: &mut TokenizerState,
    line_num: usize,
) -> Vec<Token> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut pos: usize = 0; // byte offset into `line`

    // --- Block comment continuation ---
    if state.in_block_comment {
        if let Some(end) = line.find("*/") {
            let region_end = end + 2;
            tokens.extend(extract_words(
                &line[..region_end],
                Context::Comment,
                line_num,
                0,
            ));
            pos = region_end;
            state.in_block_comment = false;
        } else {
            tokens.extend(extract_words(line, Context::Comment, line_num, 0));
            return tokens;
        }
    }

    // --- Multiline string continuation ---
    if state.in_multiline_string {
        if let Some(ref delim) = state.string_delimiter.clone() {
            if let Some(end) = line[pos..].find(delim.as_str()) {
                let abs_end = pos + end;
                let region_end = abs_end + delim.len();
                tokens.extend(extract_words(
                    &line[pos..region_end],
                    Context::String,
                    line_num,
                    pos,
                ));
                pos = region_end;
                state.in_multiline_string = false;
                state.string_delimiter = None;
            } else {
                tokens.extend(extract_words(&line[pos..], Context::String, line_num, pos));
                return tokens;
            }
        }
    }

    // --- Main loop ---
    let bytes = line.as_bytes();
    while pos < bytes.len() {
        let ch = line[pos..].chars().next().unwrap();
        let ch_len = ch.len_utf8();

        // Triple-quoted strings (Python)
        if is_triple_lang(lang) && pos + 3 <= bytes.len() {
            let tri = &line[pos..pos + 3];
            if tri == "\"\"\"" || tri == "'''" {
                if let Some(end) = line[pos + 3..].find(tri) {
                    let abs_end = pos + 3 + end;
                    let region_end = abs_end + 3;
                    tokens.extend(extract_words(
                        &line[pos..region_end],
                        Context::String,
                        line_num,
                        pos,
                    ));
                    pos = region_end;
                    continue;
                } else {
                    tokens.extend(extract_words(&line[pos..], Context::String, line_num, pos));
                    state.in_multiline_string = true;
                    state.string_delimiter = Some(tri.to_string());
                    return tokens;
                }
            }
        }

        // Hash comments
        if is_hash_lang(lang) && ch == '#' {
            tokens.extend(extract_words(&line[pos..], Context::Comment, line_num, pos));
            return tokens;
        }

        // Line comments (//)
        if is_slash_lang(lang) && ch == '/' && pos + 1 < bytes.len() && bytes[pos + 1] == b'/' {
            tokens.extend(extract_words(&line[pos..], Context::Comment, line_num, pos));
            return tokens;
        }

        // Block comment start (/*)
        if is_block_lang(lang) && ch == '/' && pos + 1 < bytes.len() && bytes[pos + 1] == b'*' {
            if let Some(end_rel) = line[pos + 2..].find("*/") {
                let region_end = pos + 2 + end_rel + 2;
                tokens.extend(extract_words(
                    &line[pos..region_end],
                    Context::Comment,
                    line_num,
                    pos,
                ));
                pos = region_end;
                continue;
            } else {
                tokens.extend(extract_words(&line[pos..], Context::Comment, line_num, pos));
                state.in_block_comment = true;
                return tokens;
            }
        }

        // String literals
        if ch == '"' || ch == '\'' || ch == '`' {
            if let Some(end) = find_str_end(line, pos, ch) {
                tokens.extend(extract_words(
                    &line[pos..end + ch_len],
                    Context::String,
                    line_num,
                    pos,
                ));
                pos = end + ch_len;
                continue;
            } else {
                tokens.extend(extract_words(&line[pos..], Context::String, line_num, pos));
                return tokens;
            }
        }

        // Identifiers
        if is_ident_start(ch) {
            let start = pos;
            pos += ch_len;
            while pos < bytes.len() {
                let c = line[pos..].chars().next().unwrap();
                if is_ident_cont(c) {
                    pos += c.len_utf8();
                } else {
                    break;
                }
            }
            tokens.push(Token {
                text: line[start..pos].to_string(),
                context: Context::Identifier,
                line: line_num,
                col: start,
            });
            continue;
        }

        // Skip anything else
        pos += ch_len;
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo/bar.py"), "python");
        assert_eq!(detect_language("foo/bar.pyw"), "python");
        assert_eq!(detect_language("src/main.rs"), "rust");
        assert_eq!(detect_language("Makefile"), "makefile");
        assert_eq!(detect_language("Gemfile"), "ruby");
        assert_eq!(detect_language("unknown.xyz"), "unknown");
        assert_eq!(detect_language("test.JS"), "javascript");
    }

    #[test]
    fn test_find_str_end() {
        assert_eq!(find_str_end(r#""hello""#, 0, '"'), Some(6));
        assert_eq!(find_str_end(r#""he\"llo""#, 0, '"'), Some(8));
        assert_eq!(find_str_end(r#""unterminated"#, 0, '"'), None);
    }

    #[test]
    fn test_extract_words() {
        let words = extract_words("foo bar_baz 123", Context::Comment, 1, 0);
        assert_eq!(words.len(), 2);
        assert_eq!(words[0].text, "foo");
        assert_eq!(words[0].col, 0);
        assert_eq!(words[1].text, "bar_baz");
        assert_eq!(words[1].col, 4);
    }

    #[test]
    fn test_tokenize_identifier() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("hello world", "python", &mut state, 1);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].text, "hello");
        assert_eq!(tokens[0].context, Context::Identifier);
        assert_eq!(tokens[1].text, "world");
    }

    #[test]
    fn test_tokenize_hash_comment() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("x = 1 # comment word", "python", &mut state, 1);
        let idents: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Identifier)
            .collect();
        let comments: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Comment)
            .collect();
        assert_eq!(idents.len(), 1);
        assert_eq!(idents[0].text, "x");
        assert_eq!(comments.len(), 2); // "comment", "word"
    }

    #[test]
    fn test_tokenize_line_comment() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("int x; // note", "rust", &mut state, 1);
        let comments: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Comment)
            .collect();
        assert!(comments.iter().any(|t| t.text == "note"));
    }

    #[test]
    fn test_tokenize_block_comment() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("a /* inner */ b", "c", &mut state, 1);
        assert!(!state.in_block_comment);
        let idents: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Identifier)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(idents, vec!["a", "b"]);
        let comments: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Comment)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(comments, vec!["inner"]);
    }

    #[test]
    fn test_tokenize_block_comment_multiline() {
        let mut state = TokenizerState::default();
        let t1 = tokenize_line("a /* start", "c", &mut state, 1);
        assert!(state.in_block_comment);
        assert!(t1
            .iter()
            .any(|t| t.text == "a" && t.context == Context::Identifier));
        assert!(t1
            .iter()
            .any(|t| t.text == "start" && t.context == Context::Comment));

        let t2 = tokenize_line("end */ b", "c", &mut state, 2);
        assert!(!state.in_block_comment);
        assert!(t2
            .iter()
            .any(|t| t.text == "end" && t.context == Context::Comment));
        assert!(t2
            .iter()
            .any(|t| t.text == "b" && t.context == Context::Identifier));
    }

    #[test]
    fn test_tokenize_triple_quote() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line(r#"x = """hello""" + y"#, "python", &mut state, 1);
        assert!(!state.in_multiline_string);
        let idents: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Identifier)
            .map(|t| t.text.as_str())
            .collect();
        assert!(idents.contains(&"x"));
        assert!(idents.contains(&"y"));
    }

    #[test]
    fn test_tokenize_triple_quote_multiline() {
        let mut state = TokenizerState::default();
        let _t1 = tokenize_line(r#"x = """start"#, "python", &mut state, 1);
        assert!(state.in_multiline_string);
        assert_eq!(state.string_delimiter.as_deref(), Some(r#"""""#));

        let t2 = tokenize_line(r#"end""" + y"#, "python", &mut state, 2);
        assert!(!state.in_multiline_string);
        assert!(t2
            .iter()
            .any(|t| t.text == "y" && t.context == Context::Identifier));
    }

    #[test]
    fn test_tokenize_string_literal() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line(r#"a = "hello" + b"#, "python", &mut state, 1);
        let idents: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Identifier)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(idents, vec!["a", "b"]);
        assert!(tokens
            .iter()
            .any(|t| t.text == "hello" && t.context == Context::String));
    }
}
