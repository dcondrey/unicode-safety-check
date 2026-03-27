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

fn supports_nested_comments(lang: &str) -> bool {
    matches!(lang, "rust" | "swift" | "kotlin" | "scala")
}

fn is_backtick_string_lang(lang: &str) -> bool {
    matches!(lang, "javascript" | "typescript")
}

/// Scan `line[start..]` for `*/` respecting nested `/*`. `depth` is the
/// current nesting depth (must be >= 1). Returns `(new_depth, byte_offset)`
/// where byte_offset is the position right after the closing `*/` if depth
/// reaches 0, or `line.len()` if the line ends still inside the comment.
fn scan_block_comment(line: &str, start: usize, mut depth: u32, nested: bool) -> (u32, usize) {
    let bytes = line.as_bytes();
    let mut pos = start;
    while pos < bytes.len() {
        if nested && pos + 1 < bytes.len() && bytes[pos] == b'/' && bytes[pos + 1] == b'*' {
            depth += 1;
            pos += 2;
            continue;
        }
        if pos + 1 < bytes.len() && bytes[pos] == b'*' && bytes[pos + 1] == b'/' {
            depth -= 1;
            pos += 2;
            if depth == 0 {
                return (0, pos);
            }
            continue;
        }
        pos += 1;
    }
    (depth, pos)
}

// ---------------------------------------------------------------------------
// Tokenizer state
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TokenizerState {
    pub in_block_comment: bool,
    pub block_comment_depth: u32,
    pub in_multiline_string: bool,
    pub string_delimiter: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a byte offset within `s` to a character (scalar) offset.
fn byte_to_char_offset(s: &str, byte_offset: usize) -> usize {
    s[..byte_offset].chars().count()
}

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
/// line. Column positions are emitted as character offsets (not byte offsets)
/// for consistency with SARIF startColumn and the Python implementation.
pub fn extract_words(
    line: &str,
    text: &str,
    ctx: Context,
    line_num: usize,
    offset: usize,
) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();
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
                col: byte_to_char_offset(line, offset + start),
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
        let nested = supports_nested_comments(lang);
        let (new_depth, end_pos) = scan_block_comment(line, 0, state.block_comment_depth, nested);
        if new_depth == 0 {
            tokens.extend(extract_words(
                line,
                &line[..end_pos],
                Context::Comment,
                line_num,
                0,
            ));
            pos = end_pos;
            state.in_block_comment = false;
            state.block_comment_depth = 0;
        } else {
            state.block_comment_depth = new_depth;
            tokens.extend(extract_words(line, line, Context::Comment, line_num, 0));
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
                    line,
                    &line[pos..region_end],
                    Context::String,
                    line_num,
                    pos,
                ));
                pos = region_end;
                state.in_multiline_string = false;
                state.string_delimiter = None;
            } else {
                tokens.extend(extract_words(
                    line,
                    &line[pos..],
                    Context::String,
                    line_num,
                    pos,
                ));
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
        if is_triple_lang(lang) && pos + 3 <= bytes.len() && line.is_char_boundary(pos + 3) {
            let tri = &line[pos..pos + 3];
            if tri == "\"\"\"" || tri == "'''" {
                if let Some(end) = line[pos + 3..].find(tri) {
                    let abs_end = pos + 3 + end;
                    let region_end = abs_end + 3;
                    tokens.extend(extract_words(
                        line,
                        &line[pos..region_end],
                        Context::String,
                        line_num,
                        pos,
                    ));
                    pos = region_end;
                    continue;
                } else {
                    tokens.extend(extract_words(
                        line,
                        &line[pos..],
                        Context::String,
                        line_num,
                        pos,
                    ));
                    state.in_multiline_string = true;
                    state.string_delimiter = Some(tri.to_string());
                    return tokens;
                }
            }
        }

        // Hash comments
        if is_hash_lang(lang) && ch == '#' {
            tokens.extend(extract_words(
                line,
                &line[pos..],
                Context::Comment,
                line_num,
                pos,
            ));
            return tokens;
        }

        // Line comments (//)
        if is_slash_lang(lang) && ch == '/' && pos + 1 < bytes.len() && bytes[pos + 1] == b'/' {
            tokens.extend(extract_words(
                line,
                &line[pos..],
                Context::Comment,
                line_num,
                pos,
            ));
            return tokens;
        }

        // Block comment start (/*)
        if is_block_lang(lang) && ch == '/' && pos + 1 < bytes.len() && bytes[pos + 1] == b'*' {
            let nested = supports_nested_comments(lang);
            let (depth, end_pos) = scan_block_comment(line, pos + 2, 1, nested);
            if depth == 0 {
                tokens.extend(extract_words(
                    line,
                    &line[pos..end_pos],
                    Context::Comment,
                    line_num,
                    pos,
                ));
                pos = end_pos;
                continue;
            } else {
                tokens.extend(extract_words(
                    line,
                    &line[pos..],
                    Context::Comment,
                    line_num,
                    pos,
                ));
                state.in_block_comment = true;
                state.block_comment_depth = depth;
                return tokens;
            }
        }

        // String literals
        if ch == '"' || ch == '\'' || ch == '`' {
            if let Some(end) = find_str_end(line, pos, ch) {
                tokens.extend(extract_words(
                    line,
                    &line[pos..end + ch_len],
                    Context::String,
                    line_num,
                    pos,
                ));
                pos = end + ch_len;
                continue;
            } else {
                tokens.extend(extract_words(
                    line,
                    &line[pos..],
                    Context::String,
                    line_num,
                    pos,
                ));
                if ch == '`' && is_backtick_string_lang(lang) {
                    state.in_multiline_string = true;
                    state.string_delimiter = Some("`".to_string());
                }
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
                col: byte_to_char_offset(line, start),
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
        let text = "foo bar_baz 123";
        let words = extract_words(text, text, Context::Comment, 1, 0);
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

    #[test]
    fn test_nested_block_comment_rust() {
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("/* /* inner */ still comment */", "rust", &mut state, 1);
        assert!(!state.in_block_comment);
        assert_eq!(state.block_comment_depth, 0);
        // Every word should be a comment
        for t in &tokens {
            assert_eq!(
                t.context,
                Context::Comment,
                "token {:?} should be Comment",
                t.text
            );
        }
    }

    #[test]
    fn test_nested_block_comment_c_not_nested() {
        // C does not support nested comments; the first */ closes
        let mut state = TokenizerState::default();
        let tokens = tokenize_line("/* /* inner */ outside", "c", &mut state, 1);
        assert!(!state.in_block_comment);
        let idents: Vec<_> = tokens
            .iter()
            .filter(|t| t.context == Context::Identifier)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(idents, vec!["outside"]);
    }

    #[test]
    fn test_backtick_template_literal_multiline_js() {
        let mut state = TokenizerState::default();
        let t1 = tokenize_line("let s = `hello", "javascript", &mut state, 1);
        assert!(state.in_multiline_string);
        assert_eq!(state.string_delimiter.as_deref(), Some("`"));
        assert!(t1
            .iter()
            .any(|t| t.text == "let" && t.context == Context::Identifier));
        assert!(t1
            .iter()
            .any(|t| t.text == "s" && t.context == Context::Identifier));
        assert!(t1
            .iter()
            .any(|t| t.text == "hello" && t.context == Context::String));

        let t2 = tokenize_line("world` + x", "javascript", &mut state, 2);
        assert!(!state.in_multiline_string);
        assert!(t2
            .iter()
            .any(|t| t.text == "world" && t.context == Context::String));
        assert!(t2
            .iter()
            .any(|t| t.text == "x" && t.context == Context::Identifier));
    }

    #[test]
    fn test_col_is_char_offset_not_byte_offset() {
        // "\u{00E9}" is e-acute, 2 bytes in UTF-8.
        // "  \u{00E9}abc" has 'a' at byte offset 4 (2 + 2) but char offset 3 (2 + 1).
        let line = "  \u{00E9}abc";
        let mut state = TokenizerState::default();
        let tokens = tokenize_line(line, "python", &mut state, 1);
        // The tokenizer should produce one identifier: the whole "\u{00E9}abc"
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].text, "\u{00E9}abc");
        // char offset of '\u{00E9}' is 2 (two spaces before it)
        assert_eq!(
            tokens[0].col, 2,
            "col should be char offset, not byte offset"
        );

        // Also test extract_words directly with an offset into multi-byte prefix.
        // "\u{00E9}" is 2 bytes in UTF-8, so "abc" starts at byte offset 4 in line.
        let abc_byte_offset = 4; // 2 spaces + 2 bytes for e-acute
        let words = extract_words(
            line,
            &line[abc_byte_offset..],
            Context::Comment,
            1,
            abc_byte_offset,
        );
        assert_eq!(words.len(), 1);
        assert_eq!(words[0].text, "abc");
        // byte offset 4 in line corresponds to char offset 3
        assert_eq!(words[0].col, 3, "extract_words col should be char offset");
    }

    #[test]
    fn test_byte_to_char_offset_ascii() {
        assert_eq!(byte_to_char_offset("hello", 0), 0);
        assert_eq!(byte_to_char_offset("hello", 3), 3);
        assert_eq!(byte_to_char_offset("hello", 5), 5);
    }

    #[test]
    fn test_byte_to_char_offset_multibyte() {
        // "\u{00E9}" is 2 bytes
        let s = "a\u{00E9}b";
        assert_eq!(byte_to_char_offset(s, 0), 0); // before 'a'
        assert_eq!(byte_to_char_offset(s, 1), 1); // before '\u{00E9}'
        assert_eq!(byte_to_char_offset(s, 3), 2); // before 'b' (1 + 2 bytes for e-acute)
        assert_eq!(byte_to_char_offset(s, 4), 3); // end
    }
}
