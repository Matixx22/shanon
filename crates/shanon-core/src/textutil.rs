//! Small, byte-exact text helpers.

/// Regex metacharacter escaping (`re.escape`-equivalent).
///
/// Escapes **only** this fixed set of ASCII characters
/// (`_special_chars_map`), leaving every other character — including all
/// non-ASCII — untouched:
///
/// ```text
/// ( ) [ ] { } ? * + - | ^ $ \ . & ~ #   (space) \t \n \r \v \f
/// ```
pub fn re_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_re_special(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn is_re_special(c: char) -> bool {
    matches!(
        c,
        '(' | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '?'
            | '*'
            | '+'
            | '-'
            | '|'
            | '^'
            | '$'
            | '\\'
            | '.'
            | '&'
            | '~'
            | '#'
            | ' '
            | '\t'
            | '\n'
            | '\r'
            | '\u{0b}'
            | '\u{0c}'
    )
}
