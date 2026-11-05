use std::collections::BTreeMap;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Parses `KEY=VALUE` lines: blank lines, `#` comments and an `export ` prefix are skipped;
/// values may be single-quoted (literal), double-quoted (with `\n`, `\r`, `\t`, `\"`, `\\`
/// escapes) or bare (ended by ` #`). Quoted values may span lines. No variable expansion.
///
/// Errors carry a line number only, never the line, which may hold a value.
pub fn parse(input: &str) -> Result<BTreeMap<String, String>> {
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser {
        chars: &chars,
        pos: 0,
        line: 1,
    };
    let mut out = BTreeMap::new();
    loop {
        p.skip_while(|c| c.is_whitespace());
        let Some(c) = p.peek() else { break };
        if c == '#' {
            p.skip_while(|c| c != '\n');
            continue;
        }
        let mut key = p.take_while(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
        if key == "export" && p.peek().is_some_and(|c| c == ' ' || c == '\t') {
            p.skip_while(|c| c == ' ' || c == '\t');
            key = p.take_while(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
        }
        if key.is_empty() || key.starts_with(|c: char| c.is_ascii_digit()) {
            bail!("line {}: invalid key", p.line);
        }
        p.skip_while(|c| c == ' ' || c == '\t');
        if p.next() != Some('=') {
            bail!("line {}: expected KEY=VALUE", p.line);
        }
        p.skip_while(|c| c == ' ' || c == '\t');
        let value = match p.peek() {
            Some(q @ ('\'' | '"')) => {
                p.next();
                let value = p.quoted(q)?;
                p.skip_while(|c| c == ' ' || c == '\t');
                match p.peek() {
                    None | Some('\n') => {}
                    Some('#') => p.skip_while(|c| c != '\n'),
                    Some(_) => bail!("line {}: unexpected text after closing quote", p.line),
                }
                value
            }
            _ => p.bare(),
        };
        out.insert(key, value);
    }
    Ok(out)
}

/// SHA-256 over the sorted pairs, each field length-prefixed so that no two sets collide by
/// concatenation.
pub fn fingerprint<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> [u8; 32] {
    let mut sorted: Vec<_> = pairs.into_iter().collect();
    sorted.sort();
    let mut h = Sha256::new();
    for (k, v) in sorted {
        for field in [k, v] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
    }
    h.finalize().into()
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
    line: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn take_while(&mut self, f: impl Fn(char) -> bool) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek().filter(|&c| f(c)) {
            s.push(c);
            self.next();
        }
        s
    }

    fn skip_while(&mut self, f: impl Fn(char) -> bool) {
        self.take_while(f);
    }

    fn quoted(&mut self, quote: char) -> Result<String> {
        let start = self.line;
        let mut s = String::new();
        loop {
            match self.next() {
                None => bail!("line {start}: unterminated quoted value"),
                Some(c) if c == quote => return Ok(s),
                Some('\\') if quote == '"' => match self.next() {
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some(c @ ('"' | '\\' | '$')) => s.push(c),
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => bail!("line {start}: unterminated quoted value"),
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn bare(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek().filter(|&c| c != '\n') {
            if c == '#' && s.ends_with([' ', '\t']) {
                self.skip_while(|c| c != '\n');
                break;
            }
            s.push(c);
            self.next();
        }
        s.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_comments_and_export() {
        let input = r#"
# comment
export A=plain value # trailing comment
B = 'single # not a comment'
C="double \"quoted\"\nnext"
D=
E=x#y
F="multi
line" # after
"#;
        let m = parse(input).unwrap();
        assert_eq!(m["A"], "plain value");
        assert_eq!(m["B"], "single # not a comment");
        assert_eq!(m["C"], "double \"quoted\"\nnext");
        assert_eq!(m["D"], "");
        assert_eq!(m["E"], "x#y");
        assert_eq!(m["F"], "multi\nline");
        assert_eq!(m.len(), 6);
    }

    #[test]
    fn errors_name_the_line_but_not_the_value() {
        let err = parse("A=1\nnot a pair secretvalue\n")
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("line 2"), "{err}");
        assert!(!err.contains("secretvalue"));
        assert!(parse("A=\"open").is_err());
    }

    #[test]
    fn fingerprint_is_order_independent_and_unambiguous() {
        assert_eq!(
            fingerprint([("A", "1"), ("B", "2")]),
            fingerprint([("B", "2"), ("A", "1")])
        );
        assert_ne!(fingerprint([("AB", "")]), fingerprint([("A", "B")]));
    }
}
