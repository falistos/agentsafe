use std::collections::BTreeMap;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Parses `KEY=VALUE` lines: blank lines, `#` comments and an `export ` prefix are skipped;
/// values may be single-quoted (literal), double-quoted (with `\n`, `\r`, `\t`, `\"`, `\\`
/// escapes) or bare (ended by ` #`). Quoted values may span lines. No variable expansion.
/// Keys are `[A-Za-z0-9_.-]` and do not start with a digit.
///
/// Input whose keys all lack a value (empty, or only `=` characters) is refused: a base64 token
/// with `=` padding would otherwise be stored as a key name, which is public metadata.
///
/// Errors carry a line number only, never the line, which may hold a value.
pub fn parse(input: &str) -> Result<BTreeMap<String, String>> {
    // CRLF line endings read as LF, inside quoted values too; a lone `\r` is kept.
    let mut chars: Vec<char> = Vec::with_capacity(input.len());
    let mut it = input.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\r' || it.peek() != Some(&'\n') {
            chars.push(c);
        }
    }
    let mut p = Parser {
        chars: &chars,
        pos: 0,
        line: 1,
    };
    let mut out = BTreeMap::new();
    loop {
        p.skip_while(char::is_whitespace);
        let Some(c) = p.peek() else { break };
        if c == '#' {
            p.skip_while(|c| c != '\n');
            continue;
        }
        let mut key = p.take_while(is_key_char);
        if key == "export" && p.peek().is_some_and(|c| c == ' ' || c == '\t') {
            p.skip_while(|c| c == ' ' || c == '\t');
            key = p.take_while(is_key_char);
        }
        if key.is_empty() || key.starts_with(|c: char| c.is_ascii_digit()) {
            bail!("line {}: invalid key", p.line);
        }
        p.skip_while(|c| c == ' ' || c == '\t');
        if p.peek() != Some('=') {
            bail!("line {}: expected KEY=VALUE", p.line);
        }
        p.next();
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
    if !out.is_empty() && out.values().all(|v| v.chars().all(|c| c == '=')) {
        bail!(
            "no key has a value; to store the whole input as one value, run \
             `agentsafe set NAME --key KEY < FILE`"
        );
    }
    Ok(out)
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// Every write holds to the key grammar `parse` reads, so a key never contains `=`, which
/// `run --env NAME:KEY=VAR` splits on.
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.starts_with(|c: char| c.is_ascii_digit())
        || !key.chars().all(is_key_char)
    {
        // Not echoed: a value pasted where the key goes would land in the agent's transcript.
        bail!("invalid key: use letters, digits, '_', '.' or '-', not starting with a digit");
    }
    Ok(())
}

/// SHA-256 over the sorted pairs, each field length-prefixed so that no two sets collide by
/// concatenation.
pub fn fingerprint<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> [u8; 32] {
    let mut sorted: Vec<_> = pairs.into_iter().collect();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for (k, v) in sorted {
        for field in [k, v] {
            h.update(
                u64::try_from(field.len())
                    .expect("a length fits in u64")
                    .to_le_bytes(),
            );
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
        let err = parse("A=1\nleaked-looking-line\n").unwrap_err().to_string();
        assert!(err.starts_with("line 2"), "{err}");
    }

    #[test]
    fn input_without_a_value_is_refused_without_naming_it() {
        for input in [
            "dGhpc2lzYXNlY3JldHRva2Vu=\n",
            "dGhpc2lzYXNlY3JldHRva2Vu==\n",
            "A=\nB=\n",
            "A=\"\"\n",
            "A==\n",
        ] {
            let err = parse(input).unwrap_err().to_string();
            assert!(err.contains("set NAME --key KEY < FILE"), "{err}");
            assert!(!err.contains("dGhpc2"), "{err}");
        }
    }

    #[test]
    fn one_value_is_enough_and_empty_siblings_stay_valid() {
        let m = parse("A=\nB=real\nC=\n").unwrap();
        assert_eq!(m["A"], "");
        assert_eq!(m["B"], "real");
        assert_eq!(m["C"], "");
        assert_eq!(parse("A=x=\n").unwrap()["A"], "x=");
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn keys_accept_dashes_but_not_a_leading_digit() {
        let m = parse("hadaria-prison=v\nexport a-b.c_d=w\n").unwrap();
        assert_eq!(m["hadaria-prison"], "v");
        assert_eq!(m["a-b.c_d"], "w");
        assert!(parse("1-a=v").is_err());
        assert!(parse("-a=v").is_ok());
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
