use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

/// Values and encoded variants shorter than this are not masked: short strings occur in
/// ordinary output and masking them would corrupt it.
pub const MIN_LEN: usize = 6;

pub struct Masker {
    ac: Option<AhoCorasick>,
    patterns: Vec<Vec<u8>>,
    markers: Vec<String>,
    by_first_byte: Vec<Vec<usize>>,
    max_len: usize,
}

impl Masker {
    /// Takes `(entry name, value)` pairs; a match of any variant of a value is replaced with
    /// `***<entry name>***`.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut seen = HashSet::new();
        let mut patterns = Vec::new();
        let mut markers = Vec::new();
        for (name, value) in secrets {
            if value.len() < MIN_LEN {
                continue;
            }
            for p in variants(value) {
                if p.len() >= MIN_LEN && seen.insert(p.clone()) {
                    patterns.push(p);
                    markers.push(format!("***{name}***"));
                }
            }
        }
        let mut by_first_byte = vec![Vec::new(); 256];
        for (i, p) in patterns.iter().enumerate() {
            by_first_byte[p[0] as usize].push(i);
        }
        let ac = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .expect("patterns are small enough for aho-corasick")
        });
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        Masker {
            ac,
            patterns,
            markers,
            by_first_byte,
            max_len,
        }
    }

    pub fn stream(&self) -> Stream<'_> {
        Stream {
            masker: self,
            held: Vec::new(),
        }
    }

    /// Copies `r` to `w` masked, flushing after each read so interactive output stays live.
    pub fn copy(&self, mut r: impl Read, mut w: impl Write) -> io::Result<()> {
        let mut stream = self.stream();
        let mut buf = vec![0; 8192];
        let mut out = Vec::new();
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            out.clear();
            stream.push(&buf[..n], &mut out);
            w.write_all(&out)?;
            w.flush()?;
        }
        out.clear();
        stream.finish(&mut out);
        w.write_all(&out)?;
        w.flush()
    }

    /// Start of the shortest tail of `buf` that is a proper prefix of some pattern: those bytes
    /// may be the start of a value cut by the read boundary, so they wait for more input.
    fn hold_point(&self, buf: &[u8]) -> usize {
        let from = buf.len().saturating_sub(self.max_len.saturating_sub(1));
        (from..buf.len())
            .find(|&i| {
                let tail = &buf[i..];
                self.by_first_byte[tail[0] as usize].iter().any(|&p| {
                    let p = &self.patterns[p];
                    p.len() > tail.len() && p.starts_with(tail)
                })
            })
            .unwrap_or(buf.len())
    }
}

pub struct Stream<'a> {
    masker: &'a Masker,
    held: Vec<u8>,
}

impl Stream<'_> {
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.process(chunk, false, out);
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.process(&[], true, out);
    }

    fn process(&mut self, chunk: &[u8], eof: bool, out: &mut Vec<u8>) {
        self.held.extend_from_slice(chunk);
        let buf = std::mem::take(&mut self.held);
        let Some(ac) = &self.masker.ac else {
            out.extend_from_slice(&buf);
            return;
        };
        // A match starting before the hold point is final: any longer pattern starting at the
        // same offset would either be complete in `buf` or move the hold point before it.
        let hold = if eof {
            buf.len()
        } else {
            self.masker.hold_point(&buf)
        };
        let mut pos = 0;
        for m in ac.find_iter(&buf) {
            if m.start() >= hold {
                break;
            }
            out.extend_from_slice(&buf[pos..m.start()]);
            out.extend_from_slice(self.masker.markers[m.pattern().as_usize()].as_bytes());
            pos = m.end();
        }
        let cut = pos.max(hold);
        out.extend_from_slice(&buf[pos..cut]);
        self.held = buf[cut..].to_vec();
    }
}

fn variants(value: &str) -> Vec<Vec<u8>> {
    let v = value.as_bytes();
    let mut out = vec![v.to_vec()];
    // Inside a larger base64 blob (e.g. `user:password`), the value's encoding depends on its
    // alignment, so encode it from each of the three offsets and keep only the characters that
    // do not depend on the bytes that follow it.
    for offset in 0..3.min(v.len()) {
        let tail = &v[offset..];
        let determined = tail.len() * 4 / 3;
        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            let mut encoded = engine.encode(tail);
            encoded.truncate(determined);
            out.push(encoded.into_bytes());
        }
    }
    out.push(hex::encode(v).into_bytes());
    out.push(hex::encode_upper(v).into_bytes());
    let json = serde_json::to_string(value).expect("a string always serializes");
    let json = &json[1..json.len() - 1];
    for ascii in [false, true] {
        for slash in [false, true] {
            out.push(json_variant(json, ascii, slash).into_bytes());
        }
    }
    out.push(percent_encode(v, true).into_bytes());
    out.push(percent_encode(v, false).into_bytes());
    out
}

/// `serde_json`'s escaping, with non-ASCII as lower-case `\uXXXX` (surrogate pairs above
/// U+FFFF, as Python's `json.dumps` writes it) and/or `/` as `\/` (as PHP's `json_encode` does).
fn json_variant(json: &str, ascii: bool, slash: bool) -> String {
    let mut s = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '/' if slash => s.push_str("\\/"),
            c if ascii && !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    s.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => s.push(c),
        }
    }
    s
}

fn percent_encode(v: &[u8], upper: bool) -> String {
    let mut s = String::new();
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            s.push(b as char);
        } else if upper {
            s.push_str(&format!("%{b:02X}"));
        } else {
            s.push_str(&format!("%{b:02x}"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-Value/with+odd=chars\"q\\";

    fn mask(m: &Masker, chunks: &[&[u8]]) -> String {
        let mut stream = m.stream();
        let mut out = Vec::new();
        for c in chunks {
            stream.push(c, &mut out);
        }
        stream.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    fn masker() -> Masker {
        Masker::new([("tok", SECRET)])
    }

    #[test]
    fn masks_plain_value() {
        assert_eq!(
            mask(&masker(), &[format!("a {SECRET} b").as_bytes()]),
            "a ***tok*** b"
        );
    }

    #[test]
    fn masks_value_split_at_every_offset() {
        let m = masker();
        let text = format!("before {SECRET} after {SECRET}");
        for i in 0..text.len() {
            for j in i..text.len() {
                let b = text.as_bytes();
                let out = mask(&m, &[&b[..i], &b[i..j], &b[j..]]);
                assert_eq!(out, "before ***tok*** after ***tok***", "split at {i},{j}");
            }
        }
    }

    #[test]
    fn masks_byte_by_byte_input() {
        let text = format!("x{SECRET}y");
        let chunks: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        assert_eq!(mask(&masker(), &chunks), "x***tok***y");
    }

    #[test]
    fn holds_back_only_a_possible_value_prefix() {
        let m = masker();
        let mut stream = m.stream();
        let mut out = Vec::new();
        stream.push(b"hello s3cr", &mut out);
        assert_eq!(out, b"hello ");
        out.clear();
        stream.push(b"ap", &mut out);
        assert_eq!(out, b"s3crap");
        out.clear();
        stream.push(b"s3cr", &mut out);
        stream.finish(&mut out);
        assert_eq!(out, b"s3cr");
    }

    #[test]
    fn masks_base64_at_every_alignment() {
        let m = masker();
        for prefix in ["", "u:", "user:", "a"] {
            let blob = format!("{prefix}{SECRET}tail");
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE,
            ] {
                let encoded = engine.encode(&blob);
                let out = mask(&m, &[encoded.as_bytes()]);
                assert!(out.contains("***tok***"), "prefix {prefix:?}: {out}");
            }
        }
    }

    #[test]
    fn masks_base64_of_value_at_end_of_input() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(SECRET);
        let out = mask(&masker(), &[format!("{encoded}\n").as_bytes()]);
        assert!(out.starts_with("***tok***"), "{out}");
        assert!(!out.contains(&encoded));
    }

    #[test]
    fn masks_hex_json_and_url_encodings() {
        let m = masker();
        let json = serde_json::to_string(&serde_json::json!({ "k": SECRET })).unwrap();
        for text in [
            hex::encode(SECRET),
            hex::encode_upper(SECRET),
            json,
            format!("https://x/?t={}", percent_encode(SECRET.as_bytes(), true)),
        ] {
            let out = mask(&m, &[text.as_bytes()]);
            assert!(out.contains("***tok***"), "{text} -> {out}");
        }
    }

    #[test]
    fn short_values_are_not_masked() {
        let m = Masker::new([("pin", "12345")]);
        assert_eq!(mask(&m, &[b"pin 12345"]), "pin 12345");
    }

    #[test]
    fn longest_value_wins_when_one_extends_another() {
        let m = Masker::new([("short", "abcdefgh"), ("long", "abcdefgh-ijkl")]);
        assert_eq!(
            mask(&m, &[b"abcdefgh-ij", b"kl abcdefgh."]),
            "***long*** ***short***."
        );
    }
}
