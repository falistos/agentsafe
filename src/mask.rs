use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, ErrorKind, Read, Write};

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

/// Values and encoded variants shorter than this are not masked: short strings occur in
/// ordinary output and masking them would corrupt it.
pub const MIN_LEN: usize = 6;

pub struct Masker {
    ac: Option<AhoCorasick>,
    /// Base64 patterns only. Searched on a copy of the input with `\n` and `\r` removed, so a
    /// wrapped encoding matches at any column width. Other spellings stay contiguous: a line
    /// break there is part of the text, not an encoder's wrap.
    fold: Option<AhoCorasick>,
    patterns: Vec<Vec<u8>>,
    markers: Vec<String>,
    /// Parallel to `patterns`: this pattern is base64 and matches with line breaks inside it.
    fold_newlines: Vec<bool>,
    /// Pattern index in `patterns` / `markers` for each pattern of `fold`.
    fold_of: Vec<usize>,
    by_first_byte: Vec<Vec<usize>>,
    max_len: usize,
    fold_max_len: usize,
}

impl Masker {
    /// Takes `(entry name, value)` pairs; a match of any variant of a value is replaced with
    /// `***<entry name>***`.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut seen = HashMap::new();
        let mut patterns = Vec::new();
        let mut markers = Vec::new();
        let mut fold_newlines = Vec::new();
        for (name, value) in secrets {
            if value.len() < MIN_LEN {
                continue;
            }
            for (p, fold) in variants(value) {
                if p.len() < MIN_LEN {
                    continue;
                }
                if let Some(&i) = seen.get(&p) {
                    // The same bytes can be the raw value and a base64 form. Folding then still
                    // matches the encoding when an encoder wraps it.
                    if fold {
                        fold_newlines[i] = true;
                    }
                    continue;
                }
                seen.insert(p.clone(), patterns.len());
                patterns.push(p);
                markers.push(format!("***{name}***"));
                fold_newlines.push(fold);
            }
        }
        // The output is not masked again, so a marker that contains a pattern (a value equal to
        // its entry's name, say) would print it; `***` is shorter than any pattern.
        for marker in &mut markers {
            if patterns.iter().any(|p| {
                marker
                    .as_bytes()
                    .windows(p.len())
                    .any(|w| w == p.as_slice())
            }) {
                *marker = "***".into();
            }
        }
        let mut by_first_byte = vec![Vec::new(); 256];
        for (i, p) in patterns.iter().enumerate() {
            by_first_byte[usize::from(p[0])].push(i);
        }
        let ac = (!patterns.is_empty()).then(|| automaton(&patterns));
        let mut fold_patterns = Vec::new();
        let mut fold_of = Vec::new();
        for (i, fold) in fold_newlines.iter().enumerate() {
            if *fold {
                fold_patterns.push(&patterns[i]);
                fold_of.push(i);
            }
        }
        let fold = (!fold_patterns.is_empty()).then(|| automaton(&fold_patterns));
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let fold_max_len = fold_of
            .iter()
            .map(|&i| patterns[i].len())
            .max()
            .unwrap_or(0);
        Masker {
            ac,
            fold,
            patterns,
            markers,
            fold_newlines,
            fold_of,
            by_first_byte,
            max_len,
            fold_max_len,
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

    /// Start of the shortest tail of `buf` that may still grow into a pattern. Those bytes wait
    /// for more input. For base64, `\n` and `\r` inside that tail do not end it.
    fn hold_point(&self, buf: &[u8]) -> usize {
        self.contiguous_hold(buf).min(self.folded_hold(buf))
    }

    fn contiguous_hold(&self, buf: &[u8]) -> usize {
        self.prefix_hold(buf, PatternSet::All)
    }

    fn folded_hold(&self, buf: &[u8]) -> usize {
        if self.fold_max_len == 0 {
            return buf.len();
        }
        let (flat, map) = without_line_breaks(buf);
        let hold = self.prefix_hold(&flat, PatternSet::Folded);
        if hold >= flat.len() {
            buf.len()
        } else {
            map[hold]
        }
    }

    fn prefix_hold(&self, buf: &[u8], set: PatternSet) -> usize {
        let max = match set {
            PatternSet::All => self.max_len,
            PatternSet::Folded => self.fold_max_len,
        };
        if max == 0 {
            return buf.len();
        }
        let from = buf.len().saturating_sub(max.saturating_sub(1));
        (from..buf.len())
            .find(|&i| {
                let tail = &buf[i..];
                self.by_first_byte[usize::from(tail[0])].iter().any(|&p| {
                    let included = match set {
                        PatternSet::All => true,
                        PatternSet::Folded => self.fold_newlines[p],
                    };
                    included
                        && self.patterns[p].len() > tail.len()
                        && self.patterns[p].starts_with(tail)
                })
            })
            .unwrap_or(buf.len())
    }
}

#[derive(Clone, Copy)]
enum PatternSet {
    All,
    Folded,
}

fn automaton(patterns: &[impl AsRef<[u8]>]) -> AhoCorasick {
    // Not the DFA that the default picks for few patterns: its build follows failure
    // links per byte class and is quadratic on long periodic values.
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .kind(Some(AhoCorasickKind::ContiguousNFA))
        .build(patterns)
        .expect("patterns are small enough for aho-corasick")
}

/// Drops `\n` and `\r`, and records where each kept byte sat in `buf`.
fn without_line_breaks(buf: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut flat = Vec::with_capacity(buf.len());
    let mut map = Vec::with_capacity(buf.len());
    for (i, &b) in buf.iter().enumerate() {
        if b != b'\n' && b != b'\r' {
            flat.push(b);
            map.push(i);
        }
    }
    (flat, map)
}

pub struct Stream<'a> {
    masker: &'a Masker,
    held: Vec<u8>,
}

impl Stream<'_> {
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        self.held.extend_from_slice(chunk);
        let hold = self.masker.hold_point(&self.held);
        self.process(hold, out);
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.process(self.held.len(), out);
    }

    /// Masks what is held and writes it out, except the bytes from `hold` on, which wait for more
    /// input.
    fn process(&mut self, hold: usize, out: &mut Vec<u8>) {
        let buf = std::mem::take(&mut self.held);
        let Some(ac) = &self.masker.ac else {
            out.extend_from_slice(&buf);
            return;
        };
        // A match starting before the hold point is final: any longer pattern starting at the
        // same offset would either be complete in `buf` or move the hold point before it.
        let mut hits = Vec::new();
        for m in ac.find_iter(&buf) {
            if m.start() >= hold {
                break;
            }
            hits.push(Hit {
                start: m.start(),
                end: m.end(),
                marker: m.pattern().as_usize(),
            });
        }
        if let Some(fold) = &self.masker.fold {
            let (flat, map) = without_line_breaks(&buf);
            for m in fold.find_iter(&flat) {
                let start = map[m.start()];
                let end = map[m.end() - 1] + 1;
                if start >= hold {
                    continue;
                }
                hits.push(Hit {
                    start,
                    end,
                    marker: self.masker.fold_of[m.pattern().as_usize()],
                });
            }
        }
        // Earliest start, then the longest span, then the earliest pattern. That is the same
        // choice as `MatchKind::LeftmostLongest` once line breaks have been mapped back.
        hits.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then(b.end.cmp(&a.end))
                .then(a.marker.cmp(&b.marker))
        });
        let mut pos = 0;
        for hit in hits {
            if hit.start < pos || hit.start >= hold {
                continue;
            }
            out.extend_from_slice(&buf[pos..hit.start]);
            out.extend_from_slice(self.masker.markers[hit.marker].as_bytes());
            pos = hit.end;
        }
        let cut = pos.max(hold);
        out.extend_from_slice(&buf[pos..cut]);
        self.held = buf[cut..].to_vec();
    }
}

struct Hit {
    start: usize,
    end: usize,
    marker: usize,
}

/// `(bytes, fold line breaks)`. Line breaks fold only for base64: a wrapped encoding may break
/// at any column, and `\n` / `\r` are not characters of that encoding.
fn variants(value: &str) -> Vec<(Vec<u8>, bool)> {
    let v = value.as_bytes();
    let mut out = vec![(v.to_vec(), false)];
    // Inside a larger base64 blob (e.g. `user:password`), the value's encoding depends on its
    // alignment, so encode it from each of the three offsets and keep only the characters that
    // do not depend on the bytes that follow it.
    for offset in 0..3.min(v.len()) {
        let tail = &v[offset..];
        let determined = tail.len() * 4 / 3;
        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            if determined >= MIN_LEN || tail.len().is_multiple_of(3) {
                let mut encoded = engine.encode(tail);
                encoded.truncate(determined);
                out.push((encoded.into_bytes(), true));
                continue;
            }
            // Too short to mask alone: add the next character, which mixes the tail's last bits
            // with the following byte, in each form that byte can give it.
            let mut padded = tail.to_vec();
            padded.push(0);
            for next in 0..=u8::MAX {
                *padded.last_mut().expect("just pushed") = next;
                let mut encoded = engine.encode(&padded);
                encoded.truncate(determined + 1);
                out.push((encoded.into_bytes(), true));
            }
        }
    }
    out.push((hex::encode(v).into_bytes(), false));
    out.push((hex::encode_upper(v).into_bytes(), false));
    let json = serde_json::to_string(value).expect("a string always serializes");
    let json = &json[1..json.len() - 1];
    for ascii in [false, true] {
        for slash in [false, true] {
            let spelled = json_variant(json, ascii, slash);
            out.push((go_html_escapes(&spelled).into_bytes(), false));
            out.push((spelled.into_bytes(), false));
        }
    }
    for upper in [true, false] {
        out.push((percent_encode(v, upper, b"").into_bytes(), false));
        // `encodeURIComponent` also leaves these unescaped.
        out.push((percent_encode(v, upper, b"!*'()").into_bytes(), false));
    }
    out
}

/// Go's `encoding/json` writes `&`, `<` and `>` as `\u0026`, `\u003c` and `\u003e`.
fn go_html_escapes(json: &str) -> String {
    let mut s = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '&' => s.push_str("\\u0026"),
            '<' => s.push_str("\\u003c"),
            '>' => s.push_str("\\u003e"),
            c => s.push(c),
        }
    }
    s
}

/// `serde_json`'s escaping, with non-ASCII as lower-case `\uXXXX` (surrogate pairs above
/// U+FFFF, as Python's `json.dumps` writes it) and/or `/` as `\/` (as PHP's `json_encode` does).
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "private, and `variants` passes every combination of the two flags"
)]
fn json_variant(json: &str, ascii: bool, slash: bool) -> String {
    let mut s = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '/' if slash => s.push_str("\\/"),
            c if ascii && !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(s, "\\u{unit:04x}").expect("writing to a String cannot fail");
                }
            }
            c => s.push(c),
        }
    }
    s
}

#[expect(
    clippy::fn_params_excessive_bools,
    reason = "private, and `variants` passes both cases"
)]
fn percent_encode(v: &[u8], upper: bool, also_literal: &[u8]) -> String {
    let mut s = String::new();
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || also_literal.contains(&b) {
            s.push(char::from(b));
        } else if upper {
            write!(s, "%{b:02X}").expect("writing to a String cannot fail");
        } else {
            write!(s, "%{b:02x}").expect("writing to a String cannot fail");
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
    fn masks_base64_of_a_six_byte_value_at_every_alignment() {
        let m = Masker::new([("short", "s3cr3t")]);
        for prefix in ["", "a", "ab", "abcd"] {
            for tail in ["", "tail"] {
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{prefix}s3cr3t{tail}"));
                let out = mask(&m, &[encoded.as_bytes()]);
                assert!(out.contains("***short***"), "{prefix:?}+{tail:?}: {out}");
            }
        }
    }

    #[test]
    fn a_marker_that_would_print_a_value_is_shortened() {
        let m = Masker::new([("github", "github"), ("other", "***oth")]);
        assert_eq!(mask(&m, &[b"x github y ***oth z"]), "x *** y *** z");
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
            format!(
                "https://x/?t={}",
                percent_encode(SECRET.as_bytes(), true, b"")
            ),
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

    /// A multiple of 3 so the base64 has no `=` padding, and longer than 57 bytes so a
    /// 76-column encoder wraps it. `+` and `/` make the standard and URL-safe forms differ.
    fn wrapped_value() -> String {
        let mut value = String::from("wrap+secret/value?0123456789abcdefghijklmnopqrstuvwxyz!!");
        while value.len() < 60 || !value.len().is_multiple_of(3) {
            value.push('x');
        }
        value
    }

    fn wrap_columns(encoded: &str, width: usize, sep: &str) -> String {
        let mut out = String::new();
        for (i, chunk) in encoded.as_bytes().chunks(width).enumerate() {
            if i > 0 {
                out.push_str(sep);
            }
            out.push_str(std::str::from_utf8(chunk).unwrap());
        }
        out
    }

    #[test]
    fn masks_base64_wrapped_on_any_column() {
        let value = wrapped_value();
        let m = Masker::new([("tok", value.as_str())]);
        for width in [1, 13, 64, 76] {
            for sep in ["\n", "\r\n"] {
                for engine in [
                    base64::engine::general_purpose::STANDARD,
                    base64::engine::general_purpose::URL_SAFE,
                ] {
                    let encoded = engine.encode(&value);
                    let wrapped = wrap_columns(&encoded, width, sep);
                    assert!(wrapped.contains(sep), "width {width}");
                    let out = mask(&m, &[wrapped.as_bytes()]);
                    assert_eq!(out, "***tok***", "width {width} sep {sep:?}: {out}");
                }
            }
        }
    }

    #[test]
    fn masks_wrapped_base64_split_at_every_byte() {
        let value = wrapped_value();
        let m = Masker::new([("tok", value.as_str())]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
        let wrapped = wrap_columns(&encoded, 64, "\r\n");
        let bytes = wrapped.as_bytes();
        for i in 0..bytes.len() {
            let out = mask(&m, &[&bytes[..i], &bytes[i..]]);
            assert_eq!(out, "***tok***", "split at {i}: {out}");
        }
        let chunks: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(mask(&m, &chunks), "***tok***");
        let out = mask(&m, &[format!("{wrapped}\n").as_bytes()]);
        assert_eq!(out, "***tok***\n");
    }

    #[test]
    fn masks_base64_wrapped_inside_a_larger_blob() {
        let value = wrapped_value();
        let m = Masker::new([("tok", value.as_str())]);
        for prefix in ["", "q", "qq", "prefix-bytes:"] {
            let blob = format!("{prefix}{value}tail");
            let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
            let wrapped = wrap_columns(&encoded, 76, "\n");
            let out = mask(&m, &[wrapped.as_bytes()]);
            assert!(out.contains("***tok***"), "prefix {prefix:?}: {out}");
        }
    }

    #[test]
    fn masks_wrapped_base64_split_on_the_read_size() {
        let mut value = String::new();
        for i in 0..1800 {
            write!(value, "{i:04x}").unwrap();
        }
        assert_eq!(value.len(), 7200);
        let m = Masker::new([("tok", value.as_str())]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
        let wrapped = wrap_columns(&encoded, 76, "\n");
        assert!(wrapped.len() > 8192, "{}", wrapped.len());
        let b = wrapped.as_bytes();
        let out = mask(&m, &[&b[..8192], &b[8192..]]);
        assert!(
            out == "***tok***",
            "split on 8192 was not masked ({} bytes out)",
            out.len()
        );
    }

    #[test]
    fn a_line_break_does_not_join_a_raw_or_hex_spelling() {
        let m = masker();
        let broken_raw = SECRET.replace("Value", "Val\nue");
        assert_eq!(mask(&m, &[broken_raw.as_bytes()]), broken_raw);
        let hexed = hex::encode(SECRET);
        let broken_hex = format!("{}\n{}", &hexed[..8], &hexed[8..]);
        assert_eq!(mask(&m, &[broken_hex.as_bytes()]), broken_hex);
    }

    #[test]
    fn masks_go_json_escapes_and_encode_uri_component() {
        let value = "a&b<c>d/e!f*g(h)i'j";
        let m = Masker::new([("tok", value)]);
        let go = value
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e");
        assert_ne!(go, value);
        let js = |upper: bool| {
            let mut s = String::new();
            for &b in value.as_bytes() {
                let literal = b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'-' | b'.' | b'_' | b'~' | b'!' | b'*' | b'\'' | b'(' | b')'
                    );
                if literal {
                    s.push(char::from(b));
                } else if upper {
                    write!(s, "%{b:02X}").unwrap();
                } else {
                    write!(s, "%{b:02x}").unwrap();
                }
            }
            s
        };
        let js_lower = js(false);
        assert_ne!(js_lower, percent_encode(value.as_bytes(), false, b""));
        assert_ne!(js_lower, value);
        let mut missed = Vec::new();
        for text in [go, js_lower, js(true)] {
            let out = mask(&m, &[format!("<{text}>").as_bytes()]);
            if out != "<***tok***>" {
                missed.push(format!("{text} -> {out}"));
            }
        }
        assert!(missed.is_empty(), "{missed:?}");
    }
}
