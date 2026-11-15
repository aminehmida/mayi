//! Replaces secret values in a command's output before the agent sees it.
//!
//! This is a guard against accidental leaks (a tool echoing its token), not
//! against a command that sets out to hide the value: any encoding not listed
//! here passes through. The real control is the approval of the command.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;

const MASK: &[u8] = b"[masked]";

/// Shorter values would turn ordinary output into noise.
const MIN_LEN: usize = 4;

pub struct Masker {
    /// Longest first, so a value is preferred over a prefix of itself.
    patterns: Vec<Vec<u8>>,
    /// Output held back because it may be the start of a pattern.
    pending: Vec<u8>,
}

impl Masker {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        for value in values {
            if value.len() < MIN_LEN {
                continue;
            }
            patterns.push(value.as_bytes().to_vec());
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                patterns.push(engine.encode(value).into_bytes());
            }
            patterns.push(hex::encode(value).into_bytes());
            patterns.push(hex::encode_upper(value).into_bytes());
        }
        patterns.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        patterns.dedup();
        Self { patterns, pending: Vec::new() }
    }

    /// Feeds a chunk of output and returns what is safe to print now.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let mut out = self.replace(&self.pending);
        let hold = self.partial_suffix(&out);
        self.pending = out.split_off(out.len() - hold);
        out
    }

    /// Returns whatever was held back. Call once the output has ended.
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    fn replace(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            match self.patterns.iter().find(|p| data[i..].starts_with(p)) {
                Some(pattern) => {
                    out.extend_from_slice(MASK);
                    i += pattern.len();
                }
                None => {
                    out.push(data[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// Length of the longest tail of `data` that is a proper prefix of a pattern.
    fn partial_suffix(&self, data: &[u8]) -> usize {
        let longest = self.patterns.first().map_or(0, |p| p.len() - 1);
        (1..=longest.min(data.len()))
            .rev()
            .find(|&n| {
                let tail = &data[data.len() - n..];
                self.patterns.iter().any(|p| p.len() > n && p.starts_with(tail))
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(masker: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(masker.feed(chunk));
        }
        out.extend(masker.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_raw_and_encoded_values() {
        let mut m = Masker::new(["s3cr3t-token"]);
        let b64 = STANDARD.encode("s3cr3t-token");
        let hexed = hex::encode("s3cr3t-token");
        let input = format!("a s3cr3t-token b {b64} c {hexed} d");
        assert_eq!(run(&mut m, &[input.as_bytes()]), "a [masked] b [masked] c [masked] d");
    }

    #[test]
    fn masks_across_chunk_boundaries() {
        let secret = "s3cr3t-token";
        for split in 1..secret.len() {
            let mut m = Masker::new([secret]);
            let (a, b) = secret.split_at(split);
            let first = format!("x{a}");
            let second = format!("{b}y");
            assert_eq!(run(&mut m, &[first.as_bytes(), second.as_bytes()]), "x[masked]y");
        }
        let mut m = Masker::new([secret]);
        let bytes: Vec<&[u8]> = secret.as_bytes().chunks(1).collect();
        assert_eq!(run(&mut m, &bytes), "[masked]");
    }

    #[test]
    fn unrelated_output_is_not_delayed() {
        let mut m = Masker::new(["s3cr3t-token"]);
        assert_eq!(m.feed(b"building...\n"), b"building...\n");
        // Only a possible start of the value is held back.
        assert_eq!(m.feed(b"key=s3c"), b"key=");
        assert_eq!(m.feed(b"ond\n"), b"s3cond\n");
        assert!(m.finish().is_empty());
    }

    #[test]
    fn partial_value_at_end_is_flushed() {
        let mut m = Masker::new(["s3cr3t-token"]);
        assert_eq!(run(&mut m, &[b"tail s3cr3"]), "tail s3cr3");
    }

    #[test]
    fn short_values_are_ignored_and_several_values_work() {
        let mut m = Masker::new(["abc", "first-secret", "second-secret"]);
        assert_eq!(
            run(&mut m, &[b"abc first-secret second-secret abc"]),
            "abc [masked] [masked] abc"
        );
        let mut none = Masker::new(std::iter::empty());
        assert_eq!(run(&mut none, &[b"plain"]), "plain");
    }
}
