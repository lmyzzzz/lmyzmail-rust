use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::Path,
    sync::LazyLock,
};

use regex::Regex;
use serde::Deserialize;

const MAX_TOKENIZER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_VOCAB_SIZE: usize = 1_048_576;
const MAX_MERGES: usize = 1_048_576;
const END_OF_WORD: &str = "</w>";
const UNK_ID: u32 = 3;

static APOSTROPHE_SPACING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\w) ' (\w)").expect("static InferX regex"));
static CLOSING_SPACING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\s+([.,!?;:'"\-\)\]\}])"#).expect("static InferX regex"));
static OPENING_SPACING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([\(\[\{'"])\s+"#).expect("static InferX regex"));
static NUMBER_DOT_SPACING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d)\.\s+(\d)").expect("static InferX regex"));
static WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("static InferX regex"));

#[derive(Deserialize)]
struct TokenizerDocument {
    vocab_size: usize,
    vocab: HashMap<String, u32>,
    #[serde(default)]
    merges: Vec<[String; 2]>,
}

#[cfg(test)]
#[derive(Clone)]
struct Merge {
    first: Vec<u16>,
    second: Vec<u16>,
    joined: Vec<u16>,
}

pub(crate) struct BpeTokenizer {
    #[cfg(test)]
    vocab: HashMap<Vec<u16>, u32>,
    id_to_token: Vec<Option<String>>,
    #[cfg(test)]
    merges: Vec<Merge>,
    vocab_size: usize,
}

impl BpeTokenizer {
    pub(crate) fn load(path: &Path) -> Result<Self, TokenizerError> {
        let metadata = fs::metadata(path).map_err(TokenizerError::Io)?;
        if metadata.len() == 0 || metadata.len() > MAX_TOKENIZER_BYTES {
            return Err(TokenizerError::Invalid(format!(
                "InferX tokenizer size {} is outside 1..={MAX_TOKENIZER_BYTES}",
                metadata.len()
            )));
        }
        let bytes = fs::read(path).map_err(TokenizerError::Io)?;
        let document: TokenizerDocument =
            serde_json::from_slice(&bytes).map_err(TokenizerError::Json)?;
        if !(4..=MAX_VOCAB_SIZE).contains(&document.vocab_size) {
            return Err(TokenizerError::Invalid(format!(
                "InferX vocab size {} is outside 4..={MAX_VOCAB_SIZE}",
                document.vocab_size
            )));
        }
        if document.vocab.len() > document.vocab_size || document.merges.len() > MAX_MERGES {
            return Err(TokenizerError::Invalid(
                "InferX tokenizer exceeds its vocabulary or merge budget".into(),
            ));
        }

        let mut vocab = HashMap::with_capacity(document.vocab.len());
        let mut id_to_token = vec![None; document.vocab_size];
        let mut ids = HashSet::with_capacity(document.vocab.len());
        for (token, id) in document.vocab {
            let index = usize::try_from(id)
                .ok()
                .filter(|index| *index < document.vocab_size)
                .ok_or_else(|| {
                    TokenizerError::Invalid(format!(
                        "InferX token {token:?} has out-of-range id {id}"
                    ))
                })?;
            if !ids.insert(id) {
                return Err(TokenizerError::Invalid(format!(
                    "InferX tokenizer repeats id {id}"
                )));
            }
            let key = token.encode_utf16().collect::<Vec<_>>();
            if vocab.insert(key, id).is_some() {
                return Err(TokenizerError::Invalid(format!(
                    "InferX tokenizer repeats token {token:?}"
                )));
            }
            id_to_token[index] = Some(token);
        }
        for (name, expected) in [("<PAD>", 0), ("<BOS>", 1), ("<EOS>", 2), ("<UNK>", 3)] {
            let actual = vocab.get(&name.encode_utf16().collect::<Vec<_>>()).copied();
            if actual != Some(expected) {
                return Err(TokenizerError::Invalid(format!(
                    "InferX special token {name} has id {actual:?}, expected {expected}"
                )));
            }
        }

        #[cfg(test)]
        let merges = document
            .merges
            .into_iter()
            .map(|[first, second]| {
                let first = first.encode_utf16().collect::<Vec<_>>();
                let second = second.encode_utf16().collect::<Vec<_>>();
                let mut joined = Vec::with_capacity(first.len() + second.len());
                joined.extend_from_slice(&first);
                joined.extend_from_slice(&second);
                Merge {
                    first,
                    second,
                    joined,
                }
            })
            .collect();

        Ok(Self {
            #[cfg(test)]
            vocab,
            id_to_token,
            #[cfg(test)]
            merges,
            vocab_size: document.vocab_size,
        })
    }

    pub(crate) const fn vocab_size(&self) -> usize {
        self.vocab_size
    }

    #[cfg(test)]
    pub(crate) fn encode(&self, text: &str) -> Vec<u32> {
        let mut ids = Vec::new();
        for word in pre_tokenize(text) {
            for token in self.apply_bpe(&word) {
                ids.push(self.vocab.get(&token).copied().unwrap_or(UNK_ID));
            }
        }
        ids
    }

    pub(crate) fn decode(&self, ids: &[u32]) -> String {
        let mut text = String::new();
        for &id in ids {
            if id <= UNK_ID {
                continue;
            }
            if let Some(Some(token)) = usize::try_from(id)
                .ok()
                .and_then(|index| self.id_to_token.get(index))
            {
                text.push_str(token);
            }
        }
        text = text.replace(END_OF_WORD, " ");
        text = APOSTROPHE_SPACING.replace_all(&text, "$1'$2").into_owned();
        text = CLOSING_SPACING.replace_all(&text, "$1").into_owned();
        text = OPENING_SPACING.replace_all(&text, "$1").into_owned();
        loop {
            let next = NUMBER_DOT_SPACING.replace_all(&text, "$1.$2").into_owned();
            if next == text {
                break;
            }
            text = next;
        }
        text = WHITESPACE.replace_all(&text, " ").into_owned();
        text.trim().to_owned()
    }

    #[cfg(test)]
    fn apply_bpe(&self, word: &str) -> Vec<Vec<u16>> {
        let mut pieces = word
            .encode_utf16()
            .map(|unit| vec![unit])
            .collect::<Vec<_>>();
        pieces.push(END_OF_WORD.encode_utf16().collect());
        for merge in &self.merges {
            let mut index = 0;
            while index + 1 < pieces.len() {
                if pieces[index] == merge.first && pieces[index + 1] == merge.second {
                    pieces[index] = merge.joined.clone();
                    pieces.remove(index + 1);
                } else {
                    index += 1;
                }
            }
        }
        pieces
    }
}

#[cfg(test)]
fn pre_tokenize(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let stripped = text.trim();
    let mut punctuated = String::with_capacity(stripped.len() + 16);
    for character in stripped.chars() {
        if is_separated_punctuation(character) {
            punctuated.push(' ');
            punctuated.push(character);
            punctuated.push(' ');
        } else {
            punctuated.push(character);
        }
    }

    let characters = punctuated.chars().collect::<Vec<_>>();
    let mut apostrophes = String::with_capacity(punctuated.len() + 16);
    for (index, &character) in characters.iter().enumerate() {
        if character == '\''
            && !(index
                .checked_sub(1)
                .and_then(|previous| characters.get(previous))
                .is_some_and(|value| is_java_word(*value))
                && characters
                    .get(index + 1)
                    .is_some_and(|value| is_java_word(*value)))
        {
            apostrophes.push_str(" ' ");
        } else {
            apostrophes.push(character);
        }
    }
    apostrophes
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
fn is_java_word(value: char) -> bool {
    value.is_ascii_alphanumeric() || value == '_'
}

#[cfg(test)]
fn is_separated_punctuation(value: char) -> bool {
    matches!(
        value,
        '.' | ','
            | '!'
            | '?'
            | '"'
            | ';'
            | ':'
            | '-'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '/'
            | '\\'
            | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '+'
            | '='
            | '<'
            | '>'
            | '~'
            | '`'
    )
}

#[derive(Debug)]
pub(crate) enum TokenizerError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl fmt::Display for TokenizerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "InferX tokenizer I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "InferX tokenizer JSON is invalid: {error}"),
            Self::Invalid(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for TokenizerError {}

#[cfg(test)]
mod resource_tests {
    use std::{
        fs::{self, File},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_tokenizer_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lmyzmail-inferx-tokenizer-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn oversized_and_duplicate_id_tokenizers_are_rejected() {
        let path = temporary_tokenizer_path();
        let oversized = File::create(&path).unwrap();
        oversized.set_len(MAX_TOKENIZER_BYTES + 1).unwrap();
        drop(oversized);
        assert!(matches!(
            BpeTokenizer::load(&path),
            Err(TokenizerError::Invalid(_))
        ));

        fs::write(
            &path,
            br#"{
                "vocab_size": 4,
                "vocab": {"<PAD>": 0, "<BOS>": 1, "<EOS>": 2, "<UNK>": 2},
                "merges": []
            }"#,
        )
        .unwrap();
        assert!(matches!(
            BpeTokenizer::load(&path),
            Err(TokenizerError::Invalid(_))
        ));
        fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::pre_tokenize;

    #[test]
    fn pretokenization_matches_the_frozen_java_rules() {
        assert_eq!(
            pre_tokenize("ratio'd \"Skibidi\" [NO]"),
            ["ratio'd", "\"", "Skibidi", "\"", "[", "NO", "]"]
        );
        assert_eq!(
            pre_tokenize("'solo' mail@example.test"),
            ["'", "solo", "'", "mail", "@", "example", ".", "test"]
        );
    }
}
