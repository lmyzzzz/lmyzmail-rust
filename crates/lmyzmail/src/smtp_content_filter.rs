use std::{collections::HashSet, fmt, sync::OnceLock};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;

use crate::config::ContentFilterConfig;

pub(crate) const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_HEADER_FIELDS: usize = 4_096;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum HeaderParseError {
    TooLarge,
    TooManyFields,
}

impl fmt::Display for HeaderParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(
                formatter,
                "SMTP header section exceeds {MAX_HEADER_BYTES} bytes"
            ),
            Self::TooManyFields => write!(
                formatter,
                "SMTP header section exceeds {MAX_HEADER_FIELDS} fields"
            ),
        }
    }
}

impl std::error::Error for HeaderParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeaderField {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedHeaders {
    fields: Vec<HeaderField>,
}

impl ParsedHeaders {
    pub(crate) fn parse(message: &[u8]) -> Result<Self, HeaderParseError> {
        let mut fields = Vec::new();
        let mut current: Option<HeaderField> = None;
        let mut offset = 0_usize;

        while offset < message.len() {
            let remaining = &message[offset..];
            let line_length = remaining
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(remaining.len(), |index| index + 1);
            let end = offset.saturating_add(line_length);
            if end > MAX_HEADER_BYTES {
                return Err(HeaderParseError::TooLarge);
            }
            let line = &message[offset..end];
            let content = line
                .strip_suffix(b"\n")
                .unwrap_or(line)
                .strip_suffix(b"\r")
                .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line));

            if content.is_empty() {
                push_current(&mut fields, current.take())?;
                return Ok(Self { fields });
            }

            if matches!(line.first(), Some(b' ' | b'\t')) {
                if let Some(field) = current.as_mut() {
                    field.value.push_str(&String::from_utf8_lossy(line));
                }
            } else {
                push_current(&mut fields, current.take())?;
                current = line
                    .iter()
                    .position(|byte| *byte == b':')
                    .and_then(|colon| {
                        (colon > 0).then(|| HeaderField {
                            name: String::from_utf8_lossy(&line[..colon]).into_owned(),
                            value: String::from_utf8_lossy(&line[colon + 1..]).into_owned(),
                        })
                    });
            }

            if end == message.len() {
                break;
            }
            offset = end;
        }

        if message.len() > MAX_HEADER_BYTES {
            return Err(HeaderParseError::TooLarge);
        }
        push_current(&mut fields, current)?;
        Ok(Self { fields })
    }

    pub(crate) fn first_trimmed(&self, wanted: &str) -> Option<String> {
        self.first_raw(wanted).map(|value| value.trim().to_owned())
    }

    fn first_raw(&self, wanted: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(wanted))
            .map(|field| field.value.as_str())
    }

    fn all_raw<'a>(&'a self, wanted: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(wanted))
            .map(|field| field.value.as_str())
    }

    pub(crate) fn scan(
        &self,
        envelope_recipient_count: usize,
        config: &ContentFilterConfig,
    ) -> ContentScan {
        if !config.enabled {
            return ContentScan::default();
        }

        let mut hits = Vec::with_capacity(3);
        if config.missing_headers.enabled
            && let Some(score) = missing_headers_score(self)
        {
            hits.push(RuleHit {
                name: "MISSING_HEADERS",
                score: score * config.missing_headers.weight,
            });
        }
        if config.subject_encoding_trick.enabled
            && let Some(score) = subject_encoding_trick_score(self)
        {
            hits.push(RuleHit {
                name: "SUBJECT_ENCODING_TRICK",
                score: score * config.subject_encoding_trick.weight,
            });
        }
        if config.excessive_recipients.enabled
            && let Some(score) = excessive_recipient_score(self, envelope_recipient_count)
        {
            hits.push(RuleHit {
                name: "EXCESSIVE_RECIPIENTS",
                score: score * config.excessive_recipients.weight,
            });
        }

        let total_score = hits.iter().map(|hit| hit.score).sum();
        ContentScan { total_score, hits }
    }
}

fn push_current(
    fields: &mut Vec<HeaderField>,
    current: Option<HeaderField>,
) -> Result<(), HeaderParseError> {
    if let Some(field) = current {
        if fields.len() >= MAX_HEADER_FIELDS {
            return Err(HeaderParseError::TooManyFields);
        }
        fields.push(field);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ContentScan {
    total_score: f64,
    hits: Vec<RuleHit>,
}

impl ContentScan {
    pub(crate) fn total_score(&self) -> f64 {
        self.total_score
    }

    pub(crate) fn is_suspicious(&self, config: &ContentFilterConfig) -> bool {
        self.total_score >= config.suspicious_threshold
    }

    pub(crate) fn hits(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        self.hits.iter().map(|hit| (hit.name, hit.score))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RuleHit {
    name: &'static str,
    score: f64,
}

fn missing_headers_score(headers: &ParsedHeaders) -> Option<f64> {
    let checks = [
        ("From", 2.0_f64, true),
        ("Date", 1.5_f64, true),
        ("Message-ID", 1.0_f64, false),
        ("Subject", 0.5_f64, false),
    ];
    let mut score = 0.0;
    for (name, value, required) in checks {
        match headers.first_raw(name) {
            None => score += value,
            Some(raw) if java_is_blank(raw) => score += value,
            Some(raw) if required && malformed_required_header(name, raw) => {
                score += value * 0.5;
            }
            Some(_) => {}
        }
    }
    (score > 0.0).then_some(score)
}

fn malformed_required_header(name: &str, value: &str) -> bool {
    match name {
        "From" => !value.contains('@'),
        "Date" => value.encode_utf16().count() < 10,
        _ => false,
    }
}

fn subject_encoding_trick_score(headers: &ParsedHeaders) -> Option<f64> {
    let subject = headers.first_raw("Subject")?;
    if java_is_blank(subject) {
        return None;
    }

    let encoded_word = encoded_word_regex();
    let mut score = 0.0_f64;
    let mut charsets = HashSet::new();
    let mut encoded_words = Vec::new();
    let mut unnecessary_ascii = false;
    for captures in encoded_word.captures_iter(subject) {
        let charset = normalize_charset(&captures[1].to_ascii_lowercase());
        charsets.insert(charset);
        let encoded_text = captures[3].to_owned();
        if !unnecessary_ascii {
            unnecessary_ascii = has_unnecessary_ascii_encoding(&captures[2], &encoded_text);
        }
        encoded_words.push(encoded_text);
    }

    if charsets.len() > 1 {
        score += 1.5 * (charsets.len() - 1) as f64;
    }
    if unnecessary_ascii {
        score += 1.0;
    }

    let invisible_count = subject.chars().filter(|value| is_invisible(*value)).count();
    if invisible_count > 0 {
        score += (invisible_count as f64).min(4.0);
    }
    let homoglyph_count = subject.chars().filter(|value| is_homoglyph(*value)).count();
    if homoglyph_count > 0 {
        score += (homoglyph_count as f64 * 0.8).min(3.0);
    }
    if special_character_ratio(subject) > 0.3 {
        score += 1.5;
    }
    if has_repeating_encoded_words(&encoded_words) {
        score += 2.0;
    }

    (score > 0.0).then_some(score)
}

fn encoded_word_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"=\?([^?]+)\?([BbQq])\?([^?]*)\?=")
            .expect("frozen encoded-word regex must compile")
    })
}

fn q_escape_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX
        .get_or_init(|| Regex::new(r"=[0-9A-Fa-f]{2}").expect("frozen Q escape regex must compile"))
}

fn normalize_charset(value: &str) -> String {
    match value {
        "utf8" => "utf-8".to_owned(),
        "iso8859-1" | "latin1" => "iso-8859-1".to_owned(),
        "windows-1252" | "cp1252" => "windows-1252".to_owned(),
        _ => value.to_owned(),
    }
}

fn has_unnecessary_ascii_encoding(encoding: &str, text: &str) -> bool {
    let decoded = if encoding.eq_ignore_ascii_case("B") {
        let Ok(bytes) = BASE64_STANDARD.decode(text) else {
            return false;
        };
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        q_escape_regex()
            .replace_all(&text.replace('_', " "), "X")
            .into_owned()
    };
    decoded.encode_utf16().count() > 3
        && decoded
            .chars()
            .all(|character| (' '..='~').contains(&character))
}

fn has_repeating_encoded_words(words: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(words.len());
    for word in words {
        if word.encode_utf16().count() > 2 && !seen.insert(word.as_str()) {
            return true;
        }
    }
    words.len() > 5 && words.iter().all(|word| word.encode_utf16().count() < 5)
}

fn special_character_ratio(subject: &str) -> f64 {
    let replaced = encoded_word_regex().replace_all(subject, "$3");
    let decoded = java_trim(replaced.as_ref());
    let units = decoded.encode_utf16().collect::<Vec<_>>();
    if units.is_empty() {
        return 0.0;
    }
    let special = units
        .iter()
        .filter(|unit| !java_letter_or_digit(**unit) && !is_common_punctuation(**unit))
        .count();
    special as f64 / units.len() as f64
}

fn java_letter_or_digit(value: u16) -> bool {
    char::from_u32(u32::from(value)).is_some_and(char::is_alphanumeric)
}

fn is_common_punctuation(value: u16) -> bool {
    value <= 0x7f && b" .,!?:;'-\"()[]{}@#$%&*+=/<>".contains(&(value as u8))
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| character <= '\u{20}')
}

fn java_is_blank(value: &str) -> bool {
    value.chars().all(java_is_whitespace)
}

fn java_is_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000d}'
            | '\u{001c}'..='\u{0020}'
            | '\u{1680}'
            | '\u{2000}'..='\u{2006}'
            | '\u{2008}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn is_invisible(value: char) -> bool {
    matches!(
        value,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180b}'..='\u{180e}'
            | '\u{2000}'..='\u{200f}'
            | '\u{202a}'..='\u{202f}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206a}'..='\u{206f}'
            | '\u{3000}'
            | '\u{feff}'
            | '\u{ffa0}'
    )
}

fn is_homoglyph(value: char) -> bool {
    matches!(
        value,
        '\u{0391}'
            | '\u{0392}'
            | '\u{0395}'
            | '\u{0396}'
            | '\u{0397}'
            | '\u{0399}'
            | '\u{039a}'
            | '\u{039c}'
            | '\u{039d}'
            | '\u{039f}'
            | '\u{03a1}'
            | '\u{03a4}'
            | '\u{03a5}'
            | '\u{03a7}'
            | '\u{0430}'
            | '\u{0435}'
            | '\u{043e}'
            | '\u{0440}'
            | '\u{0441}'
            | '\u{0443}'
            | '\u{0445}'
            | '\u{0500}'
            | '\u{0501}'
    )
}

fn excessive_recipient_score(
    headers: &ParsedHeaders,
    envelope_recipient_count: usize,
) -> Option<f64> {
    let header_count = ["To", "Cc", "Bcc"]
        .into_iter()
        .flat_map(|name| headers.all_raw(name))
        .map(count_addresses)
        .sum::<usize>();
    let total = envelope_recipient_count.max(header_count);
    if total < 20 {
        return None;
    }
    if total >= 50 {
        Some((2.0 + (total - 50) as f64 * 0.05).min(5.0))
    } else {
        Some(1.0 + (total - 20) as f64 * 0.05)
    }
}

fn count_addresses(value: &str) -> usize {
    if java_is_blank(value) {
        return 0;
    }
    let at_count = value.bytes().filter(|byte| *byte == b'@').count();
    if at_count > 0 {
        at_count
    } else {
        let commas = value.bytes().filter(|byte| *byte == b',').count();
        commas.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::config::{ContentFilterConfig, ContentFilterRuleConfig};

    fn config() -> ContentFilterConfig {
        ContentFilterConfig::default()
    }

    fn parse(message: &[u8]) -> ParsedHeaders {
        ParsedHeaders::parse(message).unwrap()
    }

    #[test]
    fn golden_header_rules_and_order_match_java() {
        let clean = parse(
            b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: clean\r\nMessage-ID: <clean@example.test>\r\n\r\nbody",
        );
        assert_eq!(clean.scan(0, &config()), ContentScan::default());

        let missing = parse(b"Subject: missing\r\nMessage-ID: <missing@example.test>\r\n\r\n");
        assert_eq!(
            missing.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("MISSING_HEADERS", 3.5)]
        );

        let malformed = parse(
            b"From: not-an-address\r\nDate: short\r\nSubject: malformed\r\nMessage-ID: <malformed@example.test>\r\n\r\n",
        );
        assert_eq!(
            malformed.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("MISSING_HEADERS", 1.75)]
        );

        let encoded = parse(
            b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: =?UTF-8?Q?FREE?= =?ISO-8859-1?Q?MONEY?=\r\nMessage-ID: <encoded@example.test>\r\n\r\n",
        );
        assert_eq!(
            encoded.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("SUBJECT_ENCODING_TRICK", 2.5)]
        );

        let recipients = (0..50)
            .map(|index| format!("recipient-{index}@example.test"))
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!(
            "From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: recipients\r\nMessage-ID: <recipients@example.test>\r\nCc: {recipients}\r\n\r\n"
        );
        assert_eq!(
            parse(message.as_bytes())
                .scan(0, &config())
                .hits()
                .collect::<Vec<_>>(),
            [("EXCESSIVE_RECIPIENTS", 2.0)]
        );
    }

    #[test]
    fn parser_preserves_folded_raw_values_and_ignores_body_headers() {
        let headers = parse(
            b"From: sender@example.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: ordinary\r\nMessage-ID: <fold@example.test>\r\nCc: first@example.test,\r\n second@example.test\r\n\r\nSubject: =?UTF-8?Q?FREE?=\r\n",
        );
        assert_eq!(
            headers.all_raw("Cc").next(),
            Some(" first@example.test,\r\n second@example.test\r\n")
        );
        assert_eq!(headers.scan(0, &config()), ContentScan::default());
    }

    #[test]
    fn configuration_disables_and_weights_rules_without_reordering() {
        let headers = parse(b"Subject: =?UTF-8?Q?FREE?=\r\nCc: a@x,b@y,c@z,d@x,e@y,f@z,g@x,h@y,i@z,j@x,k@y,l@z,m@x,n@y,o@z,p@x,q@y,r@z,s@x,t@y\r\n\r\n");
        let mut settings = config();
        settings.missing_headers.enabled = false;
        settings.subject_encoding_trick.weight = 2.0;
        settings.excessive_recipients = ContentFilterRuleConfig {
            enabled: true,
            weight: 0.5,
        };
        assert_eq!(
            headers.scan(0, &settings).hits().collect::<Vec<_>>(),
            [
                ("SUBJECT_ENCODING_TRICK", 2.0),
                ("EXCESSIVE_RECIPIENTS", 0.5)
            ]
        );
    }

    #[test]
    fn parser_enforces_header_byte_and_field_budgets() {
        let oversized = vec![b'a'; MAX_HEADER_BYTES + 1];
        assert_eq!(
            ParsedHeaders::parse(&oversized),
            Err(HeaderParseError::TooLarge)
        );
        let too_many = "X:\r\n".repeat(MAX_HEADER_FIELDS + 1) + "\r\n";
        assert_eq!(
            ParsedHeaders::parse(too_many.as_bytes()),
            Err(HeaderParseError::TooManyFields)
        );
    }

    #[test]
    fn java_blank_and_trim_boundaries_are_explicit() {
        assert!(java_is_blank(" \t\r\n\u{3000}"));
        assert!(!java_is_blank("\u{00a0}"));
        assert_eq!(java_trim("\r\n value \r\n"), "value");
        assert_eq!(java_trim("\u{3000}value\u{3000}"), "\u{3000}value\u{3000}");
    }

    proptest! {
        #[test]
        fn arbitrary_bounded_input_never_panics_and_scores_stay_finite(
            input in prop::collection::vec(any::<u8>(), 0..8192)
        ) {
            if let Ok(headers) = ParsedHeaders::parse(&input) {
                let scan = headers.scan(0, &config());
                prop_assert!(scan.total_score().is_finite());
                prop_assert!(scan.hits().count() <= 3);
            }
        }
    }
}
