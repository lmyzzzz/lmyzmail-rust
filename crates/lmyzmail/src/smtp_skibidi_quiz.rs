use std::{
    collections::HashSet,
    fmt::{self, Write as _},
    sync::OnceLock,
};

use getrandom::fill as fill_random;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const QUESTION_BANK_BYTES: &[u8] = include_bytes!("../assets/brainrot_quiz.json");
const QUESTION_BANK_COUNT: usize = 474;
const QUESTION_BANK_SHA256: &str =
    "7bcbeacd0d36a58931efa49234143946cb981b4c978c74432313fcad843ba8d1";
const GREEDY_THRESHOLD: usize = 5;

const CORRECT_FEEDBACK: [&str; 10] = [
    "CORRECT! You ate that no cap.",
    "CORRECT! Sheeeesh, you got that rizz fr fr.",
    "CORRECT! That is bussin. Certified sigma moment.",
    "CORRECT! Built different energy detected.",
    "CORRECT! No cap, you are not an NPC after all.",
    "CORRECT! The aura readings are off the charts.",
    "CORRECT! Goated with the sauce.",
    "CORRECT! Unspoken rizz confirmed.",
    "CORRECT! That answer just hit different.",
    "CORRECT! Ohio could never.",
];

const WRONG_FEEDBACK: [&str; 10] = [
    "WRONG! L + ratio + no rizz.",
    "WRONG! You are cooking with zero aura.",
    "WRONG! Absolute NPC behavior detected.",
    "WRONG! The Ohio final boss is disappointed.",
    "WRONG! Bro fell off harder than a failed looksmaxx attempt.",
    "WRONG! That answer is mid at best.",
    "WRONG! You need to grind your Brainrot knowledge stat.",
    "WRONG! Genuinely the least sigma answer possible.",
    "WRONG! Skibidi dop dop no no.",
    "WRONG! Even Grimace Shake could not save you.",
];

static QUESTION_BANK: OnceLock<Result<QuestionBank, QuestionBankError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuizLevel {
    BabyGronk,
    SkibidiToilet,
    OhioFinalBoss,
}

impl QuizLevel {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 3] = [Self::BabyGronk, Self::SkibidiToilet, Self::OhioFinalBoss];

    pub(crate) fn from_arg(value: &str) -> Option<Self> {
        let value = java_trim(value);
        if value.eq_ignore_ascii_case("BABYGRONK") {
            Some(Self::BabyGronk)
        } else if value.eq_ignore_ascii_case("SKIBIDITOILET") {
            Some(Self::SkibidiToilet)
        } else if value.eq_ignore_ascii_case("OHIOFINALBOSS") {
            Some(Self::OhioFinalBoss)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) const fn arg(self) -> &'static str {
        match self {
            Self::BabyGronk => "BABYGRONK",
            Self::SkibidiToilet => "SKIBIDITOILET",
            Self::OhioFinalBoss => "OHIOFINALBOSS",
        }
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::BabyGronk => "BABY GRONK",
            Self::SkibidiToilet => "SKIBIDI TOILET",
            Self::OhioFinalBoss => "OHIO FINAL BOSS",
        }
    }

    pub(crate) const fn question_count(self) -> usize {
        match self {
            Self::BabyGronk => 15,
            Self::SkibidiToilet => 30,
            Self::OhioFinalBoss => 60,
        }
    }

    pub(crate) const fn target_total_difficulty(self) -> usize {
        match self {
            Self::BabyGronk => 60,
            Self::SkibidiToilet => 150,
            Self::OhioFinalBoss => 400,
        }
    }

    #[cfg(test)]
    pub(crate) const fn difficulty_tolerance(self) -> f64 {
        let _ = self;
        0.12
    }

    const fn bucket_weights(self) -> [f64; 10] {
        match self {
            Self::BabyGronk => [0.5, 2.0, 3.5, 4.5, 5.0, 3.0, 1.5, 0.5, 0.2, 0.1],
            Self::SkibidiToilet => [0.2, 0.8, 1.5, 2.5, 3.5, 3.5, 2.5, 1.5, 0.5, 0.2],
            Self::OhioFinalBoss => [0.05, 0.1, 0.3, 0.8, 1.5, 3.5, 5.0, 5.5, 4.0, 3.0],
        }
    }
}

#[derive(Debug)]
pub(crate) enum QuizError {
    QuestionBank(&'static QuestionBankError),
    InsufficientQuestions { needed: usize, available: usize },
    Random(getrandom::Error),
}

impl fmt::Display for QuizError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuestionBank(error) => write!(formatter, "question bank unavailable: {error}"),
            Self::InsufficientQuestions { needed, available } => {
                write!(
                    formatter,
                    "not enough questions: need {needed}, have {available}"
                )
            }
            Self::Random(error) => write!(
                formatter,
                "operating-system randomness unavailable: {error}"
            ),
        }
    }
}

impl std::error::Error for QuizError {}

#[derive(Debug)]
pub(crate) enum AnswerError {
    Empty,
    NotAwaitingAnswer,
    Complete,
}

impl fmt::Display for AnswerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("quiz answer is empty"),
            Self::NotAwaitingAnswer => formatter.write_str("quiz is not awaiting an answer"),
            Self::Complete => formatter.write_str("quiz is already complete"),
        }
    }
}

impl std::error::Error for AnswerError {}

/// The terminal question has two SMTP replies: `answer_lines` use code 250 and
/// `final_lines` are sent afterward as a distinct code-220 reply. Matching the
/// `Complete` variant is also the caller's signal to remove connection state.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum AnswerOutcome {
    Continue(Vec<String>),
    Complete {
        answer_lines: Vec<String>,
        final_lines: Vec<String>,
    },
}

#[derive(Debug)]
pub(crate) struct QuizStart {
    pub(crate) state: QuizState,
    pub(crate) lines: Vec<String>,
}

/// All mutable quiz data is owned by one SMTP connection. The process-global
/// question bank is immutable after its one validated initialization.
#[derive(Debug)]
pub(crate) struct QuizState {
    bank: &'static QuestionBank,
    level: QuizLevel,
    question_indices: Box<[usize]>,
    current_index: usize,
    correct_count: usize,
    awaiting_answer: bool,
}

impl QuizState {
    pub(crate) fn start(level: QuizLevel) -> Result<QuizStart, QuizError> {
        let bank = question_bank().map_err(QuizError::QuestionBank)?;
        let mut rng = OsQuizRng;
        Self::start_with_rng(bank, level, &mut rng)
    }

    fn start_with_rng(
        bank: &'static QuestionBank,
        level: QuizLevel,
        rng: &mut impl QuizRng,
    ) -> Result<QuizStart, QuizError> {
        let selection = assemble_quiz(bank, level, rng)?;
        let state = Self {
            bank,
            level,
            question_indices: selection,
            current_index: 0,
            correct_count: 0,
            awaiting_answer: true,
        };
        let lines = state.initial_lines();
        Ok(QuizStart { state, lines })
    }

    #[cfg(test)]
    pub(crate) const fn answered_count(&self) -> usize {
        self.current_index
    }

    #[cfg(test)]
    pub(crate) const fn correct_count(&self) -> usize {
        self.correct_count
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.current_index >= self.question_indices.len()
    }

    #[cfg(test)]
    pub(crate) const fn is_awaiting_answer(&self) -> bool {
        self.awaiting_answer
    }

    pub(crate) fn answer(&mut self, given: &str) -> Result<AnswerOutcome, AnswerError> {
        if self.is_complete() {
            return Err(AnswerError::Complete);
        }
        if !self.awaiting_answer {
            return Err(AnswerError::NotAwaitingAnswer);
        }
        if given.trim().is_empty() {
            return Err(AnswerError::Empty);
        }

        let question = self
            .current_question()
            .expect("incomplete quiz has a question");
        let correct = question.is_correct(given);
        let question_number = self.current_index + 1;
        let feedback_line = feedback(question, question_number, correct);
        if correct {
            self.correct_count += 1;
        }
        self.current_index += 1;
        self.awaiting_answer = false;

        let mut lines = vec![
            feedback_line,
            format!(
                "Score so far: {}/{} ({}%)",
                self.correct_count,
                question_number,
                java_percent(self.correct_count, question_number)
            ),
        ];

        if self.is_complete() {
            return Ok(AnswerOutcome::Complete {
                answer_lines: lines,
                final_lines: self.final_lines(),
            });
        }

        lines.push(String::new());
        self.awaiting_answer = true;
        self.append_current_question(&mut lines);
        Ok(AnswerOutcome::Continue(lines))
    }

    /// Consuming the value makes a forfeit naturally pair with clearing the
    /// connection's `Option<QuizState>` via `take()` in the SMTP layer.
    pub(crate) fn into_forfeit_lines(self) -> Vec<String> {
        vec![
            "Quiz forfeited. That is the most L take in recorded Brainrot history.".into(),
            format!(
                "Progress: {}/{} correct before you rage-quit.",
                self.correct_count, self.current_index
            ),
            "The Ohio final boss remains undefeated. You were not built different.".into(),
            "Use SKIBIDITOILET START <LEVEL> to try again and redeem your aura.".into(),
        ]
    }

    fn initial_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "QUIZ STARTED: {} ({} questions | target difficulty: {})",
                self.level.display_name(),
                self.level.question_count(),
                self.level.target_total_difficulty()
            ),
            "Demonstrate your aura or be forever NPC. No skipping. No crying.".into(),
            String::new(),
        ];
        self.append_current_question(&mut lines);
        lines
    }

    fn current_question(&self) -> Option<&Question> {
        self.question_indices
            .get(self.current_index)
            .and_then(|index| self.bank.questions.get(*index))
    }

    fn append_current_question(&self, lines: &mut Vec<String>) {
        let question = self
            .current_question()
            .expect("quiz question index is valid");
        let number = self.current_index + 1;
        let total = self.question_indices.len();
        lines.push(format!(
            "Q{number}/{total} [DIFFICULTY: {}/10] {}",
            question.difficulty, question.question
        ));
        for (index, option) in question.options.iter().enumerate() {
            let label = (b'A' + u8::try_from(index).expect("four options fit in u8")) as char;
            lines.push(format!("  {label}) {option}"));
        }
        lines.push("ANSWER with A, B, C, or D".into());
    }

    fn final_lines(&self) -> Vec<String> {
        let total = self.question_indices.len();
        let percent = java_percent(self.correct_count, total);
        vec![
            format!(
                "=== BRAINROT QUIZ COMPLETE: {} ===",
                self.level.display_name()
            ),
            format!(
                "Final Score: {}/{} ({}%)",
                self.correct_count, total, percent
            ),
            format!("Rating: {}", rating(percent)),
            final_comment(percent, self.level).into(),
            "Use SKIBIDITOILET START <LEVEL> to play again or touch grass.".into(),
        ]
    }
}

#[derive(Clone, Debug)]
struct Question {
    question: String,
    options: [String; 4],
    answer: u8,
    difficulty: u8,
}

impl Question {
    fn is_correct(&self, given: &str) -> bool {
        let expected = [b'A' + self.answer];
        java_trim(given).as_bytes().eq_ignore_ascii_case(&expected)
    }

    fn answer_label(&self) -> char {
        (b'A' + self.answer) as char
    }

    fn answer_text(&self) -> &str {
        &self.options[usize::from(self.answer)]
    }
}

#[derive(Debug)]
struct QuestionBank {
    questions: Box<[Question]>,
    buckets: [Box<[usize]>; 10],
}

#[derive(Debug)]
pub(crate) enum QuestionBankError {
    Digest { actual: String },
    Json(String),
    Validation(String),
}

impl fmt::Display for QuestionBankError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest { actual } => write!(
                formatter,
                "brainrot_quiz.json SHA-256 mismatch: expected {QUESTION_BANK_SHA256}, got {actual}"
            ),
            Self::Json(error) => write!(formatter, "invalid brainrot_quiz.json: {error}"),
            Self::Validation(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for QuestionBankError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuestion {
    id: u32,
    question: String,
    #[serde(rename = "type")]
    kind: String,
    options: RawOptions,
    answer: String,
    difficulty: u8,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptions {
    #[serde(rename = "A")]
    a: String,
    #[serde(rename = "B")]
    b: String,
    #[serde(rename = "C")]
    c: String,
    #[serde(rename = "D")]
    d: String,
}

pub(crate) fn ensure_question_bank_loaded() -> Result<(), &'static QuestionBankError> {
    question_bank().map(|_| ())
}

fn question_bank() -> Result<&'static QuestionBank, &'static QuestionBankError> {
    match QUESTION_BANK.get_or_init(|| load_question_bank(QUESTION_BANK_BYTES)) {
        Ok(bank) => Ok(bank),
        Err(error) => Err(error),
    }
}

fn load_question_bank(bytes: &[u8]) -> Result<QuestionBank, QuestionBankError> {
    let actual = sha256_hex(bytes);
    if actual != QUESTION_BANK_SHA256 {
        return Err(QuestionBankError::Digest { actual });
    }
    let raw: Vec<RawQuestion> = serde_json::from_slice(bytes)
        .map_err(|error| QuestionBankError::Json(error.to_string()))?;
    validate_and_build(raw)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn validate_and_build(raw: Vec<RawQuestion>) -> Result<QuestionBank, QuestionBankError> {
    if raw.len() != QUESTION_BANK_COUNT {
        return Err(validation(format!(
            "question bank must contain exactly {QUESTION_BANK_COUNT} questions, got {}",
            raw.len()
        )));
    }

    let mut ids = HashSet::with_capacity(raw.len());
    let mut questions = Vec::with_capacity(raw.len());
    let mut buckets: [Vec<usize>; 10] = std::array::from_fn(|_| Vec::new());

    for entry in raw {
        if entry.id == 0 {
            return Err(validation("question id must be positive"));
        }
        if !ids.insert(entry.id) {
            return Err(validation(format!("duplicate question id {}", entry.id)));
        }
        if entry.question.is_empty() || !entry.question.is_ascii() {
            return Err(validation(format!(
                "question {} text must be non-empty ASCII",
                entry.id
            )));
        }
        if entry.kind != "multiple_choice" || !entry.kind.is_ascii() {
            return Err(validation(format!(
                "question {} must have ASCII type multiple_choice",
                entry.id
            )));
        }
        let options = [
            entry.options.a,
            entry.options.b,
            entry.options.c,
            entry.options.d,
        ];
        if options
            .iter()
            .any(|option| option.is_empty() || !option.is_ascii())
        {
            return Err(validation(format!(
                "question {} options A-D must be non-empty ASCII strings",
                entry.id
            )));
        }
        if !entry.answer.is_ascii() || entry.answer.len() != 1 {
            return Err(validation(format!(
                "question {} answer must be one ASCII label A-D",
                entry.id
            )));
        }
        let answer = entry.answer.as_bytes()[0];
        if !(b'A'..=b'D').contains(&answer) {
            return Err(validation(format!(
                "question {} answer must name an option A-D",
                entry.id
            )));
        }
        if !(1..=10).contains(&entry.difficulty) {
            return Err(validation(format!(
                "question {} difficulty must be in 1..=10",
                entry.id
            )));
        }

        let index = questions.len();
        buckets[usize::from(entry.difficulty - 1)].push(index);
        questions.push(Question {
            question: entry.question,
            options,
            answer: answer - b'A',
            difficulty: entry.difficulty,
        });
    }

    for (index, bucket) in buckets.iter().enumerate() {
        if bucket.is_empty() {
            return Err(validation(format!(
                "difficulty bucket {} must not be empty",
                index + 1
            )));
        }
    }

    Ok(QuestionBank {
        questions: questions.into_boxed_slice(),
        buckets: buckets.map(Vec::into_boxed_slice),
    })
}

fn validation(message: impl Into<String>) -> QuestionBankError {
    QuestionBankError::Validation(message.into())
}

trait QuizRng {
    fn index(&mut self, upper_bound: usize) -> Result<usize, getrandom::Error>;
    fn unit_f64(&mut self) -> Result<f64, getrandom::Error>;
}

struct OsQuizRng;

impl QuizRng for OsQuizRng {
    fn index(&mut self, upper_bound: usize) -> Result<usize, getrandom::Error> {
        debug_assert!(upper_bound > 0);
        let bound = u64::try_from(upper_bound).expect("usize question count fits in u64");
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let value = os_u64()?;
            if value >= threshold {
                return Ok(usize::try_from(value % bound).expect("result is below usize bound"));
            }
        }
    }

    fn unit_f64(&mut self) -> Result<f64, getrandom::Error> {
        const DENOMINATOR: f64 = (1_u64 << 53) as f64;
        Ok(((os_u64()? >> 11) as f64) / DENOMINATOR)
    }
}

fn os_u64() -> Result<u64, getrandom::Error> {
    let mut bytes = [0_u8; 8];
    fill_random(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// This mirrors `Collections.shuffle` followed by the frozen Java service's
/// per-slot weighted choice. In particular, every bucket is shuffled before
/// any weighted rolls, and selected questions are popped from the bucket tail.
fn assemble_quiz(
    bank: &QuestionBank,
    level: QuizLevel,
    rng: &mut impl QuizRng,
) -> Result<Box<[usize]>, QuizError> {
    let needed = level.question_count();
    if bank.questions.len() < needed {
        return Err(QuizError::InsufficientQuestions {
            needed,
            available: bank.questions.len(),
        });
    }

    let mut work_buckets: [Vec<usize>; 10] =
        std::array::from_fn(|index| bank.buckets[index].to_vec());
    for bucket in &mut work_buckets {
        java_shuffle(bucket, rng).map_err(QuizError::Random)?;
    }

    let mut selected = Vec::with_capacity(needed);
    let mut total_difficulty = 0_usize;
    let target = level.target_total_difficulty();
    let base_weights = level.bucket_weights();

    for slot in 0..needed {
        let remaining = needed - slot;
        let remaining_budget = target as isize - total_difficulty as isize;
        let average_needed = remaining_budget as f64 / remaining as f64;
        let greedy = remaining <= GREEDY_THRESHOLD;
        let mut weights = [0.0_f64; 10];
        let mut total_weight = 0.0_f64;

        for bucket_index in 0..10 {
            if work_buckets[bucket_index].is_empty() {
                continue;
            }
            let difficulty = (bucket_index + 1) as f64;
            let distance = (difficulty - average_needed).abs();
            let weight = if greedy {
                (-(distance * distance) / 4.5).exp() * base_weights[bucket_index]
            } else {
                let bias = (-(distance * distance) / 6.0).exp();
                base_weights[bucket_index] * (1.0 + bias)
            }
            .max(0.0);
            weights[bucket_index] = weight;
            total_weight += weight;
        }

        if total_weight == 0.0 {
            for (bucket_index, bucket) in work_buckets.iter().enumerate() {
                if !bucket.is_empty() {
                    weights[bucket_index] = 1.0;
                    total_weight += 1.0;
                }
            }
        }

        let chosen = weighted_bucket(&weights, total_weight, rng).map_err(QuizError::Random)?;
        let question_index = work_buckets[chosen]
            .pop()
            .expect("weighted selection only chooses a non-empty bucket");
        total_difficulty += usize::from(bank.questions[question_index].difficulty);
        selected.push(question_index);
    }

    Ok(selected.into_boxed_slice())
}

fn java_shuffle(values: &mut [usize], rng: &mut impl QuizRng) -> Result<(), getrandom::Error> {
    for size in (2..=values.len()).rev() {
        let other = rng.index(size)?;
        values.swap(size - 1, other);
    }
    Ok(())
}

fn weighted_bucket(
    weights: &[f64; 10],
    total_weight: f64,
    rng: &mut impl QuizRng,
) -> Result<usize, getrandom::Error> {
    let roll = rng.unit_f64()? * total_weight;
    let mut cumulative = 0.0_f64;
    for (index, weight) in weights.iter().enumerate() {
        cumulative += weight;
        if roll < cumulative {
            return Ok(index);
        }
    }
    Ok(weights
        .iter()
        .rposition(|weight| *weight > 0.0)
        .unwrap_or(0))
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| character <= '\u{0020}')
}

fn java_percent(correct: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        ((correct as f64 / total as f64) * 100.0).round() as usize
    }
}

fn feedback(question: &Question, number: usize, correct: bool) -> String {
    if correct {
        CORRECT_FEEDBACK[number % CORRECT_FEEDBACK.len()].into()
    } else {
        format!(
            "{} Correct answer: {}) {}",
            WRONG_FEEDBACK[number % WRONG_FEEDBACK.len()],
            question.answer_label(),
            question.answer_text()
        )
    }
}

fn rating(percent: usize) -> &'static str {
    if percent == 100 {
        "CERTIFIED OHIO FINAL BOSS. You are the rizz incarnate."
    } else if percent >= 90 {
        "GIGACHAD SIGMA. Unspoken rizz fully unlocked."
    } else if percent >= 75 {
        "BUILT DIFFERENT. High aura individual detected."
    } else if percent >= 60 {
        "MAIN CHARACTER ENERGY. Could use more looksmaxxing."
    } else if percent >= 45 {
        "SIDE CHARACTER. Exists but rarely relevant."
    } else if percent >= 30 {
        "NPC BEHAVIOR. Touch grass and try harder."
    } else if percent >= 15 {
        "CERTIFIED BRAINROT PATIENT. Seek help."
    } else {
        "ABSOLUTE SNORLAX. Did you even try? L + ratio + go back to the lobby."
    }
}

fn final_comment(percent: usize, level: QuizLevel) -> &'static str {
    match (percent, level) {
        (80.., QuizLevel::BabyGronk) => {
            "You demolished Baby Gronk mode. Now stop flexing on the NPCs and step it up."
        }
        (80.., QuizLevel::SkibidiToilet) => {
            "Skibidi Toilet mode cleared with max aura. The algorithm approves."
        }
        (80.., QuizLevel::OhioFinalBoss) => {
            "Ohio Final Boss conquered. You are the only living sigma male. Respect."
        }
        (50.., QuizLevel::BabyGronk) => {
            "Barely surviving Baby Gronk mode. The bottom of the sigma grindset awaits you."
        }
        (50.., QuizLevel::SkibidiToilet) => {
            "Mid run. Your rizz is mid. Your aura is mid. You are mid. Grind harder."
        }
        (50.., QuizLevel::OhioFinalBoss) => {
            "Ohio Final Boss humbled you. Expected. Very few survive this arc."
        }
        (_, QuizLevel::BabyGronk) => {
            "You failed Baby Gronk mode. This is the most Ohio outcome possible."
        }
        (_, QuizLevel::SkibidiToilet) => {
            "Skibidi Toilet flushed you. No aura detected. RIP to your sigma journey."
        }
        (_, QuizLevel::OhioFinalBoss) => {
            "Ohio Final Boss was simply too powerful. You were not built different."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }
    }

    impl QuizRng for SplitMix64 {
        fn index(&mut self, upper_bound: usize) -> Result<usize, getrandom::Error> {
            Ok((self.next() % upper_bound as u64) as usize)
        }

        fn unit_f64(&mut self) -> Result<f64, getrandom::Error> {
            Ok(((self.next() >> 11) as f64) / ((1_u64 << 53) as f64))
        }
    }

    /// Java 24's `java.util.Random`, used only to check that Rust consumes
    /// `nextInt` and `nextDouble` in exactly the frozen service's order.
    struct JavaRandom {
        seed: u64,
    }

    impl JavaRandom {
        const MASK: u64 = (1_u64 << 48) - 1;

        fn new(seed: i64) -> Self {
            Self {
                seed: ((seed as u64) ^ 0x5deece66d) & Self::MASK,
            }
        }

        fn next_bits(&mut self, bits: u32) -> u32 {
            self.seed = self.seed.wrapping_mul(0x5deece66d).wrapping_add(0xb) & Self::MASK;
            (self.seed >> (48 - bits)) as u32
        }
    }

    impl QuizRng for JavaRandom {
        fn index(&mut self, upper_bound: usize) -> Result<usize, getrandom::Error> {
            let bound = u32::try_from(upper_bound).unwrap();
            if bound.is_power_of_two() {
                return Ok(((u64::from(bound) * u64::from(self.next_bits(31))) >> 31) as usize);
            }
            loop {
                let bits = self.next_bits(31);
                let value = bits % bound;
                let java_sum = bits.wrapping_sub(value).wrapping_add(bound - 1) as i32;
                if java_sum >= 0 {
                    return Ok(value as usize);
                }
            }
        }

        fn unit_f64(&mut self) -> Result<f64, getrandom::Error> {
            let value = (u64::from(self.next_bits(26)) << 27) + u64::from(self.next_bits(27));
            Ok(value as f64 / ((1_u64 << 53) as f64))
        }
    }

    fn bank() -> &'static QuestionBank {
        question_bank().unwrap()
    }

    fn source_ids() -> Vec<u32> {
        serde_json::from_slice::<Vec<RawQuestion>>(QUESTION_BANK_BYTES)
            .unwrap()
            .into_iter()
            .map(|question| question.id)
            .collect()
    }

    fn state_with_indices(level: QuizLevel, indices: impl IntoIterator<Item = usize>) -> QuizState {
        QuizState {
            bank: bank(),
            level,
            question_indices: indices.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            current_index: 0,
            correct_count: 0,
            awaiting_answer: true,
        }
    }

    #[test]
    fn embedded_bank_is_exactly_attested_and_strictly_validated_once() {
        let actual = sha256_hex(QUESTION_BANK_BYTES);
        assert_eq!(actual, QUESTION_BANK_SHA256);
        ensure_question_bank_loaded().unwrap();
        ensure_question_bank_loaded().unwrap();
        let bank = bank();
        assert_eq!(bank.questions.len(), QUESTION_BANK_COUNT);
        assert_eq!(
            bank.buckets
                .iter()
                .map(|bucket| bucket.len())
                .sum::<usize>(),
            QUESTION_BANK_COUNT
        );
        assert!(bank.buckets.iter().all(|bucket| !bucket.is_empty()));
        assert_eq!(
            source_ids().into_iter().collect::<HashSet<_>>().len(),
            QUESTION_BANK_COUNT
        );
    }

    #[test]
    fn byte_changes_are_rejected_before_json_is_trusted() {
        let mut changed = QUESTION_BANK_BYTES.to_vec();
        changed[0] ^= 1;
        assert!(matches!(
            load_question_bank(&changed),
            Err(QuestionBankError::Digest { .. })
        ));
    }

    #[test]
    fn serde_schema_rejects_unknown_and_missing_fields() {
        let unknown = br#"[{"id":1,"question":"q","type":"multiple_choice","options":{"A":"a","B":"b","C":"c","D":"d"},"answer":"A","difficulty":1,"extra":true}]"#;
        let missing = br#"[{"id":1,"question":"q","type":"multiple_choice","options":{"A":"a","B":"b","C":"c"},"answer":"A","difficulty":1}]"#;
        assert!(serde_json::from_slice::<Vec<RawQuestion>>(unknown).is_err());
        assert!(serde_json::from_slice::<Vec<RawQuestion>>(missing).is_err());
    }

    #[test]
    fn post_decode_validation_rejects_duplicate_ids_and_non_ascii_strings() {
        let mut raw: Vec<RawQuestion> = serde_json::from_slice(QUESTION_BANK_BYTES).unwrap();
        raw[1].id = raw[0].id;
        assert!(matches!(
            validate_and_build(raw),
            Err(QuestionBankError::Validation(message)) if message.contains("duplicate")
        ));

        let mut raw: Vec<RawQuestion> = serde_json::from_slice(QUESTION_BANK_BYTES).unwrap();
        raw[0].options.a.push('\u{e9}');
        assert!(matches!(
            validate_and_build(raw),
            Err(QuestionBankError::Validation(message)) if message.contains("ASCII")
        ));
    }

    #[test]
    fn levels_preserve_frozen_names_counts_targets_and_weights() {
        let expected = [
            (
                QuizLevel::BabyGronk,
                "BABYGRONK",
                "BABY GRONK",
                15,
                60,
                [0.5, 2.0, 3.5, 4.5, 5.0, 3.0, 1.5, 0.5, 0.2, 0.1],
            ),
            (
                QuizLevel::SkibidiToilet,
                "SKIBIDITOILET",
                "SKIBIDI TOILET",
                30,
                150,
                [0.2, 0.8, 1.5, 2.5, 3.5, 3.5, 2.5, 1.5, 0.5, 0.2],
            ),
            (
                QuizLevel::OhioFinalBoss,
                "OHIOFINALBOSS",
                "OHIO FINAL BOSS",
                60,
                400,
                [0.05, 0.1, 0.3, 0.8, 1.5, 3.5, 5.0, 5.5, 4.0, 3.0],
            ),
        ];
        for (level, arg, display, count, target, weights) in expected {
            assert_eq!(
                QuizLevel::from_arg(&format!("  {}  ", arg.to_ascii_lowercase())),
                Some(level)
            );
            assert_eq!(level.arg(), arg);
            assert_eq!(level.display_name(), display);
            assert_eq!(level.question_count(), count);
            assert_eq!(level.target_total_difficulty(), target);
            assert_eq!(level.difficulty_tolerance(), 0.12);
            assert_eq!(level.bucket_weights(), weights);
        }
        assert_eq!(QuizLevel::from_arg("OHIO FINAL BOSS"), None);
    }

    #[test]
    fn selections_are_unique_and_in_tolerance_across_many_seeds_and_levels() {
        for level in QuizLevel::ALL {
            for seed in 0..32_u64 {
                let mut rng = SplitMix64(seed);
                let selected = assemble_quiz(bank(), level, &mut rng).unwrap();
                assert_eq!(selected.len(), level.question_count());
                assert_eq!(
                    selected.iter().copied().collect::<HashSet<_>>().len(),
                    selected.len()
                );
                let total = selected
                    .iter()
                    .map(|index| usize::from(bank().questions[*index].difficulty))
                    .sum::<usize>();
                let deviation = total.abs_diff(level.target_total_difficulty()) as f64
                    / level.target_total_difficulty() as f64;
                assert!(
                    deviation <= level.difficulty_tolerance(),
                    "{} seed={seed} total={total} deviation={deviation}",
                    level.arg()
                );
            }
        }
    }

    #[test]
    fn java_random_selection_order_matches_independent_oracle_fixtures() {
        let baby = [
            48, 428, 102, 382, 391, 15, 8, 64, 404, 323, 326, 87, 58, 328, 160,
        ];
        let skibidi = [
            23, 236, 75, 158, 124, 104, 425, 275, 145, 223, 40, 238, 256, 151, 68, 327, 70, 380,
            69, 382, 290, 119, 84, 67, 393, 254, 391, 323, 383, 321,
        ];
        let ohio = [
            104, 134, 371, 244, 249, 67, 83, 142, 173, 220, 218, 65, 172, 269, 472, 18, 259, 289,
            76, 117, 333, 438, 383, 21, 34, 165, 292, 89, 169, 187, 105, 158, 291, 418, 287, 278,
            92, 225, 200, 284, 112, 426, 298, 56, 341, 258, 414, 115, 280, 270, 144, 349, 6, 197,
            370, 381, 314, 417, 3, 312,
        ];
        let fixtures = [
            (QuizLevel::BabyGronk, 0_i64, baby.as_slice()),
            (QuizLevel::SkibidiToilet, 42_i64, skibidi.as_slice()),
            (QuizLevel::OhioFinalBoss, 0x1234_5678_i64, ohio.as_slice()),
        ];
        let ids = source_ids();
        for (level, seed, expected_ids) in fixtures {
            let mut rng = JavaRandom::new(seed);
            let selected = assemble_quiz(bank(), level, &mut rng).unwrap();
            let selected_ids = selected.iter().map(|index| ids[*index]).collect::<Vec<_>>();
            assert_eq!(selected_ids, expected_ids, "{} seed={seed}", level.arg());
        }
    }

    #[test]
    fn initial_question_lines_are_exact() {
        let state = state_with_indices(QuizLevel::BabyGronk, 0..15);
        assert_eq!(
            state.initial_lines(),
            vec![
                "QUIZ STARTED: BABY GRONK (15 questions | target difficulty: 60)",
                "Demonstrate your aura or be forever NPC. No skipping. No crying.",
                "",
                "Q1/15 [DIFFICULTY: 1/10] What is the name of the animated YouTube series that popularized the 'Skibidi Toilet' meme?",
                "  A) Skibidi Universe",
                "  B) Skibidi Toilet",
                "  C) Skibidi Multiverse",
                "  D) Toilet Wars",
                "ANSWER with A, B, C, or D",
            ]
        );
    }

    #[test]
    fn answer_feedback_score_and_next_question_are_exact() {
        let mut state = state_with_indices(QuizLevel::BabyGronk, 0..15);
        assert_eq!(
            state.answer("  b\t").unwrap(),
            AnswerOutcome::Continue(vec![
                "CORRECT! Sheeeesh, you got that rizz fr fr.".into(),
                "Score so far: 1/1 (100%)".into(),
                "".into(),
                "Q2/15 [DIFFICULTY: 2/10] Who is the creator of the Skibidi Toilet YouTube series?"
                    .into(),
                "  A) DaFuq!?Boom!".into(),
                "  B) MrBeast".into(),
                "  C) Markiplier".into(),
                "  D) PewDiePie".into(),
                "ANSWER with A, B, C, or D".into(),
            ])
        );
        assert_eq!(
            state.answer("D").unwrap(),
            AnswerOutcome::Continue(vec![
                "WRONG! Absolute NPC behavior detected. Correct answer: A) DaFuq!?Boom!".into(),
                "Score so far: 1/2 (50%)".into(),
                "".into(),
                "Q3/15 [DIFFICULTY: 2/10] In Brainrot internet culture, what does the term 'Ohio' generally refer to?".into(),
                "  A) A metaphor for being extremely wealthy".into(),
                "  B) A place known for extreme cold weather".into(),
                "  C) A state famous for its cuisine".into(),
                "  D) A location associated with bizarre, cursed, or surreal events".into(),
                "ANSWER with A, B, C, or D".into(),
            ])
        );
    }

    #[test]
    fn empty_and_out_of_phase_answers_do_not_advance_state() {
        let mut state = state_with_indices(QuizLevel::BabyGronk, 0..15);
        assert!(matches!(state.answer(" \t\r\n"), Err(AnswerError::Empty)));
        assert_eq!(state.answered_count(), 0);
        assert_eq!(state.correct_count(), 0);
        assert!(state.is_awaiting_answer());

        state.awaiting_answer = false;
        assert!(matches!(
            state.answer("B"),
            Err(AnswerError::NotAwaitingAnswer)
        ));
        assert_eq!(state.answered_count(), 0);
    }

    #[test]
    fn terminal_answer_has_separate_exact_250_and_220_payloads() {
        let mut state = state_with_indices(QuizLevel::BabyGronk, 0..15);
        state.current_index = 14;
        state.correct_count = 14;
        let answer = bank().questions[state.question_indices[14]]
            .answer_label()
            .to_string();
        assert_eq!(
            state.answer(&answer).unwrap(),
            AnswerOutcome::Complete {
                answer_lines: vec![
                    "CORRECT! The aura readings are off the charts.".into(),
                    "Score so far: 15/15 (100%)".into(),
                ],
                final_lines: vec![
                    "=== BRAINROT QUIZ COMPLETE: BABY GRONK ===".into(),
                    "Final Score: 15/15 (100%)".into(),
                    "Rating: CERTIFIED OHIO FINAL BOSS. You are the rizz incarnate.".into(),
                    "You demolished Baby Gronk mode. Now stop flexing on the NPCs and step it up."
                        .into(),
                    "Use SKIBIDITOILET START <LEVEL> to play again or touch grass.".into(),
                ],
            }
        );
        assert!(state.is_complete());
        assert!(!state.is_awaiting_answer());
        assert!(matches!(state.answer("A"), Err(AnswerError::Complete)));
    }

    #[test]
    fn forfeit_consumes_state_and_returns_exact_frozen_lines() {
        let state = state_with_indices(QuizLevel::BabyGronk, 0..15);
        assert_eq!(
            state.into_forfeit_lines(),
            vec![
                "Quiz forfeited. That is the most L take in recorded Brainrot history.",
                "Progress: 0/0 correct before you rage-quit.",
                "The Ohio final boss remains undefeated. You were not built different.",
                "Use SKIBIDITOILET START <LEVEL> to try again and redeem your aura.",
            ]
        );
    }

    #[test]
    fn java_rounding_ratings_and_level_comments_match_boundaries() {
        assert_eq!(java_percent(0, 0), 0);
        assert_eq!(java_percent(10, 15), 67);
        assert_eq!(java_percent(20, 30), 67);
        assert_eq!(java_percent(40, 60), 67);
        assert_eq!(
            rating(100),
            "CERTIFIED OHIO FINAL BOSS. You are the rizz incarnate."
        );
        assert!(rating(90).starts_with("GIGACHAD"));
        assert!(rating(75).starts_with("BUILT DIFFERENT"));
        assert!(rating(60).starts_with("MAIN CHARACTER"));
        assert!(rating(45).starts_with("SIDE CHARACTER"));
        assert!(rating(30).starts_with("NPC BEHAVIOR"));
        assert!(rating(15).starts_with("CERTIFIED BRAINROT PATIENT"));
        assert!(rating(14).starts_with("ABSOLUTE SNORLAX"));

        for level in QuizLevel::ALL {
            assert_ne!(final_comment(80, level), final_comment(79, level));
            assert_ne!(final_comment(50, level), final_comment(49, level));
        }
    }

    #[test]
    fn multiple_choice_matching_uses_java_trim_and_ascii_case_folding() {
        let question = &bank().questions[0];
        assert!(question.is_correct("B"));
        assert!(question.is_correct(" \tb\r\n"));
        assert!(!question.is_correct("A"));
        assert!(!question.is_correct("\u{a0}B\u{a0}"));
        assert!(!question.is_correct("Skibidi Toilet"));
    }
}
