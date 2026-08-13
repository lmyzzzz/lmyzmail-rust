use std::{fmt, sync::OnceLock};

use getrandom::fill as fill_random;

const EXPRESSION_CAPACITY: usize = 64;
const MIN_EXPRESSION_LENGTH: usize = 18;
const MAX_EXPRESSION_LENGTH: usize = 43;
const BATCH_RECORD_CAPACITY: usize = 44;
const MAX_BATCH_EXPRESSIONS: usize = 4096;
const EXPECTED_VERSION: &str = "1.8.0-skibidi-ultra";

// Thresholds and bit boundaries are frozen from Skibidi 1.8.0 C.
const PROPHECY_THRESHOLD_NICE: u32 = 1_680_443_541;
const BRRRRR_VIBRATION_THRESHOLD: u8 = 38;
const TOILET_REJECTION_THRESHOLD: u8 = 38;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SkibidiBackend {
    Scalar,
    Avx2,
    Avx512,
}

impl SkibidiBackend {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "Scalar",
            Self::Avx2 => "AVX2",
            Self::Avx512 => "AVX-512",
        }
    }
    fn is_supported(self) -> bool {
        match self {
            Self::Scalar => true,
            Self::Avx2 => cfg!(target_arch = "x86_64") && std::is_x86_feature_detected!("avx2"),
            Self::Avx512 => {
                cfg!(target_arch = "x86_64") && std::is_x86_feature_detected!("avx512f")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SkibidiRuntimeInfo {
    pub(crate) backend: SkibidiBackend,
    pub(crate) version: String,
    pub(crate) capabilities: u32,
    pub(crate) has_avx2: bool,
    pub(crate) has_avx512: bool,
    pub(crate) avx512_enabled: bool,
    pub(crate) simd_rng_enabled: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SkibidiGenerator {
    backend: SkibidiBackend,
    enable_avx512: bool,
    enable_simd_rng: bool,
}

impl SkibidiGenerator {
    pub(crate) fn new(
        mode: &str,
        enable_avx512: bool,
        enable_simd_rng: bool,
    ) -> Result<Self, SkibidiError> {
        let normalized = mode.trim().to_ascii_uppercase();
        let backend = match normalized.as_str() {
            // JAVA remains a compatibility alias only; the implementation is Rust.
            "JAVA" | "SCALAR" => SkibidiBackend::Scalar,
            "AVX2" => {
                if !SkibidiBackend::Avx2.is_supported() {
                    return Err(SkibidiError::UnsupportedBackend("AVX2"));
                }
                SkibidiBackend::Avx2
            }
            "AVX512" | "AVX-512" => {
                if !enable_avx512 {
                    return Err(SkibidiError::InvalidMode(
                        "AVX-512 mode requires skibidi-generator-enable-avx512=true".into(),
                    ));
                }
                if !SkibidiBackend::Avx512.is_supported() {
                    return Err(SkibidiError::UnsupportedBackend("AVX-512"));
                }
                SkibidiBackend::Avx512
            }
            "AUTO" | "AUTO_SAFE" | "NATIVE" => {
                if enable_avx512 && SkibidiBackend::Avx512.is_supported() {
                    SkibidiBackend::Avx512
                } else if SkibidiBackend::Avx2.is_supported() {
                    SkibidiBackend::Avx2
                } else {
                    SkibidiBackend::Scalar
                }
            }
            _ => {
                return Err(SkibidiError::InvalidMode(format!(
                    "unsupported Skibidi generator mode {mode:?}"
                )));
            }
        };
        let generator = Self {
            backend,
            enable_avx512,
            enable_simd_rng,
        };
        generator.runtime_info()?;
        generator.validate_batch_smoke()?;
        Ok(generator)
    }

    fn validate_batch_smoke(self) -> Result<(), SkibidiError> {
        let mut context = OwnedContext::new_with_config(self.backend, 1, self.enable_simd_rng);
        let output = context.generate_batch(1)?;
        if output.lengths.len() != 1 || output.bytes.is_empty() {
            return Err(SkibidiError::InvalidOutput(
                "Skibidi batch startup probe returned no expression".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn runtime_info(self) -> Result<SkibidiRuntimeInfo, SkibidiError> {
        let capabilities = cpu_capabilities();
        Ok(SkibidiRuntimeInfo {
            backend: self.backend,
            version: EXPECTED_VERSION.to_owned(),
            capabilities,
            has_avx2: capabilities & (1 << 2) != 0,
            has_avx512: capabilities & (1 << 3) != 0,
            avx512_enabled: self.enable_avx512 && self.backend == SkibidiBackend::Avx512,
            simd_rng_enabled: self.enable_simd_rng,
        })
    }

    pub(crate) fn generate(self) -> Result<Expression, SkibidiError> {
        let mut seed = [0_u8; 8];
        fill_random(&mut seed).map_err(|error| SkibidiError::Random(error.to_string()))?;
        self.generate_seeded(u64::from_le_bytes(seed), false)
    }

    fn generate_seeded(self, seed: u64, variant: bool) -> Result<Expression, SkibidiError> {
        let mut context = OwnedContext::new_with_config(self.backend, seed, self.enable_simd_rng);
        context.generate(variant)
    }

    #[cfg(test)]
    fn generate_batch_seeded(self, seed: u64, count: usize) -> Result<BatchOutput, SkibidiError> {
        let mut context = OwnedContext::new_with_config(self.backend, seed, self.enable_simd_rng);
        context.generate_batch(count)
    }
}

pub(crate) struct Expression {
    bytes: [u8; EXPRESSION_CAPACITY],
    length: usize,
}
impl Expression {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

struct BatchOutput {
    bytes: Vec<u8>,
    lengths: Vec<usize>,
}
impl BatchOutput {
    #[cfg(test)]
    fn expressions(&self) -> impl Iterator<Item = &[u8]> {
        let mut offset = 0_usize;
        self.lengths.iter().map(move |length| {
            let expression = &self.bytes[offset..offset + *length];
            offset += *length + 1;
            expression
        })
    }
}

#[derive(Clone, Copy)]
struct RngState {
    s0: [u64; 4],
    s1: [u64; 4],
}
impl RngState {
    fn seeded(seed: u64) -> Self {
        let mut stream = seed;
        let mut s0 = [0; 4];
        let mut s1 = [0; 4];
        for lane in 0..4 {
            s0[lane] = splitmix64_next(&mut stream);
            s1[lane] = splitmix64_next(&mut stream);
            if s0[lane] == 0 && s1[lane] == 0 {
                s1[lane] = 0x9e37_79b9_7f4a_7c15;
            }
        }
        Self { s0, s1 }
    }
    fn next_lane(&mut self, lane: usize) -> u64 {
        let s0 = self.s0[lane];
        let mut s1 = self.s1[lane];
        let result = s0.wrapping_add(s1).rotate_left(17).wrapping_add(s0);
        s1 ^= s0;
        self.s0[lane] = s0.rotate_left(49) ^ s1 ^ s1.wrapping_shl(21);
        self.s1[lane] = s1.rotate_left(28);
        result
    }
}

struct OwnedContext {
    backend: SkibidiBackend,
    simd_rng_enabled: bool,
    rng: RngState,
}
impl OwnedContext {
    #[cfg(test)]
    fn new(backend: SkibidiBackend, seed: u64) -> Self {
        Self::new_with_config(backend, seed, false)
    }
    fn new_with_config(backend: SkibidiBackend, seed: u64, simd_rng_enabled: bool) -> Self {
        Self {
            backend,
            simd_rng_enabled,
            rng: RngState::seeded(seed),
        }
    }
    fn generate(&mut self, variant: bool) -> Result<Expression, SkibidiError> {
        let primary = self.rng.next_lane(0);
        if !variant && (primary as u32) < PROPHECY_THRESHOLD_NICE {
            return Ok(sacred_prophecy());
        }
        let secondary = self.rng.next_lane(0);
        speak_from_entropy_with_mode(primary, secondary, !variant)
    }
    fn generate_batch(&mut self, count: usize) -> Result<BatchOutput, SkibidiError> {
        if count > MAX_BATCH_EXPRESSIONS {
            return Err(SkibidiError::InvalidOutput(format!(
                "batch count {count} exceeds {MAX_BATCH_EXPRESSIONS}"
            )));
        }
        if count == 0 {
            return Ok(BatchOutput {
                bytes: Vec::new(),
                lengths: Vec::new(),
            });
        }
        let mut bytes = Vec::with_capacity(count * BATCH_RECORD_CAPACITY);
        let mut lengths = Vec::with_capacity(count);
        let vector_path = self.simd_rng_enabled && self.backend != SkibidiBackend::Scalar;
        let mut generated = 0;
        if vector_path {
            while generated + 4 <= count {
                let mut primary = [0_u64; 4];
                let mut secondary = [0_u64; 4];
                #[allow(clippy::needless_range_loop)]
                for lane in 0..4 {
                    primary[lane] = self.rng.next_lane(lane);
                }
                #[allow(clippy::needless_range_loop)]
                for lane in 0..4 {
                    secondary[lane] = self.rng.next_lane(lane);
                }
                for lane in 0..4 {
                    let expression = if (primary[lane] as u32) < PROPHECY_THRESHOLD_NICE {
                        sacred_prophecy()
                    } else {
                        speak_vector_from_entropy(primary[lane], secondary[lane])?
                    };
                    lengths.push(expression.length);
                    bytes.extend_from_slice(expression.as_bytes());
                    bytes.push(b'\n');
                    generated += 1;
                }
            }
        }
        while generated < count {
            let expression = self.generate(false)?;
            lengths.push(expression.length);
            bytes.extend_from_slice(expression.as_bytes());
            bytes.push(b'\n');
            generated += 1;
        }
        Ok(BatchOutput { bytes, lengths })
    }
}

fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
fn dop_case(value: u8) -> u8 {
    match value {
        25 => 1,
        26 => 2,
        27 => 3,
        28 => 4,
        29 => 5,
        30 => 6,
        31 => 7,
        _ => 0,
    }
}
fn rejection_case(value: u8) -> u8 {
    match value {
        26 => 1,
        27 => 2,
        28 => 3,
        29 => 0,
        30 => 1,
        31 => 2,
        _ => 0,
    }
}
fn dop_count(value: u8) -> usize {
    1 + usize::from(value > 12)
        + usize::from(value > 204)
        + usize::from(value > 230)
        + usize::from(value > 243)
}
const DOP_WORDS: [&[u8]; 8] = [
    b"dop", b"Dop", b"dOp", b"doP", b"DOp", b"DoP", b"dOP", b"DOP",
];
const DOM_WORDS: [&[u8]; 8] = [
    b"dom", b"Dom", b"dOm", b"doM", b"DOm", b"DoM", b"dOM", b"DOM",
];
const YES_WORDS: [&[u8]; 8] = [
    b"yes", b"Yes", b"yEs", b"yeS", b"YEs", b"YeS", b"yES", b"YES",
];
const NO_WORDS: [&[u8]; 4] = [b"no", b"No", b"nO", b"NO"];
fn dop_word(dom: bool, case: u8) -> &'static [u8] {
    if dom {
        DOM_WORDS[case as usize]
    } else {
        DOP_WORDS[case as usize]
    }
}
fn sacred_prophecy() -> Expression {
    expression_from_bytes(b"Skibidi dop dop dop yes yes!")
}
fn expression_from_bytes(bytes: &[u8]) -> Expression {
    let mut output = [0_u8; EXPRESSION_CAPACITY];
    output[..bytes.len()].copy_from_slice(bytes);
    Expression {
        bytes: output,
        length: bytes.len(),
    }
}
fn speak_from_entropy_with_mode(
    primary: u64,
    secondary: u64,
    consult_prophecy: bool,
) -> Result<Expression, SkibidiError> {
    let vibration = if consult_prophecy {
        (primary >> 40) as u8
    } else {
        (primary >> 48) as u8
    };
    let verdict = if consult_prophecy {
        (primary >> 32) as u8
    } else {
        (primary >> 40) as u8
    };
    materialize(primary, secondary, vibration, verdict)
}
fn speak_vector_from_entropy(primary: u64, secondary: u64) -> Result<Expression, SkibidiError> {
    materialize_vector(
        primary,
        secondary,
        (primary >> 40) as u8,
        (primary >> 32) as u8,
    )
}

fn materialize_vector(
    primary: u64,
    secondary: u64,
    vibration: u8,
    verdict: u8,
) -> Result<Expression, SkibidiError> {
    let mut output = Vec::with_capacity(EXPRESSION_CAPACITY);
    if vibration < BRRRRR_VIBRATION_THRESHOLD {
        output.extend_from_slice(b"Brrrrr ");
    }
    output.extend_from_slice(b"Skibidi ");
    let population = dop_count((primary >> 56) as u8);
    let dom_bits = secondary as u32;
    let zodiac_bits = (secondary >> 20) as u32;
    for index in 0..population {
        if index != 0 {
            output.push(b' ');
        }
        let dom = ((dom_bits >> (index * 3)) & 0x7) == 0;
        let case = dop_case(((zodiac_bits >> (index * 5)) & 0x1f) as u8);
        output.extend_from_slice(dop_word(dom, case));
    }
    output.push(b' ');
    let approval = verdict >= TOILET_REJECTION_THRESHOLD;
    let approval_index = ((secondary >> 40) & 0x3ff) as u16;
    let rejection_index = ((secondary >> 50) & 0x3ff) as u16;
    let variant_index = if approval {
        approval_index
    } else {
        rejection_index
    };
    if approval {
        let first = (variant_index & 0x1f) as u8;
        let second = ((variant_index >> 5) & 0x1f) as u8;
        output.extend_from_slice(YES_WORDS[dop_case(second) as usize]);
        output.push(b' ');
        output.extend_from_slice(YES_WORDS[dop_case(first) as usize]);
        output.push(b'!');
    } else {
        let first = (variant_index & 0x1f) as u8;
        let second = ((variant_index >> 5) & 0x1f) as u8;
        output.extend_from_slice(NO_WORDS[rejection_case(first) as usize]);
        output.push(b' ');
        output.extend_from_slice(NO_WORDS[rejection_case(second) as usize]);
        output.push(b'!');
    }
    if !(MIN_EXPRESSION_LENGTH..=MAX_EXPRESSION_LENGTH).contains(&output.len()) {
        return Err(SkibidiError::InvalidOutput(format!(
            "expression length {} is outside the frozen contract",
            output.len()
        )));
    }
    Ok(expression_from_bytes(&output))
}
fn materialize(
    primary: u64,
    secondary: u64,
    vibration: u8,
    verdict: u8,
) -> Result<Expression, SkibidiError> {
    let mut output = Vec::with_capacity(EXPRESSION_CAPACITY);
    if vibration < BRRRRR_VIBRATION_THRESHOLD {
        output.extend_from_slice(b"Brrrrr ");
    }
    output.extend_from_slice(b"Skibidi ");
    let population = dop_count((primary >> 56) as u8);
    let dom_bits = secondary as u32;
    let zodiac_bits = (secondary >> 20) as u32;
    for index in 0..population {
        if index != 0 {
            output.push(b' ');
        }
        let dom = ((dom_bits >> (index * 3)) & 0x7) == 0;
        let case = dop_case(((zodiac_bits >> (index * 5)) & 0x1f) as u8);
        output.extend_from_slice(dop_word(dom, case));
    }
    output.push(b' ');
    if verdict >= TOILET_REJECTION_THRESHOLD {
        let first = ((secondary >> 40) & 0x1f) as u8;
        let second = ((secondary >> 45) & 0x1f) as u8;
        if first < 25 && second < 25 {
            output.extend_from_slice(b"yes yes!");
        } else {
            output.extend_from_slice(YES_WORDS[dop_case(first) as usize]);
            output.push(b' ');
            output.extend_from_slice(YES_WORDS[dop_case(second) as usize]);
            output.push(b'!');
        }
    } else {
        let first = ((secondary >> 50) & 0x1f) as u8;
        let second = ((secondary >> 55) & 0x1f) as u8;
        if first < 26 && second < 26 {
            output.extend_from_slice(b"no no!");
        } else {
            output.extend_from_slice(NO_WORDS[rejection_case(first) as usize]);
            output.push(b' ');
            output.extend_from_slice(NO_WORDS[rejection_case(second) as usize]);
            output.push(b'!');
        }
    }
    if !(MIN_EXPRESSION_LENGTH..=MAX_EXPRESSION_LENGTH).contains(&output.len()) {
        return Err(SkibidiError::InvalidOutput(format!(
            "expression length {} is outside the frozen contract",
            output.len()
        )));
    }
    Ok(expression_from_bytes(&output))
}
fn cpu_capabilities() -> u32 {
    static CAPS: OnceLock<u32> = OnceLock::new();
    *CAPS.get_or_init(|| {
        let mut capabilities = 0;
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") {
                capabilities |= 1 << 0;
            }
            if std::is_x86_feature_detected!("avx") {
                capabilities |= 1 << 1;
            }
            if std::is_x86_feature_detected!("avx2") {
                capabilities |= 1 << 2;
            }
            if std::is_x86_feature_detected!("avx512f") {
                capabilities |= 1 << 3;
            }
            if std::is_x86_feature_detected!("avx512vl") {
                capabilities |= 1 << 4;
            }
            if std::is_x86_feature_detected!("avx512bw") {
                capabilities |= 1 << 5;
            }
            if std::is_x86_feature_detected!("avx512dq") {
                capabilities |= 1 << 6;
            }
        }
        capabilities
    })
}

#[derive(Debug)]
pub(crate) enum SkibidiError {
    InvalidMode(String),
    UnsupportedBackend(&'static str),
    InvalidOutput(String),
    Random(String),
}
impl fmt::Display for SkibidiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMode(error) | Self::InvalidOutput(error) => formatter.write_str(error),
            Self::UnsupportedBackend(backend) => write!(
                formatter,
                "Skibidi {backend} backend is not supported by this CPU/OS"
            ),
            Self::Random(error) => write!(formatter, "Skibidi seed generation failed: {error}"),
        }
    }
}
impl std::error::Error for SkibidiError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    fn golden() -> Value {
        serde_json::from_str(include_str!(
            "../../../blackbox/golden/native/skibidi-1.8.0-v1/contract.json"
        ))
        .unwrap()
    }
    fn expressions(output: &BatchOutput) -> Vec<String> {
        output
            .expressions()
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .collect()
    }
    #[test]
    fn scalar_seed_variant_and_batch_match_frozen_c_probe() {
        let _guard = TEST_LOCK.lock().unwrap();
        let expected = golden();
        let scalar = SkibidiGenerator::new("SCALAR", false, false).unwrap();
        let mut context = OwnedContext::new(SkibidiBackend::Scalar, 0);
        let singles = (0..8)
            .map(|_| {
                String::from_utf8(context.generate(false).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(singles).unwrap(),
            expected["single_seed_0"]
        );
        let mut context = OwnedContext::new(SkibidiBackend::Scalar, 0xfedc_ba98_7654_3210);
        let variants = (0..8)
            .map(|_| {
                String::from_utf8(context.generate(true).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(variants).unwrap(),
            expected["variant_seed_fedcba9876543210"]
        );
        let batch = scalar.generate_batch_seeded(42, 8).unwrap();
        assert_eq!(batch.lengths, vec![32, 32, 28, 24, 22, 24, 26, 24]);
        assert_eq!(
            serde_json::to_value(expressions(&batch)).unwrap(),
            expected["batch_scalar_seed_42"]["expressions"]
        );
    }
    #[test]
    fn vector_batch_matches_frozen_c_probe_when_available() {
        let _guard = TEST_LOCK.lock().unwrap();
        let expected = golden();
        for backend in [SkibidiBackend::Avx2, SkibidiBackend::Avx512] {
            if !backend.is_supported() {
                continue;
            }
            let generator = SkibidiGenerator {
                backend,
                enable_avx512: true,
                enable_simd_rng: true,
            };
            let batch = generator.generate_batch_seeded(42, 8).unwrap();
            assert_eq!(
                serde_json::to_value(expressions(&batch)).unwrap(),
                expected["batch_vector_seed_42"]["expressions"]
            );
        }
    }
    #[test]
    fn java_mode_is_only_a_rust_compatibility_alias() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generator = SkibidiGenerator::new("JAVA", true, true).unwrap();
        assert_eq!(generator.backend, SkibidiBackend::Scalar);
        assert_eq!(generator.runtime_info().unwrap().version, EXPECTED_VERSION);
    }
}
