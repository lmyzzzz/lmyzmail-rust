use std::fmt;

use getrandom::fill as fill_random;

const EXPRESSION_CAPACITY: usize = 64;
const MIN_EXPRESSION_LENGTH: usize = 18;
const MAX_EXPRESSION_LENGTH: usize = 43;
const BATCH_RECORD_CAPACITY: usize = 44;
const MAX_BATCH_EXPRESSIONS: usize = 4096;
const EXPECTED_VERSION: &str = "1.8.0-skibidi-ultra";
const PROPHECY_THRESHOLD_NICE: u32 = 1_680_443_541;
const BRRRRR_VIBRATION_THRESHOLD: u8 = 38;
const TOILET_REJECTION_THRESHOLD: u8 = 38;

const DOP_ZODIAC_CHART: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7,
];
const REJECTION_ZODIAC_CHART: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2,
];
const DOP_VARIANTS: [[u8; 3]; 8] = [
    *b"dop", *b"Dop", *b"dOp", *b"doP", *b"DOp", *b"DoP", *b"dOP", *b"DOP",
];
const DOM_VARIANTS: [[u8; 3]; 8] = [
    *b"dom", *b"Dom", *b"dOm", *b"doM", *b"DOm", *b"DoM", *b"dOM", *b"DOM",
];
const YES_VARIANTS: [[u8; 3]; 8] = [
    *b"yes", *b"Yes", *b"yEs", *b"yeS", *b"YEs", *b"YeS", *b"yES", *b"YES",
];
const NO_VARIANTS: [[u8; 2]; 4] = [*b"no", *b"No", *b"nO", *b"NO"];
const SACRED_PROPHECY: &[u8] = b"Skibidi dop dop dop yes yes!";

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
            Self::Avx2 => std::is_x86_feature_detected!("avx2"),
            Self::Avx512 => {
                std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("avx512f")
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
        generator.validate_batch_smoke()?;
        Ok(generator)
    }

    #[cfg(test)]
    fn for_backend(
        backend: SkibidiBackend,
        enable_avx512: bool,
        enable_simd_rng: bool,
    ) -> Result<Self, SkibidiError> {
        let generator = Self {
            backend,
            enable_avx512,
            enable_simd_rng,
        };
        generator.validate_batch_smoke()?;
        Ok(generator)
    }

    fn validate_batch_smoke(self) -> Result<(), SkibidiError> {
        let mut context = RustContext::new(0);
        let output = context.generate_batch(self.backend, self.enable_simd_rng, 1)?;
        if output.lengths.len() != 1 || output.bytes.is_empty() {
            return Err(SkibidiError::InvalidOutput(
                "Skibidi batch startup probe returned no expression".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn runtime_info(self) -> Result<SkibidiRuntimeInfo, SkibidiError> {
        let has_avx2 = std::is_x86_feature_detected!("avx2");
        let has_avx512 = has_avx2 && std::is_x86_feature_detected!("avx512f");
        let mut capabilities = 0_u32;
        if std::is_x86_feature_detected!("sse2") {
            capabilities |= 1 << 0;
        }
        if std::is_x86_feature_detected!("avx") {
            capabilities |= 1 << 1;
        }
        if has_avx2 {
            capabilities |= 1 << 2;
        }
        if has_avx512 {
            capabilities |= 1 << 3;
        }
        if has_avx512 && std::is_x86_feature_detected!("avx512vl") {
            capabilities |= 1 << 4;
        }
        if has_avx512 && std::is_x86_feature_detected!("avx512bw") {
            capabilities |= 1 << 5;
        }
        if has_avx512 && std::is_x86_feature_detected!("avx512dq") {
            capabilities |= 1 << 6;
        }
        Ok(SkibidiRuntimeInfo {
            backend: self.backend,
            version: EXPECTED_VERSION.to_owned(),
            capabilities,
            has_avx2,
            has_avx512,
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
        let mut context = RustContext::new(seed);
        context.generate_one(variant)
    }

    #[cfg(test)]
    fn generate_batch_seeded(self, seed: u64, count: usize) -> Result<BatchOutput, SkibidiError> {
        let mut context = RustContext::new(seed);
        context.generate_batch(self.backend, self.enable_simd_rng, count)
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
struct RustContext {
    s0: [u64; 4],
    s1: [u64; 4],
    call_count: u64,
}

impl RustContext {
    fn new(seed: u64) -> Self {
        let mut stream = seed;
        let mut s0 = [0_u64; 4];
        let mut s1 = [0_u64; 4];
        for lane in 0..4 {
            s0[lane] = splitmix64_next(&mut stream);
            s1[lane] = splitmix64_next(&mut stream);
            if (s0[lane] | s1[lane]) == 0 {
                s1[lane] = 0x9e37_79b9_7f4a_7c15;
            }
        }
        Self {
            s0,
            s1,
            call_count: 0,
        }
    }

    fn next(&mut self, lane: usize) -> u64 {
        let s0 = self.s0[lane];
        let mut s1 = self.s1[lane];
        let result = s0.wrapping_add(s1).rotate_left(17).wrapping_add(s0);
        s1 ^= s0;
        self.s0[lane] = s0.rotate_left(49) ^ s1 ^ (s1 << 21);
        self.s1[lane] = s1.rotate_left(28);
        result
    }

    fn generate_one(&mut self, variant: bool) -> Result<Expression, SkibidiError> {
        let primary = self.next(0);
        // The C oracle returns immediately on the dedicated prophecy path;
        // that path consumes one RNG word, while the normal/variant path
        // consumes the second word for capitalization and endings.
        if !variant && (primary as u32) < PROPHECY_THRESHOLD_NICE {
            self.call_count = self.call_count.saturating_add(1);
            let mut output = [0_u8; EXPRESSION_CAPACITY];
            output[..SACRED_PROPHECY.len()].copy_from_slice(SACRED_PROPHECY);
            return Ok(Expression {
                bytes: output,
                length: SACRED_PROPHECY.len(),
            });
        }
        let secondary = self.next(0);
        let mut output = [0_u8; EXPRESSION_CAPACITY];
        let length = materialize_with_entropy_mode(&mut output, primary, secondary, !variant)?;
        self.call_count = self.call_count.saturating_add(1);
        Ok(Expression {
            bytes: output,
            length,
        })
    }

    fn generate_batch(
        &mut self,
        backend: SkibidiBackend,
        simd_rng: bool,
        count: usize,
    ) -> Result<BatchOutput, SkibidiError> {
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
        let vector = simd_rng && matches!(backend, SkibidiBackend::Avx2 | SkibidiBackend::Avx512);
        let mut generated = 0;
        if vector {
            while generated + 4 <= count {
                let mut primary = [0_u64; 4];
                let mut secondary = [0_u64; 4];
                for lane in 0..4 {
                    primary[lane] = self.next(lane);
                }
                for lane in 0..4 {
                    secondary[lane] = self.next(lane);
                }
                for lane in 0..4 {
                    let mut record = [0_u8; EXPRESSION_CAPACITY];
                    let length = if (primary[lane] as u32) < PROPHECY_THRESHOLD_NICE {
                        record[..SACRED_PROPHECY.len()].copy_from_slice(SACRED_PROPHECY);
                        SACRED_PROPHECY.len()
                    } else {
                        materialize_with_entropy_batch(&mut record, primary[lane], secondary[lane])?
                    };
                    bytes.extend_from_slice(&record[..length]);
                    bytes.push(b'\n');
                    lengths.push(length);
                    generated += 1;
                }
            }
        }
        while generated < count {
            let expression = self.generate_one(false)?;
            bytes.extend_from_slice(expression.as_bytes());
            bytes.push(b'\n');
            lengths.push(expression.length);
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

fn dop_count(census: u8) -> usize {
    1 + usize::from(census > 12)
        + usize::from(census > 204)
        + usize::from(census > 230)
        + usize::from(census > 243)
}

fn write_word(output: &mut [u8; EXPRESSION_CAPACITY], position: &mut usize, word: &[u8]) {
    output[*position..*position + word.len()].copy_from_slice(word);
    *position += word.len();
}

fn write_dop(
    output: &mut [u8; EXPRESSION_CAPACITY],
    position: &mut usize,
    dom_draw: u32,
    zodiac_draw: u32,
) {
    let variant = if (dom_draw & 0x7) == 0 {
        &DOM_VARIANTS
    } else {
        &DOP_VARIANTS
    };
    let zodiac = DOP_ZODIAC_CHART[(zodiac_draw & 0x1f) as usize] as usize;
    write_word(output, position, &variant[zodiac]);
}

fn materialize_with_entropy_batch(
    output: &mut [u8; EXPRESSION_CAPACITY],
    primary: u64,
    secondary: u64,
) -> Result<usize, SkibidiError> {
    materialize_with_entropy_mode_impl(output, primary, secondary, true, true)
}

fn materialize_with_entropy_mode(
    output: &mut [u8; EXPRESSION_CAPACITY],
    primary: u64,
    secondary: u64,
    consult_prophecy: bool,
) -> Result<usize, SkibidiError> {
    materialize_with_entropy_mode_impl(output, primary, secondary, consult_prophecy, false)
}

fn materialize_with_entropy_mode_impl(
    output: &mut [u8; EXPRESSION_CAPACITY],
    primary: u64,
    secondary: u64,
    consult_prophecy: bool,
    batch_ending_layout: bool,
) -> Result<usize, SkibidiError> {
    let census = (primary >> 56) as u8;
    let vibration = if consult_prophecy {
        (primary >> 40) as u8
    } else {
        (primary >> 48) as u8
    };
    let judgment = if consult_prophecy {
        (primary >> 32) as u8
    } else {
        (primary >> 40) as u8
    };
    let mut position = 0;
    write_word(output, &mut position, b"Brrrrr ");
    if vibration >= BRRRRR_VIBRATION_THRESHOLD {
        position = 0;
    }
    write_word(output, &mut position, b"Skibidi ");
    let population = dop_count(census);
    let dom_draw = secondary as u32;
    let zodiac = (secondary >> 20) as u32;
    for index in 0..population {
        if index != 0 {
            output[position] = b' ';
            position += 1;
        }
        write_dop(
            output,
            &mut position,
            dom_draw >> (index * 3),
            zodiac >> (index * 5),
        );
    }
    output[position] = b' ';
    position += 1;
    if judgment >= TOILET_REJECTION_THRESHOLD {
        let (first, second) = if batch_ending_layout {
            (
                ((secondary >> 45) & 0x1f) as usize,
                ((secondary >> 40) & 0x1f) as usize,
            )
        } else {
            (
                ((secondary >> 40) & 0x1f) as usize,
                ((secondary >> 45) & 0x1f) as usize,
            )
        };
        if first < 25 && second < 25 {
            write_word(output, &mut position, b"yes yes!");
        } else {
            write_word(
                output,
                &mut position,
                &YES_VARIANTS[DOP_ZODIAC_CHART[first] as usize],
            );
            output[position] = b' ';
            position += 1;
            write_word(
                output,
                &mut position,
                &YES_VARIANTS[DOP_ZODIAC_CHART[second] as usize],
            );
            output[position] = b'!';
            position += 1;
        }
    } else {
        let (first, second) = if batch_ending_layout {
            (
                ((secondary >> 55) & 0x1f) as usize,
                ((secondary >> 50) & 0x1f) as usize,
            )
        } else {
            (
                ((secondary >> 50) & 0x1f) as usize,
                ((secondary >> 55) & 0x1f) as usize,
            )
        };
        if first < 26 && second < 26 {
            write_word(output, &mut position, b"no no!");
        } else {
            write_word(
                output,
                &mut position,
                &NO_VARIANTS[REJECTION_ZODIAC_CHART[first] as usize],
            );
            output[position] = b' ';
            position += 1;
            write_word(
                output,
                &mut position,
                &NO_VARIANTS[REJECTION_ZODIAC_CHART[second] as usize],
            );
            output[position] = b'!';
            position += 1;
        }
    }
    if !(MIN_EXPRESSION_LENGTH..=MAX_EXPRESSION_LENGTH).contains(&position) {
        return Err(SkibidiError::InvalidOutput(format!(
            "expression length {position} is outside the frozen contract"
        )));
    }
    Ok(position)
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
    fn rust_scalar_matches_frozen_c_threshold_and_seed_contract() {
        let expected = golden();
        let scalar = SkibidiGenerator::for_backend(SkibidiBackend::Scalar, false, false).unwrap();
        let mut context = RustContext::new(0);
        let singles = (0..8)
            .map(|_| {
                String::from_utf8(context.generate_one(false).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(&singles).unwrap(),
            expected["single_seed_0"]
        );
        let mut context = RustContext::new(0xfedc_ba98_7654_3210);
        let variants = (0..8)
            .map(|_| {
                String::from_utf8(context.generate_one(true).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(&variants).unwrap(),
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
    fn legacy_java_mode_is_only_a_rust_scalar_alias() {
        let generator = SkibidiGenerator::new("JAVA", true, true).unwrap();
        assert_eq!(generator.backend, SkibidiBackend::Scalar);
        assert_eq!(
            generator.generate_seeded(0, false).unwrap().as_bytes(),
            b"Skibidi dop dop yeS yes!"
        );
    }

    #[test]
    fn rust_vector_batch_matches_frozen_c_vector_contract() {
        let expected = golden();
        for backend in [SkibidiBackend::Avx2, SkibidiBackend::Avx512] {
            if !backend.is_supported() {
                continue;
            }
            let generator = SkibidiGenerator::for_backend(backend, true, true).unwrap();
            let batch = generator.generate_batch_seeded(42, 8).unwrap();
            assert_eq!(
                serde_json::to_value(expressions(&batch)).unwrap(),
                expected["batch_vector_seed_42"]["expressions"]
            );
            assert_eq!(batch.lengths, vec![32, 28, 28, 24, 32, 28, 28, 24]);
        }
    }
}
