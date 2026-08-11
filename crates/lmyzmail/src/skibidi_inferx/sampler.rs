use std::{collections::HashSet, fmt};

use sha2::{Digest, Sha256};

pub(crate) const BOS_ID: u32 = 1;
pub(crate) const EOS_ID: u32 = 2;
pub(crate) const DEFAULT_TEMPERATURE: f32 = 0.85;
pub(crate) const DEFAULT_TOP_K: usize = 50;
pub(crate) const DEFAULT_TOP_P: f32 = 0.92;
pub(crate) const DEFAULT_REPETITION_PENALTY: f32 = 1.15;
pub(crate) const DEFAULT_NO_REPEAT_NGRAM: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct SamplingParams {
    pub(crate) temperature: f32,
    pub(crate) top_k: usize,
    pub(crate) top_p: f32,
    pub(crate) repetition_penalty: f32,
    pub(crate) no_repeat_ngram: usize,
}

impl SamplingParams {
    pub(crate) fn validate(self, vocab_size: usize) -> Result<Self, SamplingError> {
        if !self.temperature.is_finite() || self.temperature <= 0.0 || self.temperature > 5.0 {
            return Err(SamplingError::Invalid(
                "InferX temperature must be finite and in (0, 5]".into(),
            ));
        }
        if self.top_k > vocab_size {
            return Err(SamplingError::Invalid(format!(
                "InferX top-k {} exceeds vocab size {vocab_size}",
                self.top_k
            )));
        }
        if !self.top_p.is_finite() || self.top_p <= 0.0 || self.top_p > 1.0 {
            return Err(SamplingError::Invalid(
                "InferX top-p must be finite and in (0, 1]".into(),
            ));
        }
        if !self.repetition_penalty.is_finite()
            || self.repetition_penalty <= 0.0
            || self.repetition_penalty > 10.0
        {
            return Err(SamplingError::Invalid(
                "InferX repetition penalty must be finite and in (0, 10]".into(),
            ));
        }
        if self.no_repeat_ngram > 32 {
            return Err(SamplingError::Invalid(
                "InferX no-repeat n-gram exceeds 32".into(),
            ));
        }
        Ok(self)
    }
}

pub(crate) struct Sampler {
    logits: Vec<f32>,
    probabilities: Vec<f32>,
    heap: Vec<f32>,
    indices: Vec<usize>,
    sorted_probabilities: Vec<f32>,
}

impl Sampler {
    pub(crate) fn new(vocab_size: usize) -> Self {
        Self {
            logits: vec![0.0; vocab_size],
            probabilities: vec![0.0; vocab_size],
            heap: Vec::with_capacity(vocab_size),
            indices: vec![0; vocab_size],
            sorted_probabilities: vec![0.0; vocab_size],
        }
    }

    pub(crate) fn sample(
        &mut self,
        source_logits: &[f32],
        params: SamplingParams,
        previous_tokens: &[u32],
        random: &mut JavaRandom,
    ) -> Result<u32, SamplingError> {
        if source_logits.len() != self.logits.len() {
            return Err(SamplingError::Invalid(
                "InferX logits length differs from the configured vocabulary".into(),
            ));
        }
        let params = params.validate(source_logits.len())?;
        self.logits.copy_from_slice(source_logits);

        if params.repetition_penalty != 1.0 && !previous_tokens.is_empty() {
            let seen = previous_tokens.iter().copied().collect::<HashSet<_>>();
            for token in seen {
                let Some(logit) = usize::try_from(token)
                    .ok()
                    .and_then(|index| self.logits.get_mut(index))
                else {
                    continue;
                };
                if *logit > 0.0 {
                    *logit /= params.repetition_penalty;
                } else {
                    *logit *= params.repetition_penalty;
                }
            }
        }

        if params.no_repeat_ngram > 0 && previous_tokens.len() >= params.no_repeat_ngram {
            let prefix_length = params.no_repeat_ngram - 1;
            let prefix_start = previous_tokens.len() - prefix_length;
            for index in 0..=previous_tokens.len() - params.no_repeat_ngram {
                if previous_tokens[index..index + prefix_length] == previous_tokens[prefix_start..]
                {
                    let blocked = previous_tokens[index + prefix_length];
                    if let Some(logit) = usize::try_from(blocked)
                        .ok()
                        .and_then(|index| self.logits.get_mut(index))
                    {
                        *logit = f32::NEG_INFINITY;
                    }
                }
            }
        }

        if params.temperature != 1.0 {
            let inverse = 1.0_f32 / params.temperature;
            for logit in &mut self.logits {
                *logit *= inverse;
            }
        }

        if params.top_k > 0 && params.top_k < self.logits.len() {
            let threshold = kth_largest(&self.logits, params.top_k, &mut self.heap);
            for logit in &mut self.logits {
                if *logit < threshold {
                    *logit = f32::NEG_INFINITY;
                }
            }
        }

        let max_logit = self
            .logits
            .iter()
            .copied()
            .fold(f32::NEG_INFINITY, f32::max);
        let mut sum = 0.0_f64;
        for (index, logit) in self.logits.iter().copied().enumerate() {
            let probability = if logit == f32::NEG_INFINITY {
                0.0
            } else {
                f64::from(logit - max_logit).exp() as f32
            };
            self.probabilities[index] = probability;
            sum += f64::from(probability);
        }
        if sum > 0.0 {
            let inverse = (1.0_f64 / sum) as f32;
            for probability in &mut self.probabilities {
                *probability *= inverse;
            }
        }

        if params.top_p < 1.0 {
            apply_top_p(
                &mut self.probabilities,
                params.top_p,
                &mut self.indices,
                &mut self.sorted_probabilities,
            );
        }
        Ok(multinomial(&self.probabilities, random))
    }
}

fn kth_largest(values: &[f32], count: usize, heap: &mut Vec<f32>) -> f32 {
    heap.clear();
    heap.extend_from_slice(&values[..count]);
    for index in (0..count / 2).rev() {
        sift_down(heap, index, count);
    }
    for &value in &values[count..] {
        if value > heap[0] {
            heap[0] = value;
            sift_down(heap, 0, count);
        }
    }
    heap[0]
}

fn sift_down(heap: &mut [f32], mut index: usize, size: usize) {
    loop {
        let mut smallest = index;
        let left = 2 * index + 1;
        let right = left + 1;
        if left < size && heap[left] < heap[smallest] {
            smallest = left;
        }
        if right < size && heap[right] < heap[smallest] {
            smallest = right;
        }
        if smallest == index {
            return;
        }
        heap.swap(index, smallest);
        index = smallest;
    }
}

fn apply_top_p(probabilities: &mut [f32], top_p: f32, indices: &mut [usize], sorted: &mut [f32]) {
    let mut count = 0;
    for (index, &probability) in probabilities.iter().enumerate() {
        if probability > 0.0 {
            indices[count] = index;
            sorted[count] = probability;
            count += 1;
        }
    }
    for index in 1..count {
        let probability = sorted[index];
        let token = indices[index];
        let mut insertion = index;
        while insertion > 0 && sorted[insertion - 1] < probability {
            sorted[insertion] = sorted[insertion - 1];
            indices[insertion] = indices[insertion - 1];
            insertion -= 1;
        }
        sorted[insertion] = probability;
        indices[insertion] = token;
    }

    probabilities.fill(0.0);
    let mut cumulative = 0.0_f32;
    let mut normalization = 0.0_f32;
    for index in 0..count {
        if cumulative >= top_p && index > 0 {
            break;
        }
        probabilities[indices[index]] = sorted[index];
        normalization += sorted[index];
        cumulative += sorted[index];
    }
    if normalization > 0.0 {
        let inverse = 1.0 / normalization;
        for probability in probabilities {
            *probability *= inverse;
        }
    }
}

fn multinomial(probabilities: &[f32], random: &mut JavaRandom) -> u32 {
    let target = random.next_float();
    let mut cumulative = 0.0_f32;
    for (index, &probability) in probabilities.iter().enumerate() {
        cumulative += probability;
        if target < cumulative {
            return index as u32;
        }
    }
    probabilities
        .iter()
        .rposition(|probability| *probability > 0.0)
        .unwrap_or(0) as u32
}

pub(crate) fn seed_from_str(input: &str) -> u64 {
    let digest = Sha256::digest(input.as_bytes());
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 prefix length"))
}

pub(crate) struct JavaRandom {
    state: u64,
}

impl JavaRandom {
    const MULTIPLIER: u64 = 0x5deece66d;
    const ADDEND: u64 = 0xb;
    const MASK: u64 = (1_u64 << 48) - 1;

    pub(crate) fn new(seed: u64) -> Self {
        Self {
            state: (seed ^ Self::MULTIPLIER) & Self::MASK,
        }
    }

    fn next(&mut self, bits: u32) -> u32 {
        self.state = self
            .state
            .wrapping_mul(Self::MULTIPLIER)
            .wrapping_add(Self::ADDEND)
            & Self::MASK;
        (self.state >> (48 - bits)) as u32
    }

    pub(crate) fn next_float(&mut self) -> f32 {
        self.next(24) as f32 / (1_u32 << 24) as f32
    }
}

#[derive(Debug)]
pub(crate) enum SamplingError {
    Invalid(String),
}

impl fmt::Display for SamplingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for SamplingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_random_matches_known_next_float_values() {
        let mut random = JavaRandom::new(0);
        assert_eq!(random.next_float().to_bits(), 0x3f3b_20b4);
        assert_eq!(random.next_float().to_bits(), 0x3f54_d951);
    }

    #[test]
    fn string_seed_matches_frozen_java_little_endian_sha256() {
        assert_eq!(
            seed_from_str("203.0.113.7:<spoof@example.test>:1700000000000"),
            0x615f_da61_1360_1482
        );
        assert_eq!(seed_from_str(""), 0x141c_fc98_42c4_b0e3);
        assert_eq!(seed_from_str("邮件:Ohio:💀"), 0x358d_9ced_6402_fe14);
    }

    #[test]
    fn ngram_and_repetition_filters_remain_bounded() {
        let params = SamplingParams {
            temperature: 1.0,
            top_k: 0,
            top_p: 1.0,
            repetition_penalty: 1.15,
            no_repeat_ngram: 3,
        };
        let mut sampler = Sampler::new(5);
        let mut random = JavaRandom::new(42);
        let token = sampler
            .sample(
                &[0.0, 1.0, 2.0, 3.0, 4.0],
                params,
                &[1, 2, 1, 2],
                &mut random,
            )
            .unwrap();
        assert_ne!(token, 1);
    }
}
