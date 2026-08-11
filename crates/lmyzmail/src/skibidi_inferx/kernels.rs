use std::{arch::x86_64::*, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SimdPreference {
    Auto,
    Scalar,
    Avx2,
    Avx512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    Scalar,
    Avx2,
    Avx512,
}

impl Backend {
    pub(crate) fn select(preference: SimdPreference) -> Result<Self, KernelError> {
        let avx2 = std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma");
        let avx512 = avx2 && std::is_x86_feature_detected!("avx512f");
        match preference {
            SimdPreference::Auto if avx512 => Ok(Self::Avx512),
            SimdPreference::Auto if avx2 => Ok(Self::Avx2),
            SimdPreference::Auto | SimdPreference::Scalar => Ok(Self::Scalar),
            SimdPreference::Avx2 if avx2 => Ok(Self::Avx2),
            SimdPreference::Avx512 if avx512 => Ok(Self::Avx512),
            SimdPreference::Avx2 => Err(KernelError::Unsupported("AVX2+FMA")),
            SimdPreference::Avx512 => Err(KernelError::Unsupported("AVX-512F")),
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "Scalar",
            Self::Avx2 => "AVX2+FMA",
            Self::Avx512 => "AVX-512F",
        }
    }

    pub(crate) fn matvec(
        self,
        matrix: &[f32],
        vector: &[f32],
        bias: Option<&[f32]>,
        output: &mut [f32],
        rows: usize,
        columns: usize,
    ) {
        debug_assert_eq!(matrix.len(), rows * columns);
        debug_assert_eq!(vector.len(), columns);
        debug_assert_eq!(output.len(), rows);
        debug_assert!(bias.is_none_or(|values| values.len() == rows));
        match self {
            Self::Scalar => scalar_matvec(matrix, vector, bias, output, rows, columns),
            Self::Avx2 => {
                // SAFETY: Backend::select checked AVX2, FMA, and OS extended
                // state before constructing this value. Slice bounds were
                // checked by the engine and the intrinsic uses unaligned loads.
                unsafe { avx2_matvec(matrix, vector, bias, output, rows, columns) }
            }
            Self::Avx512 => {
                // SAFETY: Backend::select checked AVX-512F, AVX2, FMA, and OS
                // extended state. The same validated slice invariants apply.
                unsafe { avx512_matvec(matrix, vector, bias, output, rows, columns) }
            }
        }
    }

    pub(crate) fn rms_norm(self, input: &[f32], weights: &[f32], output: &mut [f32], epsilon: f32) {
        debug_assert_eq!(input.len(), weights.len());
        debug_assert_eq!(input.len(), output.len());
        let squares = match self {
            Self::Scalar => input.iter().fold(0.0_f32, |sum, value| sum + value * value),
            Self::Avx2 => {
                // SAFETY: selected backend proves the target features.
                unsafe { avx2_sum_squares(input) }
            }
            Self::Avx512 => {
                // SAFETY: selected backend proves the target features.
                unsafe { avx512_sum_squares(input) }
            }
        };
        let inverse_rms = 1.0 / (squares / input.len() as f32 + epsilon).sqrt();
        match self {
            Self::Scalar => {
                for ((target, &value), &weight) in output.iter_mut().zip(input).zip(weights) {
                    *target = weight * value * inverse_rms;
                }
            }
            Self::Avx2 => {
                // SAFETY: selected backend proves AVX2 and all slices have
                // identical validated lengths.
                unsafe { avx2_rms_scale(input, weights, output, inverse_rms) }
            }
            Self::Avx512 => {
                // SAFETY: selected backend proves AVX-512F and all slices
                // have identical validated lengths.
                unsafe { avx512_rms_scale(input, weights, output, inverse_rms) }
            }
        }
    }

    pub(crate) fn silu_in_place(self, values: &mut [f32]) {
        match self {
            Self::Scalar => {
                for value in values {
                    *value /= 1.0 + (-*value).exp();
                }
            }
            Self::Avx2 => {
                // SAFETY: selected backend proves AVX2 and FMA.
                unsafe { avx2_silu(values) }
            }
            Self::Avx512 => {
                // SAFETY: selected backend proves AVX-512F and FMA.
                unsafe { avx512_silu(values) }
            }
        }
    }

    pub(crate) fn multiply_in_place(self, target: &mut [f32], source: &[f32]) {
        debug_assert_eq!(target.len(), source.len());
        for (target, source) in target.iter_mut().zip(source) {
            *target *= *source;
        }
    }

    pub(crate) fn add_in_place(self, target: &mut [f32], source: &[f32]) {
        debug_assert_eq!(target.len(), source.len());
        for (target, source) in target.iter_mut().zip(source) {
            *target += *source;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mha_step(
        self,
        qkv: &[f32],
        key_cache: &mut [f32],
        value_cache: &mut [f32],
        output: &mut [f32],
        score_buffer: &mut [f32],
        position: usize,
        heads: usize,
        d_k: usize,
        max_sequence: usize,
    ) {
        let d_model = heads * d_k;
        debug_assert_eq!(qkv.len(), 3 * d_model);
        debug_assert_eq!(key_cache.len(), heads * max_sequence * d_k);
        debug_assert_eq!(value_cache.len(), key_cache.len());
        debug_assert_eq!(output.len(), d_model);
        debug_assert_eq!(score_buffer.len(), heads * max_sequence);
        debug_assert!(position < max_sequence);

        let (query, rest) = qkv.split_at(d_model);
        let (key, value) = rest.split_at(d_model);
        let scale = 1.0 / (d_k as f32).sqrt();
        let sequence_length = position + 1;
        for head in 0..heads {
            let vector_start = head * d_k;
            let vector_end = vector_start + d_k;
            let cache_start = head * max_sequence * d_k;
            let cache_end = cache_start + max_sequence * d_k;
            let key_head = &mut key_cache[cache_start..cache_end];
            let value_head = &mut value_cache[cache_start..cache_end];
            let position_start = position * d_k;
            key_head[position_start..position_start + d_k]
                .copy_from_slice(&key[vector_start..vector_end]);
            value_head[position_start..position_start + d_k]
                .copy_from_slice(&value[vector_start..vector_end]);

            let scores = &mut score_buffer[head * max_sequence..(head + 1) * max_sequence];
            let query_head = &query[vector_start..vector_end];
            for index in 0..sequence_length {
                let cached = &key_head[index * d_k..(index + 1) * d_k];
                scores[index] = self.dot(query_head, cached) * scale;
            }
            self.softmax(&mut scores[..sequence_length]);

            let output_head = &mut output[vector_start..vector_end];
            output_head.fill(0.0);
            for index in 0..sequence_length {
                let weight = scores[index];
                if weight == 0.0 {
                    continue;
                }
                let cached = &value_head[index * d_k..(index + 1) * d_k];
                match self {
                    Self::Scalar => {
                        for (target, &value) in output_head.iter_mut().zip(cached) {
                            *target += weight * value;
                        }
                    }
                    Self::Avx2 | Self::Avx512 => {
                        for (target, &value) in output_head.iter_mut().zip(cached) {
                            *target = weight.mul_add(value, *target);
                        }
                    }
                }
            }
        }
    }

    fn dot(self, left: &[f32], right: &[f32]) -> f32 {
        debug_assert_eq!(left.len(), right.len());
        match self {
            Self::Scalar => left
                .iter()
                .zip(right)
                .fold(0.0_f32, |sum, (&left, &right)| sum + left * right),
            Self::Avx2 => {
                // SAFETY: selected backend proves the target features.
                unsafe { avx2_dot(left, right) }
            }
            Self::Avx512 => {
                // SAFETY: selected backend proves the target features.
                unsafe { avx512_dot(left, right) }
            }
        }
    }

    fn softmax(self, values: &mut [f32]) {
        match self {
            Self::Scalar => scalar_softmax(values),
            Self::Avx2 => {
                // SAFETY: selected backend proves AVX2 and FMA.
                unsafe { avx2_softmax(values) }
            }
            Self::Avx512 => {
                // SAFETY: selected backend proves AVX-512F and FMA.
                unsafe { avx512_softmax(values) }
            }
        }
    }
}

fn scalar_matvec(
    matrix: &[f32],
    vector: &[f32],
    bias: Option<&[f32]>,
    output: &mut [f32],
    rows: usize,
    columns: usize,
) {
    let mut row = 0;
    while row + 3 < rows {
        let mut sums = [0.0_f32; 4];
        for column in 0..columns {
            let value = vector[column];
            sums[0] += matrix[row * columns + column] * value;
            sums[1] += matrix[(row + 1) * columns + column] * value;
            sums[2] += matrix[(row + 2) * columns + column] * value;
            sums[3] += matrix[(row + 3) * columns + column] * value;
        }
        for index in 0..4 {
            output[row + index] = sums[index] + bias.map_or(0.0, |values| values[row + index]);
        }
        row += 4;
    }
    while row < rows {
        let matrix_row = &matrix[row * columns..(row + 1) * columns];
        let mut sum = 0.0_f32;
        for (&weight, &value) in matrix_row.iter().zip(vector) {
            sum += weight * value;
        }
        output[row] = sum + bias.map_or(0.0, |values| values[row]);
        row += 1;
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_matvec(
    matrix: &[f32],
    vector: &[f32],
    bias: Option<&[f32]>,
    output: &mut [f32],
    rows: usize,
    columns: usize,
) {
    // SAFETY: the caller validates features and every pointer range. Each load
    // remains within its row because the vector loop advances by eight.
    unsafe {
        let mut row = 0;
        while row + 3 < rows {
            let rows_ptr = [
                matrix.as_ptr().add(row * columns),
                matrix.as_ptr().add((row + 1) * columns),
                matrix.as_ptr().add((row + 2) * columns),
                matrix.as_ptr().add((row + 3) * columns),
            ];
            let mut accumulators = [_mm256_setzero_ps(); 4];
            let mut column = 0;
            while column + 7 < columns {
                let value = _mm256_loadu_ps(vector.as_ptr().add(column));
                for index in 0..4 {
                    accumulators[index] = _mm256_fmadd_ps(
                        _mm256_loadu_ps(rows_ptr[index].add(column)),
                        value,
                        accumulators[index],
                    );
                }
                column += 8;
            }
            let mut sums = accumulators.map(|value| hsum_avx2(value));
            while column < columns {
                let value = vector[column];
                for index in 0..4 {
                    sums[index] += *rows_ptr[index].add(column) * value;
                }
                column += 1;
            }
            for index in 0..4 {
                output[row + index] = sums[index] + bias.map_or(0.0, |values| values[row + index]);
            }
            row += 4;
        }
        while row < rows {
            let row_ptr = matrix.as_ptr().add(row * columns);
            let mut accumulator = _mm256_setzero_ps();
            let mut column = 0;
            while column + 7 < columns {
                accumulator = _mm256_fmadd_ps(
                    _mm256_loadu_ps(row_ptr.add(column)),
                    _mm256_loadu_ps(vector.as_ptr().add(column)),
                    accumulator,
                );
                column += 8;
            }
            let mut sum = hsum_avx2(accumulator);
            while column < columns {
                sum += *row_ptr.add(column) * vector[column];
                column += 1;
            }
            output[row] = sum + bias.map_or(0.0, |values| values[row]);
            row += 1;
        }
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_matvec(
    matrix: &[f32],
    vector: &[f32],
    bias: Option<&[f32]>,
    output: &mut [f32],
    rows: usize,
    columns: usize,
) {
    // SAFETY: the caller validates target features and ranges. Model columns
    // are multiples of 16; the scalar tail handles arbitrary validated inputs.
    unsafe {
        let mut row = 0;
        while row + 3 < rows {
            let rows_ptr = [
                matrix.as_ptr().add(row * columns),
                matrix.as_ptr().add((row + 1) * columns),
                matrix.as_ptr().add((row + 2) * columns),
                matrix.as_ptr().add((row + 3) * columns),
            ];
            let mut accumulators = [_mm512_setzero_ps(); 4];
            let mut column = 0;
            while column + 15 < columns {
                let value = _mm512_loadu_ps(vector.as_ptr().add(column));
                for index in 0..4 {
                    accumulators[index] = _mm512_fmadd_ps(
                        _mm512_loadu_ps(rows_ptr[index].add(column)),
                        value,
                        accumulators[index],
                    );
                }
                column += 16;
            }
            let mut sums = accumulators.map(|value| _mm512_reduce_add_ps(value));
            while column < columns {
                let value = vector[column];
                for index in 0..4 {
                    sums[index] = (*rows_ptr[index].add(column)).mul_add(value, sums[index]);
                }
                column += 1;
            }
            for index in 0..4 {
                output[row + index] = sums[index] + bias.map_or(0.0, |values| values[row + index]);
            }
            row += 4;
        }
        while row < rows {
            let row_ptr = matrix.as_ptr().add(row * columns);
            let mut accumulator = _mm512_setzero_ps();
            let mut column = 0;
            while column + 15 < columns {
                accumulator = _mm512_fmadd_ps(
                    _mm512_loadu_ps(row_ptr.add(column)),
                    _mm512_loadu_ps(vector.as_ptr().add(column)),
                    accumulator,
                );
                column += 16;
            }
            let mut sum = _mm512_reduce_add_ps(accumulator);
            while column < columns {
                sum = (*row_ptr.add(column)).mul_add(vector[column], sum);
                column += 1;
            }
            output[row] = sum + bias.map_or(0.0, |values| values[row]);
            row += 1;
        }
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_sum_squares(values: &[f32]) -> f32 {
    // SAFETY: feature and bounds invariants are established by the caller.
    unsafe {
        let mut accumulator = _mm256_setzero_ps();
        let mut index = 0;
        while index + 7 < values.len() {
            let value = _mm256_loadu_ps(values.as_ptr().add(index));
            accumulator = _mm256_fmadd_ps(value, value, accumulator);
            index += 8;
        }
        let mut sum = hsum_avx2(accumulator);
        while index < values.len() {
            sum += values[index] * values[index];
            index += 1;
        }
        sum
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_sum_squares(values: &[f32]) -> f32 {
    // SAFETY: feature and bounds invariants are established by the caller.
    unsafe {
        let mut accumulator = _mm512_setzero_ps();
        let mut index = 0;
        while index + 15 < values.len() {
            let value = _mm512_loadu_ps(values.as_ptr().add(index));
            accumulator = _mm512_fmadd_ps(value, value, accumulator);
            index += 16;
        }
        let mut sum = _mm512_reduce_add_ps(accumulator);
        while index < values.len() {
            sum = values[index].mul_add(values[index], sum);
            index += 1;
        }
        sum
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_dot(left: &[f32], right: &[f32]) -> f32 {
    // SAFETY: feature and bounds invariants are established by the caller.
    unsafe {
        let mut accumulator = _mm256_setzero_ps();
        let mut index = 0;
        while index + 7 < left.len() {
            accumulator = _mm256_fmadd_ps(
                _mm256_loadu_ps(left.as_ptr().add(index)),
                _mm256_loadu_ps(right.as_ptr().add(index)),
                accumulator,
            );
            index += 8;
        }
        let mut sum = hsum_avx2(accumulator);
        while index < left.len() {
            sum += left[index] * right[index];
            index += 1;
        }
        sum
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_dot(left: &[f32], right: &[f32]) -> f32 {
    // SAFETY: feature and bounds invariants are established by the caller.
    unsafe {
        let mut accumulator = _mm512_setzero_ps();
        let mut index = 0;
        while index + 15 < left.len() {
            accumulator = _mm512_fmadd_ps(
                _mm512_loadu_ps(left.as_ptr().add(index)),
                _mm512_loadu_ps(right.as_ptr().add(index)),
                accumulator,
            );
            index += 16;
        }
        let mut sum = _mm512_reduce_add_ps(accumulator);
        while index < left.len() {
            sum = left[index].mul_add(right[index], sum);
            index += 1;
        }
        sum
    }
}

#[target_feature(enable = "avx2")]
unsafe fn hsum_avx2(value: __m256) -> f32 {
    // SAFETY: this function is executed only inside AVX2 target functions.
    let high = _mm256_extractf128_ps(value, 1);
    let low = _mm256_castps256_ps128(value);
    let sum4 = _mm_add_ps(low, high);
    let mut shuffle = _mm_movehdup_ps(sum4);
    let sum2 = _mm_add_ps(sum4, shuffle);
    shuffle = _mm_movehl_ps(shuffle, sum2);
    _mm_cvtss_f32(_mm_add_ss(sum2, shuffle))
}

fn scalar_softmax(values: &mut [f32]) {
    let maximum = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0_f32;
    for value in values.iter_mut() {
        *value = (*value - maximum).exp();
        sum += *value;
    }
    let inverse = 1.0 / sum;
    for value in values {
        *value *= inverse;
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_fast_exp(value: __m256) -> __m256 {
    let bounded = _mm256_max_ps(
        _mm256_min_ps(value, _mm256_set1_ps(88.376_26)),
        _mm256_set1_ps(-88.376_26),
    );
    let projected = _mm256_mul_ps(bounded, _mm256_set1_ps(std::f32::consts::LOG2_E));
    let rounded = _mm256_round_ps(projected, _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
    let exponent = _mm256_cvtps_epi32(rounded);
    let fraction = _mm256_sub_ps(projected, rounded);
    let mut polynomial = _mm256_fmadd_ps(
        _mm256_set1_ps(0.009_618_129),
        fraction,
        _mm256_set1_ps(0.055_504_11),
    );
    polynomial = _mm256_fmadd_ps(polynomial, fraction, _mm256_set1_ps(0.240_226_5));
    polynomial = _mm256_fmadd_ps(polynomial, fraction, _mm256_set1_ps(std::f32::consts::LN_2));
    polynomial = _mm256_fmadd_ps(polynomial, fraction, _mm256_set1_ps(1.0));
    let exponent_bits = _mm256_slli_epi32::<23>(_mm256_add_epi32(exponent, _mm256_set1_epi32(127)));
    _mm256_mul_ps(polynomial, _mm256_castsi256_ps(exponent_bits))
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_fast_exp(value: __m512) -> __m512 {
    let bounded = _mm512_max_ps(
        _mm512_min_ps(value, _mm512_set1_ps(88.376_26)),
        _mm512_set1_ps(-88.376_26),
    );
    let projected = _mm512_mul_ps(bounded, _mm512_set1_ps(std::f32::consts::LOG2_E));
    let rounded =
        _mm512_roundscale_ps::<{ _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC }>(projected);
    let exponent = _mm512_cvtps_epi32(rounded);
    let fraction = _mm512_sub_ps(projected, rounded);
    let mut polynomial = _mm512_fmadd_ps(
        _mm512_set1_ps(0.009_618_129),
        fraction,
        _mm512_set1_ps(0.055_504_11),
    );
    polynomial = _mm512_fmadd_ps(polynomial, fraction, _mm512_set1_ps(0.240_226_5));
    polynomial = _mm512_fmadd_ps(polynomial, fraction, _mm512_set1_ps(std::f32::consts::LN_2));
    polynomial = _mm512_fmadd_ps(polynomial, fraction, _mm512_set1_ps(1.0));
    let exponent_bits = _mm512_slli_epi32::<23>(_mm512_add_epi32(exponent, _mm512_set1_epi32(127)));
    _mm512_mul_ps(polynomial, _mm512_castsi512_ps(exponent_bits))
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_rms_scale(input: &[f32], weights: &[f32], output: &mut [f32], scale: f32) {
    // SAFETY: the caller proves AVX2 and equal slice lengths.
    unsafe {
        let scalar_scale = scale;
        let scale = _mm256_set1_ps(scalar_scale);
        let mut index = 0;
        while index + 7 < input.len() {
            let value = _mm256_loadu_ps(input.as_ptr().add(index));
            let weight = _mm256_loadu_ps(weights.as_ptr().add(index));
            _mm256_storeu_ps(
                output.as_mut_ptr().add(index),
                _mm256_mul_ps(weight, _mm256_mul_ps(value, scale)),
            );
            index += 8;
        }
        while index < input.len() {
            output[index] = weights[index] * input[index] * scalar_scale;
            index += 1;
        }
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_rms_scale(input: &[f32], weights: &[f32], output: &mut [f32], scale: f32) {
    // SAFETY: the caller proves AVX-512F and equal slice lengths.
    unsafe {
        let scale = _mm512_set1_ps(scale);
        let mut index = 0;
        while index + 15 < input.len() {
            let value = _mm512_loadu_ps(input.as_ptr().add(index));
            let weight = _mm512_loadu_ps(weights.as_ptr().add(index));
            _mm512_storeu_ps(
                output.as_mut_ptr().add(index),
                _mm512_mul_ps(weight, _mm512_mul_ps(value, scale)),
            );
            index += 16;
        }
        if index < input.len() {
            let mask = avx512_tail_mask(input.len() - index);
            let value = _mm512_maskz_loadu_ps(mask, input.as_ptr().add(index));
            let weight = _mm512_maskz_loadu_ps(mask, weights.as_ptr().add(index));
            _mm512_mask_storeu_ps(
                output.as_mut_ptr().add(index),
                mask,
                _mm512_mul_ps(weight, _mm512_mul_ps(value, scale)),
            );
        }
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_silu(values: &mut [f32]) {
    // SAFETY: the caller proves AVX2 and every vector load is in bounds.
    unsafe {
        let one = _mm256_set1_ps(1.0);
        let negative_one = _mm256_set1_ps(-1.0);
        let mut index = 0;
        while index + 7 < values.len() {
            let value = _mm256_loadu_ps(values.as_ptr().add(index));
            let exponent = avx2_fast_exp(_mm256_mul_ps(value, negative_one));
            let sigmoid = _mm256_div_ps(one, _mm256_add_ps(one, exponent));
            _mm256_storeu_ps(
                values.as_mut_ptr().add(index),
                _mm256_mul_ps(value, sigmoid),
            );
            index += 8;
        }
        while index < values.len() {
            let value = values[index];
            values[index] = value / (1.0 + (-value).exp());
            index += 1;
        }
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_silu(values: &mut [f32]) {
    // SAFETY: the caller proves AVX-512F and every masked load is in bounds.
    unsafe {
        let one = _mm512_set1_ps(1.0);
        let negative_one = _mm512_set1_ps(-1.0);
        let mut index = 0;
        while index + 15 < values.len() {
            let value = _mm512_loadu_ps(values.as_ptr().add(index));
            let exponent = avx512_fast_exp(_mm512_mul_ps(value, negative_one));
            let sigmoid = _mm512_div_ps(one, _mm512_add_ps(one, exponent));
            _mm512_storeu_ps(
                values.as_mut_ptr().add(index),
                _mm512_mul_ps(value, sigmoid),
            );
            index += 16;
        }
        if index < values.len() {
            let mask = avx512_tail_mask(values.len() - index);
            let value = _mm512_maskz_loadu_ps(mask, values.as_ptr().add(index));
            let exponent = avx512_fast_exp(_mm512_mul_ps(value, negative_one));
            let sigmoid = _mm512_div_ps(one, _mm512_add_ps(one, exponent));
            _mm512_mask_storeu_ps(
                values.as_mut_ptr().add(index),
                mask,
                _mm512_mul_ps(value, sigmoid),
            );
        }
    }
}

#[target_feature(enable = "avx2,fma")]
unsafe fn avx2_softmax(values: &mut [f32]) {
    // SAFETY: the caller proves AVX2 and every vector load is in bounds.
    unsafe {
        let mut maximum_vector = _mm256_set1_ps(-1e30);
        let mut index = 0;
        while index + 7 < values.len() {
            maximum_vector =
                _mm256_max_ps(maximum_vector, _mm256_loadu_ps(values.as_ptr().add(index)));
            index += 8;
        }
        let high = _mm256_extractf128_ps(maximum_vector, 1);
        let low = _mm256_castps256_ps128(maximum_vector);
        let mut maximum = _mm_max_ps(low, high);
        maximum = _mm_max_ps(maximum, _mm_movehl_ps(maximum, maximum));
        maximum = _mm_max_ss(maximum, _mm_movehdup_ps(maximum));
        let mut maximum = _mm_cvtss_f32(maximum);
        while index < values.len() {
            maximum = maximum.max(values[index]);
            index += 1;
        }

        let maximum_vector = _mm256_set1_ps(maximum);
        let mut sum_vector = _mm256_setzero_ps();
        index = 0;
        while index + 7 < values.len() {
            let exponent = avx2_fast_exp(_mm256_sub_ps(
                _mm256_loadu_ps(values.as_ptr().add(index)),
                maximum_vector,
            ));
            _mm256_storeu_ps(values.as_mut_ptr().add(index), exponent);
            sum_vector = _mm256_add_ps(sum_vector, exponent);
            index += 8;
        }
        let mut sum = hsum_avx2(sum_vector);
        while index < values.len() {
            let exponent = (values[index] - maximum).exp();
            values[index] = exponent;
            sum += exponent;
            index += 1;
        }

        let inverse = 1.0 / sum;
        let inverse_vector = _mm256_set1_ps(inverse);
        index = 0;
        while index + 7 < values.len() {
            _mm256_storeu_ps(
                values.as_mut_ptr().add(index),
                _mm256_mul_ps(_mm256_loadu_ps(values.as_ptr().add(index)), inverse_vector),
            );
            index += 8;
        }
        while index < values.len() {
            values[index] *= inverse;
            index += 1;
        }
    }
}

#[target_feature(enable = "avx512f,avx2,fma")]
unsafe fn avx512_softmax(values: &mut [f32]) {
    // SAFETY: the caller proves AVX-512F and every vector load is in bounds.
    unsafe {
        let mut maximum_vector = _mm512_set1_ps(-1e30);
        let mut index = 0;
        while index + 15 < values.len() {
            maximum_vector =
                _mm512_max_ps(maximum_vector, _mm512_loadu_ps(values.as_ptr().add(index)));
            index += 16;
        }
        let mut maximum = _mm512_reduce_max_ps(maximum_vector);
        while index < values.len() {
            maximum = maximum.max(values[index]);
            index += 1;
        }

        let maximum_vector = _mm512_set1_ps(maximum);
        let mut sum_vector = _mm512_setzero_ps();
        index = 0;
        while index + 15 < values.len() {
            let exponent = avx512_fast_exp(_mm512_sub_ps(
                _mm512_loadu_ps(values.as_ptr().add(index)),
                maximum_vector,
            ));
            _mm512_storeu_ps(values.as_mut_ptr().add(index), exponent);
            sum_vector = _mm512_add_ps(sum_vector, exponent);
            index += 16;
        }
        let mut sum = _mm512_reduce_add_ps(sum_vector);
        while index < values.len() {
            let exponent = (values[index] - maximum).exp();
            values[index] = exponent;
            sum += exponent;
            index += 1;
        }

        let inverse = 1.0 / sum;
        let inverse_vector = _mm512_set1_ps(inverse);
        index = 0;
        while index + 15 < values.len() {
            _mm512_storeu_ps(
                values.as_mut_ptr().add(index),
                _mm512_mul_ps(_mm512_loadu_ps(values.as_ptr().add(index)), inverse_vector),
            );
            index += 16;
        }
        while index < values.len() {
            values[index] *= inverse;
            index += 1;
        }
    }
}

fn avx512_tail_mask(remaining: usize) -> __mmask16 {
    debug_assert!((1..16).contains(&remaining));
    ((1_u32 << remaining) - 1) as __mmask16
}

#[derive(Debug)]
pub(crate) enum KernelError {
    Unsupported(&'static str),
}

impl fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => {
                write!(
                    formatter,
                    "InferX {name} backend is not supported by this CPU/OS"
                )
            }
        }
    }
}

impl std::error::Error for KernelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_kernels_preserve_reference_arithmetic() {
        let matrix = [1.0, 2.0, 3.0, 4.0, -1.0, 0.5];
        let vector = [0.25, -2.0];
        let bias = [1.0, -1.0, 0.5];
        let mut output = [0.0; 3];
        Backend::Scalar.matvec(&matrix, &vector, Some(&bias), &mut output, 3, 2);
        assert_eq!(output, [-2.75, -8.25, -0.75]);

        let mut normalized = [0.0; 2];
        Backend::Scalar.rms_norm(&[3.0, 4.0], &[1.0, 2.0], &mut normalized, 1e-6);
        assert!(normalized.iter().all(|value| value.is_finite()));
    }

    #[test]
    fn runtime_dispatch_never_selects_unsupported_instructions() {
        let backend = Backend::select(SimdPreference::Auto).unwrap();
        if backend == Backend::Avx512 {
            assert!(std::is_x86_feature_detected!("avx512f"));
        }
        if matches!(backend, Backend::Avx2 | Backend::Avx512) {
            assert!(std::is_x86_feature_detected!("avx2"));
            assert!(std::is_x86_feature_detected!("fma"));
        }
    }

    #[test]
    fn vector_matvec_is_close_to_scalar_when_available() {
        let rows = 17;
        let columns = 64;
        let matrix = (0..rows * columns)
            .map(|index| ((index as f32 * 0.03125).sin()) * 0.1)
            .collect::<Vec<_>>();
        let vector = (0..columns)
            .map(|index| (index as f32 * 0.125).cos())
            .collect::<Vec<_>>();
        let mut expected = vec![0.0; rows];
        Backend::Scalar.matvec(&matrix, &vector, None, &mut expected, rows, columns);
        for preference in [SimdPreference::Avx2, SimdPreference::Avx512] {
            let Ok(backend) = Backend::select(preference) else {
                continue;
            };
            let mut actual = vec![0.0; rows];
            backend.matvec(&matrix, &vector, None, &mut actual, rows, columns);
            for (&expected, &actual) in expected.iter().zip(&actual) {
                assert!((expected - actual).abs() < 1e-5);
            }
        }
    }
}
