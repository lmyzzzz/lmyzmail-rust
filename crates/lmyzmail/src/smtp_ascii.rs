//! Bounded RGB24-to-ASCII rendering for SMTP video playback.
//!
//! This is a Rust-owned port of the frozen ASCII renderer's externally visible
//! math. The resize operation is shared with `mail_render`; no legacy ASCII C
//! implementation is linked or called. Every runtime backend preserves the
//! frozen accelerated renderer's eight-pixel rounded chunks and scalar-tail
//! charset semantics so dispatch never changes visible frame bytes.

use std::{fmt, time::Instant};

use tokio_util::sync::CancellationToken;

use crate::mail_render::{
    RenderBackend, RenderError, Rgb24ResizeSpec, resize_rgb24_box_with_backend,
};

pub(crate) const DEFAULT_ASCII_RAMP: &[u8] =
    b" .'`^\",:;Il!i><~+_-?][}{1)(|/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$";
pub(crate) const HARD_MAX_SOURCE_PIXELS: usize = 16 * 1024 * 1024;
pub(crate) const HARD_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const HARD_MAX_OUTPUT_DIMENSION: usize = 8192;

const GAMMA_CHECKPOINT_INTERVAL: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AsciiSimdMode {
    Auto,
    Scalar,
    Avx2,
    Avx512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AsciiBackend {
    Scalar,
    Avx2,
    Avx512,
}

impl AsciiBackend {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Avx2 => "avx2+fma",
            Self::Avx512 => "avx512f+avx512bw",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AsciiHostCapabilities {
    pub(crate) avx2_fma: bool,
    pub(crate) avx512f_bw: bool,
}

pub(crate) fn host_ascii_capabilities() -> AsciiHostCapabilities {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        AsciiHostCapabilities {
            avx2_fma: std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("fma"),
            avx512f_bw: std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bw"),
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        AsciiHostCapabilities {
            avx2_fma: false,
            avx512f_bw: false,
        }
    }
}

pub(crate) fn resolve_ascii_backend(mode: AsciiSimdMode) -> AsciiBackend {
    let capabilities = host_ascii_capabilities();
    let best = || {
        if capabilities.avx512f_bw {
            AsciiBackend::Avx512
        } else if capabilities.avx2_fma {
            AsciiBackend::Avx2
        } else {
            AsciiBackend::Scalar
        }
    };
    match mode {
        AsciiSimdMode::Auto => best(),
        AsciiSimdMode::Scalar => AsciiBackend::Scalar,
        AsciiSimdMode::Avx2 if capabilities.avx2_fma => AsciiBackend::Avx2,
        AsciiSimdMode::Avx512 if capabilities.avx512f_bw => AsciiBackend::Avx512,
        AsciiSimdMode::Avx2 | AsciiSimdMode::Avx512 => best(),
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AsciiRenderSpec {
    pub(crate) source_width: usize,
    pub(crate) source_height: usize,
    pub(crate) output_width: usize,
    pub(crate) output_height: Option<usize>,
    pub(crate) contrast: f32,
    pub(crate) brightness: f32,
    pub(crate) gamma: f32,
    pub(crate) char_aspect: f32,
    pub(crate) invert: bool,
    pub(crate) simd_mode: AsciiSimdMode,
    pub(crate) max_source_pixels: usize,
    pub(crate) max_output_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AsciiFrame {
    pub(crate) chars: Vec<u8>,
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) backend: AsciiBackend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AsciiRenderError {
    InvalidInput(&'static str),
    LimitExceeded(&'static str),
    Cancelled,
    DeadlineExceeded,
    ResizeFailed,
}

impl fmt::Display for AsciiRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid ASCII frame: {message}"),
            Self::LimitExceeded(message) => {
                write!(formatter, "ASCII frame limit exceeded: {message}")
            }
            Self::Cancelled => formatter.write_str("ASCII rendering cancelled"),
            Self::DeadlineExceeded => formatter.write_str("ASCII rendering deadline exceeded"),
            Self::ResizeFailed => formatter.write_str("ASCII frame resize failed"),
        }
    }
}

impl std::error::Error for AsciiRenderError {}

pub(crate) fn render_rgb24_ascii(
    rgb: &[u8],
    spec: AsciiRenderSpec,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<AsciiFrame, AsciiRenderError> {
    checkpoint(cancellation, deadline)?;
    let ValidatedSpec {
        output_width,
        output_height,
        contrast,
        brightness,
        gamma,
        invert,
        backend,
        source_pixels,
        output_pixels,
    } = validate_spec(rgb, spec)?;

    if source_pixels > spec.max_source_pixels {
        return Err(AsciiRenderError::LimitExceeded("source pixels"));
    }
    if output_pixels > spec.max_output_bytes {
        return Err(AsciiRenderError::LimitExceeded("output bytes"));
    }

    let resized_bytes = output_pixels
        .checked_mul(3)
        .ok_or(AsciiRenderError::LimitExceeded("resize bytes"))?;
    let resize_backend = match backend {
        AsciiBackend::Scalar => RenderBackend::Scalar,
        AsciiBackend::Avx2 => RenderBackend::Avx2Fma,
        AsciiBackend::Avx512 => RenderBackend::Avx512,
    };
    let resized = resize_rgb24_box_with_backend(
        rgb,
        Rgb24ResizeSpec {
            source_width: spec.source_width,
            source_height: spec.source_height,
            output_width,
            output_height,
            max_output_bytes: resized_bytes,
        },
        resize_backend,
        cancellation,
        deadline,
    )
    .map_err(map_resize_error)?;

    let gamma_lut = build_gamma_lut(gamma, cancellation, deadline)?;
    checkpoint(cancellation, deadline)?;
    let mut chars = vec![0_u8; output_pixels];
    for row_index in 0..output_height {
        checkpoint(cancellation, deadline)?;
        let row_start = row_index * output_width;
        let rgb_start = row_start * 3;
        let row_rgb = &resized[rgb_start..rgb_start + output_width * 3];
        let row_chars = &mut chars[row_start..row_start + output_width];
        match backend {
            AsciiBackend::Scalar => {
                convert_row_scalar(row_rgb, &gamma_lut, contrast, brightness, invert, row_chars)
            }
            AsciiBackend::Avx2 => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    // SAFETY: backend resolution checked both AVX2 and FMA OS-aware
                    // feature bits. The row slices have the exact lengths required
                    // by the kernel and remain live for the duration of the call.
                    unsafe {
                        convert_row_avx2(
                            row_rgb, &gamma_lut, contrast, brightness, invert, row_chars,
                        );
                    }
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                unreachable!("AVX2 backend cannot resolve on this target");
            }
            AsciiBackend::Avx512 => {
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                {
                    // SAFETY: backend resolution checked AVX-512F and AVX-512BW
                    // through Rust's OS-aware detector. Only the narrow inline-asm
                    // helper executes ZMM instructions, and all pointers refer to
                    // fixed-size live arrays.
                    unsafe {
                        convert_row_avx512(
                            row_rgb, &gamma_lut, contrast, brightness, invert, row_chars,
                        );
                    }
                }
                #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                unreachable!("AVX-512 backend cannot resolve on this target");
            }
        }
    }
    Ok(AsciiFrame {
        chars,
        width: output_width,
        height: output_height,
        backend,
    })
}

struct ValidatedSpec {
    output_width: usize,
    output_height: usize,
    contrast: f32,
    brightness: f32,
    gamma: f32,
    invert: bool,
    backend: AsciiBackend,
    source_pixels: usize,
    output_pixels: usize,
}

fn validate_spec(rgb: &[u8], spec: AsciiRenderSpec) -> Result<ValidatedSpec, AsciiRenderError> {
    if spec.source_width == 0 || spec.source_height == 0 || spec.output_width == 0 {
        return Err(AsciiRenderError::InvalidInput("dimensions"));
    }
    if spec.max_source_pixels == 0 || spec.max_source_pixels > HARD_MAX_SOURCE_PIXELS {
        return Err(AsciiRenderError::InvalidInput("source pixel budget"));
    }
    if spec.max_output_bytes == 0 || spec.max_output_bytes > HARD_MAX_OUTPUT_BYTES {
        return Err(AsciiRenderError::InvalidInput("output byte budget"));
    }
    if spec.output_width > HARD_MAX_OUTPUT_DIMENSION {
        return Err(AsciiRenderError::LimitExceeded("output width"));
    }
    if !spec.contrast.is_finite()
        || !spec.brightness.is_finite()
        || !spec.gamma.is_finite()
        || !spec.char_aspect.is_finite()
    {
        return Err(AsciiRenderError::InvalidInput("non-finite adjustment"));
    }

    let source_pixels = spec
        .source_width
        .checked_mul(spec.source_height)
        .ok_or(AsciiRenderError::LimitExceeded("source pixels"))?;
    if source_pixels > HARD_MAX_SOURCE_PIXELS {
        return Err(AsciiRenderError::LimitExceeded("source pixels"));
    }
    let source_bytes = source_pixels
        .checked_mul(3)
        .ok_or(AsciiRenderError::LimitExceeded("source bytes"))?;
    if rgb.len() != source_bytes {
        return Err(AsciiRenderError::InvalidInput("RGB24 input length"));
    }

    // These normalizations are the frozen context-construction semantics.
    let contrast = if spec.contrast <= 0.0 {
        1.0
    } else {
        spec.contrast
    };
    let gamma = if spec.gamma <= 0.0 { 1.0 } else { spec.gamma };
    let char_aspect = if spec.char_aspect <= 0.0 {
        2.0
    } else {
        spec.char_aspect
    };
    let output_height = match spec.output_height {
        Some(height) if height > 0 => height,
        Some(_) => return Err(AsciiRenderError::InvalidInput("output height")),
        None => auto_height(
            spec.output_width,
            spec.source_width,
            spec.source_height,
            char_aspect,
        )?,
    };
    if output_height > HARD_MAX_OUTPUT_DIMENSION {
        return Err(AsciiRenderError::LimitExceeded("output height"));
    }
    let output_pixels = spec
        .output_width
        .checked_mul(output_height)
        .ok_or(AsciiRenderError::LimitExceeded("output pixels"))?;
    if output_pixels > HARD_MAX_OUTPUT_BYTES {
        return Err(AsciiRenderError::LimitExceeded("output bytes"));
    }

    Ok(ValidatedSpec {
        output_width: spec.output_width,
        output_height,
        contrast,
        brightness: spec.brightness,
        gamma,
        invert: spec.invert,
        backend: resolve_ascii_backend(spec.simd_mode),
        source_pixels,
        output_pixels,
    })
}

fn auto_height(
    output_width: usize,
    source_width: usize,
    source_height: usize,
    char_aspect: f32,
) -> Result<usize, AsciiRenderError> {
    let calculated =
        output_width as f32 * source_height as f32 / (source_width as f32 * char_aspect);
    if !calculated.is_finite() || calculated > HARD_MAX_OUTPUT_DIMENSION as f32 {
        return Err(AsciiRenderError::LimitExceeded("automatic output height"));
    }
    Ok(((calculated + 0.5) as usize).max(1))
}

fn build_gamma_lut(
    gamma: f32,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<[u8; 256], AsciiRenderError> {
    let mut lut = [0_u8; 256];
    if (gamma - 1.0).abs() < 0.001 {
        for (index, entry) in lut.iter_mut().enumerate() {
            *entry = index as u8;
        }
        return Ok(lut);
    }
    let inverse_gamma = 1.0 / gamma;
    for (index, entry) in lut.iter_mut().enumerate() {
        if index % GAMMA_CHECKPOINT_INTERVAL == 0 {
            checkpoint(cancellation, deadline)?;
        }
        let value = ((index as f32 / 255.0).powf(inverse_gamma) * 255.0 + 0.5)
            .trunc()
            .clamp(0.0, 255.0);
        *entry = value as u8;
    }
    Ok(lut)
}

fn convert_row_scalar(
    rgb: &[u8],
    gamma_lut: &[u8; 256],
    contrast: f32,
    brightness: f32,
    invert: bool,
    output: &mut [u8],
) {
    debug_assert_eq!(rgb.len(), output.len() * 3);
    let accelerated_pixels = output.len() & !7;
    for (index, (pixel, character)) in rgb.chunks_exact(3).zip(output).enumerate() {
        let luma = bt601_luma(pixel[0], pixel[1], pixel[2]);
        let charset_index = if index < accelerated_pixels {
            accelerated_charset_index(gamma_lut[luma], contrast, brightness, invert)
        } else {
            scalar_tail_charset_index(gamma_lut[luma], contrast, brightness, invert)
        };
        *character = DEFAULT_ASCII_RAMP[charset_index];
    }
}

#[inline]
fn bt601_luma(red: u8, green: u8, blue: u8) -> usize {
    (77 * usize::from(red) + 150 * usize::from(green) + 29 * usize::from(blue)) >> 8
}

#[inline]
fn accelerated_charset_index(
    gamma_luma: u8,
    contrast: f32,
    brightness: f32,
    invert: bool,
) -> usize {
    let mut value = (f32::from(gamma_luma) - 128.0).mul_add(contrast, 128.0) + brightness;
    value = value.clamp(0.0, 255.0);
    if invert {
        value = 255.0 - value;
    }
    let scale = (DEFAULT_ASCII_RAMP.len() - 1) as f32 / 255.0;
    (value * scale + 0.5)
        .trunc()
        .clamp(0.0, (DEFAULT_ASCII_RAMP.len() - 1) as f32) as usize
}

#[inline]
fn scalar_tail_charset_index(
    gamma_luma: u8,
    contrast: f32,
    brightness: f32,
    invert: bool,
) -> usize {
    let adjusted = ((f32::from(gamma_luma) - 128.0) * contrast + 128.0 + brightness + 0.5)
        .trunc()
        .clamp(0.0, 255.0) as u8;
    let value = if invert { 255 - adjusted } else { adjusted };
    usize::from(value) * (DEFAULT_ASCII_RAMP.len() - 1) / 255
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,fma")]
unsafe fn convert_row_avx2(
    rgb: &[u8],
    gamma_lut: &[u8; 256],
    contrast: f32,
    brightness: f32,
    invert: bool,
    output: &mut [u8],
) {
    use std::arch::x86_64::*;

    debug_assert_eq!(rgb.len(), output.len() * 3);
    let simd_count = output.len() & !7;
    let mut index = 0;

    // SAFETY: the caller established AVX2+FMA support. Every RGB access below
    // is within a complete 8-pixel chunk, and all vector loads/stores target
    // local arrays of exactly eight lanes.
    unsafe {
        let contrast_vector = _mm256_set1_ps(contrast);
        let brightness_vector = _mm256_set1_ps(brightness);
        let center = _mm256_set1_ps(128.0);
        let zero = _mm256_setzero_ps();
        let maximum = _mm256_set1_ps(255.0);
        let half = _mm256_set1_ps(0.5);
        let scale = _mm256_set1_ps((DEFAULT_ASCII_RAMP.len() - 1) as f32 / 255.0);
        let red_weight = _mm256_set1_epi32(77);
        let green_weight = _mm256_set1_epi32(150);
        let blue_weight = _mm256_set1_epi32(29);

        while index < simd_count {
            let pixel = &rgb[index * 3..index * 3 + 24];
            let red = _mm256_setr_epi32(
                i32::from(pixel[0]),
                i32::from(pixel[3]),
                i32::from(pixel[6]),
                i32::from(pixel[9]),
                i32::from(pixel[12]),
                i32::from(pixel[15]),
                i32::from(pixel[18]),
                i32::from(pixel[21]),
            );
            let green = _mm256_setr_epi32(
                i32::from(pixel[1]),
                i32::from(pixel[4]),
                i32::from(pixel[7]),
                i32::from(pixel[10]),
                i32::from(pixel[13]),
                i32::from(pixel[16]),
                i32::from(pixel[19]),
                i32::from(pixel[22]),
            );
            let blue = _mm256_setr_epi32(
                i32::from(pixel[2]),
                i32::from(pixel[5]),
                i32::from(pixel[8]),
                i32::from(pixel[11]),
                i32::from(pixel[14]),
                i32::from(pixel[17]),
                i32::from(pixel[20]),
                i32::from(pixel[23]),
            );
            let luma = _mm256_srli_epi32::<8>(_mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_mullo_epi32(red, red_weight),
                    _mm256_mullo_epi32(green, green_weight),
                ),
                _mm256_mullo_epi32(blue, blue_weight),
            ));
            let mut luma_lanes = [0_i32; 8];
            _mm256_storeu_si256(luma_lanes.as_mut_ptr().cast(), luma);
            for lane in &mut luma_lanes {
                *lane = i32::from(gamma_lut[*lane as usize]);
            }
            let luma_float = _mm256_cvtepi32_ps(_mm256_loadu_si256(luma_lanes.as_ptr().cast()));
            let mut value = _mm256_add_ps(
                _mm256_fmadd_ps(_mm256_sub_ps(luma_float, center), contrast_vector, center),
                brightness_vector,
            );
            value = _mm256_max_ps(value, zero);
            value = _mm256_min_ps(value, maximum);
            if invert {
                value = _mm256_sub_ps(maximum, value);
            }
            let charset_indices =
                _mm256_cvttps_epi32(_mm256_add_ps(_mm256_mul_ps(value, scale), half));
            let mut lanes = [0_i32; 8];
            _mm256_storeu_si256(lanes.as_mut_ptr().cast(), charset_indices);
            for (offset, lane) in lanes.into_iter().enumerate() {
                let charset_index = lane.clamp(0, DEFAULT_ASCII_RAMP.len() as i32 - 1) as usize;
                output[index + offset] = DEFAULT_ASCII_RAMP[charset_index];
            }
            index += 8;
        }
    }

    convert_row_scalar(
        &rgb[index * 3..],
        gamma_lut,
        contrast,
        brightness,
        invert,
        &mut output[index..],
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn convert_row_avx512(
    rgb: &[u8],
    gamma_lut: &[u8; 256],
    contrast: f32,
    brightness: f32,
    invert: bool,
    output: &mut [u8],
) {
    debug_assert_eq!(rgb.len(), output.len() * 3);
    let simd_count = output.len() & !15;
    let scale = (DEFAULT_ASCII_RAMP.len() - 1) as f32 / 255.0;
    let invert_factor = if invert { -1.0_f32 } else { 1.0_f32 };
    let invert_bias = if invert { 255.0_f32 } else { 0.0_f32 };
    let mut index = 0;
    while index < simd_count {
        let mut gamma_luma = [0_f32; 16];
        for (lane, value) in gamma_luma.iter_mut().enumerate() {
            let pixel_index = (index + lane) * 3;
            let luma = bt601_luma(rgb[pixel_index], rgb[pixel_index + 1], rgb[pixel_index + 2]);
            *value = f32::from(gamma_lut[luma]);
        }
        let mut lanes = [0_i32; 16];
        // SAFETY: the caller established AVX-512F+BW support using the
        // OS-aware detector. Both pointers address live 64-byte arrays and the
        // helper performs one unaligned load and store without retaining them.
        unsafe {
            avx512_adjust_and_map(
                &gamma_luma,
                contrast,
                brightness,
                invert_factor,
                invert_bias,
                scale,
                &mut lanes,
            );
        }
        for (offset, lane) in lanes.into_iter().enumerate() {
            let charset_index = lane.clamp(0, DEFAULT_ASCII_RAMP.len() as i32 - 1) as usize;
            output[index + offset] = DEFAULT_ASCII_RAMP[charset_index];
        }
        index += 16;
    }

    convert_row_scalar(
        &rgb[index * 3..],
        gamma_lut,
        contrast,
        brightness,
        invert,
        &mut output[index..],
    );
}

/// Applies the frozen AVX-512 floating-point adjustment and rounded charset
/// mapping to one complete 16-pixel chunk.
///
/// # Safety
///
/// The caller must first establish OS-enabled AVX-512F and AVX-512BW support.
/// `input` and `output` are fixed-size live arrays, so the unaligned 64-byte
/// load and store are in bounds. No pointer or register value escapes this
/// function. Keeping this boundary narrow avoids unstable AVX-512 intrinsics
/// while retaining an independently executed AVX-512 kernel on stable Rust.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(never)]
unsafe fn avx512_adjust_and_map(
    input: &[f32; 16],
    contrast: f32,
    brightness: f32,
    invert_factor: f32,
    invert_bias: f32,
    scale: f32,
    output: &mut [i32; 16],
) {
    let center = 128.0_f32;
    let zero = 0.0_f32;
    let maximum = 255.0_f32;
    let half = 0.5_f32;
    // SAFETY: upheld by this function's contract. The explicit ZMM clobbers
    // prevent surrounding generic code from relying on any modified register.
    unsafe {
        std::arch::asm!(
            "vmovups zmm0, [{input}]",
            "vbroadcastss zmm1, dword ptr [{center}]",
            "vsubps zmm0, zmm0, zmm1",
            "vbroadcastss zmm2, dword ptr [{contrast}]",
            "vfmadd213ps zmm0, zmm2, zmm1",
            "vbroadcastss zmm2, dword ptr [{brightness}]",
            "vaddps zmm0, zmm0, zmm2",
            "vbroadcastss zmm3, dword ptr [{zero}]",
            "vmaxps zmm0, zmm0, zmm3",
            "vbroadcastss zmm4, dword ptr [{maximum}]",
            "vminps zmm0, zmm0, zmm4",
            "vbroadcastss zmm2, dword ptr [{invert_factor}]",
            "vbroadcastss zmm3, dword ptr [{invert_bias}]",
            "vfmadd213ps zmm0, zmm2, zmm3",
            "vbroadcastss zmm2, dword ptr [{scale}]",
            "vmulps zmm0, zmm0, zmm2",
            "vbroadcastss zmm3, dword ptr [{half}]",
            "vaddps zmm0, zmm0, zmm3",
            "vcvttps2dq zmm0, zmm0",
            "vmovups [{output}], zmm0",
            input = in(reg) input.as_ptr(),
            center = in(reg) &center,
            contrast = in(reg) &contrast,
            brightness = in(reg) &brightness,
            zero = in(reg) &zero,
            maximum = in(reg) &maximum,
            invert_factor = in(reg) &invert_factor,
            invert_bias = in(reg) &invert_bias,
            scale = in(reg) &scale,
            half = in(reg) &half,
            output = in(reg) output.as_mut_ptr(),
            lateout("zmm0") _,
            lateout("zmm1") _,
            lateout("zmm2") _,
            lateout("zmm3") _,
            lateout("zmm4") _,
            options(nostack, preserves_flags),
        );
    }
}

fn checkpoint(cancellation: &CancellationToken, deadline: Instant) -> Result<(), AsciiRenderError> {
    if cancellation.is_cancelled() {
        return Err(AsciiRenderError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(AsciiRenderError::DeadlineExceeded);
    }
    Ok(())
}

fn map_resize_error(error: RenderError) -> AsciiRenderError {
    match error {
        RenderError::InvalidRequest(message) => AsciiRenderError::InvalidInput(message),
        RenderError::LimitExceeded(message) => AsciiRenderError::LimitExceeded(message),
        RenderError::Cancelled => AsciiRenderError::Cancelled,
        RenderError::DeadlineExceeded => AsciiRenderError::DeadlineExceeded,
        _ => AsciiRenderError::ResizeFailed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn spec(source_width: usize, source_height: usize, output_width: usize) -> AsciiRenderSpec {
        AsciiRenderSpec {
            source_width,
            source_height,
            output_width,
            output_height: None,
            contrast: 1.0,
            brightness: 0.0,
            gamma: 1.0,
            char_aspect: 2.0,
            invert: false,
            simd_mode: AsciiSimdMode::Scalar,
            max_source_pixels: HARD_MAX_SOURCE_PIXELS,
            max_output_bytes: HARD_MAX_OUTPUT_BYTES,
        }
    }

    fn live_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn patterned_rgb(pixel_count: usize) -> Vec<u8> {
        (0..pixel_count)
            .flat_map(|index| {
                let value = index as u32;
                [
                    value.wrapping_mul(47).wrapping_add(19) as u8,
                    value.wrapping_mul(113).wrapping_add(7) as u8,
                    value.wrapping_mul(197).wrapping_add(31) as u8,
                ]
            })
            .collect()
    }

    fn scalar_row_chars(
        rgb: &[u8],
        gamma_lut: &[u8; 256],
        contrast: f32,
        brightness: f32,
        invert: bool,
    ) -> Vec<u8> {
        let mut output = vec![0_u8; rgb.len() / 3];
        convert_row_scalar(rgb, gamma_lut, contrast, brightness, invert, &mut output);
        output
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_backend_matches_scalar(
        backend: &str,
        mut convert: impl FnMut(&[u8], &[u8; 256], f32, f32, bool, &mut [u8]),
    ) {
        let identity = std::array::from_fn(|index| index as u8);
        let grayscale = (0_u8..=u8::MAX)
            .flat_map(|value| [value, value, value])
            .collect::<Vec<_>>();
        let expected = scalar_row_chars(&grayscale, &identity, 1.0, 0.0, false);
        let mut actual = vec![0_u8; expected.len()];
        convert(&grayscale, &identity, 1.0, 0.0, false, &mut actual);
        assert_eq!(actual, expected, "{backend} exhaustive grayscale mismatch");

        let rgb = patterned_rgb(256);
        for &(gamma, contrast, brightness, invert) in &[
            (1.0, 1.0, 0.0, false),
            (1.7, 1.2, -4.0, true),
            (0.5, 0.25, 63.75, false),
            (2.4, 3.0, -400.0, false),
            (2.4, 3.0, 400.0, true),
        ] {
            let gamma_lut =
                build_gamma_lut(gamma, &CancellationToken::new(), live_deadline()).unwrap();
            let expected = scalar_row_chars(&rgb, &gamma_lut, contrast, brightness, invert);
            let mut actual = vec![0_u8; expected.len()];
            convert(&rgb, &gamma_lut, contrast, brightness, invert, &mut actual);
            assert_eq!(
                actual, expected,
                "{backend} mismatch for gamma={gamma}, contrast={contrast}, brightness={brightness}, invert={invert}"
            );
        }

        let gamma_lut = build_gamma_lut(1.7, &CancellationToken::new(), live_deadline()).unwrap();
        for pixel_count in 1..=31 {
            let rgb = patterned_rgb(pixel_count);
            let expected = scalar_row_chars(&rgb, &gamma_lut, 1.2, -4.0, true);
            let mut actual = vec![0_u8; expected.len()];
            convert(&rgb, &gamma_lut, 1.2, -4.0, true, &mut actual);
            assert_eq!(
                actual, expected,
                "{backend} remainder mismatch for {pixel_count} pixels"
            );
        }
    }

    #[test]
    fn default_ramp_and_auto_height_match_frozen_contract() {
        assert_eq!(DEFAULT_ASCII_RAMP.len(), 69);
        assert_eq!(DEFAULT_ASCII_RAMP.first(), Some(&b' '));
        assert_eq!(DEFAULT_ASCII_RAMP.last(), Some(&b'$'));
        assert_eq!(auto_height(10, 1920, 1080, 2.0).unwrap(), 3);
    }

    #[test]
    fn scalar_preserves_frozen_accelerated_chunks_and_scalar_tail() {
        let cancellation = CancellationToken::new();
        let mut request = spec(10, 1, 10);
        request.output_height = Some(1);
        let input = vec![2_u8; 10 * 3];
        let frame = render_rgb24_ascii(&input, request, &cancellation, live_deadline()).unwrap();
        assert_eq!(&frame.chars[..8], &[DEFAULT_ASCII_RAMP[1]; 8]);
        assert_eq!(&frame.chars[8..], &[DEFAULT_ASCII_RAMP[0]; 2]);
        assert_eq!(frame.backend, AsciiBackend::Scalar);
    }

    #[test]
    fn malformed_budgets_cancellation_and_deadline_are_rejected() {
        let cancellation = CancellationToken::new();
        assert!(matches!(
            render_rgb24_ascii(&[0; 2], spec(1, 1, 1), &cancellation, live_deadline()),
            Err(AsciiRenderError::InvalidInput("RGB24 input length"))
        ));

        let mut request = spec(2, 2, 2);
        request.output_height = Some(2);
        request.max_source_pixels = 3;
        assert!(matches!(
            render_rgb24_ascii(&[0; 12], request, &cancellation, live_deadline()),
            Err(AsciiRenderError::LimitExceeded("source pixels"))
        ));

        request = spec(2, 2, 2);
        request.output_height = Some(2);
        request.max_output_bytes = 3;
        assert!(matches!(
            render_rgb24_ascii(&[0; 12], request, &cancellation, live_deadline()),
            Err(AsciiRenderError::LimitExceeded("output bytes"))
        ));

        request = spec(1, 1, 1);
        request.gamma = f32::NAN;
        assert!(matches!(
            render_rgb24_ascii(&[0; 3], request, &cancellation, live_deadline()),
            Err(AsciiRenderError::InvalidInput("non-finite adjustment"))
        ));

        cancellation.cancel();
        assert!(matches!(
            render_rgb24_ascii(&[0; 3], spec(1, 1, 1), &cancellation, live_deadline()),
            Err(AsciiRenderError::Cancelled)
        ));
        let active = CancellationToken::new();
        assert!(matches!(
            render_rgb24_ascii(&[0; 3], spec(1, 1, 1), &active, Instant::now()),
            Err(AsciiRenderError::DeadlineExceeded)
        ));
    }

    #[test]
    fn forced_unsupported_backends_fall_back_to_best_supported() {
        let capabilities = host_ascii_capabilities();
        let best = resolve_ascii_backend(AsciiSimdMode::Auto);
        if !capabilities.avx512f_bw {
            assert_eq!(resolve_ascii_backend(AsciiSimdMode::Avx512), best);
        }
        if !capabilities.avx2_fma {
            assert_eq!(resolve_ascii_backend(AsciiSimdMode::Avx2), best);
        }
        assert_eq!(
            resolve_ascii_backend(AsciiSimdMode::Scalar),
            AsciiBackend::Scalar
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn avx2_matches_scalar_for_all_luma_values_adjustments_and_remainders() {
        if !host_ascii_capabilities().avx2_fma {
            return;
        }
        assert_backend_matches_scalar(
            "AVX2",
            |rgb, gamma_lut, contrast, brightness, invert, output| {
                // SAFETY: this test is gated by the production OS-aware detector.
                unsafe {
                    convert_row_avx2(rgb, gamma_lut, contrast, brightness, invert, output);
                }
            },
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn avx512_matches_scalar_for_all_luma_values_adjustments_and_remainders() {
        if !host_ascii_capabilities().avx512f_bw {
            return;
        }
        assert_backend_matches_scalar(
            "AVX-512",
            |rgb, gamma_lut, contrast, brightness, invert, output| {
                // SAFETY: this test is gated by the production OS-aware detector.
                unsafe {
                    convert_row_avx512(rgb, gamma_lut, contrast, brightness, invert, output);
                }
            },
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn frozen_video_second_decoded_frame_matches_managed_smtp_golden_for_all_backends() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets/skibidi_toilet_episode_1.mp4");
        let mut decoder =
            crate::ffmpeg_video::VideoDecoder::open(&path).expect("frozen Skibidi video must open");
        assert_eq!(decoder.dimensions(), (1920, 1080));
        let mut rgb = vec![0_u8; 1920 * 1080 * 3];
        assert!(
            decoder
                .next_frame(&mut rgb)
                .expect("first frame must decode")
        );
        assert!(
            decoder
                .next_frame(&mut rgb)
                .expect("second frame must decode")
        );

        let cancellation = CancellationToken::new();
        let mut request = spec(1920, 1080, 10);
        request.contrast = 1.2;
        request.max_source_pixels = 1920 * 1080;
        request.max_output_bytes = 30;
        let scalar = render_rgb24_ascii(&rgb, request, &cancellation, live_deadline()).unwrap();
        assert_eq!((scalar.width, scalar.height), (10, 3));
        assert_eq!(scalar.backend, AsciiBackend::Scalar);
        assert_eq!(
            scalar.chars, b"?[/fxu|{cC<luzYJ<}Yr^l1{vLYj->",
            "managed golden rows must match without SMTP framing"
        );

        let capabilities = host_ascii_capabilities();
        if capabilities.avx2_fma {
            request.simd_mode = AsciiSimdMode::Avx2;
            let avx2 = render_rgb24_ascii(&rgb, request, &cancellation, live_deadline()).unwrap();
            assert_eq!(avx2.backend, AsciiBackend::Avx2);
            assert_eq!(
                avx2.chars, scalar.chars,
                "AVX2 changed managed golden bytes"
            );
        }
        if capabilities.avx512f_bw {
            request.simd_mode = AsciiSimdMode::Avx512;
            let avx512 = render_rgb24_ascii(&rgb, request, &cancellation, live_deadline()).unwrap();
            assert_eq!(avx512.backend, AsciiBackend::Avx512);
            assert_eq!(
                avx512.chars, scalar.chars,
                "AVX-512 changed managed golden bytes"
            );
        }
    }
}
