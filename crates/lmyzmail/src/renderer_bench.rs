use std::{
    fmt,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    config::MailRenderSimdMode,
    ffmpeg_video::VideoDecoder,
    mail_render::{
        RenderBackend, Rgb24ResizeSpec, apply_rgb24_contrast, host_simd_capabilities,
        resize_rgb24_box_with_backend, resolve_render_backend_for_mode,
        rgb24_to_map_colors_with_dither_and_backend,
    },
    minecraft_block_palette::{
        convert_rgb24_to_palette_rgb_with_backend, convert_rgb24_to_states_with_backend,
    },
};

pub const SCHEMA: &str = "lmyzmail.renderer-simd-benchmark.v1";
pub const SOURCE_WIDTH: usize = 1920;
pub const SOURCE_HEIGHT: usize = 1080;
pub const MAX_BLOCK_PIXELS: usize = 4096;
pub const DEFAULT_SIZES: [usize; 4] = [64, 128, 256, 512];

const MAX_OUTPUT_EDGE: usize = 2048;
const OPERATION_DEADLINE: Duration = Duration::from_secs(3_600);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Scalar,
    Avx2Fma,
    Avx512F,
}

impl Backend {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Avx2Fma => "avx2+fma",
            Self::Avx512F => "avx512f",
        }
    }

    const fn render_backend(self) -> RenderBackend {
        match self {
            Self::Scalar => RenderBackend::Scalar,
            Self::Avx2Fma => RenderBackend::Avx2Fma,
            Self::Avx512F => RenderBackend::Avx512,
        }
    }

    const fn simd_mode(self) -> MailRenderSimdMode {
        match self {
            Self::Scalar => MailRenderSimdMode::Scalar,
            Self::Avx2Fma => MailRenderSimdMode::Avx2,
            Self::Avx512F => MailRenderSimdMode::Avx512,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedPolicy {
    Fail,
    Record,
}

#[derive(Clone, Debug)]
pub struct BenchmarkConfig {
    pub input: PathBuf,
    pub frame_index: usize,
    pub backend: Backend,
    pub sizes: Vec<usize>,
    pub contrast: f32,
    pub dither: u8,
    pub warmup: usize,
    pub iterations: usize,
    pub unsupported: UnsupportedPolicy,
}

#[derive(Debug)]
pub struct BenchmarkError(String);

impl BenchmarkError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BenchmarkError {}

#[derive(Debug, Serialize)]
pub struct BenchmarkReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub requested_backend: &'static str,
    pub resolved_backend: &'static str,
    pub fallback_used: bool,
    pub host_capabilities: CapabilityReport,
    pub unsupported_reason: Option<String>,
    pub input: String,
    pub frame_index: usize,
    pub frame: Option<FrameReport>,
    pub parameters: ParameterReport,
    pub sizes: Vec<SizeReport>,
}

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub avx2: bool,
    pub fma: bool,
    pub avx512f: bool,
}

#[derive(Debug, Serialize)]
pub struct FrameReport {
    pub width: usize,
    pub height: usize,
    pub rgb24_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ParameterReport {
    pub contrast: f32,
    pub dither: u8,
    pub warmup: usize,
    pub iterations: usize,
    pub timing_unit: &'static str,
    pub p95_method: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SizeReport {
    pub edge: usize,
    pub pixels: usize,
    pub stages: Vec<StageReport>,
}

#[derive(Debug, Serialize)]
pub struct StageReport {
    pub stage: &'static str,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_output_hash_validation: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_iterations_hashed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub samples_ns: Option<Vec<u64>>,
}

impl StageReport {
    fn timed(stage: &'static str, output_sha256: String, samples: Vec<u64>) -> Self {
        let (median_ns, p95_ns) = summarize(&samples);
        Self {
            stage,
            status: "timed",
            reason: None,
            output_sha256: Some(output_sha256),
            measured_output_hash_validation: Some("passed"),
            measured_iterations_hashed: Some(samples.len()),
            median_ns: Some(median_ns),
            p95_ns: Some(p95_ns),
            samples_ns: Some(samples),
        }
    }

    fn not_applicable(stage: &'static str, reason: &'static str) -> Self {
        Self {
            stage,
            status: "not_applicable",
            reason: Some(reason),
            output_sha256: None,
            measured_output_hash_validation: None,
            measured_iterations_hashed: None,
            median_ns: None,
            p95_ns: None,
            samples_ns: None,
        }
    }
}

pub fn run(config: &BenchmarkConfig) -> Result<BenchmarkReport, BenchmarkError> {
    validate_config(config)?;
    let capabilities = host_simd_capabilities();
    let requested = config.backend.render_backend();
    let renderer_resolved = resolve_render_backend_for_mode(config.backend.simd_mode());
    let resolved = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        renderer_resolved
    } else {
        RenderBackend::Scalar
    };
    let capability_report = CapabilityReport {
        avx2: capabilities.avx2,
        fma: capabilities.fma,
        avx512f: capabilities.avx512f,
    };

    let fallback_used = requested != resolved;
    if fallback_used {
        let reason = format!(
            "requested backend {} resolved to {}; fallback timing is forbidden",
            config.backend.name(),
            resolved.name()
        );
        if config.unsupported == UnsupportedPolicy::Fail {
            return Err(BenchmarkError::new(reason));
        }
        return Ok(BenchmarkReport {
            schema: SCHEMA,
            status: "unsupported",
            requested_backend: config.backend.name(),
            resolved_backend: resolved.name(),
            fallback_used,
            host_capabilities: capability_report,
            unsupported_reason: Some(reason),
            input: config.input.to_string_lossy().into_owned(),
            frame_index: config.frame_index,
            frame: None,
            parameters: parameters(config),
            sizes: Vec::new(),
        });
    }

    // Decode and hash the real source frame before any benchmark clock starts.
    let frame = decode_frame(&config.input, config.frame_index)?;
    let frame_report = FrameReport {
        width: SOURCE_WIDTH,
        height: SOURCE_HEIGHT,
        rgb24_sha256: sha256_bytes(&frame),
    };
    let cancellation = CancellationToken::new();
    let mut sizes = Vec::with_capacity(config.sizes.len());
    for &edge in &config.sizes {
        sizes.push(benchmark_size(
            &frame,
            edge,
            config,
            requested,
            &cancellation,
        )?);
    }

    Ok(BenchmarkReport {
        schema: SCHEMA,
        status: "ok",
        requested_backend: config.backend.name(),
        resolved_backend: resolved.name(),
        fallback_used,
        host_capabilities: capability_report,
        unsupported_reason: None,
        input: config.input.to_string_lossy().into_owned(),
        frame_index: config.frame_index,
        frame: Some(frame_report),
        parameters: parameters(config),
        sizes,
    })
}

fn parameters(config: &BenchmarkConfig) -> ParameterReport {
    ParameterReport {
        contrast: config.contrast,
        dither: config.dither,
        warmup: config.warmup,
        iterations: config.iterations,
        timing_unit: "nanoseconds",
        p95_method: "nearest-rank",
    }
}

fn validate_config(config: &BenchmarkConfig) -> Result<(), BenchmarkError> {
    if config.sizes.is_empty() {
        return Err(BenchmarkError::new("at least one output size is required"));
    }
    if config
        .sizes
        .iter()
        .any(|&edge| edge == 0 || edge > MAX_OUTPUT_EDGE)
    {
        return Err(BenchmarkError::new(format!(
            "output edges must be within 1..={MAX_OUTPUT_EDGE}"
        )));
    }
    if config.sizes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BenchmarkError::new(
            "output sizes must be unique and strictly increasing",
        ));
    }
    if !config.contrast.is_finite() || config.contrast < 0.0 {
        return Err(BenchmarkError::new(
            "contrast must be finite and non-negative",
        ));
    }
    if config.dither > 2 {
        return Err(BenchmarkError::new("dither must be 0, 1, or 2"));
    }
    if config.warmup == 0 || config.iterations == 0 {
        return Err(BenchmarkError::new(
            "warmup and iterations must both be positive",
        ));
    }
    Ok(())
}

fn decode_frame(path: &Path, frame_index: usize) -> Result<Vec<u8>, BenchmarkError> {
    let mut decoder = VideoDecoder::open(path)
        .map_err(|error| BenchmarkError::new(format!("open input video: {error}")))?;
    let dimensions = decoder.dimensions();
    if dimensions != (SOURCE_WIDTH, SOURCE_HEIGHT) {
        return Err(BenchmarkError::new(format!(
            "input video is {}x{}, expected {SOURCE_WIDTH}x{SOURCE_HEIGHT}",
            dimensions.0, dimensions.1
        )));
    }
    let mut frame = vec![0_u8; SOURCE_WIDTH * SOURCE_HEIGHT * 3];
    for index in 0..=frame_index {
        let decoded = decoder
            .next_frame(&mut frame)
            .map_err(|error| BenchmarkError::new(format!("decode frame {index}: {error}")))?;
        if !decoded {
            return Err(BenchmarkError::new(format!(
                "input video ended before frame {frame_index}"
            )));
        }
    }
    Ok(frame)
}

fn benchmark_size(
    frame: &[u8],
    edge: usize,
    config: &BenchmarkConfig,
    backend: RenderBackend,
    cancellation: &CancellationToken,
) -> Result<SizeReport, BenchmarkError> {
    let pixels = edge
        .checked_mul(edge)
        .ok_or_else(|| BenchmarkError::new("output pixel count overflowed"))?;
    let output_bytes = pixels
        .checked_mul(3)
        .ok_or_else(|| BenchmarkError::new("output byte count overflowed"))?;

    let resize = || {
        resize_rgb24_box_with_backend(
            frame,
            Rgb24ResizeSpec {
                source_width: SOURCE_WIDTH,
                source_height: SOURCE_HEIGHT,
                output_width: edge,
                output_height: edge,
                max_output_bytes: output_bytes,
            },
            backend,
            cancellation,
            operation_deadline(),
        )
        .map_err(|error| BenchmarkError::new(format!("resize {edge}: {error}")))
    };
    let (resized, resize_hash, resize_samples) = measure_owned(
        &format!("resize edge={edge}"),
        config.warmup,
        config.iterations,
        resize,
        |output| sha256_bytes(output),
    )?;
    let resize_report = StageReport::timed("resize", resize_hash, resize_samples);

    let (contrasted, contrast_hash, contrast_samples) = measure_in_place(
        &format!("contrast edge={edge}"),
        &resized,
        config.warmup,
        config.iterations,
        |scratch| {
            apply_rgb24_contrast(
                scratch,
                config.contrast,
                backend,
                cancellation,
                operation_deadline(),
            )
            .map_err(|error| BenchmarkError::new(format!("contrast {edge}: {error}")))
        },
    )?;
    let contrast_report = StageReport::timed("contrast", contrast_hash, contrast_samples);

    let block_palette_rgb = || {
        convert_rgb24_to_palette_rgb_with_backend(
            &contrasted,
            pixels,
            cancellation,
            operation_deadline(),
            backend,
        )
        .map_err(|error| BenchmarkError::new(format!("block_palette_rgb {edge}: {error}")))
    };
    let (representative_rgb, block_palette_hash, block_palette_samples) = measure_owned(
        &format!("block_palette_rgb edge={edge}"),
        config.warmup,
        config.iterations,
        block_palette_rgb,
        |output| sha256_bytes(output),
    )?;
    let block_palette_report = StageReport::timed(
        "block_palette_rgb",
        block_palette_hash,
        block_palette_samples,
    );

    let map_palette = || {
        rgb24_to_map_colors_with_dither_and_backend(
            &representative_rgb,
            edge,
            edge,
            pixels,
            config.dither,
            backend,
            cancellation,
            operation_deadline(),
        )
        .map_err(|error| BenchmarkError::new(format!("map_palette {edge}: {error}")))
    };
    let (_map_colors, map_palette_hash, map_palette_samples) = measure_owned(
        &format!("map_palette edge={edge}"),
        config.warmup,
        config.iterations,
        map_palette,
        |output| sha256_bytes(output),
    )?;
    let map_palette_report =
        StageReport::timed("map_palette", map_palette_hash, map_palette_samples);

    let block_states_report = if pixels <= MAX_BLOCK_PIXELS {
        let block_states = || {
            convert_rgb24_to_states_with_backend(
                &contrasted,
                pixels,
                cancellation,
                operation_deadline(),
                backend,
            )
            .map_err(|error| BenchmarkError::new(format!("block_states {edge}: {error}")))
        };
        let (_states, output_hash, samples) = measure_owned(
            &format!("block_states edge={edge}"),
            config.warmup,
            config.iterations,
            block_states,
            |output| sha256_u16_le(output),
        )?;
        StageReport::timed("block_states", output_hash, samples)
    } else {
        StageReport::not_applicable(
            "block_states",
            "pixel count exceeds MAX_BLOCK_PIXELS=4096; production does not chunk block frames",
        )
    };

    Ok(SizeReport {
        edge,
        pixels,
        stages: vec![
            resize_report,
            contrast_report,
            block_palette_report,
            map_palette_report,
            block_states_report,
        ],
    })
}

fn measure_owned<T, F, H>(
    label: &str,
    warmup: usize,
    iterations: usize,
    mut operation: F,
    hash_output: H,
) -> Result<(T, String, Vec<u64>), BenchmarkError>
where
    F: FnMut() -> Result<T, BenchmarkError>,
    H: Fn(&T) -> String,
{
    for _ in 0..warmup {
        black_box(operation()?);
    }
    let mut samples = Vec::with_capacity(iterations);
    let mut final_output = None;
    let mut expected_hash = None;
    for iteration in 0..iterations {
        let started = Instant::now();
        let output = operation()?;
        samples.push(duration_ns(started.elapsed()));
        black_box(&output);
        validate_measured_hash(label, iteration, &mut expected_hash, hash_output(&output))?;
        final_output = Some(output);
    }
    Ok((
        final_output.expect("validated iteration count is positive"),
        expected_hash.expect("validated iteration count is positive"),
        samples,
    ))
}

fn measure_in_place<F>(
    label: &str,
    input: &[u8],
    warmup: usize,
    iterations: usize,
    mut operation: F,
) -> Result<(Vec<u8>, String, Vec<u64>), BenchmarkError>
where
    F: FnMut(&mut [u8]) -> Result<(), BenchmarkError>,
{
    let mut scratch = input.to_vec();
    for _ in 0..warmup {
        scratch.copy_from_slice(input);
        operation(&mut scratch)?;
        black_box(&scratch);
    }
    let mut samples = Vec::with_capacity(iterations);
    let mut expected_hash = None;
    for iteration in 0..iterations {
        scratch.copy_from_slice(input);
        let started = Instant::now();
        operation(&mut scratch)?;
        samples.push(duration_ns(started.elapsed()));
        black_box(&scratch);
        validate_measured_hash(label, iteration, &mut expected_hash, sha256_bytes(&scratch))?;
    }
    Ok((
        scratch,
        expected_hash.expect("validated iteration count is positive"),
        samples,
    ))
}

fn validate_measured_hash(
    label: &str,
    iteration: usize,
    expected: &mut Option<String>,
    actual: String,
) -> Result<(), BenchmarkError> {
    if let Some(expected) = expected {
        if *expected != actual {
            return Err(BenchmarkError::new(format!(
                "{label}: measured output hash changed at iteration {}: expected {expected}, got {actual}",
                iteration + 1
            )));
        }
    } else {
        *expected = Some(actual);
    }
    Ok(())
}

fn summarize(samples: &[u64]) -> (u64, u64) {
    debug_assert!(!samples.is_empty());
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let middle = ordered.len() / 2;
    let median = if ordered.len().is_multiple_of(2) {
        ordered[middle - 1] + (ordered[middle] - ordered[middle - 1]) / 2
    } else {
        ordered[middle]
    };
    let rank = (95 * ordered.len()).div_ceil(100);
    (median, ordered[rank.saturating_sub(1)])
}

fn operation_deadline() -> Instant {
    Instant::now() + OPERATION_DEADLINE
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn sha256_u16_le(values: &[u16]) -> String {
    let mut digest = Sha256::new();
    for value in values {
        digest.update(value.to_le_bytes());
    }
    hex_digest(digest.finalize())
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        Backend, BenchmarkConfig, DEFAULT_SIZES, MAX_BLOCK_PIXELS, UnsupportedPolicy,
        measure_owned, sha256_bytes, summarize, validate_config,
    };

    fn config(sizes: Vec<usize>) -> BenchmarkConfig {
        BenchmarkConfig {
            input: PathBuf::from("unused-by-validation-tests.mp4"),
            frame_index: 0,
            backend: Backend::Scalar,
            sizes,
            contrast: 1.2,
            dither: 1,
            warmup: 5,
            iterations: 30,
            unsupported: UnsupportedPolicy::Fail,
        }
    }

    #[test]
    fn default_size_matrix_has_one_legal_block_state_row() {
        let config = config(DEFAULT_SIZES.to_vec());
        assert!(validate_config(&config).is_ok());
        assert_eq!(DEFAULT_SIZES[0] * DEFAULT_SIZES[0], MAX_BLOCK_PIXELS);
        assert!(
            DEFAULT_SIZES[1..]
                .iter()
                .all(|edge| edge * edge > MAX_BLOCK_PIXELS)
        );
    }

    #[test]
    fn validation_rejects_invalid_duplicate_and_zero_warmup_inputs() {
        for sizes in [
            Vec::new(),
            vec![0, 64],
            vec![64, 64],
            vec![128, 64],
            vec![64, 2049],
        ] {
            assert!(validate_config(&config(sizes)).is_err());
        }

        let mut invalid_contrast = config(DEFAULT_SIZES.to_vec());
        invalid_contrast.contrast = -0.1;
        assert!(validate_config(&invalid_contrast).is_err());

        let mut invalid_dither = config(DEFAULT_SIZES.to_vec());
        invalid_dither.dither = 3;
        assert!(validate_config(&invalid_dither).is_err());

        let mut zero_warmup = config(DEFAULT_SIZES.to_vec());
        zero_warmup.warmup = 0;
        assert!(validate_config(&zero_warmup).is_err());
    }

    #[test]
    fn summary_uses_even_median_and_nearest_rank_p95() {
        let samples: Vec<u64> = (1..=20).rev().collect();
        assert_eq!(summarize(&samples), (10, 19));
        assert_eq!(summarize(&[7]), (7, 7));
        assert_eq!(summarize(&[5, 1, 4, 2, 3]), (3, 5));
    }

    #[test]
    fn measured_iteration_hash_gate_rejects_intermittent_output() {
        let mut invocation = 0_u8;
        let error = measure_owned(
            "intermittent-test",
            1,
            3,
            || {
                invocation = invocation.wrapping_add(1);
                Ok(vec![invocation])
            },
            |output| sha256_bytes(output),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("measured output hash changed at iteration 2")
        );
    }
}
