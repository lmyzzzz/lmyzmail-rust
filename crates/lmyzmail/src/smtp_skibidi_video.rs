use std::{
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant as StdInstant},
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    ffmpeg_video::VideoDecoder,
    smtp_ascii::{AsciiFrame, AsciiRenderSpec, AsciiSimdMode, render_rgb24_ascii},
};

const SOURCE_WIDTH: usize = 1920;
const SOURCE_HEIGHT: usize = 1080;
const SOURCE_FPS: f64 = 30.0;
const MAX_SOURCE_FRAME_BYTES: usize = SOURCE_WIDTH * SOURCE_HEIGHT * 3;
const MAX_ASCII_PIXELS: usize = 4 * 1024 * 1024;
const MAX_ASCII_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const VIDEO_JOB_TIMEOUT: Duration = Duration::from_secs(15);
const VIDEO_POOL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(crate) struct VideoDefaults {
    pub(crate) max_width: usize,
    pub(crate) max_fps: f32,
    pub(crate) default_width: usize,
    pub(crate) default_fps: f32,
    pub(crate) default_contrast: f32,
    pub(crate) char_aspect: f32,
    pub(crate) simd_mode: AsciiSimdMode,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct VideoParams {
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) fps: f32,
    pub(crate) contrast: f32,
    pub(crate) brightness: f32,
    pub(crate) gamma: f32,
    pub(crate) char_aspect: f32,
    pub(crate) invert: bool,
    pub(crate) simd_mode: AsciiSimdMode,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum VideoStartError {
    Busy,
    Invalid(String),
    Unavailable(String),
    Cancelled,
}

pub(crate) struct VideoService {
    defaults: VideoDefaults,
    video_asset: PathBuf,
    worker: BoundedBlockingPool,
    admission: Arc<Semaphore>,
}

impl VideoService {
    pub(crate) fn new(video_asset: PathBuf, defaults: VideoDefaults) -> io::Result<Self> {
        Ok(Self {
            defaults,
            video_asset,
            worker: BoundedBlockingPool::new("lmyzmail-smtp-ascii-video", 1, 1)?,
            admission: Arc::new(Semaphore::new(1)),
        })
    }

    pub(crate) async fn start(
        self: &Arc<Self>,
        arguments: &str,
        parent_cancellation: &CancellationToken,
    ) -> Result<VideoPlayback, VideoStartError> {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| VideoStartError::Busy)?;
        let params = parse_video_params(arguments, self.defaults)?;
        let cancellation = parent_cancellation.child_token();
        let worker_cancellation = cancellation.clone();
        let path = self.video_asset.clone();
        let receiver = self
            .worker
            .submit(move || VideoWorkerState::open(path, &worker_cancellation, permit))
            .map_err(submit_error)?;
        let opened = tokio::select! {
            _ = cancellation.cancelled() => Err(VideoStartError::Cancelled),
            result = timeout(VIDEO_JOB_TIMEOUT, receiver) => match result {
                Err(_) => Err(VideoStartError::Unavailable(
                    "video decoder open deadline exceeded".to_owned(),
                )),
                Ok(Err(_)) => Err(VideoStartError::Unavailable(
                    "video decoder open task was cancelled".to_owned(),
                )),
                Ok(Ok(Err(error))) => Err(VideoStartError::Unavailable(error)),
                Ok(Ok(Ok(state))) => Ok(state),
            },
        };
        let state = match opened {
            Ok(state) => state,
            Err(error) => {
                cancellation.cancel();
                return Err(error);
            }
        };
        Ok(VideoPlayback {
            service: Arc::clone(self),
            cancellation,
            params,
            state: Some(state),
        })
    }

    pub(crate) async fn shutdown(&self) -> bool {
        self.worker.shutdown(VIDEO_POOL_SHUTDOWN_TIMEOUT).await
    }
}

fn submit_error(error: SubmitError) -> VideoStartError {
    VideoStartError::Unavailable(format!("video decoder queue is {error}"))
}

pub(crate) struct VideoPlayback {
    service: Arc<VideoService>,
    cancellation: CancellationToken,
    params: VideoParams,
    state: Option<VideoWorkerState>,
}

impl VideoPlayback {
    pub(crate) fn params(&self) -> VideoParams {
        self.params
    }

    pub(crate) async fn next_frame(&mut self) -> Result<Option<AsciiFrame>, String> {
        let state = self
            .state
            .take()
            .ok_or_else(|| "video worker state is unavailable".to_owned())?;
        let params = self.params;
        let worker_cancellation = self.cancellation.clone();
        let deadline = StdInstant::now() + VIDEO_JOB_TIMEOUT;
        let receiver = match self
            .service
            .worker
            .submit(move || state.decode_and_render(params, &worker_cancellation, deadline))
        {
            Ok(receiver) => receiver,
            Err(error) => {
                self.cancellation.cancel();
                return Err(format!("video decoder queue is {error}"));
            }
        };
        let completed = tokio::select! {
            _ = self.cancellation.cancelled() => Err("video playback was cancelled".to_owned()),
            result = timeout(VIDEO_JOB_TIMEOUT, receiver) => match result {
                Err(_) => Err("video frame deadline exceeded".to_owned()),
                Ok(Err(_)) => Err("video frame task was cancelled".to_owned()),
                Ok(Ok(result)) => result,
            },
        };
        let result = match completed {
            Ok(result) => result,
            Err(error) => {
                self.cancellation.cancel();
                return Err(error);
            }
        };
        self.state = Some(result.state);
        Ok(result.frame)
    }
}

impl Drop for VideoPlayback {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.state.take();
    }
}

struct VideoWorkerState {
    _permit: OwnedSemaphorePermit,
    decoder: VideoDecoder,
    raw: Vec<u8>,
    decoded_frames: u64,
    emitted_frames: u64,
}

impl VideoWorkerState {
    fn open(
        path: PathBuf,
        cancellation: &CancellationToken,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, String> {
        if cancellation.is_cancelled() {
            return Err("video decoder open was cancelled".to_owned());
        }
        let decoder = VideoDecoder::open(&path)
            .map_err(|error| format!("video decoder open failed: {error}"))?;
        let (width, height) = decoder.dimensions();
        if width != SOURCE_WIDTH || height != SOURCE_HEIGHT {
            return Err(format!(
                "video dimensions are {width}x{height}; expected {SOURCE_WIDTH}x{SOURCE_HEIGHT}"
            ));
        }
        Ok(Self {
            _permit: permit,
            decoder,
            raw: vec![0_u8; MAX_SOURCE_FRAME_BYTES],
            decoded_frames: 0,
            emitted_frames: 0,
        })
    }

    fn decode_and_render(
        mut self,
        params: VideoParams,
        cancellation: &CancellationToken,
        deadline: StdInstant,
    ) -> Result<VideoWorkerResult, String> {
        loop {
            if cancellation.is_cancelled() || StdInstant::now() >= deadline {
                return Err("video frame conversion was cancelled or timed out".to_owned());
            }
            if !self
                .decoder
                .next_frame(&mut self.raw)
                .map_err(|error| format!("video decode failed: {error}"))?
            {
                return Ok(VideoWorkerResult {
                    state: self,
                    frame: None,
                });
            }
            self.decoded_frames = self.decoded_frames.saturating_add(1);
            let threshold =
                (self.emitted_frames.saturating_add(1) as f64) * SOURCE_FPS / f64::from(params.fps);
            if f64::from(params.fps) < SOURCE_FPS && (self.decoded_frames as f64) < threshold {
                continue;
            }
            self.emitted_frames = self.emitted_frames.saturating_add(1);
            break;
        }

        let frame = render_rgb24_ascii(
            &self.raw,
            AsciiRenderSpec {
                source_width: SOURCE_WIDTH,
                source_height: SOURCE_HEIGHT,
                output_width: params.width,
                output_height: Some(params.height),
                contrast: params.contrast,
                brightness: params.brightness,
                gamma: params.gamma,
                char_aspect: params.char_aspect,
                invert: params.invert,
                simd_mode: params.simd_mode,
                max_source_pixels: SOURCE_WIDTH * SOURCE_HEIGHT,
                max_output_bytes: MAX_ASCII_OUTPUT_BYTES,
            },
            cancellation,
            deadline,
        )
        .map_err(|error| format!("ASCII frame conversion failed: {error}"))?;
        Ok(VideoWorkerResult {
            state: self,
            frame: Some(frame),
        })
    }
}

struct VideoWorkerResult {
    state: VideoWorkerState,
    frame: Option<AsciiFrame>,
}

pub(crate) fn frame_wire_bytes(frame: &AsciiFrame) -> Result<Vec<u8>, String> {
    let width = frame.width;
    let height = frame.height;
    let chars = frame.chars.as_slice();
    if width == 0
        || height == 0
        || width.checked_mul(height) != Some(chars.len())
        || chars.len() > MAX_ASCII_OUTPUT_BYTES
    {
        return Err("ASCII frame dimensions exceed the SMTP output budget".to_owned());
    }
    let capacity = chars
        .len()
        .checked_add(height.saturating_mul(6))
        .and_then(|value| value.checked_add(7))
        .ok_or_else(|| "ASCII SMTP frame size overflow".to_owned())?;
    let mut output = Vec::with_capacity(capacity);
    for (row, line) in chars.chunks_exact(width).enumerate() {
        output.extend_from_slice(b"250-");
        if row == 0 {
            output.extend_from_slice(b"\x1b[H    ");
        }
        output.extend_from_slice(line);
        output.extend_from_slice(b"\r\n");
    }
    Ok(output)
}

fn parse_video_params(
    arguments: &str,
    defaults: VideoDefaults,
) -> Result<VideoParams, VideoStartError> {
    let mut width = defaults.default_width;
    let mut fps = defaults.default_fps;
    let mut contrast = defaults.default_contrast;
    let mut brightness = 0.0_f32;
    let mut gamma = 1.0_f32;
    let mut char_aspect = defaults.char_aspect;
    let mut invert = false;

    for part in arguments.split_whitespace() {
        let upper = part.to_ascii_uppercase();
        if upper.starts_with("WIDTH=") {
            width = part[6..]
                .parse::<usize>()
                .map_err(|_| invalid_value("WIDTH"))?;
        } else if upper.starts_with("FPS=") {
            fps = part[4..].parse::<f32>().map_err(|_| invalid_value("FPS"))?;
        } else if upper.starts_with("CONTRAST=") {
            contrast = part[9..]
                .parse::<f32>()
                .map_err(|_| invalid_value("CONTRAST"))?;
        } else if upper.starts_with("BRIGHTNESS=") {
            brightness = part[11..]
                .parse::<f32>()
                .map_err(|_| invalid_value("BRIGHTNESS"))?;
        } else if upper.starts_with("GAMMA=") {
            gamma = part[6..]
                .parse::<f32>()
                .map_err(|_| invalid_value("GAMMA"))?;
        } else if upper.starts_with("ASPECT=") {
            char_aspect = part[7..]
                .parse::<f32>()
                .map_err(|_| invalid_value("ASPECT"))?;
        } else if upper == "INVERT" {
            invert = true;
        }
    }

    if width < 10 || width > defaults.max_width {
        return Err(VideoStartError::Invalid(format!(
            "5.5.4 WIDTH must be 10..{}. Got {width}. Your terminal is either microscopic or you are trying to crash the server.",
            defaults.max_width
        )));
    }
    if !fps.is_finite() {
        return Err(invalid_value("FPS"));
    }
    if fps < 1.0 || fps > defaults.max_fps {
        return Err(VideoStartError::Invalid(format!(
            "5.5.4 FPS must be 1..{}. Got {}. This is not a gaming PC benchmark.",
            defaults.max_fps as u32,
            java_float(fps)
        )));
    }
    for (name, value) in [
        ("CONTRAST", contrast),
        ("BRIGHTNESS", brightness),
        ("GAMMA", gamma),
        ("ASPECT", char_aspect),
    ] {
        if !value.is_finite() {
            return Err(invalid_value(name));
        }
    }
    if contrast <= 0.0 {
        contrast = 1.0;
    }
    if gamma <= 0.0 {
        gamma = 1.0;
    }
    if char_aspect <= 0.0 {
        char_aspect = 2.0;
    }
    if contrast > 8.0 || brightness.abs() > 255.0 || gamma > 8.0 || char_aspect > 8.0 {
        return Err(VideoStartError::Invalid(
            "5.5.4 ASCII transform parameter exceeds the safe processing budget.".to_owned(),
        ));
    }
    let height = ((width as f32 * SOURCE_HEIGHT as f32 / (SOURCE_WIDTH as f32 * char_aspect)) + 0.5)
        as usize;
    let height = height.max(1);
    if width
        .checked_mul(height)
        .is_none_or(|pixels| pixels > MAX_ASCII_PIXELS)
    {
        return Err(VideoStartError::Invalid(
            "5.5.4 Requested ASCII frame exceeds the safe output budget.".to_owned(),
        ));
    }
    Ok(VideoParams {
        width,
        height,
        fps,
        contrast,
        brightness,
        gamma,
        char_aspect,
        invert,
        simd_mode: defaults.simd_mode,
    })
}

fn invalid_value(name: &str) -> VideoStartError {
    VideoStartError::Invalid(format!("5.5.4 Invalid {name} value."))
}

fn java_float(value: f32) -> String {
    if value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> VideoDefaults {
        VideoDefaults {
            max_width: 450,
            max_fps: 20.0,
            default_width: 120,
            default_fps: 10.0,
            default_contrast: 1.2,
            char_aspect: 2.0,
            simd_mode: AsciiSimdMode::Auto,
        }
    }

    #[test]
    fn parameter_defaults_and_frozen_boundaries_match_java() {
        let parsed = parse_video_params("", defaults()).unwrap();
        assert_eq!(parsed.width, 120);
        assert_eq!(parsed.height, 34);
        assert_eq!(parsed.fps, 10.0);
        assert_eq!(
            parse_video_params("WIDTH=10 FPS=20 CONTRAST=1.2", defaults())
                .unwrap()
                .height,
            3
        );
        assert_eq!(
            parse_video_params("WIDTH=9", defaults()).unwrap_err(),
            VideoStartError::Invalid(
                "5.5.4 WIDTH must be 10..450. Got 9. Your terminal is either microscopic or you are trying to crash the server.".to_owned()
            )
        );
        assert_eq!(
            parse_video_params("FPS=21", defaults()).unwrap_err(),
            VideoStartError::Invalid(
                "5.5.4 FPS must be 1..20. Got 21.0. This is not a gaming PC benchmark.".to_owned()
            )
        );
    }

    #[test]
    fn rejects_non_finite_and_budget_bypass_parameters() {
        assert_eq!(
            parse_video_params("FPS=NaN", defaults()).unwrap_err(),
            invalid_value("FPS")
        );
        assert_eq!(
            parse_video_params("ASPECT=NaN", defaults()).unwrap_err(),
            invalid_value("ASPECT")
        );
        assert!(parse_video_params("BRIGHTNESS=100000", defaults()).is_err());
    }
}
