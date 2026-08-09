use std::{
    ffi::{CStr, CString},
    io,
    os::raw::{c_char, c_int},
    path::Path,
    ptr,
};

#[repr(C)]
struct NativeVideo {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn lmyzmail_ffmpeg_video_open(
        path: *const c_char,
        output: *mut *mut NativeVideo,
        width: *mut c_int,
        height: *mut c_int,
    ) -> c_int;
    fn lmyzmail_ffmpeg_video_next(
        video: *mut NativeVideo,
        output: *mut u8,
        output_len: usize,
    ) -> c_int;
    fn lmyzmail_ffmpeg_video_error(video: *const NativeVideo) -> *const c_char;
    fn lmyzmail_ffmpeg_video_close(video: *mut NativeVideo);
}

pub(crate) struct VideoDecoder {
    native: *mut NativeVideo,
    width: usize,
    height: usize,
}

// The native handle is owned by exactly one bounded blocking-pool job at a
// time. It is never accessed concurrently or from the async runtime thread.
unsafe impl Send for VideoDecoder {}

impl VideoDecoder {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "video path contains a NUL byte",
            )
        })?;
        let mut native = ptr::null_mut();
        let mut width = 0;
        let mut height = 0;
        // SAFETY: `path` is a live NUL-terminated string, and the output
        // pointers refer to initialized local storage owned by this call.
        let status = unsafe {
            lmyzmail_ffmpeg_video_open(path.as_ptr(), &mut native, &mut width, &mut height)
        };
        if status != 0 || native.is_null() {
            return Err(io::Error::other(format!(
                "FFmpeg video open failed with status {status}"
            )));
        }
        let width = usize::try_from(width)
            .map_err(|_| io::Error::other("FFmpeg returned a negative video width"))?;
        let height = usize::try_from(height)
            .map_err(|_| io::Error::other("FFmpeg returned a negative video height"))?;
        if width == 0 || height == 0 {
            // SAFETY: `native` was initialized by the successful open call.
            unsafe { lmyzmail_ffmpeg_video_close(native) };
            return Err(io::Error::other("FFmpeg returned empty video dimensions"));
        }
        Ok(Self {
            native,
            width,
            height,
        })
    }

    pub(crate) fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    pub(crate) fn next_frame(&mut self, output: &mut [u8]) -> io::Result<bool> {
        let expected = self
            .width
            .checked_mul(self.height)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| io::Error::other("FFmpeg frame size overflow"))?;
        if output.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FFmpeg output buffer length is invalid",
            ));
        }
        // SAFETY: `self.native` is a live handle owned by this instance, and
        // `output` is a uniquely borrowed buffer of exactly the required size.
        let status =
            unsafe { lmyzmail_ffmpeg_video_next(self.native, output.as_mut_ptr(), output.len()) };
        match status {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(io::Error::other(self.error_message())),
        }
    }

    fn error_message(&self) -> String {
        // SAFETY: the native handle remains live while the diagnostic is read.
        let pointer = unsafe { lmyzmail_ffmpeg_video_error(self.native) };
        if pointer.is_null() {
            return "FFmpeg video operation failed".to_owned();
        }
        // SAFETY: the C wrapper owns a bounded NUL-terminated diagnostic.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for VideoDecoder {
    fn drop(&mut self) {
        if !self.native.is_null() {
            // SAFETY: this is the unique owner and Drop runs at most once.
            unsafe { lmyzmail_ffmpeg_video_close(self.native) };
            self.native = ptr::null_mut();
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use std::time::{Duration, Instant};

    use sha2::{Digest as _, Sha256};
    use tokio_util::sync::CancellationToken;

    use super::VideoDecoder;

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn frozen_n7_1_frame_zero_matches_native_representative_rgb() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets/skibidi_toilet_episode_1.mp4");
        let mut decoder = VideoDecoder::open(&path).expect("frozen video must open");
        assert_eq!(decoder.dimensions(), (1920, 1080));
        let mut raw = vec![0_u8; 1920 * 1080 * 3];
        assert!(
            decoder
                .next_frame(&mut raw)
                .expect("first frame must decode")
        );

        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let resized = crate::mail_render::resize_rgb24_box(
            &raw,
            crate::mail_render::Rgb24ResizeSpec {
                source_width: 1920,
                source_height: 1080,
                output_width: 256,
                output_height: 256,
                max_output_bytes: 256 * 256 * 3,
            },
            &cancellation,
            deadline,
        )
        .expect("frozen frame resize must succeed");
        let representative = crate::minecraft_block_palette::convert_rgb24_to_palette_rgb(
            &resized,
            256 * 256,
            &cancellation,
            deadline,
        )
        .expect("frozen palette conversion must succeed");
        let digest = sha256_hex(&representative);
        assert_eq!(
            digest,
            "5284ed225c0a5a535f1e11afc39e8f6dbe4bfca042bdf7a3710d5e2f80e9a98e"
        );
    }

    #[test]
    fn frozen_map_video_first_emitted_frame_matches_native_pipeline() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets/skibidi_toilet_episode_1.mp4");
        let mut decoder = VideoDecoder::open(&path).expect("frozen video must open");
        let mut raw = vec![0_u8; 1920 * 1080 * 3];
        for _ in 0..30 {
            assert!(decoder.next_frame(&mut raw).expect("frame must decode"));
        }

        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut resized = crate::mail_render::resize_rgb24_box(
            &raw,
            crate::mail_render::Rgb24ResizeSpec {
                source_width: 1920,
                source_height: 1080,
                output_width: 256,
                output_height: 256,
                max_output_bytes: 256 * 256 * 3,
            },
            &cancellation,
            deadline,
        )
        .expect("frozen frame resize must succeed");
        for channel in &mut resized {
            let adjusted = (f32::from(*channel) - 128.0) * 3.0 + 128.0;
            *channel = (adjusted.clamp(0.0, 255.0) + 0.5).floor() as u8;
        }
        let representative = crate::minecraft_block_palette::convert_rgb24_to_palette_rgb(
            &resized,
            256 * 256,
            &cancellation,
            deadline,
        )
        .expect("frozen block-palette conversion must succeed");
        assert_eq!(
            sha256_hex(&representative),
            "8e4fadf0f363fe5cbfbb47cadd706f07c3b2fb4db880daf90a6aea70fe1b730c"
        );

        let map_colors = crate::mail_render::rgb24_to_map_colors_with_dither(
            &representative,
            256,
            256,
            256 * 256,
            1,
            &cancellation,
            deadline,
        )
        .expect("frozen map-palette conversion must succeed");
        assert_eq!(
            sha256_hex(&map_colors),
            "b84f38e9169d6a5d170c72df09e15ff310d94ecbb9397c03971b18753fc04475"
        );
    }
}
