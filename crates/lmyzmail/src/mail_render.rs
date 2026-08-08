//! Bounded, synchronous rendering of mail for Minecraft map walls.
//!
//! The renderer owns layout, pagination, palette matching, dithering, and tile
//! addressing. Cairo and FreeType provide font rasterization; pinned litehtml
//! source provides HTML layout through an ABI-versioned C boundary. All
//! `unsafe` code is confined to that FFI boundary, whose input lifetimes,
//! ownership, cancellation callback, and single-threaded context invariants are
//! documented at each call. No raw native handle or surface data escapes this
//! module.

use std::{
    collections::{HashMap, HashSet},
    ffi::{c_char, c_void},
    fmt,
    io::Cursor,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    ptr::NonNull,
    sync::OnceLock,
    time::Instant,
};

use cairo::{Context, FontFace, Format, ImageSurface};
use image::{DynamicImage, ImageDecoder, ImageReader, Limits};
use tokio_util::sync::CancellationToken;

pub const MAP_EDGE: usize = 128;
pub const MAP_PIXELS: usize = MAP_EDGE * MAP_EDGE;
pub const MIN_MAPS_X: u8 = 2;
pub const MAX_MAPS_X: u8 = 24;
pub const MIN_PAGE_MAPS_Y: u8 = 2;
pub const MAX_PAGE_MAPS_Y: u8 = 20;

const DEFAULT_MONOSPACE_FONT: &str = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf";
const FALLBACK_MONOSPACE_FONT: &str = "/usr/share/fonts/TTF/DejaVuSansMono.ttf";
const ABSOLUTE_MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const ABSOLUTE_MAX_DOCUMENT_HEIGHT: u32 = 32_768;
const ABSOLUTE_MAX_PAGES: usize = 128;
const ABSOLUTE_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const ABSOLUTE_MAX_FRAME_PIXELS: usize =
    (MAX_MAPS_X as usize) * MAP_EDGE * (MAX_PAGE_MAPS_Y as usize) * MAP_EDGE;
const CHECKPOINT_PIXEL_INTERVAL: usize = 64;
const MAX_GLYPH_WIDTH_CACHE_ENTRIES: usize = 256;
const MAX_CAIRO_TEXT_CHUNK_BYTES: usize = 4 * 1024;
const MAX_PREPARED_HTML_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CID_RESOURCE_BYTES: usize = 4_000_000;
pub const MAX_CID_RESOURCES: usize = 20;
pub const MAX_EXTERNAL_RESOURCE_BYTES: usize = 2_000_000;
pub const MAX_EXTERNAL_RESOURCES: usize = 20;
pub const MAX_IMAGE_RESOURCES: usize = 40;
pub const MAX_TOTAL_RESOURCE_BYTES: usize = 24_000_000;
const MAX_IMAGE_DIMENSION: u32 = 4096;
const MAX_IMAGE_PIXELS: u64 = 4 * 1024 * 1024;
const MAX_DOCUMENT_IMAGE_PIXELS: u64 = 16 * 1024 * 1024;
const MAX_DECODER_ALLOCATION_BYTES: u64 = MAX_IMAGE_PIXELS * 16;
const NATIVE_ERROR_CAPACITY: usize = 512;
const NATIVE_ABI_VERSION: u32 = 1;
const NATIVE_OK: i32 = 0;
const NATIVE_INVALID_ARGUMENT: i32 = 1;
const NATIVE_LIMIT_EXCEEDED: i32 = 2;
const NATIVE_CANCELLED: i32 = 3;
const NATIVE_RENDER_ERROR: i32 = 4;
const NATIVE_OUT_OF_MEMORY: i32 = 5;

const SAFE_CID_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/svg+xml",
];
const SAFE_EXTERNAL_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
];

/// A byte-bounded image resource. The Rust caller owns every string and byte
/// for the entire native-layout lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedResource {
    pub content_id: String,
    pub data: Box<[u8]>,
    pub mime_type: String,
}

impl EmbeddedResource {
    pub fn new(content_id: String, data: Vec<u8>, mime_type: String) -> Self {
        Self {
            content_id,
            data: data.into_boxed_slice(),
            mime_type,
        }
    }
}

#[derive(Debug)]
struct DecodedResource {
    content_id: String,
    rgba: Box<[u8]>,
    width: u32,
    height: u32,
    stride: u32,
}

#[repr(C)]
struct NativeHtmlConfig {
    struct_size: u32,
    viewport_width: u32,
    max_document_height: u32,
    base_font_size: f32,
    background_rgb: u32,
    reserved: [u32; 3],
    cancel: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    cancel_userdata: *mut c_void,
}

#[repr(C)]
struct NativeHtmlResource {
    cid: *const u8,
    cid_len: usize,
    rgba: *const u8,
    rgba_len: usize,
    width: u32,
    height: u32,
    stride: u32,
    reserved: u32,
}

#[repr(C)]
struct NativeHtmlContext {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn lmyzmail_mail_html_abi_version() -> u32;
    fn lmyzmail_mail_html_create(
        config: *const NativeHtmlConfig,
        html: *const u8,
        html_len: usize,
        resources: *const NativeHtmlResource,
        resource_count: usize,
        out_context: *mut *mut NativeHtmlContext,
        error: *mut c_char,
        error_capacity: usize,
    ) -> i32;
    fn lmyzmail_mail_html_query_size(
        context: *const NativeHtmlContext,
        out_width: *mut u32,
        out_height: *mut u32,
        error: *mut c_char,
        error_capacity: usize,
    ) -> i32;
    fn lmyzmail_mail_html_render_range(
        context: *mut NativeHtmlContext,
        y_start: u32,
        output_width: u32,
        output_height: u32,
        output_rgb: *mut u8,
        output_len: usize,
        output_stride: usize,
        error: *mut c_char,
        error_capacity: usize,
    ) -> i32;
    fn lmyzmail_mail_html_destroy(
        context: *mut NativeHtmlContext,
        error: *mut c_char,
        error_capacity: usize,
    ) -> i32;
}

struct NativeCancellation<'a> {
    cancellation: &'a CancellationToken,
    deadline: Instant,
}

/// This callback is the only native-to-Rust call. `userdata` points to a
/// stack value retained by `render_html` until after the native context is
/// destroyed. The callback catches any panic and converts it into a stop
/// request, so Rust never unwinds through C++.
unsafe extern "C" fn native_html_cancel(userdata: *mut c_void) -> i32 {
    if userdata.is_null() {
        return 1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `userdata` is installed from a live `NativeCancellation`
        // and the native context is destroyed before that value is dropped.
        let state = unsafe { &*userdata.cast::<NativeCancellation<'_>>() };
        i32::from(state.cancellation.is_cancelled() || Instant::now() >= state.deadline)
    }))
    .unwrap_or(1)
}

struct NativeHtmlHandle(NonNull<NativeHtmlContext>);

impl Drop for NativeHtmlHandle {
    fn drop(&mut self) {
        // SAFETY: this handle uniquely owns the context returned by a
        // successful create call. Destroy accepts a null error buffer.
        unsafe {
            let _ = lmyzmail_mail_html_destroy(self.0.as_ptr(), std::ptr::null_mut(), 0);
        }
    }
}

fn decode_embedded_resources(
    resources: &[EmbeddedResource],
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<DecodedResource>, RenderError> {
    if resources.len() > MAX_IMAGE_RESOURCES {
        return Err(RenderError::LimitExceeded("image resource count"));
    }
    let total_bytes = resources.iter().try_fold(0usize, |total, resource| {
        total
            .checked_add(resource.data.len())
            .ok_or(RenderError::LimitExceeded("image resource bytes"))
    })?;
    if total_bytes > MAX_TOTAL_RESOURCE_BYTES {
        return Err(RenderError::LimitExceeded("image resource bytes"));
    }

    let mut decoded = Vec::with_capacity(resources.len());
    let mut content_ids = HashSet::with_capacity(resources.len());
    let mut total_pixels = 0u64;
    for resource in resources {
        resource_checkpoint(cancellation, deadline)?;
        if resource.content_id.is_empty()
            || resource.data.is_empty()
            || resource.data.len() > MAX_CID_RESOURCE_BYTES
            || !content_ids.insert(resource.content_id.clone())
        {
            continue;
        }
        let mime = normalize_image_content_type(Some(&resource.mime_type));
        if !SAFE_CID_IMAGE_TYPES.contains(&mime.as_str()) {
            continue;
        }
        let decoded_image = if mime == "image/svg+xml" {
            decode_svg_resource(&resource.data)
        } else {
            decode_raster_resource(&resource.data)
        };
        let Some((rgba, width, height)) = decoded_image else {
            continue;
        };
        let pixels = checked_image_pixels(width, height)?;
        total_pixels = total_pixels
            .checked_add(pixels)
            .ok_or(RenderError::LimitExceeded("document image pixels"))?;
        if total_pixels > MAX_DOCUMENT_IMAGE_PIXELS {
            return Err(RenderError::LimitExceeded("document image pixels"));
        }
        let stride = width
            .checked_mul(4)
            .ok_or(RenderError::LimitExceeded("image stride"))?;
        let expected_len = usize::try_from(pixels)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or(RenderError::LimitExceeded("decoded image bytes"))?;
        if rgba.len() != expected_len {
            return Err(RenderError::Raster(
                "decoded image has an invalid RGBA length".to_owned(),
            ));
        }
        decoded.push(DecodedResource {
            content_id: resource.content_id.clone(),
            rgba: rgba.into_boxed_slice(),
            width,
            height,
            stride,
        });
    }
    resource_checkpoint(cancellation, deadline)?;
    Ok(decoded)
}

fn decode_raster_resource(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let mut reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODER_ALLOCATION_BYTES);
    reader.limits(limits);
    let decoder = reader.into_decoder().ok()?;
    let (width, height) = decoder.dimensions();
    checked_image_pixels(width, height).ok()?;
    let image = DynamicImage::from_decoder(decoder).ok()?;
    let rgba = image.into_rgba8();
    Some((rgba.into_raw(), width, height))
}

fn decode_svg_resource(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let options = resvg::usvg::Options {
        resources_dir: None,
        image_href_resolver: resvg::usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..Default::default()
    };
    let tree = resvg::usvg::Tree::from_data(data, &options).ok()?;
    let size = tree.size();
    let width = size.width().ceil() as u32;
    let height = size.height().ceil() as u32;
    checked_image_pixels(width, height).ok()?;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::identity(),
        &mut pixmap.as_mut(),
    );
    let mut rgba = pixmap.take();
    unpremultiply_rgba(&mut rgba);
    Some((rgba, width, height))
}

fn checked_image_pixels(width: u32, height: u32) -> Result<u64, RenderError> {
    if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return Err(RenderError::LimitExceeded("image dimensions"));
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels > MAX_IMAGE_PIXELS {
        return Err(RenderError::LimitExceeded("image pixels"));
    }
    Ok(pixels)
}

fn unpremultiply_rgba(rgba: &mut [u8]) {
    for pixel in rgba.chunks_exact_mut(4) {
        let alpha = u32::from(pixel[3]);
        if alpha == 0 {
            pixel[..3].fill(0);
            continue;
        }
        for channel in &mut pixel[..3] {
            let value = (u32::from(*channel) * 255 + alpha / 2) / alpha;
            *channel = value.min(255) as u8;
        }
    }
}

fn resource_checkpoint(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(), RenderError> {
    if cancellation.is_cancelled() {
        return Err(RenderError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(RenderError::DeadlineExceeded);
    }
    Ok(())
}

pub fn normalize_image_content_type(value: Option<&str>) -> String {
    let value = value.unwrap_or_default();
    value
        .split_once(';')
        .map_or(value, |(mime, _)| mime)
        .trim()
        .to_ascii_lowercase()
}

pub fn is_safe_cid_image_type(value: Option<&str>) -> bool {
    let mime = normalize_image_content_type(value);
    SAFE_CID_IMAGE_TYPES.contains(&mime.as_str())
}

pub fn is_safe_external_image_type(value: Option<&str>) -> bool {
    let mime = normalize_image_content_type(value);
    SAFE_EXTERNAL_IMAGE_TYPES.contains(&mime.as_str())
}

/// Metadata used to reproduce the frozen Java attachment-card HTML.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentDescriptor<'a> {
    pub filename: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub size: u64,
    pub inline: bool,
}

/// An email body after the Java-compatible content-selection and attachment
/// composition steps, but before HTML resource fetching or rasterization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedDocument {
    PlainText(String),
    Html(String),
}

impl PreparedDocument {
    pub fn compose(
        raw_html: Option<&str>,
        plain_text: Option<&str>,
        attachments: &[AttachmentDescriptor<'_>],
    ) -> Result<Self, RenderError> {
        if !attachments.is_empty() {
            let html = append_attachment_cards(raw_html, plain_text, attachments)?;
            return Ok(Self::Html(html));
        }

        if let Some(html) = raw_html.filter(|value| !java_is_blank(value)) {
            if html.len() > MAX_PREPARED_HTML_BYTES {
                return Err(RenderError::LimitExceeded("prepared HTML bytes"));
            }
            return Ok(Self::Html(html.to_owned()));
        }

        Ok(Self::PlainText(plain_text.unwrap_or_default().to_owned()))
    }
}

/// Applies the deliberately narrow transformations used by the frozen Java
/// HTML renderer. Resource discovery happens before this step.
pub fn preprocess_html(html: &str) -> String {
    use regex::Regex;

    struct Patterns {
        script: Regex,
        double_quoted_handler: Regex,
        single_quoted_handler: Regex,
        javascript_url: Regex,
    }

    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| Patterns {
        script: Regex::new(r"(?is)<script[^>]*>.*?</script>")
            .expect("the script-removal pattern is valid"),
        double_quoted_handler: Regex::new(
            r#"(?i)(?-u:\s)+on(?-u:\w)+(?-u:\s)*=(?-u:\s)*\"[^\"]*\""#,
        )
        .expect("the double-quoted event-handler pattern is valid"),
        single_quoted_handler: Regex::new(r#"(?i)(?-u:\s)+on(?-u:\w)+(?-u:\s)*=(?-u:\s)*'[^']*'"#)
            .expect("the single-quoted event-handler pattern is valid"),
        javascript_url: Regex::new(
            r#"(?i)(href|src)(?-u:\s)*=(?-u:\s)*[\"']javascript:[^\"']*[\"']"#,
        )
        .expect("the javascript URL pattern is valid"),
    });

    let html = patterns.script.replace_all(html, "");
    let html = patterns.double_quoted_handler.replace_all(&html, "");
    let html = patterns.single_quoted_handler.replace_all(&html, "");
    patterns
        .javascript_url
        .replace_all(&html, "${1}=\"\"")
        .into_owned()
}

fn append_attachment_cards(
    raw_html: Option<&str>,
    plain_text: Option<&str>,
    attachments: &[AttachmentDescriptor<'_>],
) -> Result<String, RenderError> {
    let initial_html = match raw_html.filter(|value| !java_is_blank(value)) {
        Some(value) => {
            ensure_prepared_html_bound(value.len())?;
            value.to_owned()
        }
        None => match plain_text.filter(|value| !java_is_blank(value)) {
            Some(value) => {
                let mut html = String::new();
                push_bounded(
                    &mut html,
                    "<html><body><pre style=\"font-family:monospace;white-space:pre-wrap;\">",
                )?;
                push_escaped_bounded(&mut html, value)?;
                push_bounded(&mut html, "</pre></body></html>")?;
                html
            }
            None => "<html><body></body></html>".to_owned(),
        },
    };
    ensure_prepared_html_bound(initial_html.len())?;

    let mut cards = String::new();
    push_bounded(
        &mut cards,
        "<div style=\"margin-top:20px;padding:10px;border:1px solid #999;border-radius:5px;background:#f5f5f5;\">",
    )?;
    push_bounded(
        &mut cards,
        "<div style=\"font-weight:bold;margin-bottom:8px;color:#333;\">Attachments (",
    )?;
    push_bounded(&mut cards, &attachments.len().to_string())?;
    push_bounded(&mut cards, ")</div>")?;

    for attachment in attachments {
        push_bounded(
            &mut cards,
            "<div style=\"padding:4px 8px;margin:3px 0;background:white;border:1px solid #ddd;border-radius:3px;font-size:13px;\">",
        )?;
        push_bounded(&mut cards, "<span style=\"font-weight:bold;\">")?;
        let filename = attachment.filename.unwrap_or("(unnamed)");
        push_escaped_bounded(&mut cards, filename)?;
        push_bounded(
            &mut cards,
            "</span> <span style=\"color:#888;font-size:11px;\">(",
        )?;
        let content_type = attachment.content_type.unwrap_or("unknown");
        push_escaped_bounded(&mut cards, content_type)?;
        if attachment.size > 0 {
            push_bounded(&mut cards, ", ")?;
            push_bounded(&mut cards, &format_attachment_size(attachment.size))?;
        }
        if attachment.inline {
            push_bounded(&mut cards, ", inline")?;
        }
        push_bounded(&mut cards, ")</span></div>")?;
    }
    push_bounded(&mut cards, "</div>")?;

    let output = if initial_html.contains("</body>") {
        replace_with_cards_bounded(&initial_html, "</body>", &cards)?
    } else if initial_html.contains("</html>") {
        replace_with_cards_bounded(&initial_html, "</html>", &cards)?
    } else {
        let capacity = initial_html
            .len()
            .checked_add(cards.len())
            .ok_or(RenderError::LimitExceeded("prepared HTML bytes"))?;
        ensure_prepared_html_bound(capacity)?;
        let mut output = String::with_capacity(capacity);
        output.push_str(&initial_html);
        output.push_str(&cards);
        output
    };
    ensure_prepared_html_bound(output.len())?;
    Ok(output)
}

fn push_bounded(output: &mut String, value: &str) -> Result<(), RenderError> {
    let new_len = output
        .len()
        .checked_add(value.len())
        .ok_or(RenderError::LimitExceeded("prepared HTML bytes"))?;
    ensure_prepared_html_bound(new_len)?;
    output.push_str(value);
    Ok(())
}

fn ensure_prepared_html_bound(length: usize) -> Result<(), RenderError> {
    if length > MAX_PREPARED_HTML_BYTES {
        return Err(RenderError::LimitExceeded("prepared HTML bytes"));
    }
    Ok(())
}

fn push_escaped_bounded(output: &mut String, value: &str) -> Result<(), RenderError> {
    let mut last = 0;
    for (offset, character) in value.char_indices() {
        let replacement = match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            _ => continue,
        };
        push_bounded(output, &value[last..offset])?;
        push_bounded(output, replacement)?;
        last = offset + character.len_utf8();
    }
    push_bounded(output, &value[last..])
}

fn replace_with_cards_bounded(
    html: &str,
    marker: &str,
    cards: &str,
) -> Result<String, RenderError> {
    let count = html.match_indices(marker).count();
    let added = cards
        .len()
        .checked_mul(count)
        .ok_or(RenderError::LimitExceeded("prepared HTML bytes"))?;
    let output_len = html
        .len()
        .checked_add(added)
        .ok_or(RenderError::LimitExceeded("prepared HTML bytes"))?;
    ensure_prepared_html_bound(output_len)?;

    let replacement_len = cards
        .len()
        .checked_add(marker.len())
        .ok_or(RenderError::LimitExceeded("prepared HTML bytes"))?;
    let mut replacement = String::with_capacity(replacement_len);
    replacement.push_str(cards);
    replacement.push_str(marker);
    Ok(html.replace(marker, &replacement))
}

fn format_attachment_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn java_is_blank(value: &str) -> bool {
    value.chars().all(java_is_whitespace)
}

fn java_is_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000D}'
            | '\u{001C}'..='\u{0020}'
            | '\u{1680}'
            | '\u{2000}'..='\u{2006}'
            | '\u{2008}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Hard resource limits applied before allocation and throughout rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderLimits {
    pub max_input_bytes: usize,
    pub max_document_height: u32,
    pub max_pages: usize,
    pub max_output_bytes: usize,
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_document_height: ABSOLUTE_MAX_DOCUMENT_HEIGHT,
            max_pages: 64,
            max_output_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Plain-text styling matching the frozen Java renderer's `<pre>` wrapper.
#[derive(Clone, Debug, PartialEq)]
pub struct PlainTextStyle {
    pub font_path: PathBuf,
    pub font_size_px: f64,
    pub margin_px: u16,
    pub foreground_rgb: [u8; 3],
    pub background_rgb: [u8; 3],
}

impl Default for PlainTextStyle {
    fn default() -> Self {
        Self {
            font_path: PathBuf::from(DEFAULT_MONOSPACE_FONT),
            font_size_px: 14.0,
            margin_px: 8,
            foreground_rgb: [0, 0, 0],
            background_rgb: [255, 255, 255],
        }
    }
}

/// A synchronous render request intended for a caller-owned bounded CPU pool.
#[derive(Debug)]
pub enum RenderDocument<'a> {
    PlainText(&'a str),
    Html {
        html: &'a str,
        resources: &'a [EmbeddedResource],
    },
}

/// A synchronous render request intended for a caller-owned bounded CPU pool.
#[derive(Debug)]
pub struct RenderRequest<'a> {
    pub document: RenderDocument<'a>,
    pub viewport_maps_x: u8,
    pub max_page_maps_y: u8,
    pub style: PlainTextStyle,
    pub limits: RenderLimits,
    pub cancellation: &'a CancellationToken,
    pub deadline: Instant,
}

impl<'a> RenderRequest<'a> {
    pub fn plain_text(
        plain_text: &'a str,
        viewport_maps_x: u8,
        max_page_maps_y: u8,
        cancellation: &'a CancellationToken,
        deadline: Instant,
    ) -> Self {
        Self {
            document: RenderDocument::PlainText(plain_text),
            viewport_maps_x,
            max_page_maps_y,
            style: PlainTextStyle::default(),
            limits: RenderLimits::default(),
            cancellation,
            deadline,
        }
    }

    pub fn html(
        html: &'a str,
        resources: &'a [EmbeddedResource],
        viewport_maps_x: u8,
        max_page_maps_y: u8,
        cancellation: &'a CancellationToken,
        deadline: Instant,
    ) -> Self {
        let limits = RenderLimits {
            max_input_bytes: MAX_PREPARED_HTML_BYTES,
            ..Default::default()
        };
        Self {
            document: RenderDocument::Html { html, resources },
            viewport_maps_x,
            max_page_maps_y,
            style: PlainTextStyle::default(),
            limits,
            cancellation,
            deadline,
        }
    }
}

/// The implementation selected for palette matching.
///
/// AVX2 and AVX-512 host support is reported separately. They are deliberately
/// not advertised here until distinct, tested kernels exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RenderBackend {
    Scalar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostSimdCapabilities {
    pub avx2: bool,
    pub avx512f: bool,
    pub fma: bool,
}

pub fn host_simd_capabilities() -> HostSimdCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        HostSimdCapabilities {
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            avx512f: std::arch::is_x86_feature_detected!("avx512f"),
            fma: std::arch::is_x86_feature_detected!("fma"),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        HostSimdCapabilities {
            avx2: false,
            avx512f: false,
            fma: false,
        }
    }
}

#[derive(Debug)]
pub struct RenderResult {
    pages: Vec<Page>,
    content_width: u32,
    content_height: u32,
    truncated: bool,
    backend: RenderBackend,
}

impl RenderResult {
    pub fn pages(&self) -> &[Page] {
        &self.pages
    }

    pub fn content_width(&self) -> u32 {
        self.content_width
    }

    pub fn content_height(&self) -> u32 {
        self.content_height
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn backend(&self) -> RenderBackend {
        self.backend
    }
}

#[derive(Debug)]
pub struct Page {
    maps_x: u8,
    maps_y: u8,
    pixel_width: usize,
    pixel_height: usize,
    map_colors: Box<[u8]>,
    rgb: Box<[u8]>,
}

impl Page {
    pub fn maps_x(&self) -> u8 {
        self.maps_x
    }

    pub fn maps_y(&self) -> u8 {
        self.maps_y
    }

    pub fn pixel_width(&self) -> usize {
        self.pixel_width
    }

    pub fn pixel_height(&self) -> usize {
        self.pixel_height
    }

    pub fn map_colors(&self) -> &[u8] {
        &self.map_colors
    }

    pub fn rgb(&self) -> &[u8] {
        &self.rgb
    }

    pub fn tile_count(&self) -> usize {
        usize::from(self.maps_x) * usize::from(self.maps_y)
    }

    /// Returns tile `index` in row-major map-wall order.
    pub fn tile(&self, index: usize) -> Option<MapTile<'_>> {
        if index >= self.tile_count() {
            return None;
        }
        let maps_x = usize::from(self.maps_x);
        Some(MapTile {
            page: self,
            col: index % maps_x,
            row: index / maps_x,
        })
    }

    pub fn tile_at(&self, col: usize, row: usize) -> Option<MapTile<'_>> {
        if col >= usize::from(self.maps_x) || row >= usize::from(self.maps_y) {
            return None;
        }
        Some(MapTile {
            page: self,
            col,
            row,
        })
    }

    pub fn tiles(&self) -> Tiles<'_> {
        Tiles {
            page: self,
            next: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MapTile<'a> {
    page: &'a Page,
    col: usize,
    row: usize,
}

impl MapTile<'_> {
    pub fn col(&self) -> usize {
        self.col
    }

    pub fn row_index(&self) -> usize {
        self.row
    }

    pub fn row(&self, y: usize) -> Option<&[u8]> {
        if y >= MAP_EDGE {
            return None;
        }
        let start = (self.row * MAP_EDGE + y) * self.page.pixel_width + self.col * MAP_EDGE;
        Some(&self.page.map_colors[start..start + MAP_EDGE])
    }

    pub fn copy_into(&self, output: &mut [u8; MAP_PIXELS]) {
        for y in 0..MAP_EDGE {
            let destination = &mut output[y * MAP_EDGE..(y + 1) * MAP_EDGE];
            destination.copy_from_slice(self.row(y).expect("tile row is in bounds"));
        }
    }
}

#[derive(Debug)]
pub struct Tiles<'a> {
    page: &'a Page,
    next: usize,
}

impl<'a> Iterator for Tiles<'a> {
    type Item = MapTile<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let tile = self.page.tile(self.next)?;
        self.next += 1;
        Some(tile)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.page.tile_count().saturating_sub(self.next);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Tiles<'_> {}

#[derive(Debug)]
pub enum RenderError {
    InvalidRequest(&'static str),
    LimitExceeded(&'static str),
    Cancelled,
    DeadlineExceeded,
    Font(String),
    Raster(String),
    NativeInvalidArgument(String),
    NativeLimitExceeded(String),
    NativeOutOfMemory(String),
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(formatter, "invalid render request: {message}"),
            Self::LimitExceeded(message) => write!(formatter, "render limit exceeded: {message}"),
            Self::Cancelled => formatter.write_str("mail rendering cancelled"),
            Self::DeadlineExceeded => formatter.write_str("mail rendering deadline exceeded"),
            Self::Font(message) => write!(formatter, "font error: {message}"),
            Self::Raster(message) => write!(formatter, "rasterization error: {message}"),
            Self::NativeInvalidArgument(message) => {
                write!(formatter, "native HTML argument error: {message}")
            }
            Self::NativeLimitExceeded(message) => {
                write!(formatter, "native HTML limit exceeded: {message}")
            }
            Self::NativeOutOfMemory(message) => {
                write!(formatter, "native HTML allocation failed: {message}")
            }
        }
    }
}

impl std::error::Error for RenderError {}

/// Renders one explicitly selected document type synchronously. Callers must
/// execute this in their bounded CPU pool rather than on a Tokio worker thread.
pub fn render(request: &RenderRequest<'_>) -> Result<RenderResult, RenderError> {
    validate_request(request)?;
    match &request.document {
        RenderDocument::PlainText(_) => render_plain_text(request),
        RenderDocument::Html { html, resources } => render_html(request, html, resources),
    }
}

/// Converts one bounded row-major RGB24 frame to Minecraft map protocol
/// indices. The input slice is borrowed for the duration of conversion and is
/// never copied; only the one-byte-per-pixel output and two error rows are
/// allocated. `max_output_bytes` applies to the returned map-index buffer.
pub(crate) fn rgb24_to_map_colors(
    rgb: &[u8],
    width: usize,
    height: usize,
    max_output_bytes: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, RenderError> {
    if width == 0 || height == 0 {
        return Err(RenderError::InvalidRequest("RGB24 frame dimensions"));
    }
    let pixels = width
        .checked_mul(height)
        .ok_or(RenderError::LimitExceeded("RGB24 frame pixels"))?;
    if pixels > ABSOLUTE_MAX_FRAME_PIXELS {
        return Err(RenderError::LimitExceeded("RGB24 frame pixels"));
    }
    let expected_bytes = pixels
        .checked_mul(3)
        .ok_or(RenderError::LimitExceeded("RGB24 input bytes"))?;
    if rgb.len() != expected_bytes {
        return Err(RenderError::InvalidRequest("RGB24 input length"));
    }
    if max_output_bytes == 0 || max_output_bytes > ABSOLUTE_MAX_OUTPUT_BYTES {
        return Err(RenderError::InvalidRequest("RGB24 output budget"));
    }
    if pixels > max_output_bytes {
        return Err(RenderError::LimitExceeded("RGB24 output bytes"));
    }
    checkpoint_at(cancellation, deadline)?;
    floyd_steinberg(rgb, width, height, cancellation, deadline)
}

fn render_plain_text(request: &RenderRequest<'_>) -> Result<RenderResult, RenderError> {
    checkpoint(request)?;

    let viewport_width = usize::from(request.viewport_maps_x) * MAP_EDGE;
    let page_height = usize::from(request.max_page_maps_y) * MAP_EDGE;
    let margin = usize::from(request.style.margin_px);
    let horizontal_inset = margin
        .checked_mul(2)
        .ok_or(RenderError::InvalidRequest("text margin overflows"))?;
    let text_width =
        viewport_width
            .checked_sub(horizontal_inset * 2)
            .ok_or(RenderError::InvalidRequest(
                "text margin leaves no horizontal viewport",
            ))?;

    let font_path = resolve_font_path(&request.style.font_path)?;
    let freetype =
        cairo::freetype::Library::init().map_err(|error| RenderError::Font(error.to_string()))?;
    let face = freetype
        .new_face(font_path, 0)
        .map_err(|error| RenderError::Font(error.to_string()))?;
    let font_face =
        FontFace::create_from_ft(&face).map_err(|error| RenderError::Font(error.to_string()))?;

    let measuring_surface = ImageSurface::create(Format::ARgb32, 1, 1)
        .map_err(|error| RenderError::Raster(error.to_string()))?;
    let measuring_context =
        Context::new(&measuring_surface).map_err(|error| RenderError::Raster(error.to_string()))?;
    configure_font(&measuring_context, &font_face, request.style.font_size_px);
    let font_extents = measuring_context
        .font_extents()
        .map_err(|error| RenderError::Raster(error.to_string()))?;
    let line_height = round_positive(font_extents.height());
    let ascent = round_positive(font_extents.ascent());

    let layout = layout_plain_text(request, &measuring_context, text_width, line_height, margin)?;
    checkpoint(request)?;

    let page_count = usize::try_from(layout.content_height)
        .expect("document height fits usize")
        .div_ceil(page_height);
    if page_count > request.limits.max_pages {
        return Err(RenderError::LimitExceeded("page count"));
    }

    let output_bytes =
        output_size_bytes(viewport_width, page_height, layout.content_height as usize)?;
    if output_bytes > request.limits.max_output_bytes {
        return Err(RenderError::LimitExceeded("output bytes"));
    }

    let mut pages = Vec::with_capacity(page_count);
    for page_index in 0..page_count {
        checkpoint(request)?;
        let y_start = page_index * page_height;
        let raw_height = (layout.content_height as usize - y_start).min(page_height);
        let pixel_height = raw_height.max(1).div_ceil(MAP_EDGE) * MAP_EDGE;
        pages.push(render_page(
            request,
            &font_face,
            &layout.lines,
            viewport_width,
            pixel_height,
            y_start,
            line_height,
            ascent,
            horizontal_inset,
        )?);
    }

    Ok(RenderResult {
        pages,
        content_width: viewport_width as u32,
        content_height: layout.content_height,
        truncated: layout.truncated,
        backend: RenderBackend::Scalar,
    })
}

fn render_html(
    request: &RenderRequest<'_>,
    html: &str,
    resources: &[EmbeddedResource],
) -> Result<RenderResult, RenderError> {
    checkpoint(request)?;
    let decoded = decode_embedded_resources(resources, request.cancellation, request.deadline)?;
    let viewport_width = usize::from(request.viewport_maps_x) * MAP_EDGE;
    let page_height = usize::from(request.max_page_maps_y) * MAP_EDGE;
    let mut cancellation_state = NativeCancellation {
        cancellation: request.cancellation,
        deadline: request.deadline,
    };
    let native_resources = decoded
        .iter()
        .map(|resource| NativeHtmlResource {
            cid: resource.content_id.as_ptr(),
            cid_len: resource.content_id.len(),
            rgba: resource.rgba.as_ptr(),
            rgba_len: resource.rgba.len(),
            width: resource.width,
            height: resource.height,
            stride: resource.stride,
            reserved: 0,
        })
        .collect::<Vec<_>>();
    let background = request.style.background_rgb;
    let config = NativeHtmlConfig {
        struct_size: u32::try_from(std::mem::size_of::<NativeHtmlConfig>())
            .expect("native HTML config size fits u32"),
        viewport_width: u32::try_from(viewport_width)
            .map_err(|_| RenderError::LimitExceeded("page width"))?,
        max_document_height: request.limits.max_document_height,
        base_font_size: request.style.font_size_px as f32,
        background_rgb: (u32::from(background[0]) << 16)
            | (u32::from(background[1]) << 8)
            | u32::from(background[2]),
        reserved: [0; 3],
        cancel: Some(native_html_cancel),
        cancel_userdata: (&mut cancellation_state as *mut NativeCancellation<'_>).cast(),
    };

    // SAFETY: the symbol is linked from the pinned native source and takes no
    // pointers. A mismatch is rejected before any ABI structure is passed.
    if unsafe { lmyzmail_mail_html_abi_version() } != NATIVE_ABI_VERSION {
        return Err(RenderError::Raster(
            "native HTML ABI version mismatch".to_owned(),
        ));
    }

    let mut context = std::ptr::null_mut();
    let mut error = [0u8; NATIVE_ERROR_CAPACITY];
    // SAFETY: every slice pointer remains live and immutable until `handle` is
    // destroyed. The C++ boundary validates lengths, catches exceptions, and
    // initializes `context` only on success.
    let status = unsafe {
        lmyzmail_mail_html_create(
            &config,
            html.as_ptr(),
            html.len(),
            native_resources.as_ptr(),
            native_resources.len(),
            &mut context,
            error.as_mut_ptr().cast(),
            error.len(),
        )
    };
    map_native_status(status, &error, request)?;
    let handle = NonNull::new(context)
        .map(NativeHtmlHandle)
        .ok_or_else(|| RenderError::Raster("native HTML context is null".to_owned()))?;

    let mut content_width = 0u32;
    let mut content_height = 0u32;
    error.fill(0);
    // SAFETY: `handle` owns a live single-threaded context, and the output
    // pointers refer to initialized local integers.
    let status = unsafe {
        lmyzmail_mail_html_query_size(
            handle.0.as_ptr(),
            &mut content_width,
            &mut content_height,
            error.as_mut_ptr().cast(),
            error.len(),
        )
    };
    map_native_status(status, &error, request)?;
    if content_width == 0
        || content_width > config.viewport_width
        || content_height == 0
        || content_height > request.limits.max_document_height
    {
        return Err(RenderError::Raster(
            "native HTML renderer returned invalid dimensions".to_owned(),
        ));
    }

    let content_height_usize = usize::try_from(content_height)
        .map_err(|_| RenderError::LimitExceeded("document height"))?;
    let page_count = content_height_usize.div_ceil(page_height);
    if page_count > request.limits.max_pages {
        return Err(RenderError::LimitExceeded("page count"));
    }
    let output_bytes = output_size_bytes(viewport_width, page_height, content_height_usize)?;
    if output_bytes > request.limits.max_output_bytes {
        return Err(RenderError::LimitExceeded("output bytes"));
    }

    let mut pages = Vec::with_capacity(page_count);
    for page_index in 0..page_count {
        checkpoint(request)?;
        let y_start = page_index
            .checked_mul(page_height)
            .ok_or(RenderError::LimitExceeded("page offset"))?;
        let raw_height = (content_height_usize - y_start).min(page_height);
        let pixel_height = raw_height.max(1).div_ceil(MAP_EDGE) * MAP_EDGE;
        let rgb_len = viewport_width
            .checked_mul(pixel_height)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or(RenderError::LimitExceeded("page RGB bytes"))?;
        let mut rgb = vec![0u8; rgb_len];
        let stride = viewport_width
            .checked_mul(3)
            .ok_or(RenderError::LimitExceeded("page RGB stride"))?;
        error.fill(0);
        // SAFETY: `handle` remains live and uniquely used on this thread. The
        // RGB allocation covers exactly `stride * pixel_height` bytes.
        let status = unsafe {
            lmyzmail_mail_html_render_range(
                handle.0.as_ptr(),
                u32::try_from(y_start).map_err(|_| RenderError::LimitExceeded("page offset"))?,
                config.viewport_width,
                u32::try_from(pixel_height)
                    .map_err(|_| RenderError::LimitExceeded("page height"))?,
                rgb.as_mut_ptr(),
                rgb.len(),
                stride,
                error.as_mut_ptr().cast(),
                error.len(),
            )
        };
        map_native_status(status, &error, request)?;
        let map_colors = rgb24_to_map_colors(
            &rgb,
            viewport_width,
            pixel_height,
            request.limits.max_output_bytes,
            request.cancellation,
            request.deadline,
        )?;
        pages.push(Page {
            maps_x: request.viewport_maps_x,
            maps_y: u8::try_from(pixel_height / MAP_EDGE)
                .expect("validated page height fits map count"),
            pixel_width: viewport_width,
            pixel_height,
            map_colors: map_colors.into_boxed_slice(),
            rgb: rgb.into_boxed_slice(),
        });
    }
    drop(handle);

    Ok(RenderResult {
        pages,
        content_width,
        content_height,
        truncated: false,
        backend: RenderBackend::Scalar,
    })
}

fn map_native_status(
    status: i32,
    error: &[u8],
    request: &RenderRequest<'_>,
) -> Result<(), RenderError> {
    if status == NATIVE_OK {
        return Ok(());
    }
    let message = native_error_message(error);
    Err(match status {
        NATIVE_INVALID_ARGUMENT => RenderError::NativeInvalidArgument(message),
        NATIVE_LIMIT_EXCEEDED => RenderError::NativeLimitExceeded(message),
        NATIVE_CANCELLED => match checkpoint(request) {
            Err(error @ (RenderError::Cancelled | RenderError::DeadlineExceeded)) => error,
            _ => RenderError::Cancelled,
        },
        NATIVE_RENDER_ERROR => RenderError::Raster(message),
        NATIVE_OUT_OF_MEMORY => RenderError::NativeOutOfMemory(message),
        _ => RenderError::Raster(format!(
            "native HTML renderer returned unknown status {status}: {message}"
        )),
    })
}

fn native_error_message(error: &[u8]) -> String {
    let length = error
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(error.len());
    let value = String::from_utf8_lossy(&error[..length]).trim().to_owned();
    if value.is_empty() {
        "no native diagnostic was provided".to_owned()
    } else {
        value
    }
}

fn validate_request(request: &RenderRequest<'_>) -> Result<(), RenderError> {
    if !(MIN_MAPS_X..=MAX_MAPS_X).contains(&request.viewport_maps_x) {
        return Err(RenderError::InvalidRequest(
            "viewport_maps_x must be in 2..=24",
        ));
    }
    if !(MIN_PAGE_MAPS_Y..=MAX_PAGE_MAPS_Y).contains(&request.max_page_maps_y) {
        return Err(RenderError::InvalidRequest(
            "max_page_maps_y must be in 2..=20",
        ));
    }
    let input = match &request.document {
        RenderDocument::PlainText(value) => *value,
        RenderDocument::Html { html, .. } => *html,
    };
    if input.len() > request.limits.max_input_bytes {
        return Err(RenderError::LimitExceeded("input bytes"));
    }
    if input.contains('\0') {
        return Err(RenderError::InvalidRequest("input contains a NUL byte"));
    }
    if request.limits.max_input_bytes == 0
        || request.limits.max_input_bytes > ABSOLUTE_MAX_INPUT_BYTES
    {
        return Err(RenderError::InvalidRequest(
            "max_input_bytes is outside hard bounds",
        ));
    }
    if request.limits.max_document_height == 0
        || request.limits.max_document_height > ABSOLUTE_MAX_DOCUMENT_HEIGHT
    {
        return Err(RenderError::InvalidRequest(
            "max_document_height is outside hard bounds",
        ));
    }
    if request.limits.max_pages == 0 || request.limits.max_pages > ABSOLUTE_MAX_PAGES {
        return Err(RenderError::InvalidRequest(
            "max_pages is outside hard bounds",
        ));
    }
    if request.limits.max_output_bytes == 0
        || request.limits.max_output_bytes > ABSOLUTE_MAX_OUTPUT_BYTES
    {
        return Err(RenderError::InvalidRequest(
            "max_output_bytes is outside hard bounds",
        ));
    }
    if !request.style.font_size_px.is_finite()
        || !(6.0..=72.0).contains(&request.style.font_size_px)
    {
        return Err(RenderError::InvalidRequest(
            "font_size_px must be finite and in 6..=72",
        ));
    }
    Ok(())
}

fn resolve_font_path(requested: &Path) -> Result<&Path, RenderError> {
    if requested.is_file() {
        return Ok(requested);
    }
    if requested == Path::new(DEFAULT_MONOSPACE_FONT) {
        let fallback = Path::new(FALLBACK_MONOSPACE_FONT);
        if fallback.is_file() {
            return Ok(fallback);
        }
    }
    Err(RenderError::Font(format!(
        "font not found: {}",
        requested.display()
    )))
}

fn configure_font(context: &Context, font_face: &FontFace, size: f64) {
    context.set_font_face(font_face);
    context.set_font_size(size);
}

fn round_positive(value: f64) -> usize {
    (value + 0.5).max(1.0) as usize
}

struct TextLayout {
    lines: Vec<String>,
    content_height: u32,
    truncated: bool,
    #[cfg(test)]
    expanded_characters: usize,
}

fn layout_plain_text(
    request: &RenderRequest<'_>,
    context: &Context,
    text_width: usize,
    line_height: usize,
    vertical_margin: usize,
) -> Result<TextLayout, RenderError> {
    let RenderDocument::PlainText(plain_text) = &request.document else {
        return Err(RenderError::InvalidRequest(
            "plain-text layout received HTML",
        ));
    };
    let source = if plain_text.trim().is_empty() {
        "(empty email)"
    } else {
        plain_text
    };
    let max_height = request.limits.max_document_height as usize;
    let max_stored_lines = max_height
        .saturating_sub(vertical_margin)
        .div_ceil(line_height)
        .max(1);
    let mut lines = Vec::with_capacity(max_stored_lines.min(256));
    let mut truncated = false;
    let mut expanded_character_count = 0usize;

    let mut logical_lines = source.split('\n').peekable();
    while let Some(logical_line) = logical_lines.next() {
        checkpoint(request)?;
        let logical_line = logical_line.strip_suffix('\r').unwrap_or(logical_line);
        if lines.len() >= max_stored_lines {
            truncated = true;
            break;
        }
        let (line_truncated, expanded_characters) = wrap_pre_line(
            request,
            context,
            logical_line,
            text_width as f64,
            &mut lines,
            max_stored_lines,
        )?;
        expanded_character_count = expanded_character_count.saturating_add(expanded_characters);
        if line_truncated {
            truncated = true;
            break;
        }
        if lines.len() >= max_stored_lines && logical_lines.peek().is_some() {
            truncated = true;
            break;
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    let natural_height = vertical_margin
        .checked_mul(2)
        .and_then(|margins| lines.len().checked_mul(line_height)?.checked_add(margins))
        .ok_or(RenderError::LimitExceeded("document height"))?;
    if natural_height > max_height {
        truncated = true;
    }
    let content_height = natural_height.min(max_height).max(1) as u32;
    debug_assert!(expanded_character_count <= ABSOLUTE_MAX_INPUT_BYTES.saturating_mul(8));
    Ok(TextLayout {
        lines,
        content_height,
        truncated,
        #[cfg(test)]
        expanded_characters: expanded_character_count,
    })
}

struct ExpandedTabs<'a> {
    characters: std::str::Chars<'a>,
    pending_spaces: u8,
    column: usize,
}

impl<'a> ExpandedTabs<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            characters: value.chars(),
            pending_spaces: 0,
            column: 0,
        }
    }
}

impl Iterator for ExpandedTabs<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_spaces > 0 {
            self.pending_spaces -= 1;
            self.column += 1;
            return Some(' ');
        }

        let character = self.characters.next()?;
        if character == '\t' {
            self.pending_spaces = (8 - self.column % 8) as u8;
            return self.next();
        }
        self.column += 1;
        Some(character)
    }
}

fn wrap_pre_line(
    request: &RenderRequest<'_>,
    context: &Context,
    line: &str,
    max_width: f64,
    output: &mut Vec<String>,
    max_stored_lines: usize,
) -> Result<(bool, usize), RenderError> {
    if line.is_empty() {
        if output.len() >= max_stored_lines {
            return Ok((true, 0));
        }
        output.push(String::new());
        return Ok((false, 0));
    }

    let mut characters = ExpandedTabs::new(line).peekable();
    let mut expanded_character_count = 0usize;
    let mut current = String::new();
    let mut current_width = 0.0;
    let mut last_whitespace_end = None;
    let mut width_after_last_whitespace = 0.0;
    let mut width_cache = HashMap::new();

    for index in 0usize.. {
        let Some(character) = characters.next() else {
            break;
        };
        expanded_character_count += 1;
        if index % CHECKPOINT_PIXEL_INTERVAL == 0 {
            checkpoint(request)?;
        }
        let width = if let Some(width) = width_cache.get(&character) {
            *width
        } else {
            let mut encoded = [0u8; 4];
            let width = text_advance(context, character.encode_utf8(&mut encoded))?;
            if width_cache.len() < MAX_GLYPH_WIDTH_CACHE_ENTRIES {
                width_cache.insert(character, width);
            }
            width
        };

        loop {
            if current.is_empty() || current_width + width <= max_width {
                current.push(character);
                current_width += width;
                if character.is_whitespace() {
                    last_whitespace_end = Some(current.len());
                    width_after_last_whitespace = 0.0;
                } else if last_whitespace_end.is_some() {
                    width_after_last_whitespace += width;
                }
                break;
            }
            if character.is_whitespace() {
                current.push(character);
                output.push(std::mem::take(&mut current));
                if output.len() >= max_stored_lines {
                    return Ok((characters.peek().is_some(), expanded_character_count));
                }
                current_width = 0.0;
                last_whitespace_end = None;
                width_after_last_whitespace = 0.0;
                break;
            }
            if let Some(space_end) = last_whitespace_end {
                let remainder = current.split_off(space_end);
                output.push(std::mem::take(&mut current));
                if output.len() >= max_stored_lines {
                    return Ok((true, expanded_character_count));
                }
                current = remainder;
                current_width = width_after_last_whitespace;
                last_whitespace_end = None;
                width_after_last_whitespace = 0.0;
            } else {
                output.push(std::mem::take(&mut current));
                if output.len() >= max_stored_lines {
                    return Ok((true, expanded_character_count));
                }
                current_width = 0.0;
            }
        }
    }

    if !current.is_empty() {
        if output.len() >= max_stored_lines {
            return Ok((true, expanded_character_count));
        }
        output.push(current);
    }
    Ok((false, expanded_character_count))
}

fn text_runs(value: &str) -> impl Iterator<Item = (bool, &str)> {
    struct Runs<'a> {
        value: &'a str,
        offset: usize,
    }

    impl<'a> Iterator for Runs<'a> {
        type Item = (bool, &'a str);

        fn next(&mut self) -> Option<Self::Item> {
            let remaining = self.value.get(self.offset..)?;
            let first = remaining.chars().next()?;
            let is_space = first.is_whitespace();
            let mut length = first.len_utf8();
            for character in remaining[length..].chars() {
                if character.is_whitespace() != is_space
                    || length + character.len_utf8() > MAX_CAIRO_TEXT_CHUNK_BYTES
                {
                    break;
                }
                length += character.len_utf8();
            }
            let start = self.offset;
            self.offset += length;
            Some((is_space, &self.value[start..self.offset]))
        }
    }

    Runs { value, offset: 0 }
}

fn text_advance(context: &Context, value: &str) -> Result<f64, RenderError> {
    let extents = context
        .text_extents(value)
        .map_err(|error| RenderError::Raster(error.to_string()))?;
    Ok(extents.x_advance().max(0.0).floor())
}

#[allow(clippy::too_many_arguments)]
fn render_page(
    request: &RenderRequest<'_>,
    font_face: &FontFace,
    lines: &[String],
    pixel_width: usize,
    pixel_height: usize,
    y_start: usize,
    line_height: usize,
    ascent: usize,
    horizontal_inset: usize,
) -> Result<Page, RenderError> {
    let width_i32 =
        i32::try_from(pixel_width).map_err(|_| RenderError::LimitExceeded("page width"))?;
    let height_i32 =
        i32::try_from(pixel_height).map_err(|_| RenderError::LimitExceeded("page height"))?;
    let mut surface = ImageSurface::create(Format::ARgb32, width_i32, height_i32)
        .map_err(|error| RenderError::Raster(error.to_string()))?;
    let context = Context::new(&surface).map_err(|error| RenderError::Raster(error.to_string()))?;
    let background = request.style.background_rgb;
    context.set_source_rgb(
        f64::from(background[0]) / 255.0,
        f64::from(background[1]) / 255.0,
        f64::from(background[2]) / 255.0,
    );
    context
        .paint()
        .map_err(|error| RenderError::Raster(error.to_string()))?;
    configure_font(&context, font_face, request.style.font_size_px);
    let foreground = request.style.foreground_rgb;
    context.set_source_rgb(
        f64::from(foreground[0]) / 255.0,
        f64::from(foreground[1]) / 255.0,
        f64::from(foreground[2]) / 255.0,
    );

    let vertical_margin = usize::from(request.style.margin_px);
    let first_line = y_start
        .saturating_sub(vertical_margin + line_height)
        .div_ceil(line_height);
    let page_end = y_start + pixel_height;
    for (line_index, line) in lines.iter().enumerate().skip(first_line) {
        let top = vertical_margin + line_index * line_height;
        if top >= page_end {
            break;
        }
        checkpoint(request)?;
        draw_line(
            request,
            &context,
            line,
            horizontal_inset as f64,
            (top + ascent) as f64 - y_start as f64,
        )?;
    }
    drop(context);
    surface.flush();

    let pixel_count = pixel_width
        .checked_mul(pixel_height)
        .ok_or(RenderError::LimitExceeded("page pixels"))?;
    let mut rgb = vec![0u8; pixel_count * 3];
    let stride = surface.stride() as usize;
    {
        let data = surface
            .data()
            .map_err(|error| RenderError::Raster(error.to_string()))?;
        for y in 0..pixel_height {
            checkpoint(request)?;
            let source = &data[y * stride..y * stride + pixel_width * 4];
            let destination = &mut rgb[y * pixel_width * 3..(y + 1) * pixel_width * 3];
            for x in 0..pixel_width {
                destination[x * 3] = source[x * 4 + 2];
                destination[x * 3 + 1] = source[x * 4 + 1];
                destination[x * 3 + 2] = source[x * 4];
            }
        }
    }
    drop(surface);
    checkpoint(request)?;

    let map_colors = rgb24_to_map_colors(
        &rgb,
        pixel_width,
        pixel_height,
        request.limits.max_output_bytes,
        request.cancellation,
        request.deadline,
    )?;
    Ok(Page {
        maps_x: request.viewport_maps_x,
        maps_y: u8::try_from(pixel_height / MAP_EDGE)
            .expect("validated page height fits map count"),
        pixel_width,
        pixel_height,
        map_colors: map_colors.into_boxed_slice(),
        rgb: rgb.into_boxed_slice(),
    })
}

fn draw_line(
    request: &RenderRequest<'_>,
    context: &Context,
    line: &str,
    mut x: f64,
    baseline: f64,
) -> Result<(), RenderError> {
    for (_, run) in text_runs(line) {
        checkpoint(request)?;
        context.move_to(x, baseline);
        context
            .show_text(run)
            .map_err(|error| RenderError::Raster(error.to_string()))?;
        x += text_advance(context, run)?;
    }
    Ok(())
}

fn output_size_bytes(
    width: usize,
    page_height: usize,
    content_height: usize,
) -> Result<usize, RenderError> {
    let full_pages = content_height / page_height;
    let remainder = content_height % page_height;
    let total_aligned_height = full_pages
        .checked_mul(page_height)
        .and_then(|height| {
            let tail = if remainder == 0 {
                0
            } else {
                remainder.div_ceil(MAP_EDGE) * MAP_EDGE
            };
            height.checked_add(tail)
        })
        .ok_or(RenderError::LimitExceeded("output bytes"))?;
    width
        .checked_mul(total_aligned_height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(RenderError::LimitExceeded("output bytes"))
}

#[derive(Clone, Copy)]
struct PaletteEntry {
    protocol_index: u8,
    rgb: [u8; 3],
    lab: [f32; 3],
}

fn minecraft_palette() -> &'static [PaletteEntry; 140] {
    static PALETTE: OnceLock<[PaletteEntry; 140]> = OnceLock::new();
    PALETTE.get_or_init(|| {
        const BASE_COLORS: [[u8; 3]; 35] = [
            [127, 178, 56],
            [247, 233, 163],
            [199, 199, 199],
            [255, 0, 0],
            [160, 160, 255],
            [167, 167, 167],
            [0, 124, 0],
            [255, 255, 255],
            [164, 168, 184],
            [151, 109, 77],
            [112, 112, 112],
            [64, 64, 255],
            [143, 119, 72],
            [255, 252, 245],
            [216, 127, 51],
            [178, 76, 216],
            [102, 153, 216],
            [229, 229, 51],
            [127, 204, 25],
            [242, 127, 165],
            [76, 76, 76],
            [153, 153, 153],
            [76, 127, 153],
            [127, 63, 178],
            [51, 76, 178],
            [102, 76, 51],
            [102, 127, 51],
            [153, 51, 51],
            [25, 25, 25],
            [250, 238, 77],
            [92, 219, 213],
            [74, 128, 255],
            [0, 217, 58],
            [129, 86, 49],
            [112, 2, 0],
        ];
        const SHADES: [u16; 4] = [180, 220, 255, 135];
        let mut entries = [PaletteEntry {
            protocol_index: 0,
            rgb: [0, 0, 0],
            lab: [0.0, 0.0, 0.0],
        }; 140];
        let mut index = 0;
        for (base_index, base) in BASE_COLORS.iter().enumerate() {
            for (shade_index, multiplier) in SHADES.iter().enumerate() {
                let rgb = [
                    (u16::from(base[0]) * multiplier / 255) as u8,
                    (u16::from(base[1]) * multiplier / 255) as u8,
                    (u16::from(base[2]) * multiplier / 255) as u8,
                ];
                entries[index] = PaletteEntry {
                    protocol_index: ((base_index + 1) * 4 + shade_index) as u8,
                    rgb,
                    lab: rgb_to_lab(rgb),
                };
                index += 1;
            }
        }
        entries
    })
}

fn floyd_steinberg(
    rgb: &[u8],
    width: usize,
    height: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, RenderError> {
    let mut output = vec![0u8; width * height];
    let mut current = vec![[0.0; 3]; width];
    load_rgb_row(&mut current, rgb, width, 0);
    let mut next = if height > 1 {
        let mut row = vec![[0.0; 3]; width];
        load_rgb_row(&mut row, rgb, width, 1);
        row
    } else {
        vec![[0.0; 3]; width]
    };
    let palette = minecraft_palette();

    for y in 0..height {
        checkpoint_at(cancellation, deadline)?;
        for x in 0..width {
            if x % CHECKPOINT_PIXEL_INTERVAL == 0 {
                checkpoint_at(cancellation, deadline)?;
            }
            let clamped = [
                current[x][0].clamp(0.0, 255.0),
                current[x][1].clamp(0.0, 255.0),
                current[x][2].clamp(0.0, 255.0),
            ];
            let rounded = [
                (clamped[0] + 0.5) as u8,
                (clamped[1] + 0.5) as u8,
                (clamped[2] + 0.5) as u8,
            ];
            let selected = nearest_palette(rgb_to_lab(rounded), palette);
            output[y * width + x] = selected.protocol_index;
            let error = [
                clamped[0] - f32::from(selected.rgb[0]),
                clamped[1] - f32::from(selected.rgb[1]),
                clamped[2] - f32::from(selected.rgb[2]),
            ];

            if x + 1 < width {
                diffuse(&mut current[x + 1], error, 7.0 / 16.0);
            }
            if y + 1 < height {
                if x > 0 {
                    diffuse(&mut next[x - 1], error, 3.0 / 16.0);
                }
                diffuse(&mut next[x], error, 5.0 / 16.0);
                if x + 1 < width {
                    diffuse(&mut next[x + 1], error, 1.0 / 16.0);
                }
            }
        }
        if y + 1 < height {
            std::mem::swap(&mut current, &mut next);
            if y + 2 < height {
                load_rgb_row(&mut next, rgb, width, y + 2);
            } else {
                next.fill([0.0; 3]);
            }
        }
    }
    Ok(output)
}

fn load_rgb_row(output: &mut [[f32; 3]], rgb: &[u8], width: usize, y: usize) {
    let row = &rgb[y * width * 3..(y + 1) * width * 3];
    for (destination, pixel) in output.iter_mut().zip(row.chunks_exact(3)) {
        *destination = [
            f32::from(pixel[0]),
            f32::from(pixel[1]),
            f32::from(pixel[2]),
        ];
    }
}

fn diffuse(pixel: &mut [f32; 3], error: [f32; 3], factor: f32) {
    pixel[0] += error[0] * factor;
    pixel[1] += error[1] * factor;
    pixel[2] += error[2] * factor;
}

fn nearest_palette(lab: [f32; 3], palette: &[PaletteEntry; 140]) -> PaletteEntry {
    let mut best = palette[0];
    let mut minimum = f32::MAX;
    for candidate in palette {
        let dl = lab[0] - candidate.lab[0];
        let da = lab[1] - candidate.lab[1];
        let db = lab[2] - candidate.lab[2];
        let distance = dl * dl + da * da + db * db;
        if distance < minimum {
            minimum = distance;
            best = *candidate;
        }
    }
    best
}

fn rgb_to_lab(rgb: [u8; 3]) -> [f32; 3] {
    let red = srgb_linearize(f32::from(rgb[0]) / 255.0);
    let green = srgb_linearize(f32::from(rgb[1]) / 255.0);
    let blue = srgb_linearize(f32::from(rgb[2]) / 255.0);

    let x = 0.412_456_4 * red + 0.357_576_1 * green + 0.180_437_5 * blue;
    let y = 0.212_672_9 * red + 0.715_152_2 * green + 0.072_175 * blue;
    let z = 0.019_333_9 * red + 0.096_104_5 * green + 0.950_304_1 * blue;
    let fx = lab_component(x / 0.950_47);
    let fy = lab_component(y);
    let fz = lab_component(z / 1.088_83);
    [116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz)]
}

fn srgb_linearize(component: f32) -> f32 {
    if component <= 0.040_45 {
        component / 12.92
    } else {
        ((component + 0.055) / 1.055).powf(2.4)
    }
}

fn lab_component(component: f32) -> f32 {
    let delta = 6.0 / 29.0;
    if component > delta * delta * delta {
        component.cbrt()
    } else {
        component / (3.0 * delta * delta) + 4.0 / 29.0
    }
}

fn checkpoint(request: &RenderRequest<'_>) -> Result<(), RenderError> {
    checkpoint_at(request.cancellation, request.deadline)
}

fn checkpoint_at(cancellation: &CancellationToken, deadline: Instant) -> Result<(), RenderError> {
    if cancellation.is_cancelled() {
        return Err(RenderError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(RenderError::DeadlineExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};
    use mail_parser::{MessageParser, MimeHeaders, PartType};
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;

    fn request<'a>(text: &'a str, cancellation: &'a CancellationToken) -> RenderRequest<'a> {
        RenderRequest::plain_text(
            text,
            2,
            2,
            cancellation,
            Instant::now() + Duration::from_secs(30),
        )
    }

    #[test]
    fn frozen_v2_attachment_composition_is_byte_exact() {
        let source = include_str!("../../../blackbox/fixtures/minecraft/mail-view-v2.eml")
            .replace("\r\n", "\n")
            .replace('\n', "\r\n");
        let message = MessageParser::default().parse(source.as_bytes()).unwrap();
        let plain_text = message.parts.iter().find_map(|part| match &part.body {
            PartType::Text(value) => Some(value.as_ref()),
            _ => None,
        });
        let raw_html = message.parts.iter().find_map(|part| match &part.body {
            PartType::Html(value) => Some(value.as_ref()),
            _ => None,
        });
        let metadata = message
            .attachments()
            .map(|part| {
                let filename = part
                    .content_disposition()
                    .and_then(|value| value.attribute("filename"))
                    .or_else(|| {
                        part.content_type()
                            .and_then(|value| value.attribute("name"))
                    });
                let content_type = part.content_type().map(|value| {
                    format!(
                        "{}{}",
                        value.ctype(),
                        value
                            .subtype()
                            .map_or(String::new(), |subtype| format!("/{subtype}"))
                    )
                });
                let inline = part
                    .content_disposition()
                    .is_some_and(|value| value.ctype().eq_ignore_ascii_case("inline"));
                (filename, content_type, part.len() as u64, inline)
            })
            .collect::<Vec<_>>();
        let descriptors = metadata
            .iter()
            .map(
                |(filename, content_type, size, inline)| AttachmentDescriptor {
                    filename: *filename,
                    content_type: content_type.as_deref(),
                    size: *size,
                    inline: *inline,
                },
            )
            .collect::<Vec<_>>();

        let PreparedDocument::Html(html) =
            PreparedDocument::compose(raw_html, plain_text, &descriptors).unwrap()
        else {
            panic!("attachments must select the HTML renderer");
        };
        assert_eq!(html.len(), 2904);
        let html_sha256 = Sha256::digest(html.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            html_sha256,
            "52146f663acdc4e283833b137184c9b7d0c546773a4cb53a47702ef63ef65f48"
        );
        assert!(html.contains("fixture.png</span>"));
        assert!(html.contains("(image/png, 67 B, inline)</span>"));
        assert!(html.contains("status&lt;&amp;&gt;.txt"));
        assert!(!html.contains("status<&>.txt"));
    }

    #[test]
    fn content_selection_and_attachment_cards_match_java_contract() {
        assert_eq!(
            PreparedDocument::compose(Some("  \n"), Some("plain"), &[]).unwrap(),
            PreparedDocument::PlainText("plain".to_owned())
        );
        assert_eq!(
            PreparedDocument::compose(Some("\u{00a0}"), Some("plain"), &[]).unwrap(),
            PreparedDocument::Html("\u{00a0}".to_owned())
        );

        let attachment = AttachmentDescriptor {
            filename: Some("a'&<>\".bin"),
            content_type: None,
            size: 1536,
            inline: true,
        };
        let PreparedDocument::Html(html) =
            PreparedDocument::compose(None, Some("<&\"'"), &[attachment]).unwrap()
        else {
            panic!("attachments must select HTML");
        };
        assert!(html.starts_with(
            "<html><body><pre style=\"font-family:monospace;white-space:pre-wrap;\">&lt;&amp;&quot;'"
        ));
        assert!(html.contains("a'&amp;&lt;&gt;&quot;.bin"));
        assert!(html.contains("(unknown, 1.5 KB, inline)"));
        assert!(html.ends_with("</div></body></html>"));
    }

    #[test]
    fn java_html_preprocessing_keeps_legacy_scope_exact() {
        let html = concat!(
            "<SCRIPT>x</SCRIPT><img onclick=\"x\" onload='y' ",
            "onbare=x src='javascript:alert(1)' href=\"JAVASCRIPT:x\">",
            "<p on\u{00a0}click=\"kept\">ok</p>"
        );
        assert_eq!(
            preprocess_html(html),
            "<img onbare=x src=\"\" href=\"\"><p on\u{00a0}click=\"kept\">ok</p>"
        );
    }

    #[test]
    fn repeated_closing_tags_fail_before_unbounded_card_expansion() {
        let html = "</body>".repeat(100_000);
        let attachment = AttachmentDescriptor {
            filename: Some("bounded"),
            content_type: Some("text/plain"),
            size: 1,
            inline: false,
        };
        assert!(matches!(
            PreparedDocument::compose(Some(&html), None, &[attachment]),
            Err(RenderError::LimitExceeded("prepared HTML bytes"))
        ));
    }

    #[test]
    fn embedded_raster_and_svg_decode_into_rust_owned_straight_rgba() {
        let mut png = Vec::new();
        PngEncoder::new(&mut png)
            .write_image(
                &[
                    255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 255, 255, 255, 255, 0,
                ],
                2,
                2,
                ExtendedColorType::Rgba8,
            )
            .unwrap();
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="3" height="2">
            <rect width="3" height="2" fill="#ff0000"/>
            <image href="/etc/passwd" width="1" height="1"/>
        </svg>"##;
        let resources = vec![
            EmbeddedResource::new("png".to_owned(), png, "IMAGE/PNG; x=y".to_owned()),
            EmbeddedResource::new("svg".to_owned(), svg.to_vec(), "image/svg+xml".to_owned()),
        ];
        let cancellation = CancellationToken::new();
        let decoded = decode_embedded_resources(
            &resources,
            &cancellation,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(
            (
                decoded[0].content_id.as_str(),
                decoded[0].width,
                decoded[0].height,
                decoded[0].stride,
                decoded[0].rgba.len(),
            ),
            ("png", 2, 2, 8, 16)
        );
        assert_eq!(
            (
                decoded[1].content_id.as_str(),
                decoded[1].width,
                decoded[1].height,
                decoded[1].stride,
                decoded[1].rgba.len(),
            ),
            ("svg", 3, 2, 12, 24)
        );
        assert_eq!(&decoded[1].rgba[..4], &[255, 0, 0, 255]);
    }

    #[test]
    fn image_decode_rejects_oversized_geometry_and_observes_cancellation() {
        let mut png = Vec::new();
        PngEncoder::new(&mut png)
            .write_image(
                &vec![255; (MAX_IMAGE_DIMENSION as usize + 1) * 4],
                MAX_IMAGE_DIMENSION + 1,
                1,
                ExtendedColorType::Rgba8,
            )
            .unwrap();
        let resources = vec![EmbeddedResource::new(
            "wide".to_owned(),
            png,
            "image/png".to_owned(),
        )];
        let cancellation = CancellationToken::new();
        let decoded = decode_embedded_resources(
            &resources,
            &cancellation,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert!(decoded.is_empty());

        cancellation.cancel();
        assert!(matches!(
            decode_embedded_resources(
                &resources,
                &cancellation,
                Instant::now() + Duration::from_secs(5)
            ),
            Err(RenderError::Cancelled)
        ));
    }

    #[test]
    fn native_html_abi_layout_and_cancellation_are_enforced() {
        assert_eq!(std::mem::size_of::<NativeHtmlConfig>(), 48);
        assert_eq!(std::mem::size_of::<NativeHtmlResource>(), 48);
        // SAFETY: this ABI query takes no pointers and is linked from the
        // pinned native source compiled by this crate's build script.
        assert_eq!(
            unsafe { lmyzmail_mail_html_abi_version() },
            NATIVE_ABI_VERSION
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let request = RenderRequest::html(
            "<html><body>cancelled</body></html>",
            &[],
            2,
            2,
            &cancellation,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(matches!(render(&request), Err(RenderError::Cancelled)));
    }

    #[test]
    fn valid_high_contrast_cid_is_visible_in_native_html_pixels() {
        let mut png = Vec::new();
        let mut pixels = Vec::with_capacity(32 * 32 * 4);
        for y in 0..32 {
            for x in 0..32 {
                let rgb = if x < 16 && y < 16 {
                    [255, 0, 0]
                } else if x >= 16 && y < 16 {
                    [0, 255, 0]
                } else if x < 16 {
                    [0, 0, 255]
                } else {
                    [0, 0, 0]
                };
                pixels.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 255]);
            }
        }
        PngEncoder::new(&mut png)
            .write_image(&pixels, 32, 32, ExtendedColorType::Rgba8)
            .unwrap();
        let resources = vec![EmbeddedResource::new(
            "visible".to_owned(),
            png,
            "image/png".to_owned(),
        )];
        let cancellation = CancellationToken::new();
        let mut request = RenderRequest::html(
            concat!(
                "<html><body style=\"margin:0;background:white\">",
                "<img src=\"cid:visible\" width=\"96\" height=\"96\">",
                "</body></html>"
            ),
            &resources,
            2,
            2,
            &cancellation,
            Instant::now() + Duration::from_secs(10),
        );
        request.style.font_size_px = 16.0;
        let result = render(&request).unwrap();
        let rgb = result.pages()[0].rgb();
        assert!(rgb.chunks_exact(3).any(|pixel| pixel == [255, 0, 0]));
        assert!(rgb.chunks_exact(3).any(|pixel| pixel == [0, 255, 0]));
        assert!(rgb.chunks_exact(3).any(|pixel| pixel == [0, 0, 255]));
        assert!(
            result.pages()[0]
                .map_colors()
                .iter()
                .any(|value| *value != 34)
        );
    }

    #[test]
    fn frozen_v2_html_render_matches_every_java_page() {
        let source = include_str!("../../../blackbox/fixtures/minecraft/mail-view-v2.eml")
            .replace("\r\n", "\n")
            .replace('\n', "\r\n");
        let message = MessageParser::default().parse(source.as_bytes()).unwrap();
        let plain_text = message.parts.iter().find_map(|part| match &part.body {
            PartType::Text(value) => Some(value.as_ref()),
            _ => None,
        });
        let raw_html = message.parts.iter().find_map(|part| match &part.body {
            PartType::Html(value) => Some(value.as_ref()),
            _ => None,
        });
        let metadata = message
            .attachments()
            .map(|part| {
                let filename = part
                    .content_disposition()
                    .and_then(|value| value.attribute("filename"))
                    .or_else(|| {
                        part.content_type()
                            .and_then(|value| value.attribute("name"))
                    });
                let content_type = part.content_type().map(|value| {
                    format!(
                        "{}{}",
                        value.ctype(),
                        value
                            .subtype()
                            .map_or(String::new(), |subtype| format!("/{subtype}"))
                    )
                });
                let inline = part
                    .content_disposition()
                    .is_some_and(|value| value.ctype().eq_ignore_ascii_case("inline"));
                (filename, content_type, part.len() as u64, inline)
            })
            .collect::<Vec<_>>();
        let descriptors = metadata
            .iter()
            .map(
                |(filename, content_type, size, inline)| AttachmentDescriptor {
                    filename: *filename,
                    content_type: content_type.as_deref(),
                    size: *size,
                    inline: *inline,
                },
            )
            .collect::<Vec<_>>();
        let resources = message
            .attachments()
            .filter_map(|part| {
                let content_id = part.content_id()?.to_owned();
                let content_type = part.content_type().map(|value| {
                    format!(
                        "{}{}",
                        value.ctype(),
                        value
                            .subtype()
                            .map_or(String::new(), |subtype| format!("/{subtype}"))
                    )
                })?;
                let data = match &part.body {
                    PartType::Binary(value) | PartType::InlineBinary(value) => value.to_vec(),
                    _ => return None,
                };
                Some(EmbeddedResource::new(content_id, data, content_type))
            })
            .collect::<Vec<_>>();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].data.len(), 67);
        let PreparedDocument::Html(html) =
            PreparedDocument::compose(raw_html, plain_text, &descriptors).unwrap()
        else {
            panic!("v2 fixture must select HTML");
        };
        let html = preprocess_html(&html);
        let cancellation = CancellationToken::new();
        let mut request = RenderRequest::html(
            &html,
            &resources,
            2,
            2,
            &cancellation,
            Instant::now() + Duration::from_secs(30),
        );
        request.style.font_size_px = 16.0;
        let result = render(&request).unwrap();
        assert_eq!(result.content_width(), 256);
        assert_eq!(result.content_height(), 1596);
        assert_eq!(result.pages().len(), 7);
        assert_eq!(result.pages()[6].pixel_height(), 128);
        let last_page = &result.pages()[6];
        let last_page_tile_hashes = last_page
            .tiles()
            .map(|tile| {
                let mut pixels = [0_u8; MAP_PIXELS];
                tile.copy_into(&mut pixels);
                Sha256::digest(pixels)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            last_page_tile_hashes,
            [
                "f680c83fc721266a65545d6b60cc04d68a93560ade7024085aa285698609fd24",
                "857d9ed9900f6a9208b44220a251b12f39b069f6b5c11dcdc140fe4a9907c1b1",
            ]
        );
        let expected = [
            "5d671786017068bd3ab94617468895c80258c100cd50e8027c78e35624fa8591",
            "51a3019d6d333ec797e2da18ef72f338711bff6b4d563516d123fa4613d88f1b",
            "cea2affb5cd5b6784154471e9ee9a6296af5fd7797248abd64b9a4c8a131c0b6",
            "d757706778c2bbfb1de2514b48d7c53afe6432915c0a5659c3181224ccf98cfb",
            "c8fdc2779dcc88ba2c60c402905b408a3817c38196099910f81bc8fee82d391f",
            "45923281d922f9d1a7d342a9f6418a44fce0ee02c93f4739259044533dc9c26c",
            "d0e736614a11ab43b931a8280480883ab39923a4a31c7ff66da1c1b8835bd4a1",
        ];
        let actual = result
            .pages()
            .iter()
            .map(|page| {
                let mut wall_pixels = page.map_colors().to_vec();
                wall_pixels.resize(2 * 2 * MAP_PIXELS, 34);
                Sha256::digest(wall_pixels)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn frozen_plain_text_fixture_matches_layout_and_page_shape() {
        let mut text = String::from("Minecraft mail-view renderer fixture\n\n");
        for line in 0..48 {
            text.push_str(&format!(
                "Line {line:02}: deterministic ASCII text for map paging and pixels."
            ));
            if line != 47 {
                text.push('\n');
            }
        }
        let cancellation = CancellationToken::new();
        let result = render(&request(&text, &cancellation)).unwrap();

        assert_eq!(result.backend(), RenderBackend::Scalar);
        assert_eq!(result.content_width(), 256);
        assert_eq!(result.content_height(), 2368);
        assert_eq!(result.pages().len(), 10);
        assert!(result.pages()[..9].iter().all(|page| page.maps_y() == 2));
        assert_eq!(result.pages()[9].maps_y(), 1);
        assert!(!result.truncated());

        let mut actual_output_bytes = 0usize;
        for (page_index, page) in result.pages().iter().enumerate() {
            let expected_maps_y = if page_index < 9 { 2 } else { 1 };
            let expected_height = usize::from(expected_maps_y) * MAP_EDGE;
            assert_eq!(page.maps_x(), 2, "page {page_index}");
            assert_eq!(page.maps_y(), expected_maps_y, "page {page_index}");
            assert_eq!(page.pixel_width(), 2 * MAP_EDGE, "page {page_index}");
            assert_eq!(page.pixel_height(), expected_height, "page {page_index}");
            assert_eq!(page.tile_count(), 2 * usize::from(expected_maps_y));
            assert_eq!(page.map_colors().len(), 2 * MAP_EDGE * expected_height);
            assert_eq!(page.rgb().len(), 2 * MAP_EDGE * expected_height * 3);
            actual_output_bytes += page.map_colors().len() + page.rgb().len();
        }
        assert_eq!(
            actual_output_bytes,
            output_size_bytes(2 * MAP_EDGE, 2 * MAP_EDGE, 2368).unwrap()
        );

        let expected = [
            [
                "8bc7ccf8d96360c7268da3385dc74f16c236760d45ebc400de6cab038974245f",
                "b2f37b6602682757c04f59f83e868a03bf76dd441dc74c88900da05f7f47b596",
                "8acf3a0e53e7027cce680fc224f444394c4f5acfb3067a07600e3283236c8568",
                "ee346779b9ebb960666b690ad9d2bf97a5d1df44b832ae9c7c092b20f10c1d5f",
            ],
            [
                "03317dfe3a09a2405c92d37d91637f18da422570ba63995426661ab2ba78b724",
                "2d0aafb39e153e082af65ec755e857959ff8bfbc0db7958935187c94189583d9",
                "68009fce77b25f837f44c25420c640f1438c0df3f25423163af30c19681f044c",
                "8774f094414119dbce51b16d84a78818624330a74153b9d43d4bde4f1bac8d22",
            ],
        ];
        for (page, expected_page) in result.pages()[..2].iter().zip(expected) {
            for (tile, expected_hash) in page.tiles().zip(expected_page) {
                let mut bytes = [0u8; MAP_PIXELS];
                tile.copy_into(&mut bytes);
                let actual_hash = Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert_eq!(actual_hash, expected_hash);
            }
        }
    }

    #[test]
    fn white_page_uses_minecraft_1_8_snow_bright_palette_index() {
        let cancellation = CancellationToken::new();
        let mut request = request("visible text", &cancellation);
        request.style.foreground_rgb = [255, 255, 255];
        let result = render(&request).unwrap();
        let page = &result.pages()[0];
        assert!(page.map_colors().iter().all(|color| *color == 34));
    }

    #[test]
    fn rgb24_helper_converts_without_copying_or_exceeding_budget() {
        let cancellation = CancellationToken::new();
        let input = vec![255u8; 4 * 3];
        let output = rgb24_to_map_colors(
            &input,
            2,
            2,
            4,
            &cancellation,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(output, vec![34; 4]);

        assert!(matches!(
            rgb24_to_map_colors(
                &input,
                2,
                2,
                3,
                &cancellation,
                Instant::now() + Duration::from_secs(30),
            ),
            Err(RenderError::LimitExceeded("RGB24 output bytes"))
        ));
    }

    #[test]
    fn rgb24_helper_rejects_malformed_dimensions_and_signals() {
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        assert!(matches!(
            rgb24_to_map_colors(&[0; 2], 1, 1, 4, &cancellation, deadline),
            Err(RenderError::InvalidRequest("RGB24 input length"))
        ));
        assert!(matches!(
            rgb24_to_map_colors(&[], 0, 1, 1, &cancellation, deadline),
            Err(RenderError::InvalidRequest("RGB24 frame dimensions"))
        ));

        cancellation.cancel();
        assert!(matches!(
            rgb24_to_map_colors(&[255; 3], 1, 1, 1, &cancellation, deadline),
            Err(RenderError::Cancelled)
        ));

        let active = CancellationToken::new();
        assert!(matches!(
            rgb24_to_map_colors(&[255; 3], 1, 1, 1, &active, Instant::now()),
            Err(RenderError::DeadlineExceeded)
        ));
    }

    #[test]
    fn cancellation_and_deadline_are_observed_before_font_or_output_work() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            render(&request("cancelled", &cancellation)),
            Err(RenderError::Cancelled)
        ));

        let active = CancellationToken::new();
        let mut expired = request("expired", &active);
        expired.deadline = Instant::now();
        assert!(matches!(
            render(&expired),
            Err(RenderError::DeadlineExceeded)
        ));
    }

    #[test]
    fn low_document_height_stops_four_mibibyte_tab_expansion_early() {
        let mut text = String::with_capacity(ABSOLUTE_MAX_INPUT_BYTES);
        text.push('x');
        text.extend(std::iter::repeat_n(
            '\t',
            ABSOLUTE_MAX_INPUT_BYTES - text.len(),
        ));
        let cancellation = CancellationToken::new();
        let mut request = request(&text, &cancellation);
        request.limits.max_input_bytes = ABSOLUTE_MAX_INPUT_BYTES;
        request.limits.max_document_height = 32;

        let surface = ImageSurface::create(Format::ARgb32, 1, 1).unwrap();
        let context = Context::new(&surface).unwrap();
        context.set_font_size(request.style.font_size_px);
        let layout = layout_plain_text(&request, &context, 224, 16, 8).unwrap();

        assert!(layout.truncated);
        assert_eq!(layout.content_height, 32);
        assert_eq!(layout.lines.len(), 2);
        assert!(
            layout.expanded_characters < 256,
            "consumed {} expanded characters",
            layout.expanded_characters
        );
    }

    #[test]
    fn cairo_text_chunks_bound_combining_runs_and_observe_abort_signals() {
        let mut text = String::from("a");
        text.extend(std::iter::repeat_n(
            '\u{0301}',
            (ABSOLUTE_MAX_INPUT_BYTES - text.len()) / '\u{0301}'.len_utf8(),
        ));
        let runs: Vec<_> = text_runs(&text).collect();
        assert!(runs.len() > 1_000);
        assert_eq!(
            runs.iter().map(|(_, run)| run.len()).sum::<usize>(),
            text.len()
        );
        assert!(
            runs.iter()
                .all(|(_, run)| !run.is_empty() && run.len() <= MAX_CAIRO_TEXT_CHUNK_BYTES)
        );

        let surface = ImageSurface::create(Format::ARgb32, 1, 1).unwrap();
        let context = Context::new(&surface).unwrap();

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_request = request(&text, &cancelled);
        assert!(matches!(
            draw_line(&cancelled_request, &context, &text, 0.0, 0.0),
            Err(RenderError::Cancelled)
        ));

        let active = CancellationToken::new();
        let mut expired_request = request(&text, &active);
        expired_request.deadline = Instant::now();
        assert!(matches!(
            draw_line(&expired_request, &context, &text, 0.0, 0.0),
            Err(RenderError::DeadlineExceeded)
        ));
    }

    #[test]
    fn dimensions_and_budgets_are_hard_errors() {
        let cancellation = CancellationToken::new();
        let mut invalid = request("mail", &cancellation);
        invalid.viewport_maps_x = 1;
        assert!(matches!(
            render(&invalid),
            Err(RenderError::InvalidRequest(_))
        ));

        let nul = request("mail\0body", &cancellation);
        assert!(matches!(render(&nul), Err(RenderError::InvalidRequest(_))));

        let mut oversized = request("mail", &cancellation);
        oversized.limits.max_output_bytes = 1;
        assert!(matches!(
            render(&oversized),
            Err(RenderError::LimitExceeded("output bytes"))
        ));
    }

    #[test]
    fn tile_order_is_row_major_and_copy_is_exact() {
        let width = 2 * MAP_EDGE;
        let height = 2 * MAP_EDGE;
        let colors: Vec<u8> = (0..height)
            .flat_map(|row| {
                (0..width).map(move |col| ((row / MAP_EDGE) * 2 + col / MAP_EDGE) as u8)
            })
            .collect();
        let page = Page {
            maps_x: 2,
            maps_y: 2,
            pixel_width: width,
            pixel_height: height,
            map_colors: colors.into_boxed_slice(),
            rgb: vec![0; width * height * 3].into_boxed_slice(),
        };

        for (index, tile) in page.tiles().enumerate() {
            assert_eq!((tile.col(), tile.row_index()), (index % 2, index / 2));
            let mut copied = [0u8; MAP_PIXELS];
            tile.copy_into(&mut copied);
            assert!(copied.iter().all(|value| usize::from(*value) == index));
        }
    }

    proptest! {
        #[test]
        fn rgb_to_lab_and_palette_matching_are_finite_and_in_protocol_range(
            red in any::<u8>(),
            green in any::<u8>(),
            blue in any::<u8>(),
        ) {
            let lab = rgb_to_lab([red, green, blue]);
            prop_assert!(lab.iter().all(|component| component.is_finite()));
            let selected = nearest_palette(lab, minecraft_palette());
            prop_assert!((4..=143).contains(&selected.protocol_index));
        }
    }
}
