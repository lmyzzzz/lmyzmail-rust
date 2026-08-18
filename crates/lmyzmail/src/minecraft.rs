use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::ZlibEncoder};
use getrandom::fill as fill_random;
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use icu_casemap::CaseMapper;
use md5::{Digest as _, Md5};
use openssl::{
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    symm::{Cipher, Crypter, Mode},
};
use regex::Regex;
use reqwest::{Client, StatusCode, redirect::Policy};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{AuthError, AuthService, LoginOutcome},
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::{MailRenderSimdMode, MinecraftConfig, RuntimeConfig},
    ffmpeg_video::VideoDecoder,
    mail_render,
    mailbox::{EmailListItem, EmailListPage, MailboxService},
    minecraft_world::{self, NbtValue, WorldTemplate},
    outbound::{OutboundService, QueueResponse, SendRequest, WebStatusResponse},
};

const MAX_FRAME_LENGTH: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(25);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);
const COMPRESSION_WORKERS: usize = 2;
const COMPRESSION_QUEUE: usize = 8;
const COMPRESSION_CHUNK_BYTES: usize = 64 * 1024;
const CRYPTO_WORKERS: usize = 2;
const CRYPTO_QUEUE: usize = 8;
const ENCRYPTION_FIELD_MAX_BYTES: usize = 512;
const VERIFY_TOKEN_BYTES: usize = 4;
const SHARED_SECRET_BYTES: usize = 16;
const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AUTH_RESPONSE_BYTES: usize = 64 * 1024;
const POSITION_CHECK_INTERVAL: Duration = Duration::from_secs(2);
const HOLOGRAM_TELEPORT_INTERVAL: Duration = Duration::from_secs(2);
const TIME_UPDATE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_SPAWN_DISTANCE: f64 = 100.0;
const RENDER_MAPS_X_DEFAULT: i32 = 10;
const RENDER_MAPS_X_MIN: i32 = 2;
const RENDER_MAPS_X_MAX: i32 = 24;
const RENDER_MAPS_Y_DEFAULT: i32 = 20;
const RENDER_MAPS_Y_MIN: i32 = 2;
const RENDER_MAPS_Y_MAX: i32 = 20;
const RENDER_FONT_SIZE_DEFAULT: i32 = 20;
const RENDER_FONT_SIZE_MIN: i32 = 8;
const RENDER_FONT_SIZE_MAX: i32 = 48;
const UPDATE_SIGN_LINE_MAX_UTF16_UNITS: usize = 384;
const MAX_MINECRAFT_DRAFTS: usize = 4_096;
const MAX_DRAFT_STORE_CONTENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DRAFT_PAGES: usize = 256;
const MAX_DRAFT_PAGE_BYTES: usize = 32_767;
const MAX_DRAFT_BODY_BYTES: usize = 1024 * 1024;
const OUTBOUND_SEND_BUTTON: (i32, i32, i32) = (5, 161, 6);
const OUTBOUND_FAST_POLLS: u8 = 30;
const OUTBOUND_BACKGROUND_POLLS: u8 = 60;
const OUTBOUND_FAST_POLL_INTERVAL: Duration = Duration::from_secs(1);
const OUTBOUND_BACKGROUND_POLL_INTERVAL: Duration = Duration::from_secs(10);
const OUTBOUND_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(30);
const OUTBOUND_STATUS_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);
const OUTBOUND_MINECRAFT_FOOTER: &str = "--- Sent with lmyzmail from Minecraft 1.8.9 ---";
const FOLDER_PAGE_SIZE: i32 = 36;
const FOLDER_LOAD_TIMEOUT: Duration = Duration::from_secs(8);
const MAIL_RENDER_TIMEOUT: Duration = Duration::from_secs(60);
const MAIL_RENDER_WORKERS: usize = 2;
const MAIL_RENDER_QUEUE: usize = 2;
const IMAGE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10);
const IMAGE_DOWNLOAD_PERMITS: usize = 16;
const IMAGE_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const IMAGE_DNS_CACHE_ENTRIES: u64 = 256;
const IMAGE_DNS_MAX_ACTIVE_REQUESTS: usize = 16;
const MAX_IMAGE_ADDRESSES: usize = 16;
const MAP_TILE_PIXELS: usize = 128 * 128;
const MAP_BLANK_COLOR: u8 = 34;
const MAP_SUPPORT_BLOCK_STATE: i32 = 155 << 4;
const HOTBAR_CLICK_COOLDOWN: Duration = Duration::from_millis(400);
const VIDEO_SOURCE_WIDTH: usize = 1920;
const VIDEO_SOURCE_HEIGHT: usize = 1080;
const VIDEO_SOURCE_FPS: f64 = 30.0;
const VIDEO_DURATION_SECONDS: u64 = 66;
const VIDEO_SETTLE_SECONDS: u8 = 2;
const VIDEO_PAUSE_POLL: Duration = Duration::from_millis(100);
const VIDEO_CONVERSION_WORKERS: usize = 2;
const VIDEO_CONVERSION_QUEUE: usize = 2;
const VIDEO_MAX_FRAME_BYTES: usize = 16 * 128 * 16 * 128 * 3;
const BLOCK_VIDEO_SETTLE_SECONDS: u8 = 3;
const BLOCK_VIDEO_MAX_CHUNKS: usize = 64;
const BLOCK_VIDEO_MAX_REGION_BLOCKS: usize = 2_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Handshake,
    Status,
    Login,
    Play,
}

#[derive(Debug)]
enum ProtocolError {
    Cancelled,
    TimedOut,
    Malformed,
    Io(io::Error),
}

const MAX_MINECRAFT_AUTH_RECORDS: usize = 16_384;

struct MinecraftAuthLimiter {
    max_attempts: usize,
    lockout: Duration,
    window: Duration,
    records: Mutex<HashMap<String, MinecraftAuthAttempt>>,
}

struct MinecraftAuthAttempt {
    failures: VecDeque<StdInstant>,
    locked_until: Option<StdInstant>,
}

#[derive(Clone, Default)]
struct MinecraftDraft {
    to: String,
    cc: String,
    bcc: String,
    subject: String,
    body_pages: Vec<String>,
}

struct StoredMinecraftDraft {
    draft: MinecraftDraft,
    sequence: u64,
}

#[derive(Default)]
struct MinecraftDraftStore {
    drafts: HashMap<String, StoredMinecraftDraft>,
    next_sequence: u64,
    content_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct WindowClick {
    window_id: u8,
    slot: i16,
    action_number: i16,
    mode: u8,
}

#[derive(Clone)]
struct UpdateSign {
    x: i32,
    y: i32,
    z: i32,
    lines: [String; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HotbarAction {
    None,
    PreviousPage,
    CloseMailView,
    NextPage,
    OpenMainMenu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RenderSettings {
    maps_x: i32,
    maps_y: i32,
    font_size: i32,
}

impl Default for RenderSettings {
    fn default() -> Self {
        Self {
            maps_x: RENDER_MAPS_X_DEFAULT,
            maps_y: RENDER_MAPS_Y_DEFAULT,
            font_size: RENDER_FONT_SIZE_DEFAULT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MainMenuEffect {
    None,
    Close,
    SwitchAccount,
    OpenRenderSettings,
    OpenVideoMenu(u8),
    OpenLogoutConfirm(u8),
    OpenFolder(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogoutConfirmEffect {
    None,
    OpenMainMenu(u8),
    Disconnect,
}

struct FolderGui {
    window_id: u8,
    folder: String,
    page: EmailListPage,
}

enum FolderLoadAction {
    Open { folder: String },
    Refresh { window_id: u8, folder: String },
}

type FolderLoadFuture =
    Pin<Box<dyn Future<Output = Result<EmailListPage, String>> + Send + 'static>>;

struct PendingFolderLoad {
    action: FolderLoadAction,
    future: FolderLoadFuture,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FolderGuiEffect {
    None,
    LoadPage(i32),
    OpenMainMenu(u8),
    OpenMail { folder: String, file_name: String },
}

#[derive(Debug)]
enum MailRenderFailure {
    Busy,
    Unavailable,
    Read(String),
    Render(String),
    Cancelled,
}

type MailRenderFuture = Pin<
    Box<dyn Future<Output = Result<mail_render::RenderResult, MailRenderFailure>> + Send + 'static>,
>;

struct PendingMailRender {
    cancellation: CancellationToken,
    future: MailRenderFuture,
}

type OutboundStepFuture = Pin<Box<dyn Future<Output = OutboundStepResult> + Send + 'static>>;

enum OutboundStepResult {
    Enqueued(Result<QueueResponse, String>),
    Status(Result<Option<WebStatusResponse>, String>),
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundPollTransition {
    ContinueFast,
    EnterBackground,
    ContinueBackground,
    Exhausted,
}

fn advance_outbound_poll(fast_polls: &mut u8, background_polls: &mut u8) -> OutboundPollTransition {
    if *fast_polls < OUTBOUND_FAST_POLLS {
        *fast_polls = fast_polls.saturating_add(1);
        return if *fast_polls < OUTBOUND_FAST_POLLS {
            OutboundPollTransition::ContinueFast
        } else {
            OutboundPollTransition::EnterBackground
        };
    }

    *background_polls = background_polls.saturating_add(1);
    if *background_polls < OUTBOUND_BACKGROUND_POLLS {
        OutboundPollTransition::ContinueBackground
    } else {
        OutboundPollTransition::Exhausted
    }
}

struct PendingOutboundSend {
    cancellation: CancellationToken,
    sender: String,
    queue_id: Option<i64>,
    message_id: Option<String>,
    fast_polls: u8,
    background_polls: u8,
    future: OutboundStepFuture,
}

impl Drop for PendingOutboundSend {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl PendingOutboundSend {
    fn start(
        outbound: Arc<OutboundService>,
        sender: String,
        request: SendRequest,
        parent_cancellation: &CancellationToken,
    ) -> Self {
        let cancellation = parent_cancellation.child_token();
        let future_cancellation = cancellation.clone();
        let future = Box::pin(async move {
            tokio::select! {
                biased;
                _ = future_cancellation.cancelled() => OutboundStepResult::Cancelled,
                result = timeout(
                    OUTBOUND_ENQUEUE_TIMEOUT,
                    outbound.enqueue_with_cancellation(
                        request,
                        None,
                        &future_cancellation,
                    ),
                ) => OutboundStepResult::Enqueued(match result {
                    Ok(result) => result.map_err(|error| error.to_string()),
                    Err(_) => Err("outbound queue unavailable".to_owned()),
                }),
            }
        });
        Self {
            cancellation,
            sender,
            queue_id: None,
            message_id: None,
            fast_polls: 0,
            background_polls: 0,
            future,
        }
    }

    fn schedule_status(&mut self, outbound: Arc<OutboundService>, delay: Duration) {
        let cancellation = self.cancellation.clone();
        let sender = self.sender.clone();
        let queue_id = self
            .queue_id
            .expect("status polling requires an assigned queue ID");
        self.future = Box::pin(async move {
            let cancelled = tokio::select! {
                biased;
                _ = cancellation.cancelled() => true,
                _ = tokio::time::sleep(delay) => false,
            };
            if cancelled {
                return OutboundStepResult::Cancelled;
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => OutboundStepResult::Cancelled,
                result = timeout(
                    OUTBOUND_STATUS_OPERATION_TIMEOUT,
                    outbound.web_status_by_id(queue_id, &sender),
                ) => OutboundStepResult::Status(match result {
                    Ok(result) => result.map_err(|error| error.to_string()),
                    Err(_) => Err("outbound queue unavailable".to_owned()),
                }),
            }
        });
    }
}

impl Drop for PendingMailRender {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MapWallFacing {
    South,
    West,
    North,
    East,
}

struct MapWall {
    maps_x: usize,
    maps_y: usize,
    facing: MapWallFacing,
    center_x: i32,
    center_y: i32,
    center_z: i32,
    map_ids: Box<[i32]>,
    entity_ids: Box<[i32]>,
    saved_blocks: Vec<((i32, i32, i32), i32)>,
}

struct ActiveMailView {
    wall: MapWall,
    result: mail_render::RenderResult,
    current_page: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct MapVideoParams {
    maps_x: usize,
    fps: u32,
    dither: u8,
    contrast: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct BlockVideoParams {
    width: usize,
    height: usize,
    fps: u32,
    contrast: f32,
}

#[derive(Clone, Debug)]
struct VideoControl {
    stopped: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl VideoControl {
    fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    fn toggle_pause(&self) -> bool {
        let previous = self.paused.fetch_xor(true, Ordering::AcqRel);
        !previous
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
}

enum VideoEvent {
    Packets(Vec<Vec<u8>>),
    Finished(Vec<Vec<u8>>),
}

struct PendingMapVideo {
    control: VideoControl,
    cancellation: CancellationToken,
    permit: Option<OwnedSemaphorePermit>,
    decoder: Option<VideoDecoder>,
    pending_open: Option<PendingVideoOpen>,
    pending_decode: Option<PendingVideoDecode>,
    wall: Option<MapWall>,
    maps_x: usize,
    maps_y: usize,
    fps: u32,
    contrast: f32,
    dither: u8,
    decoded_frames: u64,
    emitted_frames: u64,
    previous_frame: Option<Vec<u8>>,
    pending_conversion: Option<PendingVideoConversion>,
    setup_packets: Option<Vec<Vec<u8>>>,
    countdown: Option<u8>,
    next_countdown: Instant,
    next_frame: Instant,
    finished: bool,
}

struct BlockVideoChunk {
    original: minecraft_world::ChunkData,
    cleared: minecraft_world::ChunkData,
    touched: bool,
}

struct BlockVideoWall {
    width: usize,
    height: usize,
    min_x: i32,
    max_y: i32,
    wall_z: i32,
    min_cx: i32,
    max_cx: i32,
    min_sy: usize,
    max_sy: usize,
    saved_block_positions: Vec<i64>,
    chunks: Vec<BlockVideoChunk>,
}

struct PendingBlockVideo {
    control: VideoControl,
    cancellation: CancellationToken,
    permit: Option<OwnedSemaphorePermit>,
    decoder: Option<VideoDecoder>,
    pending_open: Option<PendingVideoOpen>,
    pending_decode: Option<PendingVideoDecode>,
    wall: Option<BlockVideoWall>,
    decoded_frames: u64,
    emitted_frames: u64,
    pending_conversion: Option<PendingBlockConversion>,
    previous_frame: Option<Vec<u16>>,
    setup_packets: Option<Vec<Vec<u8>>>,
    countdown: Option<u8>,
    next_countdown: Instant,
    next_frame: Instant,
    fps: u32,
    contrast: f32,
    finished: bool,
}

struct PendingBlockConversion {
    cancellation: CancellationToken,
    receiver: oneshot::Receiver<Result<Vec<u16>, String>>,
}

struct PendingVideoConversion {
    cancellation: CancellationToken,
    receiver: oneshot::Receiver<Result<Vec<u8>, String>>,
}

struct PendingVideoOpen {
    cancellation: CancellationToken,
    receiver: oneshot::Receiver<Result<VideoDecoder, String>>,
}

struct PendingVideoDecode {
    cancellation: CancellationToken,
    receiver: oneshot::Receiver<Result<DecodedVideoFrame, String>>,
}

struct DecodedVideoFrame {
    decoder: VideoDecoder,
    frame: Option<Vec<u8>>,
    decoded_frames: u64,
    emitted_frames: u64,
}

impl Drop for PendingMapVideo {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(pending) = self.pending_open.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_decode.take() {
            pending.cancellation.cancel();
        }
        self.decoder.take();
        let _ = self.permit.take();
    }
}

impl Drop for PendingBlockVideo {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(pending) = self.pending_open.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_decode.take() {
            pending.cancellation.cancel();
        }
        self.decoder.take();
        let _ = self.permit.take();
    }
}

fn submit_video_open(
    service: &StatusService,
    path: &std::path::Path,
    parent_cancellation: &CancellationToken,
) -> Result<PendingVideoOpen, String> {
    let cancellation = parent_cancellation.child_token();
    let worker_cancellation = cancellation.clone();
    let path = path.to_owned();
    let receiver = service
        .video_conversion_pool
        .submit(move || {
            if worker_cancellation.is_cancelled() {
                return Err("video decoder open was cancelled".to_owned());
            }
            VideoDecoder::open(&path).map_err(|error| error.to_string())
        })
        .map_err(|error| format!("video decoder queue is {error}"))?;
    Ok(PendingVideoOpen {
        cancellation,
        receiver,
    })
}

fn submit_video_decode(
    service: &StatusService,
    decoder: VideoDecoder,
    decoded_frames: u64,
    emitted_frames: u64,
    fps: u32,
    parent_cancellation: &CancellationToken,
) -> Result<PendingVideoDecode, String> {
    let cancellation = parent_cancellation.child_token();
    let worker_cancellation = cancellation.clone();
    let receiver = service
        .video_conversion_pool
        .submit(move || {
            decode_selected_video_frame(
                decoder,
                decoded_frames,
                emitted_frames,
                fps,
                &worker_cancellation,
            )
        })
        .map_err(|error| format!("video decoder queue is {error}"))?;
    Ok(PendingVideoDecode {
        cancellation,
        receiver,
    })
}

fn decode_selected_video_frame(
    mut decoder: VideoDecoder,
    mut decoded_frames: u64,
    mut emitted_frames: u64,
    fps: u32,
    cancellation: &CancellationToken,
) -> Result<DecodedVideoFrame, String> {
    let (width, height) = decoder.dimensions();
    if width != VIDEO_SOURCE_WIDTH || height != VIDEO_SOURCE_HEIGHT {
        return Err(format!(
            "video dimensions are {width}x{height}; expected {VIDEO_SOURCE_WIDTH}x{VIDEO_SOURCE_HEIGHT}"
        ));
    }
    let frame_bytes = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or_else(|| "video frame size overflow".to_owned())?;
    if frame_bytes > VIDEO_MAX_FRAME_BYTES {
        return Err("video frame exceeds the configured memory budget".to_owned());
    }
    let mut frame = vec![0_u8; frame_bytes];
    loop {
        if cancellation.is_cancelled() {
            return Err("video decode was cancelled".to_owned());
        }
        if !decoder
            .next_frame(&mut frame)
            .map_err(|error| format!("video decode failed: {error}"))?
        {
            return Ok(DecodedVideoFrame {
                decoder,
                frame: None,
                decoded_frames,
                emitted_frames,
            });
        }
        decoded_frames = decoded_frames.saturating_add(1);
        let threshold =
            (emitted_frames.saturating_add(1) as f64) * VIDEO_SOURCE_FPS / f64::from(fps);
        if f64::from(fps) < VIDEO_SOURCE_FPS && (decoded_frames as f64) < threshold {
            continue;
        }
        emitted_frames = emitted_frames.saturating_add(1);
        return Ok(DecodedVideoFrame {
            decoder,
            frame: Some(frame),
            decoded_frames,
            emitted_frames,
        });
    }
}

impl MinecraftDraft {
    fn clear(&mut self) {
        self.to.clear();
        self.cc.clear();
        self.bcc.clear();
        self.subject.clear();
        self.body_pages.clear();
    }
}

impl MinecraftDraftStore {
    fn get_or_create(
        &mut self,
        uuid: &str,
        active_players: &HashSet<String>,
    ) -> Option<MinecraftDraft> {
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let sequence = self.next_sequence;
        if let Some(stored) = self.drafts.get_mut(uuid) {
            stored.sequence = sequence;
            return Some(stored.draft.clone());
        }
        if self.drafts.len() >= MAX_MINECRAFT_DRAFTS {
            let evicted = self
                .drafts
                .iter()
                .filter(|(player, _)| !active_players.contains(*player))
                .min_by_key(|(_, stored)| stored.sequence)
                .map(|(player, _)| player.clone())?;
            if let Some(removed) = self.drafts.remove(&evicted) {
                self.content_bytes = self
                    .content_bytes
                    .saturating_sub(draft_content_bytes(&removed.draft));
            }
        }
        self.drafts.insert(
            uuid.to_owned(),
            StoredMinecraftDraft {
                draft: MinecraftDraft::default(),
                sequence,
            },
        );
        Some(MinecraftDraft::default())
    }

    fn update(
        &mut self,
        uuid: &str,
        active_players: &HashSet<String>,
        apply: impl FnOnce(&mut MinecraftDraft),
    ) -> Option<MinecraftDraft> {
        self.update_with_budget(uuid, active_players, MAX_DRAFT_STORE_CONTENT_BYTES, apply)
    }

    fn update_with_budget(
        &mut self,
        uuid: &str,
        active_players: &HashSet<String>,
        content_budget: usize,
        apply: impl FnOnce(&mut MinecraftDraft),
    ) -> Option<MinecraftDraft> {
        let (previous, previous_bytes, updated_bytes) = {
            let stored = self.drafts.get_mut(uuid)?;
            let previous = stored.draft.clone();
            let previous_bytes = draft_content_bytes(&previous);
            apply(&mut stored.draft);
            let updated_bytes = draft_content_bytes(&stored.draft);
            (previous, previous_bytes, updated_bytes)
        };
        let Some(base_bytes) = self.content_bytes.checked_sub(previous_bytes) else {
            self.drafts.get_mut(uuid)?.draft = previous;
            return None;
        };
        let Some(required_bytes) = base_bytes.checked_add(updated_bytes) else {
            self.drafts.get_mut(uuid)?.draft = previous;
            return None;
        };

        if required_bytes > content_budget {
            let mut candidates = self
                .drafts
                .iter()
                .filter(|(player, _)| player.as_str() != uuid && !active_players.contains(*player))
                .map(|(player, stored)| {
                    (
                        stored.sequence,
                        player.clone(),
                        draft_content_bytes(&stored.draft),
                    )
                })
                .collect::<Vec<_>>();
            candidates.sort_unstable_by_key(|candidate| candidate.0);
            let mut reclaimed = 0_usize;
            let mut victim_count = 0_usize;
            for (_, _, bytes) in &candidates {
                let Some(next_reclaimed) = reclaimed.checked_add(*bytes) else {
                    self.drafts.get_mut(uuid)?.draft = previous;
                    return None;
                };
                reclaimed = next_reclaimed;
                victim_count += 1;
                if required_bytes.saturating_sub(reclaimed) <= content_budget {
                    break;
                }
            }
            if required_bytes.saturating_sub(reclaimed) > content_budget {
                self.drafts.get_mut(uuid)?.draft = previous;
                return None;
            }
            for (_, victim, expected_bytes) in candidates.iter().take(victim_count) {
                let removed = self
                    .drafts
                    .remove(victim)
                    .expect("draft eviction candidate must still exist");
                debug_assert_eq!(draft_content_bytes(&removed.draft), *expected_bytes);
            }
            self.content_bytes = required_bytes - reclaimed;
        } else {
            self.content_bytes = required_bytes;
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let sequence = self.next_sequence;
        let stored = self.drafts.get_mut(uuid)?;
        stored.sequence = sequence;
        Some(stored.draft.clone())
    }
}

fn draft_content_bytes(draft: &MinecraftDraft) -> usize {
    draft
        .to
        .len()
        .saturating_add(draft.cc.len())
        .saturating_add(draft.bcc.len())
        .saturating_add(draft.subject.len())
        .saturating_add(draft.body_pages.iter().fold(0_usize, |total, page| {
            total
                .saturating_add(page.len())
                .saturating_add(std::mem::size_of::<String>())
        }))
}

#[derive(Clone)]
struct MinecraftSlot {
    item_id: i16,
    count: u8,
    damage: i16,
    nbt: Option<NbtValue>,
}

impl MinecraftSlot {
    fn empty() -> Self {
        Self {
            item_id: -1,
            count: 0,
            damage: 0,
            nbt: None,
        }
    }

    fn item(item_id: i16, damage: i16, nbt: NbtValue) -> Self {
        Self {
            item_id,
            count: 1,
            damage,
            nbt: Some(nbt),
        }
    }
}

impl MinecraftAuthLimiter {
    fn new(config: &MinecraftConfig) -> Self {
        Self {
            max_attempts: config.auth_max_attempts as usize,
            lockout: Duration::from_secs(config.auth_lockout_seconds),
            window: Duration::from_secs(config.auth_window_seconds),
            records: Mutex::new(HashMap::with_capacity(64)),
        }
    }

    fn locked_remaining(&self, ip: &str) -> Option<u64> {
        self.locked_remaining_at(ip, StdInstant::now())
    }

    fn locked_remaining_at(&self, ip: &str, now: StdInstant) -> Option<u64> {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = records.get_mut(ip)?;
        match record.locked_until {
            Some(until) if until > now => Some(until.duration_since(now).as_secs()),
            Some(_) => {
                record.locked_until = None;
                record.failures.clear();
                None
            }
            None => None,
        }
    }

    fn record_failure(&self, ip: &str) -> (bool, usize) {
        self.record_failure_at(ip, StdInstant::now())
    }

    fn record_failure_at(&self, ip: &str, now: StdInstant) -> (bool, usize) {
        let window_start = now.checked_sub(self.window).unwrap_or(now);
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !records.contains_key(ip) && records.len() >= MAX_MINECRAFT_AUTH_RECORDS {
            records.retain(|_, record| {
                record.locked_until.is_some_and(|until| until > now)
                    || record
                        .failures
                        .back()
                        .is_some_and(|last| *last > window_start)
            });
            if records.len() >= MAX_MINECRAFT_AUTH_RECORDS {
                return (true, 0);
            }
        }
        let record = records
            .entry(ip.to_owned())
            .or_insert_with(|| MinecraftAuthAttempt {
                failures: VecDeque::new(),
                locked_until: None,
            });
        while record
            .failures
            .front()
            .is_some_and(|failure| *failure < window_start)
        {
            record.failures.pop_front();
        }
        record.failures.push_back(now);
        if record.failures.len() >= self.max_attempts {
            record.locked_until = Some(now + self.lockout);
            (true, 0)
        } else {
            (false, self.max_attempts - record.failures.len())
        }
    }

    fn clear(&self, ip: &str) {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(ip);
    }
}

struct OnlineModeService {
    private_key: Arc<Rsa<Private>>,
    public_key_der: Arc<[u8]>,
    crypto_pool: BoundedBlockingPool,
    session_client: Client,
    session_server_url: reqwest::Url,
}

impl OnlineModeService {
    fn new(config: &MinecraftConfig) -> io::Result<Self> {
        let rsa = Rsa::generate(1024).map_err(crypto_io)?;
        let public_key_der = PKey::from_rsa(rsa.clone())
            .and_then(|key| key.public_key_to_der())
            .map_err(crypto_io)?;
        if public_key_der.len() > ENCRYPTION_FIELD_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Minecraft RSA public key exceeded the protocol field limit",
            ));
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let session_client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(AUTH_REQUEST_TIMEOUT)
            .timeout(AUTH_REQUEST_TIMEOUT)
            .user_agent("lmyzmail-minecraft/0.1")
            .build()
            .map_err(io::Error::other)?;
        let session_server_url = reqwest::Url::parse(&config.session_server_url)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            private_key: Arc::new(rsa),
            public_key_der: public_key_der.into(),
            crypto_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-crypto",
                CRYPTO_WORKERS,
                CRYPTO_QUEUE,
            )?,
            session_client,
            session_server_url,
        })
    }
}

struct PendingOnlineLogin {
    username: String,
    verify_token: [u8; VERIFY_TOKEN_BYTES],
}

struct MinecraftCipher {
    decryptor: Crypter,
    encryptor: Crypter,
    decrypt_scratch: Vec<u8>,
    encrypt_scratch: Vec<u8>,
}

impl MinecraftCipher {
    fn new(secret: &[u8; SHARED_SECRET_BYTES]) -> Result<Self, ProtocolError> {
        let cipher = Cipher::aes_128_cfb8();
        let mut decryptor =
            Crypter::new(cipher, Mode::Decrypt, secret, Some(secret)).map_err(crypto_protocol)?;
        let mut encryptor =
            Crypter::new(cipher, Mode::Encrypt, secret, Some(secret)).map_err(crypto_protocol)?;
        decryptor.pad(false);
        encryptor.pad(false);
        Ok(Self {
            decryptor,
            encryptor,
            decrypt_scratch: Vec::new(),
            encrypt_scratch: Vec::new(),
        })
    }

    fn decrypt_in_place(&mut self, bytes: &mut [u8]) -> Result<(), ProtocolError> {
        transform_in_place(&mut self.decryptor, &mut self.decrypt_scratch, bytes)
    }

    fn encrypt<'a>(&'a mut self, bytes: &[u8]) -> Result<&'a [u8], ProtocolError> {
        transform_to_scratch(&mut self.encryptor, &mut self.encrypt_scratch, bytes)
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
struct PinnedImageClient {
    resolver: TokioResolver,
    permits: Arc<Semaphore>,
}

#[derive(Debug)]
struct DownloadedImage {
    body: Vec<u8>,
    mime_type: String,
}

impl PinnedImageClient {
    fn new() -> io::Result<Self> {
        let mut builder = TokioResolver::builder_tokio().map_err(|error| {
            io::Error::other(format!("image DNS configuration is unavailable: {error}"))
        })?;
        builder.options_mut().timeout = IMAGE_DNS_TIMEOUT;
        builder.options_mut().attempts = 2;
        builder.options_mut().cache_size = IMAGE_DNS_CACHE_ENTRIES;
        builder.options_mut().max_active_requests = IMAGE_DNS_MAX_ACTIVE_REQUESTS;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = builder.build().map_err(|error| {
            io::Error::other(format!("image DNS resolver initialization failed: {error}"))
        })?;
        Ok(Self {
            resolver,
            permits: Arc::new(Semaphore::new(IMAGE_DOWNLOAD_PERMITS)),
        })
    }

    async fn get(
        &self,
        url: &reqwest::Url,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Option<DownloadedImage>, String> {
        let operation_deadline = deadline.min(Instant::now() + IMAGE_DOWNLOAD_TIMEOUT);
        let _permit = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err("image download cancelled".to_owned()),
            result = timeout_at(operation_deadline, self.permits.clone().acquire_owned()) => result
                .map_err(|_| "image download admission timed out".to_owned())?
                .map_err(|_| "image download admission closed".to_owned())?,
        };
        let host = url
            .host_str()
            .ok_or_else(|| "external image URL has no host".to_owned())?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "external image URL has no port".to_owned())?;
        let addresses = if let Ok(address) = host.parse::<IpAddr>() {
            vec![address]
        } else {
            let lookup = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err("image DNS lookup cancelled".to_owned()),
                result = timeout_at(operation_deadline, self.resolver.lookup_ip(&host)) => result
                    .map_err(|_| "image DNS lookup timed out".to_owned())?
                    .map_err(|_| "image DNS lookup failed".to_owned())?,
            };
            lookup.iter().collect::<Vec<_>>()
        };
        if addresses.is_empty() || addresses.len() > MAX_IMAGE_ADDRESSES {
            return Err("image DNS answer exceeds its address budget".to_owned());
        }
        if addresses
            .iter()
            .any(|address| !crate::outbound_smtp::is_public_smtp_ip(*address))
        {
            return Err("external image resolved to a non-public address".to_owned());
        }

        let socket_addresses = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect::<Vec<_>>();
        let remaining = operation_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("image download deadline exceeded".to_owned());
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(remaining)
            .timeout(remaining)
            .resolve_to_addrs(&host, &socket_addresses)
            .build()
            .map_err(|_| "image HTTP client initialization failed".to_owned())?;
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err("image download cancelled".to_owned()),
            result = timeout_at(
                operation_deadline,
                client
                    .get(url.clone())
                    .header("User-Agent", "MailRenderer/1.0")
                    .header("Accept", "image/*")
                    .send(),
            ) => result
                .map_err(|_| "image HTTP request timed out".to_owned())?
                .map_err(|_| "image HTTP request failed".to_owned())?,
        };
        if response.status() != StatusCode::OK {
            return Ok(None);
        }
        if response
            .content_length()
            .is_some_and(|length| length > mail_render::MAX_EXTERNAL_RESOURCE_BYTES as u64)
        {
            return Err("external image exceeds its byte budget".to_owned());
        }
        let mime_type = mail_render::normalize_image_content_type(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
        );
        if !mail_render::is_safe_external_image_type(Some(&mime_type)) {
            return Ok(None);
        }

        let mut response = response;
        let mut body = Vec::with_capacity(
            response.content_length().unwrap_or_default().min(16 * 1024) as usize,
        );
        loop {
            let chunk = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err("image download cancelled".to_owned()),
                result = timeout_at(operation_deadline, response.chunk()) => result
                    .map_err(|_| "image response body timed out".to_owned())?
                    .map_err(|_| "image response body failed".to_owned())?,
            };
            let Some(chunk) = chunk else {
                break;
            };
            if body.len().saturating_add(chunk.len()) > mail_render::MAX_EXTERNAL_RESOURCE_BYTES {
                return Err("external image exceeds its byte budget".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        Ok((!body.is_empty()).then_some(DownloadedImage { body, mime_type }))
    }
}

#[derive(Debug)]
struct ExternalImageTarget {
    source: String,
    url: reqwest::Url,
    content_id: String,
}

#[derive(Debug)]
struct CidAttachmentTarget {
    index: i32,
    content_id: String,
    mime_type: String,
}

#[derive(Debug)]
struct MailRenderPreparation {
    document: mail_render::PreparedDocument,
    cid_targets: Vec<CidAttachmentTarget>,
    external_targets: Vec<ExternalImageTarget>,
}

fn prepare_mail_render(
    detail: crate::mailbox::EmailDetail,
) -> Result<MailRenderPreparation, String> {
    let descriptors = detail
        .attachments
        .iter()
        .map(|attachment| mail_render::AttachmentDescriptor {
            filename: Some(attachment.filename.as_str()),
            content_type: attachment.content_type.as_deref(),
            size: attachment.size,
            inline: attachment.inline,
        })
        .collect::<Vec<_>>();
    let document = mail_render::PreparedDocument::compose(
        detail.raw_html.as_deref(),
        detail.text.as_deref(),
        &descriptors,
    )
    .map_err(|error| error.to_string())?;

    let mut seen_content_ids = HashSet::with_capacity(mail_render::MAX_CID_RESOURCES);
    let mut cid_targets = Vec::with_capacity(mail_render::MAX_CID_RESOURCES);
    for (index, attachment) in detail.attachments.iter().enumerate() {
        if cid_targets.len() >= mail_render::MAX_CID_RESOURCES {
            break;
        }
        let Some(content_id) = attachment
            .content_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        if !attachment.inline
            || attachment.size == 0
            || attachment.size > mail_render::MAX_CID_RESOURCE_BYTES as u64
            || !mail_render::is_safe_cid_image_type(attachment.content_type.as_deref())
            || !seen_content_ids.insert(content_id.to_owned())
        {
            continue;
        }
        let Ok(index) = i32::try_from(index) else {
            break;
        };
        cid_targets.push(CidAttachmentTarget {
            index,
            content_id: content_id.to_owned(),
            mime_type: mail_render::normalize_image_content_type(
                attachment.content_type.as_deref(),
            ),
        });
    }

    let mut external_targets = match &document {
        mail_render::PreparedDocument::Html(html) => {
            collect_external_image_targets(html, cid_targets.len())
        }
        mail_render::PreparedDocument::PlainText(_) => Vec::new(),
    };
    for (sequence, target) in external_targets.iter_mut().enumerate() {
        let mut suffix = sequence;
        while seen_content_ids.contains(&target.content_id) {
            suffix = suffix.saturating_add(1);
            target.content_id = format!("__http_{suffix}");
        }
        seen_content_ids.insert(target.content_id.clone());
    }

    Ok(MailRenderPreparation {
        document,
        cid_targets,
        external_targets,
    })
}

fn collect_external_image_targets(
    html: &str,
    current_resource_count: usize,
) -> Vec<ExternalImageTarget> {
    static SRC_PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = SRC_PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)src(?-u:\s)*=(?-u:\s)*["'](https?://[^"'\t\n\x0B\x0C\r >]+)["']"#)
            .expect("the external image source pattern is valid")
    });
    let remaining_slots = mail_render::MAX_IMAGE_RESOURCES.saturating_sub(current_resource_count);
    let target_count = mail_render::MAX_EXTERNAL_RESOURCES.min(remaining_slots);
    let mut seen = HashSet::with_capacity(target_count);
    let mut targets = Vec::with_capacity(target_count);

    for captures in pattern.captures_iter(html) {
        if targets.len() >= target_count {
            break;
        }
        let Some(source) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if seen.contains(source) {
            continue;
        }
        let Some(url) = parse_allowed_external_image_url(source) else {
            continue;
        };
        seen.insert(source.to_owned());
        targets.push(ExternalImageTarget {
            source: source.to_owned(),
            url,
            content_id: format!("__http_{}", targets.len()),
        });
    }
    targets
}

fn parse_allowed_external_image_url(source: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(source).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return None;
    }
    let allowed_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    if url.host_str().is_none() || url.port_or_known_default() != Some(allowed_port) {
        return None;
    }
    Some(url)
}

struct StatusService {
    config: MinecraftConfig,
    mail_render_simd_mode: MailRenderSimdMode,
    status_frame: Arc<[u8]>,
    blacklist_frame: Arc<[u8]>,
    whitelist_frame: Arc<[u8]>,
    whitelist_enabled: bool,
    whitelist_players: Arc<[String]>,
    blacklist_players: Arc<[String]>,
    compression_pool: BoundedBlockingPool,
    mail_render_pool: BoundedBlockingPool,
    video_conversion_pool: BoundedBlockingPool,
    video_semaphore: Arc<Semaphore>,
    video_asset: PathBuf,
    image_http: Option<PinnedImageClient>,
    online_mode: Option<OnlineModeService>,
    next_entity_id: AtomicI32,
    next_hologram_entity_id: AtomicI32,
    next_map_id: AtomicI32,
    next_map_entity_id: AtomicI32,
    next_window_id: AtomicI32,
    next_connection_id: AtomicU64,
    online_sessions: Arc<Mutex<HashMap<String, u64>>>,
    drafts: Mutex<MinecraftDraftStore>,
    world: Arc<WorldTemplate>,
    connection_timeout: Duration,
    auth: Option<Arc<AuthService>>,
    mailbox: Option<Arc<MailboxService>>,
    outbound: Option<Arc<OutboundService>>,
    auth_limiter: Arc<MinecraftAuthLimiter>,
}

impl StatusService {
    #[cfg(test)]
    fn new(config: &MinecraftConfig) -> io::Result<Self> {
        Self::new_with_mail_render_simd(config, MailRenderSimdMode::Auto)
    }

    fn new_with_mail_render_simd(
        config: &MinecraftConfig,
        mail_render_simd_mode: MailRenderSimdMode,
    ) -> io::Result<Self> {
        let status_frame = build_status_frame(config, 0)?;
        let blacklist_frame =
            login_disconnect_frame(r#"{"text":"You are banned from this server.","color":"red"}"#)?;
        let whitelist_frame =
            login_disconnect_frame(r#"{"text":"You are not whitelisted.","color":"red"}"#)?;
        let world = WorldTemplate::load_shared(&config.world_template)?;
        Ok(Self {
            config: config.clone(),
            mail_render_simd_mode,
            status_frame: status_frame.into(),
            blacklist_frame: blacklist_frame.into(),
            whitelist_frame: whitelist_frame.into(),
            whitelist_enabled: config.whitelist_enabled,
            whitelist_players: config.whitelist_players.clone().into(),
            blacklist_players: config.blacklist_players.clone().into(),
            compression_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-zlib",
                COMPRESSION_WORKERS,
                COMPRESSION_QUEUE,
            )?,
            mail_render_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-mail-render",
                MAIL_RENDER_WORKERS,
                MAIL_RENDER_QUEUE,
            )?,
            video_conversion_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-video-convert",
                VIDEO_CONVERSION_WORKERS,
                VIDEO_CONVERSION_QUEUE,
            )?,
            video_semaphore: Arc::new(Semaphore::new(
                config.max_concurrent_videos.clamp(1, 64) as usize
            )),
            video_asset: crate::video_asset::locate_frozen_video_asset()?,
            image_http: PinnedImageClient::new().ok(),
            online_mode: config
                .online_mode
                .then(|| OnlineModeService::new(config))
                .transpose()?,
            next_entity_id: AtomicI32::new(1),
            next_hologram_entity_id: AtomicI32::new(900_000),
            next_map_id: AtomicI32::new(config.video.base_map_id),
            next_map_entity_id: AtomicI32::new(config.video.base_entity_id),
            next_window_id: AtomicI32::new(1),
            next_connection_id: AtomicU64::new(1),
            online_sessions: Arc::new(Mutex::new(HashMap::with_capacity(MAX_CONNECTIONS))),
            drafts: Mutex::new(MinecraftDraftStore::default()),
            world,
            connection_timeout: Duration::from_secs(config.read_timeout_seconds),
            auth: None,
            mailbox: None,
            outbound: None,
            auth_limiter: Arc::new(MinecraftAuthLimiter::new(config)),
        })
    }

    fn with_services(
        config: &MinecraftConfig,
        mail_render_simd_mode: MailRenderSimdMode,
        auth: Arc<AuthService>,
        mailbox: Arc<MailboxService>,
        outbound: Arc<OutboundService>,
    ) -> io::Result<Self> {
        let mut service = Self::new_with_mail_render_simd(config, mail_render_simd_mode)?;
        service.auth = Some(auth);
        service.mailbox = Some(mailbox);
        service.outbound = Some(outbound);
        Ok(service)
    }

    fn rejection_frame(&self, username: &str) -> Option<&[u8]> {
        if contains_player(&self.blacklist_players, username) {
            Some(&self.blacklist_frame)
        } else if self.whitelist_enabled && !contains_player(&self.whitelist_players, username) {
            Some(&self.whitelist_frame)
        } else {
            None
        }
    }

    fn current_status_frame(&self) -> io::Result<Vec<u8>> {
        let online = self
            .online_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u32;
        if online == 0 {
            Ok(self.status_frame.to_vec())
        } else {
            build_status_frame(&self.config, online)
        }
    }

    fn next_entity_id(&self) -> i32 {
        self.next_entity_id.fetch_add(1, Ordering::Relaxed)
    }

    fn reserve_hologram_entity_ids(&self, count: i32) -> i32 {
        self.next_hologram_entity_id
            .fetch_add(count, Ordering::Relaxed)
    }

    fn reserve_map_wall_ids(&self, count: i32) -> io::Result<(i32, i32)> {
        fn reserve(counter: &AtomicI32, count: i32, label: &str) -> io::Result<i32> {
            counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(count)
                })
                .map_err(|_| io::Error::other(format!("Minecraft {label} ID space exhausted")))
        }

        if count <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Minecraft map wall must contain at least one tile",
            ));
        }
        let map_base = reserve(&self.next_map_id, count, "map")?;
        let entity_base = reserve(&self.next_map_entity_id, count, "map entity")?;
        Ok((map_base, entity_base))
    }

    fn next_window_id(&self) -> u8 {
        self.next_window_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some((current % 100) + 1)
            })
            .unwrap_or_else(|current| current) as u8
    }

    fn register_online(&self, uuid: String) -> OnlineCountGuard {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        self.online_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(uuid.clone(), connection_id);
        OnlineCountGuard {
            sessions: Arc::clone(&self.online_sessions),
            uuid,
            connection_id,
        }
    }

    fn draft_snapshot(&self, uuid: &str) -> Option<MinecraftDraft> {
        self.with_draft_store(|drafts, active_players| drafts.get_or_create(uuid, active_players))
    }

    fn update_draft(
        &self,
        uuid: &str,
        apply: impl FnOnce(&mut MinecraftDraft),
    ) -> Option<MinecraftDraft> {
        self.with_draft_store(|drafts, active_players| drafts.update(uuid, active_players, apply))
    }

    fn with_draft_store<T>(
        &self,
        apply: impl FnOnce(&mut MinecraftDraftStore, &HashSet<String>) -> T,
    ) -> T {
        let online_sessions = self
            .online_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active_players = online_sessions.keys().cloned().collect::<HashSet<_>>();
        let mut drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        apply(&mut drafts, &active_players)
    }
}

impl PendingMapVideo {
    fn start(
        service: &StatusService,
        params: MapVideoParams,
        permit: OwnedSemaphorePermit,
        cancellation: CancellationToken,
    ) -> Result<Self, String> {
        let maps_y = ((params.maps_x * VIDEO_SOURCE_HEIGHT).saturating_add(VIDEO_SOURCE_WIDTH - 1)
            / VIDEO_SOURCE_WIDTH)
            .clamp(1, service.config.video.map_max_maps_y as usize);
        let wall = MapWall::new(service, params.maps_x, maps_y)
            .map_err(|error| format!("map wall setup failed: {error}"))?;
        let mut wall = wall;
        let mut setup_packets = wall
            .setup_packets(&service.world)
            .map_err(|error| format!("map wall setup failed: {error}"))?;
        setup_packets.push(
            chat_packet(
                &format!(
                    "\u{00a7}7Map wall: \u{00a7}f{}\u{00d7}{} \u{00a7}7maps (\u{00a7}f{}\u{00d7}{}\u{00a7}7 px), \u{00a7}f{}\u{00a7}7 fps",
                    params.maps_x,
                    maps_y,
                    params.maps_x * 128,
                    maps_y * 128,
                    params.fps
                ),
                Some("gray"),
            )
            .map_err(|error| format!("map wall announcement failed: {error}"))?,
        );
        let now = Instant::now();
        Ok(Self {
            control: VideoControl::new(),
            cancellation,
            permit: Some(permit),
            decoder: None,
            pending_open: None,
            pending_decode: None,
            wall: Some(wall),
            maps_x: params.maps_x,
            maps_y,
            fps: params.fps,
            contrast: params.contrast,
            dither: params.dither,
            decoded_frames: 0,
            emitted_frames: 0,
            previous_frame: None,
            pending_conversion: None,
            setup_packets: Some(setup_packets),
            countdown: Some(VIDEO_SETTLE_SECONDS),
            next_countdown: now,
            next_frame: now,
            finished: false,
        })
    }

    async fn next_event(
        &mut self,
        service: &StatusService,
        deadline: Instant,
    ) -> Result<VideoEvent, String> {
        if self.finished {
            return Ok(VideoEvent::Finished(Vec::new()));
        }
        if let Some(packets) = self.setup_packets.take() {
            return Ok(VideoEvent::Packets(packets));
        }
        if self.control.is_stopped() || self.cancellation.is_cancelled() {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        }
        if let Some(remaining) = self.countdown {
            if Instant::now() < self.next_countdown {
                tokio::select! {
                    _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                    _ = tokio::time::sleep_until(self.next_countdown) => {}
                }
            }
            if self.control.is_stopped() || self.cancellation.is_cancelled() {
                return Ok(VideoEvent::Finished(self.finish_packets()?));
            }
            let mut packets = vec![
                chat_packet(
                    &format!("\u{00a7}7Starting in {remaining}..."),
                    Some("gray"),
                )
                .map_err(|error| error.to_string())?,
            ];
            if remaining == 1 {
                self.countdown = None;
                packets.push(
                    chat_packet("\u{00a7}a\u{25b6} Playing!", Some("green"))
                        .map_err(|error| error.to_string())?,
                );
            } else {
                self.countdown = Some(remaining - 1);
                self.next_countdown = Instant::now() + Duration::from_secs(1);
            }
            return Ok(VideoEvent::Packets(packets));
        }
        while self.control.is_paused() {
            tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                _ = tokio::time::sleep(VIDEO_PAUSE_POLL) => {}
            }
            if self.control.is_stopped() {
                return Ok(VideoEvent::Finished(self.finish_packets()?));
            }
        }
        if Instant::now() < self.next_frame {
            tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                _ = tokio::time::sleep_until(self.next_frame) => {}
            }
        }
        if self.control.is_stopped() || self.cancellation.is_cancelled() {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        }
        if self.decoder.is_none() {
            if self.pending_open.is_none() {
                self.pending_open = Some(submit_video_open(
                    service,
                    &service.video_asset,
                    &self.cancellation,
                )?);
            }
            let pending = self
                .pending_open
                .as_mut()
                .ok_or_else(|| "video decoder open state was lost".to_owned())?;
            let decoder = tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                result = timeout_at(deadline, &mut pending.receiver) => result
                    .map_err(|_| "video decoder open deadline exceeded".to_owned())?
                    .map_err(|_| "video decoder open task was cancelled".to_owned())?,
            }?;
            let pending = self
                .pending_open
                .take()
                .ok_or_else(|| "video decoder open state was lost".to_owned())?;
            pending.cancellation.cancel();
            self.decoder = Some(decoder);
        }
        if self.pending_decode.is_none() {
            let decoder = self
                .decoder
                .take()
                .ok_or_else(|| "video decoder state was lost".to_owned())?;
            self.pending_decode = Some(submit_video_decode(
                service,
                decoder,
                self.decoded_frames,
                self.emitted_frames,
                self.fps,
                &self.cancellation,
            )?);
        }
        let pending = self
            .pending_decode
            .as_mut()
            .ok_or_else(|| "video decoder state was lost".to_owned())?;
        let decoded = tokio::select! {
            _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
            result = timeout_at(deadline, &mut pending.receiver) => result
                .map_err(|_| "video decode deadline exceeded".to_owned())?
                .map_err(|_| "video decode task was cancelled".to_owned())?,
        }?;
        let pending = self
            .pending_decode
            .take()
            .ok_or_else(|| "video decoder state was lost".to_owned())?;
        pending.cancellation.cancel();
        self.decoder = Some(decoded.decoder);
        self.decoded_frames = decoded.decoded_frames;
        self.emitted_frames = decoded.emitted_frames;
        let Some(rgb) = decoded.frame else {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        };
        let width = self.maps_x * 128;
        let height = self.maps_y * 128;
        if self.pending_conversion.is_none() {
            let contrast = self.contrast;
            let dither = self.dither;
            let backend =
                mail_render::resolve_render_backend_for_mode(service.mail_render_simd_mode);
            let conversion_cancellation = self.cancellation.child_token();
            let conversion_cancel_for_worker = conversion_cancellation.clone();
            let conversion_deadline = deadline.into_std();
            let receiver = service
                .video_conversion_pool
                .submit(move || {
                    let mut rgb = mail_render::resize_rgb24_box_with_backend(
                        &rgb,
                        mail_render::Rgb24ResizeSpec {
                            source_width: VIDEO_SOURCE_WIDTH,
                            source_height: VIDEO_SOURCE_HEIGHT,
                            output_width: width,
                            output_height: height,
                            max_output_bytes: width.saturating_mul(height).saturating_mul(3),
                        },
                        backend,
                        &conversion_cancel_for_worker,
                        conversion_deadline,
                    )
                    .map_err(|error| error.to_string())?;
                    if (contrast - 1.0).abs() > f32::EPSILON {
                        mail_render::apply_rgb24_contrast(
                            &mut rgb,
                            contrast,
                            backend,
                            &conversion_cancel_for_worker,
                            conversion_deadline,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    let representative_rgb =
                        crate::minecraft_block_palette::convert_rgb24_to_palette_rgb_with_backend(
                            &rgb,
                            width.saturating_mul(height),
                            &conversion_cancel_for_worker,
                            conversion_deadline,
                            backend,
                        )?;
                    mail_render::rgb24_to_minecraft_map_colors_with_dither_and_backend(
                        &representative_rgb,
                        width,
                        height,
                        width.saturating_mul(height),
                        dither,
                        backend,
                        &conversion_cancel_for_worker,
                        conversion_deadline,
                    )
                    .map_err(|error| error.to_string())
                })
                .map_err(|error| format!("video conversion queue is {error}"))?;
            self.pending_conversion = Some(PendingVideoConversion {
                cancellation: conversion_cancellation,
                receiver,
            });
        }
        let conversion = self
            .pending_conversion
            .as_mut()
            .ok_or_else(|| "video conversion state was lost".to_owned())?;
        let map_colors = tokio::select! {
            _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
            result = timeout_at(deadline, &mut conversion.receiver) => result
                .map_err(|_| "video conversion deadline exceeded".to_owned())?
                .map_err(|_| "video conversion task was cancelled".to_owned())?,
        }
        .map_err(|error| format!("video conversion failed: {error}"))?;
        let conversion = self
            .pending_conversion
            .take()
            .ok_or_else(|| "video conversion state was lost".to_owned())?;
        conversion.cancellation.cancel();
        let wall = self
            .wall
            .as_ref()
            .ok_or_else(|| "video wall was already torn down".to_owned())?;
        let mut packets = video_frame_packets(wall, &map_colors, &mut self.previous_frame)
            .map_err(|error| format!("video frame packetization failed: {error}"))?;
        if self.emitted_frames % 20 == 1 {
            let elapsed_seconds =
                ((self.emitted_frames as f64) / f64::from(self.fps)).round() as u64;
            packets.push(
                positioned_chat_packet(
                    &format!(
                        "\u{00a7}7\u{25b6} \u{00a7}f{} \u{00a7}7frames \u{00a7}8| \u{00a7}f{}s\u{00a7}7/\u{00a7}f{}s",
                        self.emitted_frames,
                        elapsed_seconds,
                        VIDEO_DURATION_SECONDS,
                    ),
                    2,
                )
                .map_err(|error| format!("video actionbar packet failed: {error}"))?,
            );
        }
        self.next_frame = Instant::now() + Duration::from_secs_f64(1.0 / f64::from(self.fps));
        Ok(VideoEvent::Packets(packets))
    }

    fn finish_packets(&mut self) -> Result<Vec<Vec<u8>>, String> {
        if self.finished {
            return Ok(Vec::new());
        }
        self.finished = true;
        if let Some(pending) = self.pending_open.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_decode.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_conversion.take() {
            pending.cancellation.cancel();
        }
        self.decoder.take();
        let wall = self.wall.take();
        self.permit.take();
        wall.map_or_else(|| Ok(Vec::new()), |wall| Ok(wall.teardown_packets()))
    }
}

impl BlockVideoWall {
    fn new(service: &StatusService, params: BlockVideoParams) -> Result<Self, String> {
        let config = &service.config.video;
        let min_x = config.center_x - (params.width as i32 / 2);
        let max_y = config.center_y + (params.height as i32 / 2);
        let min_y = max_y - params.height as i32 + 1;
        let wall_z = config.wall_z;
        let viewer_x = service.config.spawn.x as i32;
        let viewer_y = service.config.spawn.y as i32;
        let viewer_z = service.config.spawn.z as i32;
        let margin = config.clear_margin as i32;
        let clear_min_x = min_x.saturating_sub(margin);
        let clear_max_x = (min_x + params.width as i32 - 1).saturating_add(margin);
        let clear_min_y = min_y.saturating_sub(margin);
        let clear_max_y = max_y.saturating_add(margin);
        let clear_min_z = wall_z.saturating_sub(1);
        let clear_max_z = viewer_z;
        let clear_width = i64::from(clear_max_x) - i64::from(clear_min_x) + 1;
        let clear_height = i64::from(clear_max_y) - i64::from(clear_min_y) + 1;
        let clear_depth = i64::from(clear_max_z) - i64::from(clear_min_z) + 1;
        let region_blocks = clear_width
            .checked_mul(clear_height)
            .and_then(|value| value.checked_mul(clear_depth))
            .ok_or_else(|| "block video clear region size overflow".to_owned())?;
        if region_blocks <= 0 || region_blocks as usize > BLOCK_VIDEO_MAX_REGION_BLOCKS {
            return Err("block video clear region exceeds its memory budget".to_owned());
        }
        let min_cx = clear_min_x >> 4;
        let max_cx = clear_max_x >> 4;
        let min_cz = clear_min_z >> 4;
        let max_cz = clear_max_z >> 4;
        let chunk_count = i64::from(max_cx) - i64::from(min_cx) + 1;
        let chunk_depth = i64::from(max_cz) - i64::from(min_cz) + 1;
        let chunk_count = chunk_count
            .checked_mul(chunk_depth)
            .ok_or_else(|| "block video chunk count overflow".to_owned())?;
        if chunk_count <= 0 || chunk_count as usize > BLOCK_VIDEO_MAX_CHUNKS {
            return Err("block video clear area exceeds its chunk budget".to_owned());
        }

        let protect_radius = config.spawn_protect_radius as i64;
        let protect_radius_sq = protect_radius.saturating_mul(protect_radius);
        let mut saved_block_positions = Vec::new();
        let mut chunks = Vec::with_capacity(chunk_count as usize);
        for chunk_x in min_cx..=max_cx {
            for chunk_z in min_cz..=max_cz {
                let original = service
                    .world
                    .chunks()
                    .iter()
                    .find(|chunk| chunk.chunk_x == chunk_x && chunk.chunk_z == chunk_z)
                    .cloned()
                    .unwrap_or_else(|| minecraft_world::ChunkData {
                        chunk_x,
                        chunk_z,
                        sections: vec![None; 16],
                        biomes: vec![0; 256],
                        tile_entities: Vec::new(),
                    });
                let mut cleared = original.clone();
                let mut touched = false;
                for section_y in 0..16_usize {
                    let Some(section) =
                        cleared.sections.get_mut(section_y).and_then(Option::as_mut)
                    else {
                        continue;
                    };
                    if section.blocks.len() < 4096 {
                        return Err(
                            "Minecraft chunk section has an invalid block buffer".to_owned()
                        );
                    }
                    let section_bottom = (section_y as i32) << 4;
                    for local_y in 0..16_i32 {
                        let world_y = section_bottom + local_y;
                        if world_y < clear_min_y || world_y > clear_max_y {
                            continue;
                        }
                        for local_x in 0..16_i32 {
                            let world_x = (chunk_x << 4) + local_x;
                            if world_x < clear_min_x || world_x > clear_max_x {
                                continue;
                            }
                            for local_z in 0..16_i32 {
                                let world_z = (chunk_z << 4) + local_z;
                                if world_z < clear_min_z || world_z > clear_max_z {
                                    continue;
                                }
                                let dx = i64::from(world_x - viewer_x);
                                let dy = i64::from(world_y - viewer_y);
                                let dz = i64::from(world_z - viewer_z);
                                if dx * dx + dy * dy + dz * dz <= protect_radius_sq {
                                    continue;
                                }
                                let index = ((local_y as usize) << 8)
                                    | ((local_z as usize) << 4)
                                    | local_x as usize;
                                if section.blocks[index] != 0 {
                                    saved_block_positions
                                        .push(pack_block_position(world_x, world_y, world_z));
                                    section.blocks[index] = 0;
                                    touched = true;
                                }
                            }
                        }
                    }
                }
                chunks.push(BlockVideoChunk {
                    original,
                    cleared,
                    touched,
                });
            }
        }

        let min_sy = (min_y >> 4).clamp(0, 15) as usize;
        let max_sy = (max_y >> 4).clamp(0, 15) as usize;
        Ok(Self {
            width: params.width,
            height: params.height,
            min_x,
            max_y,
            wall_z,
            min_cx: min_x >> 4,
            max_cx: (min_x + params.width as i32 - 1) >> 4,
            min_sy,
            max_sy,
            saved_block_positions,
            chunks,
        })
    }

    fn setup_packets(&self) -> io::Result<Vec<Vec<u8>>> {
        self.chunks
            .iter()
            .filter(|chunk| chunk.touched)
            .map(|chunk| chunk_data_packet(&chunk.cleared, true))
            .collect()
    }

    fn frame_packets(
        &self,
        states: &[u16],
        previous: &mut Option<Vec<u16>>,
    ) -> io::Result<Vec<Vec<u8>>> {
        let expected = self.width.checked_mul(self.height).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "block video dimensions overflow",
            )
        })?;
        if states.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "block video palette frame length is invalid",
            ));
        }
        let first = previous.is_none();
        let previous_slice = previous.as_deref();
        let wall_chunk_z = self.wall_z >> 4;
        let local_z = (self.wall_z & 15) as usize;
        let mut packets = Vec::new();
        for chunk_x in self.min_cx..=self.max_cx {
            let Some(chunk) = self.chunks.iter().find(|chunk| {
                chunk.cleared.chunk_x == chunk_x && chunk.cleared.chunk_z == wall_chunk_z
            }) else {
                continue;
            };
            let mut sections = vec![None; 16];
            let mut any_dirty = false;
            for section_y in self.min_sy..=self.max_sy {
                let section_bottom = (section_y as i32) << 4;
                let mut dirty = first;
                if !dirty {
                    'pixels: for row in 0..self.height {
                        let world_y = self.max_y - row as i32;
                        if world_y < section_bottom || world_y >= section_bottom + 16 {
                            continue;
                        }
                        for column in 0..self.width {
                            let world_x = self.min_x + column as i32;
                            if (world_x >> 4) != chunk_x {
                                continue;
                            }
                            let index = row * self.width + column;
                            if previous_slice
                                .is_none_or(|previous| previous[index] != states[index])
                            {
                                dirty = true;
                                break 'pixels;
                            }
                        }
                    }
                }
                if !dirty {
                    continue;
                }
                let mut section = chunk
                    .cleared
                    .sections
                    .get(section_y)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or_else(|| minecraft_world::SectionData {
                        blocks: vec![0; 4096],
                        block_light: vec![0; 2048],
                        sky_light: Some(vec![0xff; 2048]),
                    });
                if section.blocks.len() < 4096 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Minecraft chunk section has an invalid block buffer",
                    ));
                }
                for row in 0..self.height {
                    let world_y = self.max_y - row as i32;
                    if world_y < section_bottom || world_y >= section_bottom + 16 {
                        continue;
                    }
                    let local_y = (world_y - section_bottom) as usize;
                    for column in 0..self.width {
                        let world_x = self.min_x + column as i32;
                        if (world_x >> 4) != chunk_x {
                            continue;
                        }
                        let local_x = (world_x & 15) as usize;
                        section.blocks[(local_y << 8) | (local_z << 4) | local_x] =
                            states[row * self.width + column];
                    }
                }
                *sections
                    .get_mut(section_y)
                    .expect("block video section index is bounded") = Some(section);
                any_dirty = true;
            }
            if any_dirty {
                packets.push(chunk_data_packet(
                    &minecraft_world::ChunkData {
                        chunk_x,
                        chunk_z: wall_chunk_z,
                        sections,
                        biomes: Vec::new(),
                        tile_entities: Vec::new(),
                    },
                    false,
                )?);
            }
        }
        *previous = Some(states.to_vec());
        Ok(packets)
    }

    fn teardown_packets(self) -> io::Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        // Java restores chunks by iterating a HashSet populated from the
        // HashMap keySet of cleared block positions. Reproduce both map
        // iterations so teardown bytes stay oracle-compatible.
        let saved_positions =
            minecraft_world::java_hash_map_order(self.saved_block_positions, |position| *position);
        let mut chunk_keys = Vec::new();
        for position in saved_positions {
            let chunk_x = unpack_block_position_x(position) >> 4;
            let chunk_z = unpack_block_position_z(position) >> 4;
            let key = pack_chunk_key(chunk_x, chunk_z);
            if !chunk_keys.contains(&key) {
                chunk_keys.push(key);
            }
        }
        let chunk_keys = minecraft_world::java_hash_map_order(chunk_keys, |key| *key);
        for key in chunk_keys {
            let Some(chunk) = self.chunks.iter().find(|chunk| {
                pack_chunk_key(chunk.original.chunk_x, chunk.original.chunk_z) == key
            }) else {
                continue;
            };
            packets.push(chunk_data_packet(&chunk.original, true)?);
            for tile_entity in &chunk.original.tile_entities {
                if let Some(action) = tile_entity_action(&tile_entity.id) {
                    packets.push(tile_entity_packet(tile_entity, action)?);
                }
            }
        }
        packets.push(chat_packet("\u{00a7}aBlocks restored.", Some("green"))?);
        Ok(packets)
    }
}

fn pack_chunk_key(chunk_x: i32, chunk_z: i32) -> i64 {
    (i64::from(chunk_x) << 32) | i64::from(u32::from_ne_bytes(chunk_z.to_ne_bytes()))
}

fn pack_block_position(x: i32, y: i32, z: i32) -> i64 {
    ((i64::from(x) & 0x3ff_ffff) << 38)
        | ((i64::from(y) & 0xfff) << 26)
        | (i64::from(z) & 0x3ff_ffff)
}

fn unpack_block_position_x(value: i64) -> i32 {
    (((value >> 38) & 0x3ff_ffff) as i32) << 6 >> 6
}

fn unpack_block_position_z(value: i64) -> i32 {
    ((value & 0x3ff_ffff) as i32) << 6 >> 6
}

impl PendingBlockVideo {
    fn start(
        service: &StatusService,
        params: BlockVideoParams,
        permit: OwnedSemaphorePermit,
        cancellation: CancellationToken,
    ) -> Result<Self, String> {
        let wall = BlockVideoWall::new(service, params)?;
        let mut setup_packets = vec![
            chat_packet("\u{00a7}7Preparing screen...", Some("gray"))
                .map_err(|error| error.to_string())?,
        ];
        setup_packets.extend(wall.setup_packets().map_err(|error| error.to_string())?);
        let now = Instant::now();
        Ok(Self {
            control: VideoControl::new(),
            cancellation,
            permit: Some(permit),
            decoder: None,
            pending_open: None,
            pending_decode: None,
            wall: Some(wall),
            decoded_frames: 0,
            emitted_frames: 0,
            pending_conversion: None,
            previous_frame: None,
            setup_packets: Some(setup_packets),
            countdown: Some(BLOCK_VIDEO_SETTLE_SECONDS),
            next_countdown: now,
            next_frame: now,
            fps: params.fps,
            contrast: params.contrast,
            finished: false,
        })
    }

    async fn next_event(
        &mut self,
        service: &StatusService,
        deadline: Instant,
    ) -> Result<VideoEvent, String> {
        if self.finished {
            return Ok(VideoEvent::Finished(Vec::new()));
        }
        if let Some(packets) = self.setup_packets.take() {
            return Ok(VideoEvent::Packets(packets));
        }
        if self.control.is_stopped() || self.cancellation.is_cancelled() {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        }
        if let Some(remaining) = self.countdown {
            if Instant::now() < self.next_countdown {
                tokio::select! {
                    _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                    _ = sleep_until(self.next_countdown) => {}
                }
            }
            if self.control.is_stopped() || self.cancellation.is_cancelled() {
                return Ok(VideoEvent::Finished(self.finish_packets()?));
            }
            let mut packets = vec![
                chat_packet(
                    &format!("\u{00a7}7Starting in {remaining}..."),
                    Some("gray"),
                )
                .map_err(|error| error.to_string())?,
            ];
            if remaining == 1 {
                self.countdown = None;
                packets.push(
                    chat_packet("\u{00a7}a\u{25b6} Playing!", Some("green"))
                        .map_err(|error| error.to_string())?,
                );
            } else {
                self.countdown = Some(remaining - 1);
                self.next_countdown = Instant::now() + Duration::from_secs(1);
            }
            return Ok(VideoEvent::Packets(packets));
        }
        while self.control.is_paused() {
            tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                _ = tokio::time::sleep(VIDEO_PAUSE_POLL) => {}
            }
            if self.control.is_stopped() {
                return Ok(VideoEvent::Finished(self.finish_packets()?));
            }
        }
        if Instant::now() < self.next_frame {
            tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                _ = sleep_until(self.next_frame) => {}
            }
        }
        if self.control.is_stopped() || self.cancellation.is_cancelled() {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        }
        if self.decoder.is_none() {
            if self.pending_open.is_none() {
                self.pending_open = Some(submit_video_open(
                    service,
                    &service.video_asset,
                    &self.cancellation,
                )?);
            }
            let pending = self
                .pending_open
                .as_mut()
                .ok_or_else(|| "video decoder open state was lost".to_owned())?;
            let decoder = tokio::select! {
                _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
                result = timeout_at(deadline, &mut pending.receiver) => result
                    .map_err(|_| "block video decoder open deadline exceeded".to_owned())?
                    .map_err(|_| "block video decoder open task was cancelled".to_owned())?,
            }?;
            let pending = self
                .pending_open
                .take()
                .ok_or_else(|| "video decoder open state was lost".to_owned())?;
            pending.cancellation.cancel();
            self.decoder = Some(decoder);
        }
        if self.pending_decode.is_none() {
            let decoder = self
                .decoder
                .take()
                .ok_or_else(|| "video decoder state was lost".to_owned())?;
            self.pending_decode = Some(submit_video_decode(
                service,
                decoder,
                self.decoded_frames,
                self.emitted_frames,
                self.fps,
                &self.cancellation,
            )?);
        }
        let pending = self
            .pending_decode
            .as_mut()
            .ok_or_else(|| "video decoder state was lost".to_owned())?;
        let decoded = tokio::select! {
            _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
            result = timeout_at(deadline, &mut pending.receiver) => result
                .map_err(|_| "block video decode deadline exceeded".to_owned())?
                .map_err(|_| "block video decode task was cancelled".to_owned())?,
        }?;
        let pending = self
            .pending_decode
            .take()
            .ok_or_else(|| "video decoder state was lost".to_owned())?;
        pending.cancellation.cancel();
        self.decoder = Some(decoded.decoder);
        self.decoded_frames = decoded.decoded_frames;
        self.emitted_frames = decoded.emitted_frames;
        let Some(rgb) = decoded.frame else {
            return Ok(VideoEvent::Finished(self.finish_packets()?));
        };
        if self.pending_conversion.is_none() {
            let wall = self
                .wall
                .as_ref()
                .ok_or_else(|| "block video wall was already torn down".to_owned())?;
            let width = wall.width;
            let height = wall.height;
            let contrast = self.contrast;
            let backend =
                mail_render::resolve_render_backend_for_mode(service.mail_render_simd_mode);
            let conversion_cancellation = self.cancellation.child_token();
            let conversion_cancel_for_worker = conversion_cancellation.clone();
            let conversion_deadline = deadline.into_std();
            let receiver = service
                .video_conversion_pool
                .submit(move || {
                    let mut resized = mail_render::resize_rgb24_box_with_backend(
                        &rgb,
                        mail_render::Rgb24ResizeSpec {
                            source_width: VIDEO_SOURCE_WIDTH,
                            source_height: VIDEO_SOURCE_HEIGHT,
                            output_width: width,
                            output_height: height,
                            max_output_bytes: width.saturating_mul(height).saturating_mul(3),
                        },
                        backend,
                        &conversion_cancel_for_worker,
                        conversion_deadline,
                    )
                    .map_err(|error| error.to_string())?;
                    mail_render::apply_rgb24_contrast(
                        &mut resized,
                        contrast,
                        backend,
                        &conversion_cancel_for_worker,
                        conversion_deadline,
                    )
                    .map_err(|error| error.to_string())?;
                    crate::minecraft_block_palette::convert_rgb24_to_states_with_backend(
                        &resized,
                        width.saturating_mul(height),
                        &conversion_cancel_for_worker,
                        conversion_deadline,
                        backend,
                    )
                })
                .map_err(|error| format!("block video conversion queue is {error}"))?;
            self.pending_conversion = Some(PendingBlockConversion {
                cancellation: conversion_cancellation,
                receiver,
            });
        }
        let conversion = self
            .pending_conversion
            .as_mut()
            .ok_or_else(|| "block video conversion state was lost".to_owned())?;
        let states = tokio::select! {
            _ = self.cancellation.cancelled() => return Ok(VideoEvent::Finished(self.finish_packets()?)),
            result = timeout_at(deadline, &mut conversion.receiver) => result
                .map_err(|_| "block video conversion deadline exceeded".to_owned())?
                .map_err(|_| "block video conversion task was cancelled".to_owned())?,
        }
        .map_err(|error| format!("block video conversion failed: {error}"))?;
        let conversion = self
            .pending_conversion
            .take()
            .ok_or_else(|| "block video conversion state was lost".to_owned())?;
        conversion.cancellation.cancel();
        let wall = self
            .wall
            .as_mut()
            .ok_or_else(|| "block video wall was already torn down".to_owned())?;
        let mut packets = wall
            .frame_packets(&states, &mut self.previous_frame)
            .map_err(|error| format!("block video chunk packetization failed: {error}"))?;
        if self.emitted_frames % 50 == 1 {
            packets.push(
                positioned_chat_packet(
                    &format!(
                        "\u{00a7}7\u{25b6} \u{00a7}f{} \u{00a7}7frames",
                        self.emitted_frames
                    ),
                    2,
                )
                .map_err(|error| format!("block video actionbar packet failed: {error}"))?,
            );
        }
        self.next_frame = Instant::now() + Duration::from_secs_f64(1.0 / f64::from(self.fps));
        Ok(VideoEvent::Packets(packets))
    }

    fn finish_packets(&mut self) -> Result<Vec<Vec<u8>>, String> {
        if self.finished {
            return Ok(Vec::new());
        }
        self.finished = true;
        if let Some(pending) = self.pending_open.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_decode.take() {
            pending.cancellation.cancel();
        }
        if let Some(pending) = self.pending_conversion.take() {
            pending.cancellation.cancel();
        }
        self.decoder.take();
        self.permit.take();
        self.wall.take().map_or_else(
            || Ok(Vec::new()),
            |wall| wall.teardown_packets().map_err(|e| e.to_string()),
        )
    }
}

fn chunk_data_packet(chunk: &minecraft_world::ChunkData, ground_up: bool) -> io::Result<Vec<u8>> {
    let (mask, data) = minecraft_world::serialize_chunk(chunk, true, ground_up);
    let mut packet = vec![0x21];
    packet.extend_from_slice(&chunk.chunk_x.to_be_bytes());
    packet.extend_from_slice(&chunk.chunk_z.to_be_bytes());
    packet.push(u8::from(ground_up));
    packet.extend_from_slice(&mask.to_be_bytes());
    write_byte_array(&mut packet, &data)?;
    Ok(packet)
}

fn tile_entity_action(id: &str) -> Option<u8> {
    match id {
        "Sign" => Some(9),
        "Banner" => Some(6),
        _ => None,
    }
}

fn tile_entity_packet(
    tile_entity: &minecraft_world::TileEntity,
    action: u8,
) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x35];
    write_block_position(&mut packet, tile_entity.x, tile_entity.y, tile_entity.z);
    packet.push(action);
    minecraft_world::write_nbt(Some(&tile_entity.nbt), &mut packet)?;
    Ok(packet)
}

struct OnlineCountGuard {
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    uuid: String,
    connection_id: u64,
}

impl Drop for OnlineCountGuard {
    fn drop(&mut self) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.get(&self.uuid) == Some(&self.connection_id) {
            sessions.remove(&self.uuid);
        }
    }
}

pub async fn serve_minecraft(
    config: Arc<RuntimeConfig>,
    database_pool: deadpool_postgres::Pool,
    outbound: Arc<OutboundService>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener =
        TcpListener::bind((config.listen.host.as_str(), config.listen.minecraft)).await?;
    let auth =
        AuthService::from_config(&config, database_pool.clone()).map_err(io::Error::other)?;
    let mailbox = MailboxService::from_config(&config, database_pool);
    let service = Arc::new(StatusService::with_services(
        &config.minecraft,
        config.mail_render.simd_mode,
        Arc::new(auth),
        Arc::new(mailbox),
        outbound,
    )?);
    serve_listener(listener, service, cancellation, MAX_CONNECTIONS).await
}

async fn serve_listener(
    listener: TcpListener,
    service: Arc<StatusService>,
    cancellation: CancellationToken,
    max_connections: usize,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections.clamp(1, MAX_CONNECTIONS)));
    let mut tasks = JoinSet::new();
    let mut retry_delay = ACCEPT_RETRY_MIN;
    let mut terminal_error = None;

    loop {
        while let Some(result) = tasks.try_join_next() {
            match result {
                Ok(Err(error)) => eprintln!("lmyzmail Minecraft connection failed: {error}"),
                Err(error) => eprintln!("lmyzmail Minecraft connection task failed: {error}"),
                Ok(Ok(())) => {}
            }
        }
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = match accepted {
            Ok(value) => {
                retry_delay = ACCEPT_RETRY_MIN;
                value
            }
            Err(error) if retryable_accept_error(&error) => {
                eprintln!(
                    "lmyzmail Minecraft accept failed; retrying in {} ms: {error}",
                    retry_delay.as_millis()
                );
                let delay = retry_delay;
                retry_delay = retry_delay.saturating_mul(2).min(ACCEPT_RETRY_MAX);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(delay) => continue,
                }
            }
            Err(error) => {
                terminal_error = Some(error);
                cancellation.cancel();
                break;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let deadline = Instant::now() + service.connection_timeout;
        let service = Arc::clone(&service);
        let child = cancellation.child_token();
        tasks.spawn(
            async move { handle_connection(stream, service, child, permit, deadline).await },
        );
    }

    if timeout(SHUTDOWN_DEADLINE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    terminal_error.map_or(Ok(()), Err)
}

async fn handle_connection(
    stream: TcpStream,
    service: Arc<StatusService>,
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
    mut deadline: Instant,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let client_ip = stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let (mut reader, mut writer) = stream.into_split();
    let mut state = ConnectionState::Handshake;
    let mut compression = None;
    let mut cipher = None;
    let mut pending_online = None;
    let mut _online_guard = None;
    let mut player_position = (
        service.config.spawn.x,
        service.config.spawn.y,
        service.config.spawn.z,
    );
    let mut hologram_entity_base = 0;
    let mut next_position_check = None;
    let mut next_hologram_teleport = None;
    let mut next_time_update = None;
    let mut pending_email = None;
    let mut authenticated: Option<(String, Zeroizing<String>)> = None;
    let mut player_username = String::new();
    let mut player_uuid = String::new();
    let mut draft = MinecraftDraft::default();
    let mut open_menu_window_id = None;
    let mut open_video_menu_window_id = None;
    let mut logout_confirm_window_id = None;
    let mut open_folder_gui: Option<FolderGui> = None;
    let mut pending_folder_load: Option<PendingFolderLoad> = None;
    let mut pending_mail_render: Option<PendingMailRender> = None;
    let mut pending_outbound_send: Option<PendingOutboundSend> = None;
    let mut pending_map_video: Option<PendingMapVideo> = None;
    let mut pending_block_video: Option<PendingBlockVideo> = None;
    let mut active_mail_view: Option<ActiveMailView> = None;
    let mut render_settings = RenderSettings::default();
    let mut render_settings_pending = false;
    let mut held_slot = 0_i16;
    let mut last_hotbar_click = None;

    loop {
        let (raw_frame_result, next_deadline) = if state == ConnectionState::Play {
            let position_at = next_position_check.expect("PLAY position timer was not armed");
            let hologram_at = next_hologram_teleport.expect("PLAY hologram timer was not armed");
            let time_update_at = next_time_update.expect("PLAY time timer was not armed");
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                outbound_result = async {
                    pending_outbound_send
                        .as_mut()
                        .expect("guarded outbound send was missing")
                        .future
                        .as_mut()
                        .await
                }, if pending_outbound_send.is_some() => {
                    let mut pending = pending_outbound_send
                        .take()
                        .expect("completed outbound send was missing");
                    let (responses, keep_pending) = outbound_step_packets(
                        &service,
                        &mut pending,
                        outbound_result,
                        &player_uuid,
                        &mut draft,
                    )?;
                    if keep_pending {
                        pending_outbound_send = Some(pending);
                    }
                    let write_deadline = Instant::now() + service.connection_timeout;
                    deadline = write_deadline;
                    if responses.is_empty() {
                        continue;
                    }
                    if let Err(error) = write_packet_list(
                        &mut writer,
                        &service,
                        responses,
                        compression,
                        cipher.as_mut(),
                        write_deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                    continue;
                }
                folder_result = async {
                    pending_folder_load
                        .as_mut()
                        .expect("guarded folder load was missing")
                        .future
                        .as_mut()
                        .await
                }, if pending_folder_load.is_some() => {
                    let pending = pending_folder_load
                        .take()
                        .expect("completed folder load was missing");
                    let responses = match (pending.action, folder_result) {
                        (FolderLoadAction::Open { folder }, Ok(page)) => {
                            let gui = FolderGui {
                                window_id: service.next_window_id(),
                                folder,
                                page,
                            };
                            let packets = folder_gui_packets(&gui)?;
                            open_folder_gui = Some(gui);
                            packets
                        }
                        (FolderLoadAction::Open { .. }, Err(error)) => vec![chat_packet(
                            &format!("\u{00a7}cFailed to load: {error}"),
                            Some("red"),
                        )?],
                        (
                            FolderLoadAction::Refresh { window_id, folder },
                            Ok(page),
                        ) => {
                            if let Some(gui) = open_folder_gui.as_mut().filter(|gui| {
                                gui.window_id == window_id && gui.folder == folder
                            }) {
                                gui.page = page;
                                vec![folder_contents_packet(gui)?]
                            } else {
                                Vec::new()
                            }
                        }
                        (FolderLoadAction::Refresh { window_id, folder }, Err(error)) => {
                            if open_folder_gui.as_ref().is_some_and(|gui| {
                                gui.window_id == window_id && gui.folder == folder
                            }) {
                                vec![chat_packet(
                                    &format!("\u{00a7}cFailed: {error}"),
                                    Some("red"),
                                )?]
                            } else {
                                Vec::new()
                            }
                        }
                    };
                    if let Err(error) = write_packet_list(
                        &mut writer,
                        &service,
                        responses,
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                    continue;
                }
                render_result = async {
                    pending_mail_render
                        .as_mut()
                        .expect("guarded mail render was missing")
                        .future
                        .as_mut()
                        .await
                }, if pending_mail_render.is_some() => {
                    let pending = pending_mail_render
                        .take()
                        .expect("completed mail render was missing");
                    let responses = match render_result {
                        Ok(result) if result.pages().is_empty() => vec![chat_packet(
                            "\u{00a7}cEmail rendered with no content",
                            Some("red"),
                        )?],
                        Ok(result) => {
                            let maps_x = usize::from(result.pages()[0].maps_x());
                            let maps_y = result
                                .pages()
                                .iter()
                                .map(|page| usize::from(page.maps_y()))
                                .max()
                                .unwrap_or(1);
                            let mut wall = MapWall::new(&service, maps_x, maps_y)?;
                            let mut packets = wall.setup_packets(&service.world)?;
                            packets.extend(mail_view_page_packets(
                                &wall,
                                &result.pages()[0],
                            )?);
                            packets.extend(mail_view_started_packets(result.pages().len())?);
                            active_mail_view = Some(ActiveMailView {
                                wall,
                                result,
                                current_page: 0,
                            });
                            packets
                        }
                        Err(MailRenderFailure::Busy) => vec![chat_packet(
                            "\u{00a7}cServer busy rendering. Try again later.",
                            Some("red"),
                        )?],
                        Err(MailRenderFailure::Unavailable) => vec![chat_packet(
                            "\u{00a7}cMail rendering not available",
                            Some("red"),
                        )?],
                        Err(MailRenderFailure::Read(error)) => vec![chat_packet(
                            &format!("\u{00a7}cFailed to read email: {error}"),
                            Some("red"),
                        )?],
                        Err(MailRenderFailure::Render(error)) => vec![chat_packet(
                            &format!("\u{00a7}cRender error: {error}"),
                            Some("red"),
                        )?],
                        Err(MailRenderFailure::Cancelled) => Vec::new(),
                    };
                    drop(pending);
                    if let Err(error) = write_packet_list(
                        &mut writer,
                        &service,
                        responses,
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                    continue;
                }
                video_result = async {
                    pending_map_video
                        .as_mut()
                        .expect("guarded map video was missing")
                        .next_event(&service, deadline)
                        .await
                }, if pending_map_video.is_some() => {
                    let (result, failure) = match video_result {
                        Ok(result) => (result, None),
                        Err(error) => {
                            let Some(video) = pending_map_video.as_mut() else {
                                continue;
                            };
                            (
                                VideoEvent::Finished(video.finish_packets().unwrap_or_default()),
                                Some(error),
                            )
                        }
                    };
                    let finished = matches!(result, VideoEvent::Finished(_));
                    let mut responses = match result {
                        VideoEvent::Packets(packets) | VideoEvent::Finished(packets) => packets,
                    };
                    if let Some(error) = failure.as_ref() {
                        responses.push(chat_packet(
                            &format!("\u{00a7}cMap video error: {error}"),
                            Some("red"),
                        )?);
                    }
                    if finished {
                        pending_map_video.take();
                        responses.extend(restore_default_hotbar_packets()?);
                        if let Some((email, _)) = authenticated.as_ref() {
                            responses.extend(authenticated_scoreboard_packets(
                                &player_username,
                                email,
                                render_settings,
                            )?);
                            // Java's worker completion and session callback each
                            // refresh the authenticated scoreboard.
                            responses.extend(authenticated_scoreboard_packets(
                                &player_username,
                                email,
                                render_settings,
                            )?);
                        }
                        if failure.is_none() {
                            responses.push(chat_packet(
                                "\u{00a7}aMap video playback finished!",
                                Some("green"),
                            )?);
                        }
                    }
                    if let Err(write_error) = write_packet_list(
                        &mut writer,
                        &service,
                        responses,
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(write_error);
                    }
                    continue;
                }
                block_video_result = async {
                    pending_block_video
                        .as_mut()
                        .expect("guarded block video was missing")
                        .next_event(&service, deadline)
                        .await
                }, if pending_block_video.is_some() => {
                    let (result, failure) = match block_video_result {
                        Ok(result) => (result, None),
                        Err(error) => {
                            let Some(video) = pending_block_video.as_mut() else {
                                continue;
                            };
                            (
                                VideoEvent::Finished(video.finish_packets().unwrap_or_default()),
                                Some(error),
                            )
                        }
                    };
                    let finished = matches!(result, VideoEvent::Finished(_));
                    let mut responses = match result {
                        VideoEvent::Packets(packets) | VideoEvent::Finished(packets) => packets,
                    };
                    if let Some(error) = failure.as_ref() {
                        responses.push(chat_packet(
                            &format!("\u{00a7}cBlock video error: {error}"),
                            Some("red"),
                        )?);
                    }
                    if finished {
                        pending_block_video.take();
                        responses.extend(restore_default_hotbar_packets()?);
                        if let Some((email, _)) = authenticated.as_ref() {
                            responses.extend(authenticated_scoreboard_packets(
                                &player_username,
                                email,
                                render_settings,
                            )?);
                            // Java's worker completion and session callback each
                            // refresh the authenticated scoreboard.
                            responses.extend(authenticated_scoreboard_packets(
                                &player_username,
                                email,
                                render_settings,
                            )?);
                        }
                        if failure.is_none() {
                            responses.push(chat_packet(
                                "\u{00a7}aBlock video playback finished!",
                                Some("green"),
                            )?);
                        }
                    }
                    if let Err(write_error) = write_packet_list(
                        &mut writer,
                        &service,
                        responses,
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(write_error);
                    }
                    continue;
                }
                _ = sleep_until(position_at) => {
                    next_position_check = Some(position_at + POSITION_CHECK_INTERVAL);
                    let spawn = &service.config.spawn;
                    let dx = player_position.0 - spawn.x;
                    let dy = player_position.1 - spawn.y;
                    let dz = player_position.2 - spawn.z;
                    if dx * dx + dy * dy + dz * dz > MAX_SPAWN_DISTANCE * MAX_SPAWN_DISTANCE {
                        for packet in teleport_back_packets(&service.config)? {
                            if let Err(error) = write_packet(
                                &mut writer,
                                &service,
                                packet,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                        }
                        player_position = (spawn.x, spawn.y, spawn.z);
                    }
                    continue;
                }
                _ = sleep_until(hologram_at) => {
                    next_hologram_teleport = Some(hologram_at + HOLOGRAM_TELEPORT_INTERVAL);
                    for packet in hologram_teleport_packets(hologram_entity_base) {
                        if let Err(error) = write_packet(
                            &mut writer,
                            &service,
                            packet,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                    continue;
                }
                _ = sleep_until(time_update_at) => {
                    next_time_update = Some(time_update_at + TIME_UPDATE_INTERVAL);
                    if let Err(error) = write_packet(
                        &mut writer,
                        &service,
                        time_update_packet(),
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                    continue;
                }
                result = read_connection_frame(
                    &mut reader,
                    cipher.as_mut(),
                    state,
                    deadline,
                    service.connection_timeout,
                    &cancellation,
                ) => result,
            }
        } else {
            read_connection_frame(
                &mut reader,
                cipher.as_mut(),
                state,
                deadline,
                service.connection_timeout,
                &cancellation,
            )
            .await
        };
        deadline = next_deadline;
        let raw_frame = match raw_frame_result {
            Ok(Some(frame)) => frame,
            Ok(None)
            | Err(ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed) => {
                return Ok(());
            }
            Err(ProtocolError::Io(error)) if connection_ended(&error) => return Ok(()),
            Err(ProtocolError::Io(error)) => return Err(error),
        };
        let frame = match compression {
            Some(threshold) => match decode_compression_envelope(
                &service,
                raw_frame,
                threshold,
                deadline,
                &cancellation,
            )
            .await
            {
                Ok(frame) => frame,
                Err(
                    ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed,
                ) => {
                    return Ok(());
                }
                Err(ProtocolError::Io(error)) if connection_ended(&error) => return Ok(()),
                Err(ProtocolError::Io(error)) => return Err(error),
            },
            None => raw_frame,
        };

        let mut packet = PacketReader::new(&frame);
        let packet_id = match packet.read_varint() {
            Ok(value) => value,
            Err(()) => return Ok(()),
        };
        match state {
            ConnectionState::Handshake => {
                if packet_id != 0 {
                    continue;
                }
                if parse_handshake(&mut packet).is_err() {
                    return Ok(());
                }
                match packet.read_varint() {
                    Ok(1) => state = ConnectionState::Status,
                    Ok(2) => state = ConnectionState::Login,
                    Ok(_) | Err(_) => return Ok(()),
                }
            }
            ConnectionState::Status => match packet_id {
                0 => {
                    let frame = service.current_status_frame()?;
                    if let Err(error) =
                        write_bytes(&mut writer, &frame, None, deadline, &cancellation).await
                    {
                        return finish_write_error(error);
                    }
                }
                1 => {
                    let Ok(payload) = packet.read_i64() else {
                        return Ok(());
                    };
                    let mut packet = [0_u8; 9];
                    packet[0] = 1;
                    packet[1..].copy_from_slice(&payload.to_be_bytes());
                    let pong = encode_frame(&packet)?;
                    if let Err(error) =
                        write_bytes(&mut writer, &pong, None, deadline, &cancellation).await
                    {
                        return finish_write_error(error);
                    }
                    let _ = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => Ok(()),
                        result = timeout_at(deadline, writer.shutdown()) => result
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Minecraft shutdown timed out"))?,
                    };
                    return Ok(());
                }
                _ => {}
            },
            ConnectionState::Login => match packet_id {
                0 => {
                    let Ok(username) = packet.read_string(16) else {
                        return Ok(());
                    };
                    if let Some(frame) = service.rejection_frame(&username) {
                        if let Err(error) =
                            write_bytes(&mut writer, frame, None, deadline, &cancellation).await
                        {
                            return finish_write_error(error);
                        }
                        shutdown_stream(&mut writer, deadline, &cancellation).await?;
                        return Ok(());
                    }
                    if service.config.online_mode {
                        let Some(online) = service.online_mode.as_ref() else {
                            return Ok(());
                        };
                        let mut verify_token = [0_u8; VERIFY_TOKEN_BYTES];
                        fill_random(&mut verify_token).map_err(io::Error::other)?;
                        let frame =
                            encryption_request_frame(&online.public_key_der, &verify_token)?;
                        if let Err(error) =
                            write_bytes(&mut writer, &frame, None, deadline, &cancellation).await
                        {
                            return finish_write_error(error);
                        }
                        pending_online = Some(PendingOnlineLogin {
                            username,
                            verify_token,
                        });
                        continue;
                    }
                    let uuid = offline_uuid(&username)?;
                    match complete_login(
                        &mut writer,
                        &service,
                        uuid.clone(),
                        &username,
                        None,
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok((active_compression, online_guard, entity_base)) => {
                            compression = active_compression;
                            _online_guard = Some(online_guard);
                            hologram_entity_base = entity_base;
                            player_username = username;
                            player_uuid = uuid;
                            let now = Instant::now();
                            next_position_check = Some(now + POSITION_CHECK_INTERVAL);
                            next_hologram_teleport = Some(now + HOLOGRAM_TELEPORT_INTERVAL);
                            next_time_update = Some(now + TIME_UPDATE_INTERVAL);
                            state = ConnectionState::Play;
                        }
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) if connection_ended(&error) => {
                            return Ok(());
                        }
                        Err(ProtocolError::Io(error)) => return Err(error),
                    }
                }
                1 => {
                    let Some(pending) = pending_online.take() else {
                        continue;
                    };
                    let Ok(encrypted_secret) = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES)
                    else {
                        return Ok(());
                    };
                    let Ok(encrypted_token) = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES)
                    else {
                        return Ok(());
                    };
                    let Some(online) = service.online_mode.as_ref() else {
                        return Ok(());
                    };
                    let mut secret = match decrypt_online_response(
                        online,
                        encrypted_secret,
                        encrypted_token,
                        pending.verify_token,
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok(secret) => secret,
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) => return Err(error),
                    };
                    let mut active_cipher = match MinecraftCipher::new(&secret) {
                        Ok(cipher) => cipher,
                        Err(_) => {
                            secret.zeroize();
                            return Ok(());
                        }
                    };
                    let auth = authenticate_online(
                        online,
                        &pending.username,
                        &secret,
                        deadline,
                        &cancellation,
                    )
                    .await;
                    secret.zeroize();
                    let profile = match auth {
                        Ok(profile) => profile,
                        Err(error) => {
                            let packet = authentication_failure_packet(error.message())?;
                            let frame = encode_frame(&packet)?;
                            let _ = write_bytes(
                                &mut writer,
                                &frame,
                                Some(&mut active_cipher),
                                deadline,
                                &cancellation,
                            )
                            .await;
                            let _ = shutdown_stream(&mut writer, deadline, &cancellation).await;
                            return Ok(());
                        }
                    };
                    let profile_uuid = profile.uuid.clone();
                    match complete_login(
                        &mut writer,
                        &service,
                        profile.uuid,
                        &profile.name,
                        Some(&mut active_cipher),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok((active_compression, online_guard, entity_base)) => {
                            compression = active_compression;
                            cipher = Some(active_cipher);
                            _online_guard = Some(online_guard);
                            hologram_entity_base = entity_base;
                            player_username = profile.name;
                            player_uuid = profile_uuid;
                            let now = Instant::now();
                            next_position_check = Some(now + POSITION_CHECK_INTERVAL);
                            next_hologram_teleport = Some(now + HOLOGRAM_TELEPORT_INTERVAL);
                            next_time_update = Some(now + TIME_UPDATE_INTERVAL);
                            state = ConnectionState::Play;
                        }
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) if connection_ended(&error) => {
                            return Ok(());
                        }
                        Err(ProtocolError::Io(error)) => return Err(error),
                    }
                }
                _ => {}
            },
            ConnectionState::Play => match packet_id {
                0x02 | 0x08 => {
                    let mut block_position = None;
                    let primary_interaction = if packet_id == 0x02 {
                        let Ok((_target_id, action)) = read_use_entity(&mut packet) else {
                            return Ok(());
                        };
                        action == 0
                    } else {
                        let Ok((x, y, z, _face)) = read_player_block_placement(&mut packet) else {
                            return Ok(());
                        };
                        block_position = Some((x, y, z));
                        true
                    };
                    if block_position == Some(OUTBOUND_SEND_BUTTON) {
                        let responses = if let Some((email, _)) = authenticated.as_ref() {
                            if pending_outbound_send.is_some() {
                                vec![chat_packet(
                                    "§cEmail send already in progress.",
                                    Some("red"),
                                )?]
                            } else {
                                let (responses, pending) =
                                    start_outbound_send(&service, email, &draft, &cancellation)?;
                                pending_outbound_send = pending;
                                responses
                            }
                        } else {
                            vec![chat_packet(
                                "§cYou must be logged in to send email!",
                                Some("red"),
                            )?]
                        };
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        continue;
                    }
                    if primary_interaction && matches!(held_slot, 3 | 4) {
                        let responses = if let Some(video) = pending_map_video.as_ref() {
                            if held_slot == 3 {
                                let paused = video.control.toggle_pause();
                                vec![chat_packet(
                                    if paused {
                                        "\u{00a7}7\u{23f8} Paused"
                                    } else {
                                        "\u{00a7}7\u{25b6} Resumed"
                                    },
                                    None,
                                )?]
                            } else {
                                video.control.stop();
                                vec![chat_packet(
                                    "\u{00a7}aStopping video playback...",
                                    Some("green"),
                                )?]
                            }
                        } else if let Some(video) = pending_block_video.as_ref() {
                            if held_slot == 3 {
                                let paused = video.control.toggle_pause();
                                vec![chat_packet(
                                    if paused {
                                        "\u{00a7}7\u{23f8} Paused"
                                    } else {
                                        "\u{00a7}7\u{25b6} Resumed"
                                    },
                                    None,
                                )?]
                            } else {
                                video.control.stop();
                                vec![chat_packet(
                                    "\u{00a7}aStopping video playback...",
                                    Some("green"),
                                )?]
                            }
                        } else {
                            Vec::new()
                        };
                        if responses.is_empty() {
                            continue;
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        continue;
                    }
                    let action = hotbar_action(
                        active_mail_view.is_some(),
                        authenticated.is_some(),
                        held_slot,
                        primary_interaction,
                        Instant::now(),
                        &mut last_hotbar_click,
                    );
                    let responses = match action {
                        HotbarAction::None => Vec::new(),
                        HotbarAction::PreviousPage => mail_view_navigation_packets(
                            active_mail_view
                                .as_mut()
                                .expect("previous-page action lost its mail view"),
                            -1,
                        )?,
                        HotbarAction::NextPage => mail_view_navigation_packets(
                            active_mail_view
                                .as_mut()
                                .expect("next-page action lost its mail view"),
                            1,
                        )?,
                        HotbarAction::CloseMailView => {
                            let Some((email, _)) = authenticated.as_ref() else {
                                return Ok(());
                            };
                            let view = active_mail_view
                                .take()
                                .expect("close action lost its mail view");
                            mail_view_close_packets(view, &player_username, email, render_settings)?
                        }
                        HotbarAction::OpenMainMenu => {
                            let mut packets = Vec::new();
                            let window_id = service.next_window_id();
                            let replaced_gui = open_menu_window_id.take().is_some()
                                | logout_confirm_window_id.take().is_some()
                                | open_video_menu_window_id.take().is_some()
                                | open_folder_gui.take().is_some();
                            pending_folder_load = None;
                            if replaced_gui {
                                packets.extend(restore_gui_hotbar_packets(
                                    active_mail_view.is_some(),
                                )?);
                            }
                            packets.extend(main_menu_packets(window_id, render_settings)?);
                            open_menu_window_id = Some(window_id);
                            logout_confirm_window_id = None;
                            packets
                        }
                    };
                    if !responses.is_empty()
                        && let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                    {
                        return finish_write_error(error);
                    }
                }
                0x01 => {
                    let Ok(mut message) = packet.read_string(100) else {
                        return Ok(());
                    };
                    if pending_email.is_none() && authenticated.is_none() {
                        let (email, responses) = awaiting_email_responses(&message)?;
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        pending_email = email;
                    } else if let Some(email) = pending_email.clone() {
                        if let Some(remaining) = service.auth_limiter.locked_remaining(&client_ip) {
                            let responses = vec![chat_packet(
                                &format!(
                                    "\u{00a7}cToo many failed attempts. Try again in {remaining} seconds."
                                ),
                                Some("red"),
                            )?];
                            if let Err(error) = write_packet_list(
                                &mut writer,
                                &service,
                                responses,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                            message.zeroize();
                            continue;
                        }
                        let Some(auth) = service.auth.as_ref().cloned() else {
                            return Ok(());
                        };
                        let auth_cancellation = cancellation.child_token();
                        let result = {
                            let auth_future = auth.login_with_cancellation(
                                &email,
                                &message,
                                &client_ip,
                                Some("Minecraft"),
                                &auth_cancellation,
                            );
                            tokio::pin!(auth_future);
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => {
                                    auth_cancellation.cancel();
                                    let _ = auth_future.await;
                                    None
                                }
                                result = timeout_at(deadline, &mut auth_future) => match result {
                                    Ok(result) => Some(result),
                                    Err(_) => {
                                        auth_cancellation.cancel();
                                        let _ = auth_future.await;
                                        None
                                    }
                                },
                            }
                        };
                        message.zeroize();
                        let Some(result) = result else {
                            return Ok(());
                        };
                        auth_cancellation.cancel();
                        let mut close_after_write = false;
                        let responses = match result {
                            Ok((LoginOutcome::Invalid { .. }, _)) => {
                                let (locked, remaining) =
                                    service.auth_limiter.record_failure(&client_ip);
                                if locked {
                                    close_after_write = true;
                                    vec![
                                        chat_packet(
                                            "\u{00a7}c\u{00a7}lToo many failed attempts!",
                                            Some("red"),
                                        )?,
                                        chat_packet(
                                            &format!(
                                                "\u{00a7}cLocked out for {} seconds.",
                                                service.config.auth_lockout_seconds
                                            ),
                                            Some("red"),
                                        )?,
                                        disconnect_play_packet(
                                            "Too many failed authentication attempts",
                                        )?,
                                    ]
                                } else {
                                    vec![
                                        chat_packet(
                                            &format!(
                                                "\u{00a7}cAuthentication failed. {remaining} attempt(s) remaining."
                                            ),
                                            Some("red"),
                                        )?,
                                        chat_packet(
                                            "\u{00a7}aPlease enter your password:",
                                            Some("green"),
                                        )?,
                                    ]
                                }
                            }
                            Ok((LoginOutcome::Success, Some(login))) => {
                                service.auth_limiter.clear(&client_ip);
                                pending_email = None;
                                authenticated = Some((email.clone(), Zeroizing::new(login.token)));
                                let Some(restored_draft) = service.draft_snapshot(&player_uuid)
                                else {
                                    return Ok(());
                                };
                                draft = restored_draft;
                                authenticated_packets_with_draft(
                                    &player_username,
                                    &email,
                                    render_settings,
                                    &draft,
                                )?
                            }
                            Ok((LoginOutcome::Success, None))
                            | Err(AuthError::Cancelled)
                            | Err(AuthError::Database(_))
                            | Err(AuthError::OutcomeUnknown)
                            | Err(AuthError::Unavailable)
                            | Err(AuthError::InvalidInput(_)) => vec![
                                chat_packet(
                                    "\u{00a7}cAuthentication service unavailable.",
                                    Some("red"),
                                )?,
                                chat_packet("\u{00a7}aPlease enter your password:", Some("green"))?,
                            ],
                        };
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        if close_after_write {
                            shutdown_stream(&mut writer, deadline, &cancellation).await?;
                            return Ok(());
                        }
                    } else if let Some((authenticated_email, _)) = authenticated.as_ref() {
                        let command = java_trim(&message);
                        if active_mail_view.is_some() {
                            let parts = command.split_ascii_whitespace().collect::<Vec<_>>();
                            let subcommand = parts
                                .get(1)
                                .map(|value| value.to_ascii_lowercase())
                                .unwrap_or_default();
                            let responses = if command.starts_with("/mail") {
                                match subcommand.as_str() {
                                    "next" | "n" => mail_view_navigation_packets(
                                        active_mail_view
                                            .as_mut()
                                            .expect("active mail view disappeared"),
                                        1,
                                    )?,
                                    "prev" | "p" | "previous" => mail_view_navigation_packets(
                                        active_mail_view
                                            .as_mut()
                                            .expect("active mail view disappeared"),
                                        -1,
                                    )?,
                                    "close" | "c" | "exit" => {
                                        let view = active_mail_view
                                            .take()
                                            .expect("active mail view disappeared");
                                        mail_view_close_packets(
                                            view,
                                            &player_username,
                                            authenticated_email,
                                            render_settings,
                                        )?
                                    }
                                    "rendersize" | "rs" => {
                                        if let Some((packets, opens_editor)) =
                                            render_size_command_packets(
                                                &message,
                                                &mut render_settings,
                                                &player_username,
                                                authenticated_email,
                                            )?
                                        {
                                            render_settings_pending |= opens_editor;
                                            packets
                                        } else {
                                            Vec::new()
                                        }
                                    }
                                    _ => {
                                        let view = active_mail_view
                                            .as_ref()
                                            .expect("active mail view disappeared");
                                        vec![chat_packet(
                                            &format!(
                                                "\u{00a7}ePage \u{00a7}f{}\u{00a7}e/\u{00a7}f{} \u{00a7}e\u{2014} hotbar arrows or /mail next|prev|close",
                                                view.current_page + 1,
                                                view.result.pages().len(),
                                            ),
                                            None,
                                        )?]
                                    }
                                }
                            } else if command.starts_with("/stuck") {
                                stuck_command_packets(&service.config)?
                            } else {
                                vec![chat_packet(
                                    "\u{00a7}7Use hotbar items or \u{00a7}f/mail close \u{00a7}7to exit",
                                    Some("gray"),
                                )?]
                            };
                            message.zeroize();
                            if let Err(error) = write_packet_list(
                                &mut writer,
                                &service,
                                responses,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                            continue;
                        }
                        if command
                            .split(java_regex_space)
                            .next()
                            .is_some_and(|name| name.eq_ignore_ascii_case("/video"))
                        {
                            let video_command = parse_video_command(command, &service.config);
                            let responses = match video_command {
                                ParsedVideoCommand::Usage => video_usage_packets()?,
                                ParsedVideoCommand::Error(error) => {
                                    vec![chat_packet(&format!("\u{00a7}c{error}"), Some("red"))?]
                                }
                                ParsedVideoCommand::StartMap(params) => start_map_video_packets(
                                    &service,
                                    &mut pending_map_video,
                                    &pending_block_video,
                                    params,
                                    &cancellation,
                                )?,
                                ParsedVideoCommand::StartBlock(params) => {
                                    start_block_video_packets(
                                        &service,
                                        &mut pending_map_video,
                                        &mut pending_block_video,
                                        params,
                                        &cancellation,
                                    )?
                                }
                                ParsedVideoCommand::Stop => {
                                    if let Some(video) = pending_map_video.as_ref() {
                                        video.control.stop();
                                        vec![chat_packet(
                                            "\u{00a7}aStopping video playback...",
                                            Some("green"),
                                        )?]
                                    } else if let Some(video) = pending_block_video.as_ref() {
                                        video.control.stop();
                                        vec![chat_packet(
                                            "\u{00a7}aStopping video playback...",
                                            Some("green"),
                                        )?]
                                    } else {
                                        vec![chat_packet(
                                            "\u{00a7}cNo video is currently playing.",
                                            Some("red"),
                                        )?]
                                    }
                                }
                                ParsedVideoCommand::Pause => {
                                    if let Some(video) = pending_map_video.as_ref() {
                                        let paused = video.control.toggle_pause();
                                        vec![chat_packet(
                                            if paused {
                                                "\u{00a7}7\u{23f8} Paused"
                                            } else {
                                                "\u{00a7}7\u{25b6} Resumed"
                                            },
                                            None,
                                        )?]
                                    } else if let Some(video) = pending_block_video.as_ref() {
                                        let paused = video.control.toggle_pause();
                                        vec![chat_packet(
                                            if paused {
                                                "\u{00a7}7\u{23f8} Paused"
                                            } else {
                                                "\u{00a7}7\u{25b6} Resumed"
                                            },
                                            None,
                                        )?]
                                    } else {
                                        vec![chat_packet(
                                            "\u{00a7}cNo video is currently playing.",
                                            Some("red"),
                                        )?]
                                    }
                                }
                            };
                            message.zeroize();
                            if let Err(error) = write_packet_list(
                                &mut writer,
                                &service,
                                responses,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                            continue;
                        }
                        let command_end = command.find(java_regex_space).unwrap_or(command.len());
                        let menu_window_id = command[..command_end]
                            .eq_ignore_ascii_case("/menu")
                            .then(|| service.next_window_id());
                        let mut responses = Vec::new();
                        if menu_window_id.is_some() {
                            let replaced_gui = open_menu_window_id.take().is_some()
                                | logout_confirm_window_id.take().is_some()
                                | open_video_menu_window_id.take().is_some()
                                | open_folder_gui.take().is_some();
                            pending_folder_load = None;
                            if replaced_gui {
                                responses.extend(restore_gui_hotbar_packets(
                                    active_mail_view.is_some(),
                                )?);
                            }
                        }
                        if let Some((command_packets, opens_render_settings)) =
                            render_size_command_packets(
                                &message,
                                &mut render_settings,
                                &player_username,
                                authenticated_email,
                            )?
                        {
                            render_settings_pending |= opens_render_settings;
                            responses.extend(command_packets);
                        } else {
                            let command_name = java_trim(&message)
                                .split(java_regex_space)
                                .next()
                                .unwrap_or_default()
                                .to_ascii_lowercase();
                            responses.extend(authenticated_command_packets(
                                &message,
                                &service.config,
                                &mut draft,
                                menu_window_id,
                                render_settings,
                            )?);
                            if command_name == "/clear" {
                                let Some(updated) = service.update_draft(&player_uuid, |stored| {
                                    stored.clear();
                                }) else {
                                    return Ok(());
                                };
                                draft = updated;
                            }
                        }
                        message.zeroize();
                        if let Some(window_id) = menu_window_id {
                            open_menu_window_id = Some(window_id);
                            logout_confirm_window_id = None;
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                }
                0x0d => {
                    if packet.read_u8().is_err() {
                        return Ok(());
                    }
                    let closed_gui = open_menu_window_id.take().is_some()
                        | logout_confirm_window_id.take().is_some()
                        | open_video_menu_window_id.take().is_some()
                        | open_folder_gui.take().is_some();
                    if closed_gui {
                        pending_folder_load = None;
                    }
                    if closed_gui
                        && let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            restore_gui_hotbar_packets(active_mail_view.is_some())?,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                    {
                        return finish_write_error(error);
                    }
                }
                0x0e => {
                    let Ok(click) = read_window_click(&mut packet) else {
                        return Ok(());
                    };
                    if open_menu_window_id == Some(click.window_id) {
                        let logout_window_id =
                            (click.mode == 0 && click.slot == 34).then(|| service.next_window_id());
                        let video_window_id =
                            (click.mode == 0 && click.slot == 28).then(|| service.next_window_id());
                        let (responses, effect) = main_menu_click_packets_with_video(
                            click,
                            logout_window_id,
                            video_window_id.map(|window_id| (window_id, &service.config)),
                            render_settings,
                            active_mail_view.is_some(),
                        )?;
                        match effect {
                            MainMenuEffect::None => {}
                            MainMenuEffect::Close => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                open_video_menu_window_id = None;
                            }
                            MainMenuEffect::SwitchAccount => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                open_video_menu_window_id = None;
                                pending_email = None;
                                authenticated = None;
                            }
                            MainMenuEffect::OpenRenderSettings => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                open_video_menu_window_id = None;
                                render_settings_pending = true;
                            }
                            MainMenuEffect::OpenVideoMenu(window_id) => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                open_video_menu_window_id = Some(window_id);
                            }
                            MainMenuEffect::OpenLogoutConfirm(window_id) => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = Some(window_id);
                                open_video_menu_window_id = None;
                            }
                            MainMenuEffect::OpenFolder(folder) => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                open_video_menu_window_id = None;
                                open_folder_gui = None;
                                let Some((email, _)) = authenticated.as_ref() else {
                                    return Ok(());
                                };
                                pending_folder_load = Some(start_folder_load(
                                    &service,
                                    email,
                                    folder,
                                    0,
                                    FolderLoadAction::Open {
                                        folder: folder.to_owned(),
                                    },
                                    deadline,
                                )?);
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    } else if logout_confirm_window_id == Some(click.window_id) {
                        let main_window_id =
                            (click.mode == 0 && click.slot == 15).then(|| service.next_window_id());
                        let (responses, effect) = logout_confirmation_click_packets(
                            click,
                            main_window_id,
                            render_settings,
                            active_mail_view.is_some(),
                        )?;
                        match effect {
                            LogoutConfirmEffect::None => {}
                            LogoutConfirmEffect::OpenMainMenu(window_id) => {
                                logout_confirm_window_id = None;
                                open_menu_window_id = Some(window_id);
                                open_video_menu_window_id = None;
                            }
                            LogoutConfirmEffect::Disconnect => {
                                logout_confirm_window_id = None;
                                open_menu_window_id = None;
                                open_video_menu_window_id = None;
                                pending_email = None;
                                authenticated = None;
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        if effect == LogoutConfirmEffect::Disconnect {
                            shutdown_stream(&mut writer, deadline, &cancellation).await?;
                            return Ok(());
                        }
                    } else if open_video_menu_window_id == Some(click.window_id) {
                        let main_window_id =
                            (click.mode == 0 && click.slot == 22).then(|| service.next_window_id());
                        let clicked_window_id = click.window_id;
                        let (responses, effect) = video_menu_click_packets(
                            click,
                            main_window_id,
                            render_settings,
                            &service.config,
                        )?;
                        let mut responses = responses;
                        open_video_menu_window_id = None;
                        match effect {
                            VideoMenuEffect::None => {
                                open_video_menu_window_id = Some(clicked_window_id);
                            }
                            VideoMenuEffect::Back(window_id) => {
                                open_menu_window_id = Some(window_id);
                            }
                            VideoMenuEffect::StartMap => {
                                let params = MapVideoParams {
                                    maps_x: service.config.video.map_default_maps_x as usize,
                                    fps: service.config.video.map_default_fps,
                                    dither: 1,
                                    contrast: service.config.video.map_default_contrast,
                                };
                                responses.extend(start_map_video_packets(
                                    &service,
                                    &mut pending_map_video,
                                    &pending_block_video,
                                    params,
                                    &cancellation,
                                )?);
                            }
                            VideoMenuEffect::StartBlock => {
                                let params = BlockVideoParams {
                                    width: service.config.video.default_width as usize,
                                    height: ((service.config.video.default_width as usize)
                                        .saturating_mul(VIDEO_SOURCE_HEIGHT)
                                        + VIDEO_SOURCE_WIDTH / 2)
                                        / VIDEO_SOURCE_WIDTH,
                                    fps: service.config.video.default_fps,
                                    contrast: service.config.video.default_contrast,
                                };
                                responses.extend(start_block_video_packets(
                                    &service,
                                    &mut pending_map_video,
                                    &mut pending_block_video,
                                    params,
                                    &cancellation,
                                )?);
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    } else if open_folder_gui
                        .as_ref()
                        .is_some_and(|gui| gui.window_id == click.window_id)
                    {
                        let main_window_id =
                            (click.mode == 0 && click.slot == 49).then(|| service.next_window_id());
                        let (mut responses, effect) = folder_gui_click_packets(
                            click,
                            open_folder_gui
                                .as_ref()
                                .expect("matched folder GUI was missing"),
                            main_window_id,
                            render_settings,
                            active_mail_view.is_some(),
                        )?;
                        match effect {
                            FolderGuiEffect::None => {}
                            FolderGuiEffect::LoadPage(page) => {
                                if pending_folder_load.is_none() {
                                    let gui = open_folder_gui
                                        .as_ref()
                                        .expect("folder GUI page request lost its state");
                                    let Some((email, _)) = authenticated.as_ref() else {
                                        return Ok(());
                                    };
                                    pending_folder_load = Some(start_folder_load(
                                        &service,
                                        email,
                                        &gui.folder,
                                        page,
                                        FolderLoadAction::Refresh {
                                            window_id: gui.window_id,
                                            folder: gui.folder.clone(),
                                        },
                                        deadline,
                                    )?);
                                }
                            }
                            FolderGuiEffect::OpenMainMenu(window_id) => {
                                pending_folder_load = None;
                                open_folder_gui = None;
                                open_menu_window_id = Some(window_id);
                                logout_confirm_window_id = None;
                            }
                            FolderGuiEffect::OpenMail { folder, file_name } => {
                                pending_folder_load = None;
                                open_folder_gui = None;
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                let Some((email, _)) = authenticated.as_ref() else {
                                    return Ok(());
                                };
                                if let Some(view) = active_mail_view.take() {
                                    responses.extend(mail_view_close_packets(
                                        view,
                                        &player_username,
                                        email,
                                        render_settings,
                                    )?);
                                }
                                pending_mail_render = Some(start_mail_render(
                                    Arc::clone(&service),
                                    email,
                                    folder,
                                    file_name,
                                    render_settings,
                                    deadline,
                                )?);
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                }
                0x09 => {
                    let Ok(slot) = read_held_item_change(&mut packet) else {
                        return Ok(());
                    };
                    held_slot = slot;
                }
                0x12 => {
                    let Ok(update) = read_update_sign(&mut packet) else {
                        return Ok(());
                    };
                    if render_settings_pending && let Some((email, _)) = authenticated.as_ref() {
                        render_settings_pending = false;
                        let responses = render_settings_update_packets(
                            update,
                            &mut render_settings,
                            &player_username,
                            email,
                            &draft,
                        )?;
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    } else if authenticated.is_some() {
                        let store_update = update.clone();
                        let Some(updated) = service.update_draft(&player_uuid, |stored| {
                            apply_draft_update(&store_update, stored);
                        }) else {
                            return Ok(());
                        };
                        draft = updated;
                        let responses = draft_update_packets(update, &mut draft)?;
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                }
                0x17 => {
                    if authenticated.is_none() {
                        continue;
                    }
                    let Ok(channel) = packet.read_string(20) else {
                        return Ok(());
                    };
                    if channel != "MC|BEdit" {
                        continue;
                    }
                    let Some(pages) = read_book_edit(&mut packet) else {
                        continue;
                    };
                    let Some(updated) = service.update_draft(&player_uuid, |stored| {
                        stored.body_pages = pages;
                    }) else {
                        return Ok(());
                    };
                    draft = updated;
                    let response = vec![chat_packet(
                        &format!("\u{00a7}7Book saved: {} page(s)", draft.body_pages.len()),
                        Some("gray"),
                    )?];
                    if let Err(error) = write_packet_list(
                        &mut writer,
                        &service,
                        response,
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                }
                0x04 | 0x06 => match read_player_position(&mut packet, packet_id) {
                    Ok(position) => player_position = position,
                    Err(()) => return Ok(()),
                },
                _ => {}
            },
        }
    }
}

async fn shutdown_stream<W: AsyncWrite + Unpin>(
    stream: &mut W,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        result = timeout_at(deadline, stream.shutdown()) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Minecraft shutdown timed out"))?,
    }
}

fn finish_write_error(error: ProtocolError) -> io::Result<()> {
    match error {
        ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed => Ok(()),
        ProtocolError::Io(error) if connection_ended(&error) => Ok(()),
        ProtocolError::Io(error) => Err(error),
    }
}

fn parse_handshake(packet: &mut PacketReader<'_>) -> Result<(), ()> {
    packet.read_varint()?;
    packet.read_string(255)?;
    packet.read_u16()?;
    Ok(())
}

fn read_player_position(
    packet: &mut PacketReader<'_>,
    packet_id: i32,
) -> Result<(f64, f64, f64), ()> {
    let position = (packet.read_f64()?, packet.read_f64()?, packet.read_f64()?);
    if packet_id == 0x06 {
        packet.read_f32()?;
        packet.read_f32()?;
    }
    packet.read_u8()?;
    Ok(position)
}

fn read_use_entity(packet: &mut PacketReader<'_>) -> Result<(i32, i32), ()> {
    let target_id = packet.read_varint()?;
    let action = packet.read_varint()?;
    Ok((target_id, action))
}

fn read_player_block_placement(packet: &mut PacketReader<'_>) -> Result<(i32, i32, i32, i8), ()> {
    let packed = packet.read_i64()? as u64;
    let x = ((packed >> 38) as i32) << 6 >> 6;
    let y = ((packed >> 26) & 0xfff) as i32;
    let z = (packed as i32) << 6 >> 6;
    let face = packet.read_u8()? as i8;
    packet.skip_slot()?;
    packet.read_u8()?;
    packet.read_u8()?;
    packet.read_u8()?;
    Ok((x, y, z, face))
}

fn read_held_item_change(packet: &mut PacketReader<'_>) -> Result<i16, ()> {
    Ok(packet.read_i16()? & 0x0f)
}

fn hotbar_action(
    mail_view_active: bool,
    authenticated: bool,
    held_slot: i16,
    primary_interaction: bool,
    now: Instant,
    last_hotbar_click: &mut Option<Instant>,
) -> HotbarAction {
    if !authenticated || !primary_interaction {
        return HotbarAction::None;
    }
    if held_slot == 8 {
        return HotbarAction::OpenMainMenu;
    }
    if !mail_view_active {
        return HotbarAction::None;
    }
    let action = match held_slot {
        3 => HotbarAction::PreviousPage,
        4 => HotbarAction::CloseMailView,
        5 => HotbarAction::NextPage,
        _ => HotbarAction::None,
    };
    if action == HotbarAction::None {
        return action;
    }
    if last_hotbar_click.is_some_and(|last| {
        now.checked_duration_since(last)
            .is_none_or(|elapsed| elapsed < HOTBAR_CLICK_COOLDOWN)
    }) {
        return HotbarAction::None;
    }
    *last_hotbar_click = Some(now);
    action
}

fn read_window_click(packet: &mut PacketReader<'_>) -> Result<WindowClick, ()> {
    let window_id = packet.read_u8()?;
    let slot = packet.read_i16()?;
    let _button = packet.read_u8()?;
    let action_number = packet.read_i16()?;
    let mode = packet.read_u8()?;
    packet.skip_slot()?;
    Ok(WindowClick {
        window_id,
        slot,
        action_number,
        mode,
    })
}

fn read_update_sign(packet: &mut PacketReader<'_>) -> Result<UpdateSign, ()> {
    let packed = packet.read_i64()? as u64;
    Ok(UpdateSign {
        x: ((packed >> 38) as i32) << 6 >> 6,
        y: ((packed >> 26) & 0xfff) as i32,
        z: (packed as i32) << 6 >> 6,
        lines: [
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
        ],
    })
}

fn read_book_edit(packet: &mut PacketReader<'_>) -> Option<Vec<String>> {
    if packet.read_i16().ok()? != 386 {
        return None;
    }
    packet.read_u8().ok()?;
    packet.read_i16().ok()?;
    let (nbt, consumed) = minecraft_world::read_network_nbt(packet.remaining()).ok()?;
    packet.advance(consumed).ok()?;
    let NbtValue::Compound(entries) = nbt else {
        return None;
    };
    let NbtValue::List {
        element_type: 8,
        values,
    } = entries
        .into_iter()
        .find_map(|(name, value)| (name == "pages").then_some(value))?
    else {
        return None;
    };
    if values.len() > MAX_DRAFT_PAGES {
        return None;
    }
    let mut total = 0_usize;
    let mut pages = Vec::new();
    pages.try_reserve_exact(values.len()).ok()?;
    for value in values {
        let NbtValue::String(page) = value else {
            return None;
        };
        if page.len() > MAX_DRAFT_PAGE_BYTES {
            return None;
        }
        total = total.checked_add(page.len())?;
        if total > MAX_DRAFT_BODY_BYTES {
            return None;
        }
        pages.push(page);
    }
    Some(pages)
}

fn encryption_request_frame(
    public_key_der: &[u8],
    verify_token: &[u8; VERIFY_TOKEN_BYTES],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(public_key_der.len() + verify_token.len() + 12)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    packet.push(0x01);
    write_string(&mut packet, "")?;
    write_byte_array(&mut packet, public_key_der)?;
    write_byte_array(&mut packet, verify_token)?;
    encode_frame(&packet)
}

async fn decrypt_online_response(
    online: &OnlineModeService,
    encrypted_secret: Vec<u8>,
    encrypted_token: Vec<u8>,
    expected_token: [u8; VERIFY_TOKEN_BYTES],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<[u8; SHARED_SECRET_BYTES], ProtocolError> {
    let private_key = Arc::clone(&online.private_key);
    let worker_cancellation = cancellation.clone();
    let receiver = online
        .crypto_pool
        .submit(move || {
            compression_budget(&worker_cancellation, deadline)?;
            let mut token = rsa_private_decrypt(&private_key, &encrypted_token)?;
            let token_matches: bool = expected_token.as_slice().ct_eq(&token).into();
            token.zeroize();
            if !token_matches {
                return Err(ProtocolError::Malformed);
            }
            compression_budget(&worker_cancellation, deadline)?;
            let mut secret = rsa_private_decrypt(&private_key, &encrypted_secret)?;
            if secret.len() != SHARED_SECRET_BYTES {
                secret.zeroize();
                return Err(ProtocolError::Malformed);
            }
            let mut result = [0_u8; SHARED_SECRET_BYTES];
            result.copy_from_slice(&secret);
            secret.zeroize();
            compression_budget(&worker_cancellation, deadline)?;
            Ok(result)
        })
        .map_err(submit_error)?;
    await_compression(receiver, deadline, cancellation).await?
}

fn rsa_private_decrypt(
    private_key: &Rsa<Private>,
    encrypted: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if encrypted.len() != private_key.size() as usize {
        return Err(ProtocolError::Malformed);
    }
    let mut output = vec![0_u8; private_key.size() as usize];
    let written = private_key
        .private_decrypt(encrypted, &mut output, Padding::PKCS1)
        .map_err(crypto_protocol)?;
    output.truncate(written);
    Ok(output)
}

#[derive(Debug)]
struct JoinedProfile {
    uuid: String,
    name: String,
}

#[derive(Debug)]
struct AuthenticationFailure {
    message: String,
}

impl AuthenticationFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn message(&self) -> &str {
        &self.message
    }
}

#[derive(serde::Deserialize)]
struct JoinedResponse {
    id: String,
    name: String,
}

async fn authenticate_online(
    online: &OnlineModeService,
    username: &str,
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<JoinedProfile, AuthenticationFailure> {
    let operation_deadline = deadline.min(Instant::now() + AUTH_REQUEST_TIMEOUT);
    let server_hash = minecraft_server_hash("", shared_secret, &online.public_key_der);
    let mut url = online.session_server_url.clone();
    url.query_pairs_mut()
        .clear()
        .append_pair("username", username)
        .append_pair("serverId", &server_hash);
    let response = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            return Err(AuthenticationFailure::new("Interrupted"));
        }
        response = timeout_at(operation_deadline, online.session_client.get(url).send()) => {
            response
                .map_err(|_| AuthenticationFailure::new("Auth server error: request timed out"))?
                .map_err(|_| AuthenticationFailure::new("Auth server error: request failed"))?
        }
    };
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        return Err(AuthenticationFailure::new("Session not found"));
    }
    if status != StatusCode::OK {
        return Err(AuthenticationFailure::new(format!(
            "HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
    {
        return Err(AuthenticationFailure::new(
            "Auth server error: response exceeded byte limit",
        ));
    }
    let mut response = response;
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(AuthenticationFailure::new("Interrupted"));
            }
            chunk = timeout_at(operation_deadline, response.chunk()) => {
                chunk
                    .map_err(|_| AuthenticationFailure::new("Auth server error: response timed out"))?
                    .map_err(|_| AuthenticationFailure::new("Auth server error: response failed"))?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
            return Err(AuthenticationFailure::new(
                "Auth server error: response exceeded byte limit",
            ));
        }
        body.try_reserve_exact(chunk.len()).map_err(|_| {
            AuthenticationFailure::new("Auth server error: response allocation failed")
        })?;
        body.extend_from_slice(&chunk);
    }
    let profile: JoinedResponse = serde_json::from_slice(&body)
        .map_err(|_| AuthenticationFailure::new("Auth server error: invalid response"))?;
    let uuid = normalize_joined_uuid(&profile.id)
        .ok_or_else(|| AuthenticationFailure::new("Auth server error: invalid response"))?;
    if !valid_online_name(&profile.name) || !java_equals_ignore_case(&profile.name, username) {
        return Err(AuthenticationFailure::new(
            "Auth server error: invalid response",
        ));
    }
    Ok(JoinedProfile {
        uuid,
        name: profile.name,
    })
}

fn minecraft_server_hash(
    server_id: &str,
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    public_key_der: &[u8],
) -> String {
    let mut digest = Sha1::new();
    digest.update(server_id.as_bytes());
    digest.update(shared_secret);
    digest.update(public_key_der);
    signed_hex(digest.finalize().as_slice())
}

fn signed_hex(bytes: &[u8]) -> String {
    let negative = bytes.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut magnitude = bytes.to_vec();
    if negative {
        for byte in &mut magnitude {
            *byte = !*byte;
        }
        for byte in magnitude.iter_mut().rev() {
            let (value, carry) = byte.overflowing_add(1);
            *byte = value;
            if !carry {
                break;
            }
        }
    }
    let first = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    if first == magnitude.len() {
        return "0".to_owned();
    }
    let mut output = String::with_capacity((magnitude.len() - first) * 2 + usize::from(negative));
    if negative {
        output.push('-');
    }
    use std::fmt::Write as _;
    write!(output, "{:x}", magnitude[first]).expect("writing to String cannot fail");
    for byte in &magnitude[first + 1..] {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn normalize_joined_uuid(value: &str) -> Option<String> {
    let valid_shape = value.len() == 32
        || (value.len() == 36
            && value.as_bytes()[8] == b'-'
            && value.as_bytes()[13] == b'-'
            && value.as_bytes()[18] == b'-'
            && value.as_bytes()[23] == b'-');
    if !valid_shape {
        return None;
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &compact[0..8].to_ascii_lowercase(),
        &compact[8..12].to_ascii_lowercase(),
        &compact[12..16].to_ascii_lowercase(),
        &compact[16..20].to_ascii_lowercase(),
        &compact[20..32].to_ascii_lowercase()
    ))
}

fn valid_online_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn authentication_failure_packet(message: &str) -> io::Result<Vec<u8>> {
    let text = format!("Authentication failed: {message}");
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    login_disconnect_packet(&format!(r#"{{"text":"{escaped}","color":"red"}}"#))
}

async fn complete_login<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    uuid: String,
    username: &str,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(Option<i32>, OnlineCountGuard, i32), ProtocolError> {
    let compression = if service.config.compression_threshold >= 0 {
        let threshold = service.config.compression_threshold;
        let mut packet = vec![0x03];
        write_varint(&mut packet, threshold as u32);
        let frame = encode_frame(&packet)?;
        write_bytes(
            stream,
            &frame,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
        Some(threshold)
    } else {
        None
    };

    let mut login_success = vec![0x02];
    write_string(&mut login_success, &uuid)?;
    write_string(&mut login_success, username)?;
    write_packet(
        stream,
        service,
        login_success,
        compression,
        cipher.as_deref_mut(),
        deadline,
        cancellation,
    )
    .await?;

    let player_list_uuid = uuid.clone();
    let static_play_packets =
        static_play_packets(&player_list_uuid, username).map_err(ProtocolError::Io)?;
    let online_guard = service.register_online(uuid);
    let entity_id = service.next_entity_id();
    for packet in initial_play_packets(entity_id, &service.config)? {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    send_world_bootstrap(
        stream,
        service,
        compression,
        cipher.as_deref_mut(),
        deadline,
        cancellation,
    )
    .await?;
    for packet in static_play_packets {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    let hologram_entity_base = service.reserve_hologram_entity_ids(7);
    for packet in post_static_play_packets(hologram_entity_base).map_err(ProtocolError::Io)? {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    Ok((compression, online_guard, hologram_entity_base))
}

async fn send_world_bootstrap<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    compression: Option<i32>,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let spawn = &service.config.spawn;
    let chunk_centers = [
        ((spawn.x as i32) >> 4, (spawn.z as i32) >> 4),
        (
            service.config.video.center_x >> 4,
            service.config.video.wall_z >> 4,
        ),
    ];
    for chunk in service
        .world
        .chunks_near_centers(&chunk_centers, service.config.view_distance as i32)
    {
        let (mask, data) = minecraft_world::serialize_chunk(chunk, true, true);
        let mut packet = vec![0x21];
        packet.extend_from_slice(&chunk.chunk_x.to_be_bytes());
        packet.extend_from_slice(&chunk.chunk_z.to_be_bytes());
        packet.push(1);
        packet.extend_from_slice(&mask.to_be_bytes());
        write_byte_array(&mut packet, &data).map_err(ProtocolError::Io)?;
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    for chunk in service.world.chunks() {
        for tile_entity in &chunk.tile_entities {
            let action = match tile_entity.id.as_str() {
                "Sign" => 9,
                "Banner" => 6,
                _ => continue,
            };
            let mut packet = vec![0x35];
            write_block_position(&mut packet, tile_entity.x, tile_entity.y, tile_entity.z);
            packet.push(action);
            minecraft_world::write_nbt(Some(&tile_entity.nbt), &mut packet)
                .map_err(ProtocolError::Io)?;
            write_packet(
                stream,
                service,
                packet,
                compression,
                cipher.as_deref_mut(),
                deadline,
                cancellation,
            )
            .await?;
        }
    }
    let mut position = vec![0x08];
    position.extend_from_slice(&spawn.x.to_be_bytes());
    position.extend_from_slice(&spawn.y.to_be_bytes());
    position.extend_from_slice(&spawn.z.to_be_bytes());
    position.extend_from_slice(&spawn.yaw.to_be_bytes());
    position.extend_from_slice(&spawn.pitch.to_be_bytes());
    position.push(0);
    write_packet(
        stream,
        service,
        position,
        compression,
        cipher,
        deadline,
        cancellation,
    )
    .await?;
    Ok(())
}

fn write_block_position(output: &mut Vec<u8>, x: i32, y: i32, z: i32) {
    let packed = ((i64::from(x) & 0x3ff_ffff) << 38)
        | ((i64::from(y) & 0xfff) << 26)
        | (i64::from(z) & 0x3ff_ffff);
    output.extend_from_slice(&packed.to_be_bytes());
}

fn static_play_packets(uuid: &str, username: &str) -> io::Result<Vec<Vec<u8>>> {
    let uuid_bytes = parse_uuid_bytes(uuid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid player UUID"))?;

    let mut packets = Vec::with_capacity(11);
    let mut player_list = vec![0x38];
    write_varint(&mut player_list, 0);
    write_varint(&mut player_list, 1);
    player_list.extend_from_slice(&uuid_bytes);
    write_string(&mut player_list, username)?;
    write_varint(&mut player_list, 0);
    write_varint(&mut player_list, 2);
    write_varint(&mut player_list, 0);
    player_list.push(0);
    packets.push(player_list);

    let mut header_footer = vec![0x47];
    write_string(
        &mut header_footer,
        &chat_json("\u{00a7}6\u{00a7}lLMYZMAIL", Some("gold")),
    )?;
    write_string(
        &mut header_footer,
        &chat_json(
            "\u{00a7}7Send emails in Minecraft! Skibidi dop dop yes yes!",
            Some("gray"),
        ),
    )?;
    packets.push(header_footer);

    let titles: [(u32, Option<String>, i32, i32, i32); 3] = [
        (2, None, 10, 60, 20),
        (0, Some(chat_json("\u{00a7}6LMYZMAIL", None)), 0, 0, 0),
        (
            1,
            Some(chat_json(
                "\u{00a7}7Type your email to get started",
                Some("gray"),
            )),
            0,
            0,
            0,
        ),
    ];
    for (action, text, fade_in, stay, fade_out) in titles {
        let mut title = vec![0x45];
        write_varint(&mut title, action);
        if let Some(text) = text {
            write_string(&mut title, &text)?;
        } else {
            title.extend_from_slice(&fade_in.to_be_bytes());
            title.extend_from_slice(&stay.to_be_bytes());
            title.extend_from_slice(&fade_out.to_be_bytes());
        }
        packets.push(title);
    }

    for (text, color) in [
        (
            "\u{00a7}e\u{00a7}l=== Welcome to LMYZMAIL Minecraft Server ===",
            Some("yellow"),
        ),
        (
            "\u{00a7}7Send emails directly from Minecraft!",
            Some("gray"),
        ),
        ("", None),
        ("\u{00a7}aPlease enter your email address:", Some("green")),
    ] {
        let mut chat = vec![0x02];
        write_string(&mut chat, &chat_json(text, color))?;
        chat.push(0);
        packets.push(chat);
    }

    for (slot, item_id, nbt) in [
        (36_i16, 386_i16, book_item_nbt()),
        (44_i16, 399_i16, menu_star_nbt()),
    ] {
        let mut item = vec![0x2f, 0];
        item.extend_from_slice(&slot.to_be_bytes());
        item.extend_from_slice(&item_id.to_be_bytes());
        item.push(1);
        item.extend_from_slice(&0_i16.to_be_bytes());
        minecraft_world::write_nbt(Some(&nbt), &mut item)?;
        packets.push(item);
    }
    debug_assert_eq!(packets.len(), 11);
    Ok(packets)
}

fn post_static_play_packets(hologram_entity_base: i32) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = empty_draft_sign_packets()?;
    packets.reserve(16);

    let mut objective = vec![0x3b];
    write_string(&mut objective, "lmyz")?;
    objective.push(0);
    write_string(&mut objective, "\u{00a7}6\u{00a7}lLMYZMAIL")?;
    write_string(&mut objective, "dummy")?;
    packets.push(objective);

    let mut display = vec![0x3d, 1];
    write_string(&mut display, "lmyz")?;
    packets.push(display);

    let lines = [
        "\u{00a7}6\u{00a7}lLMYZMAIL",
        "\u{00a7}7Minecraft Skibidi Email Server",
        "\u{00a7}7by \u{00a7}elmyzzz the great skibidi scientist",
        " ",
        "\u{00a7}eHold \u{00a7}fNether Star \u{00a7}e+ Right-click -> \u{00a7}fMenu",
        "\u{00a7}eWrite in \u{00a7}fBook & Quill \u{00a7}e-> Email body",
        "\u{00a7}eClick \u{00a7}fSign Buttons \u{00a7}e-> Set To/Subject",
    ];
    for (index, line) in lines.into_iter().enumerate() {
        let entity_id = hologram_entity_base + index as i32;
        let y = 163.0 - index as f64 * 0.55;
        let mut spawn = vec![0x0f];
        write_varint(&mut spawn, entity_id as u32);
        spawn.push(30);
        spawn.extend_from_slice(&16_i32.to_be_bytes());
        spawn.extend_from_slice(&((y * 32.0) as i32).to_be_bytes());
        spawn.extend_from_slice(&16_i32.to_be_bytes());
        spawn.extend_from_slice(&[0, 0, 0]);
        spawn.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        spawn.extend_from_slice(&[0x00, 0x20, 0x0a, 0x09, 0x7f]);
        packets.push(spawn);

        let mut metadata = vec![0x1c];
        write_varint(&mut metadata, entity_id as u32);
        metadata.push(0x82);
        write_string(&mut metadata, line)?;
        metadata.extend_from_slice(&[0x03, 1, 0x7f]);
        packets.push(metadata);
    }
    debug_assert_eq!(packets.len(), 20);
    Ok(packets)
}

fn time_update_packet() -> Vec<u8> {
    let mut packet = vec![0x03];
    packet.extend_from_slice(&0_i64.to_be_bytes());
    packet.extend_from_slice(&(-6000_i64).to_be_bytes());
    packet
}

fn teleport_back_packets(config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut position = vec![0x08];
    position.extend_from_slice(&config.spawn.x.to_be_bytes());
    position.extend_from_slice(&config.spawn.y.to_be_bytes());
    position.extend_from_slice(&config.spawn.z.to_be_bytes());
    position.extend_from_slice(&config.spawn.yaw.to_be_bytes());
    position.extend_from_slice(&config.spawn.pitch.to_be_bytes());
    position.push(0);

    Ok(vec![
        position,
        chat_packet("\u{00a7}cYou were teleported back to spawn!", Some("red"))?,
    ])
}

fn hologram_teleport_packets(hologram_entity_base: i32) -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(7);
    for index in 0..7 {
        let entity_id = hologram_entity_base + index;
        let y = (163.0 - f64::from(index) * 0.55) * 32.0;
        let mut packet = vec![0x18];
        write_varint(&mut packet, entity_id as u32);
        packet.extend_from_slice(&16_i32.to_be_bytes());
        packet.extend_from_slice(&(y as i32).to_be_bytes());
        packet.extend_from_slice(&16_i32.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0]);
        packets.push(packet);
    }
    packets
}

fn awaiting_email_responses(message: &str) -> io::Result<(Option<String>, Vec<Vec<u8>>)> {
    let email = java_trim(message);
    if email.is_empty() || !email.contains('@') {
        return Ok((
            None,
            vec![chat_packet(
                "\u{00a7}cInvalid email format. Please try again:",
                Some("red"),
            )?],
        ));
    }
    Ok((
        Some(email.to_owned()),
        vec![
            chat_packet(&format!("\u{00a7}aEmail: \u{00a7}f{email}"), None)?,
            chat_packet("\u{00a7}aPlease enter your password:", Some("green"))?,
            chat_packet("\u{00a7}7(Your password will not be visible)", Some("gray"))?,
        ],
    ))
}

fn chat_packet(text: &str, color: Option<&str>) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x02];
    write_string(&mut packet, &chat_json(text, color))?;
    packet.push(0);
    Ok(packet)
}

fn disconnect_play_packet(reason: &str) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x40];
    write_string(&mut packet, &chat_json(reason, Some("red")))?;
    Ok(packet)
}

fn authenticated_packets_with_draft(
    username: &str,
    email: &str,
    render_settings: RenderSettings,
    draft: &MinecraftDraft,
) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = vec![
        chat_packet(
            "\u{00a7}a\u{00a7}lAuthentication successful!",
            Some("green"),
        )?,
        chat_packet(&format!("\u{00a7}aLogged in as: \u{00a7}f{email}"), None)?,
        chat_packet("", None)?,
    ];
    packets.extend(email_instruction_packets()?);
    if !draft.to.chars().all(char::is_whitespace) || !draft.subject.chars().all(char::is_whitespace)
    {
        packets.push(chat_packet(
            "\u{00a7}6Restored your previous draft!",
            Some("gold"),
        )?);
        packets.push(chat_packet(
            &format!(
                "\u{00a7}7To: {}, Subject: {}, Body: {} page(s)",
                draft_display(&draft.to),
                draft_display(&draft.subject),
                draft.body_pages.len()
            ),
            Some("gray"),
        )?);
    }
    packets.extend(draft_sign_packets(draft)?);
    packets.push(draft_book_packet_for(draft)?);
    packets.extend(authenticated_scoreboard_packets(
        username,
        email,
        render_settings,
    )?);
    debug_assert_eq!(
        packets.len(),
        if draft.to.is_empty() && draft.subject.is_empty() {
            29
        } else {
            31
        }
    );
    Ok(packets)
}

fn email_instruction_packets() -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}l=== How to Send Email ===",
        "\u{00a7}71. Click the buttons next to signs to edit:",
        "\u{00a7}7   \u{00a7}fTo\u{00a7}7, \u{00a7}fCC\u{00a7}7, \u{00a7}fBCC\u{00a7}7, \u{00a7}fSubject",
        "\u{00a7}72. Write your email body in the \u{00a7}fBook & Quill",
        "\u{00a7}73. Click the \u{00a7}cSend \u{00a7}7button when ready",
        "\u{00a7}74. Hold \u{00a7}f\u{2605} Nether Star \u{00a7}7+ right-click \u{2192} Mail menu",
        "\u{00a7}7   Or type \u{00a7}f/menu \u{00a7}7to open",
        "\u{00a7}e================================",
    ]
    .into_iter()
    .map(|text| chat_packet(text, None))
    .collect()
}

enum ParsedVideoCommand {
    Usage,
    StartMap(MapVideoParams),
    StartBlock(BlockVideoParams),
    Stop,
    Pause,
    Error(String),
}

fn parse_video_command(message: &str, config: &MinecraftConfig) -> ParsedVideoCommand {
    let parts = java_trim(message)
        .split(java_regex_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts
        .first()
        .is_none_or(|command| !command.eq_ignore_ascii_case("/video"))
    {
        return ParsedVideoCommand::Usage;
    }
    let Some(action) = parts.get(1) else {
        return ParsedVideoCommand::Usage;
    };
    if action.eq_ignore_ascii_case("stop") {
        return ParsedVideoCommand::Stop;
    }
    if action.eq_ignore_ascii_case("pause") {
        return ParsedVideoCommand::Pause;
    }
    if !action.eq_ignore_ascii_case("play") {
        return ParsedVideoCommand::Error("Usage: /video play|stop|pause [options]".to_owned());
    }
    if parts
        .get(2)
        .is_some_and(|mode| mode.eq_ignore_ascii_case("map"))
    {
        return parse_map_video_params(&parts[3..], config);
    }
    match parse_block_video_params(&parts[2..], config) {
        Ok(params) => ParsedVideoCommand::StartBlock(params),
        Err(error) => ParsedVideoCommand::Error(error),
    }
}

fn parse_map_video_params(parts: &[&str], config: &MinecraftConfig) -> ParsedVideoCommand {
    let mut maps_x = config.video.map_default_maps_x as i32;
    let mut fps = config.video.map_default_fps as i32;
    let mut dither = 1_i32;
    let mut contrast = config.video.map_default_contrast;
    let mut positional = 0;
    for argument in parts {
        if let Some((key, value)) = argument.split_once('=') {
            match key.to_ascii_lowercase().as_str() {
                "width" | "w" | "mapsx" => match value.parse::<i32>() {
                    Ok(value) => maps_x = value,
                    Err(_) => {
                        return ParsedVideoCommand::Error(format!("Invalid width: {value}"));
                    }
                },
                "fps" | "f" => match value.parse::<i32>() {
                    Ok(value) => fps = value,
                    Err(_) => return ParsedVideoCommand::Error(format!("Invalid fps: {value}")),
                },
                "dither" | "d" => match value.parse::<i32>() {
                    Ok(value) => dither = value,
                    Err(_) => {
                        return ParsedVideoCommand::Error(format!("Invalid dither: {value}"));
                    }
                },
                "contrast" | "c" => match value.parse::<f32>() {
                    Ok(value) if value.is_finite() => contrast = value,
                    _ => {
                        return ParsedVideoCommand::Error(format!("Invalid contrast: {value}"));
                    }
                },
                _ => return ParsedVideoCommand::Error(format!("Unknown option: {key}")),
            }
        } else {
            match positional {
                0 => match argument.parse::<i32>() {
                    Ok(value) => maps_x = value,
                    Err(_) => {
                        return ParsedVideoCommand::Error(format!("Invalid width: {argument}"));
                    }
                },
                1 => match argument.parse::<i32>() {
                    Ok(value) => fps = value,
                    Err(_) => {
                        return ParsedVideoCommand::Error(format!("Invalid fps: {argument}"));
                    }
                },
                _ => {
                    return ParsedVideoCommand::Error("Too many positional args".to_owned());
                }
            }
            positional += 1;
        }
    }
    maps_x = maps_x.max(2);
    if maps_x > config.video.map_max_maps_x as i32 {
        return ParsedVideoCommand::Error(format!(
            "Width too large (max {} maps)",
            config.video.map_max_maps_x
        ));
    }
    fps = fps.max(1);
    if fps > config.video.map_max_fps as i32 {
        return ParsedVideoCommand::Error(format!(
            "FPS too high (max {})",
            config.video.map_max_fps
        ));
    }
    if !(0..=2).contains(&dither) {
        dither = 1;
    }
    contrast = contrast.clamp(0.1, 3.0);
    ParsedVideoCommand::StartMap(MapVideoParams {
        maps_x: maps_x as usize,
        fps: fps as u32,
        dither: dither as u8,
        contrast,
    })
}

fn parse_block_video_params(
    parts: &[&str],
    config: &MinecraftConfig,
) -> Result<BlockVideoParams, String> {
    let mut width = config.video.default_width as i32;
    let mut fps = config.video.default_fps as i32;
    let mut contrast = config.video.default_contrast;
    let mut positional = 0;
    for argument in parts {
        if let Some((key, value)) = argument.split_once('=') {
            match key.to_ascii_lowercase().as_str() {
                "width" | "w" => {
                    width = value
                        .parse()
                        .map_err(|_| format!("Invalid width: {value}"))?
                }
                "fps" | "f" => fps = value.parse().map_err(|_| format!("Invalid fps: {value}"))?,
                "contrast" | "c" => {
                    contrast = value
                        .parse()
                        .map_err(|_| format!("Invalid contrast: {value}"))?;
                    if !contrast.is_finite() {
                        return Err(format!("Invalid contrast: {value}"));
                    }
                }
                _ => return Err(format!("Unknown option: {key}")),
            }
        } else {
            match positional {
                0 => {
                    width = argument
                        .parse()
                        .map_err(|_| format!("Invalid width: {argument}"))?
                }
                1 => {
                    fps = argument
                        .parse()
                        .map_err(|_| format!("Invalid fps: {argument}"))?
                }
                2 => {
                    contrast = argument
                        .parse()
                        .map_err(|_| format!("Invalid contrast: {argument}"))?;
                    if !contrast.is_finite() {
                        return Err(format!("Invalid contrast: {argument}"));
                    }
                }
                _ => return Err("Too many arguments".to_owned()),
            }
            positional += 1;
        }
    }
    width = width.max(4);
    if width > config.video.max_width as i32 {
        return Err(format!("Width too large (max {})", config.video.max_width));
    }
    fps = fps.max(1);
    if fps > config.video.max_fps as i32 {
        return Err(format!("FPS too high (max {})", config.video.max_fps));
    }
    contrast = contrast.clamp(0.1, 3.0);
    let width = width as usize;
    let height = ((width.saturating_mul(VIDEO_SOURCE_HEIGHT) + VIDEO_SOURCE_WIDTH / 2)
        / VIDEO_SOURCE_WIDTH)
        .max(1);
    Ok(BlockVideoParams {
        width,
        height,
        fps: fps as u32,
        contrast,
    })
}

fn video_usage_packets() -> io::Result<Vec<Vec<u8>>> {
    Ok(vec![
        chat_packet(
            "\u{00a7}cUsage: /video play map [width=5] [fps=10] [dither=1]",
            Some("red"),
        )?,
        chat_packet(
            "\u{00a7}c       /video play [width=48] [fps=6]",
            Some("red"),
        )?,
        chat_packet("\u{00a7}c       /video stop | /video pause", Some("red"))?,
    ])
}

fn start_map_video_packets(
    service: &Arc<StatusService>,
    pending: &mut Option<PendingMapVideo>,
    pending_block: &Option<PendingBlockVideo>,
    params: MapVideoParams,
    cancellation: &CancellationToken,
) -> io::Result<Vec<Vec<u8>>> {
    if pending.is_some() || pending_block.is_some() {
        return Ok(vec![chat_packet(
            "\u{00a7}cVideo is already playing! Use /video stop first.",
            Some("red"),
        )?]);
    }
    let permit = match service.video_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let max = service.config.max_concurrent_videos;
            return Ok(vec![chat_packet(
                &format!(
                    "\u{00a7}cToo many players watching video ({max}/{max}). Try again later."
                ),
                Some("red"),
            )?]);
        }
    };
    let video = match PendingMapVideo::start(service, params, permit, cancellation.child_token()) {
        Ok(video) => video,
        Err(error) => {
            return Ok(vec![chat_packet(
                &format!("\u{00a7}cMap video error: {error}"),
                Some("red"),
            )?]);
        }
    };
    let mut packets = video_hotbar_packets()?;
    packets.extend(video_scoreboard_packets("Map", params.fps)?);
    packets.push(chat_packet(
        "\u{00a7}a\u{00a7}lStarting map video playback...",
        Some("green"),
    )?);
    packets.push(chat_packet(
        &format!(
            "\u{00a7}7Maps: \u{00a7}f{} \u{00a7}7| FPS: \u{00a7}f{} \u{00a7}7| Dither: \u{00a7}f{} \u{00a7}7| Contrast: \u{00a7}f{:.1}",
            params.maps_x, params.fps, params.dither, params.contrast
        ),
        None,
    )?);
    packets.push(chat_packet(
        "\u{00a7}7Use \u{00a7}fbarrier item \u{00a7}7or \u{00a7}f/video stop \u{00a7}7to stop",
        None,
    )?);
    *pending = Some(video);
    Ok(packets)
}

fn start_block_video_packets(
    service: &Arc<StatusService>,
    pending_map: &mut Option<PendingMapVideo>,
    pending_block: &mut Option<PendingBlockVideo>,
    params: BlockVideoParams,
    cancellation: &CancellationToken,
) -> io::Result<Vec<Vec<u8>>> {
    if pending_map.is_some() || pending_block.is_some() {
        return Ok(vec![chat_packet(
            "\u{00a7}cVideo is already playing! Use /video stop first.",
            Some("red"),
        )?]);
    }
    let permit = match service.video_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let max = service.config.max_concurrent_videos;
            return Ok(vec![chat_packet(
                &format!(
                    "\u{00a7}cToo many players watching video ({max}/{max}). Try again later."
                ),
                Some("red"),
            )?]);
        }
    };
    let video = match PendingBlockVideo::start(service, params, permit, cancellation.child_token())
    {
        Ok(video) => video,
        Err(error) => {
            return Ok(vec![chat_packet(
                &format!("\u{00a7}cBlock video error: {error}"),
                Some("red"),
            )?]);
        }
    };
    let mut packets = video_hotbar_packets()?;
    packets.extend(video_scoreboard_packets("Block", params.fps)?);
    packets.push(chat_packet(
        "\u{00a7}a\u{00a7}lStarting block video playback...",
        Some("green"),
    )?);
    packets.push(chat_packet(
        &format!(
            "\u{00a7}7Width: \u{00a7}f{} \u{00a7}7| FPS: \u{00a7}f{} \u{00a7}7| Contrast: \u{00a7}f{:.1}",
            params.width, params.fps, params.contrast
        ),
        None,
    )?);
    packets.push(chat_packet(
        "\u{00a7}7Use \u{00a7}fbarrier item \u{00a7}7or \u{00a7}f/video stop \u{00a7}7to stop",
        None,
    )?);
    *pending_block = Some(video);
    Ok(packets)
}

fn start_outbound_send(
    service: &StatusService,
    sender: &str,
    draft: &MinecraftDraft,
    cancellation: &CancellationToken,
) -> io::Result<(Vec<Vec<u8>>, Option<PendingOutboundSend>)> {
    if draft.to.chars().all(char::is_whitespace) {
        return Ok((
            vec![chat_packet(
                "§cPlease set a recipient (To) first!",
                Some("red"),
            )?],
            None,
        ));
    }
    if draft.subject.chars().all(char::is_whitespace) {
        return Ok((
            vec![chat_packet("§cPlease set a subject first!", Some("red"))?],
            None,
        ));
    }
    let body = draft.body_pages.join("\n");
    if draft.body_pages.is_empty() || body.chars().all(char::is_whitespace) {
        return Ok((
            vec![chat_packet(
                "§cPlease write something in the book first!",
                Some("red"),
            )?],
            None,
        ));
    }
    let Some(outbound) = service.outbound.as_ref().cloned() else {
        return Ok((
            vec![chat_packet(
                "§cError sending email: outbound queue unavailable",
                Some("red"),
            )?],
            None,
        ));
    };
    let body = minecraft_outbound_body(draft);
    let request = SendRequest {
        from: Some(sender.to_owned()),
        password: None,
        to: parse_outbound_addresses(&draft.to),
        cc: parse_outbound_addresses(&draft.cc),
        bcc: parse_outbound_addresses(&draft.bcc),
        subject: Some(draft.subject.clone()),
        text: Some(body),
        html: None,
        attachments: Vec::new(),
        in_reply_to: None,
        references: None,
        asynchronous: None,
    };
    Ok((
        vec![chat_packet("§6Sending email...", Some("gold"))?],
        Some(PendingOutboundSend::start(
            outbound,
            sender.to_owned(),
            request,
            cancellation,
        )),
    ))
}

fn parse_outbound_addresses(value: &str) -> Vec<String> {
    value
        .split([',', ';'])
        .map(java_trim)
        .filter(|address| !address.is_empty())
        .map(str::to_owned)
        .collect()
}

fn minecraft_outbound_body(draft: &MinecraftDraft) -> String {
    format!(
        "{}\n\n\n\n\n\n\n\n{OUTBOUND_MINECRAFT_FOOTER}",
        draft.body_pages.join("\n")
    )
}

fn outbound_step_packets(
    service: &StatusService,
    pending: &mut PendingOutboundSend,
    result: OutboundStepResult,
    player_uuid: &str,
    draft: &mut MinecraftDraft,
) -> io::Result<(Vec<Vec<u8>>, bool)> {
    if matches!(&result, OutboundStepResult::Cancelled) {
        return Ok((Vec::new(), false));
    }
    let Some(outbound) = service.outbound.as_ref().cloned() else {
        return Ok((
            vec![chat_packet(
                "§cError sending email: outbound queue unavailable",
                Some("red"),
            )?],
            false,
        ));
    };
    match result {
        OutboundStepResult::Cancelled => unreachable!("cancelled outbound steps return early"),
        OutboundStepResult::Enqueued(Err(error)) => Ok((
            vec![chat_packet(
                &format!("§cFailed to queue email: {error}"),
                Some("red"),
            )?],
            false,
        )),
        OutboundStepResult::Enqueued(Ok(response)) => {
            pending.queue_id = Some(response.queue_id);
            pending.message_id = Some(response.message_id);
            pending.schedule_status(outbound, OUTBOUND_FAST_POLL_INTERVAL);
            Ok((
                vec![chat_packet(
                    &format!(
                        "§7Email queued (ID: {}), waiting for delivery...",
                        response.queue_id
                    ),
                    None,
                )?],
                true,
            ))
        }
        OutboundStepResult::Status(status) => {
            if let Ok(Some(status)) = status {
                let aggregate = status.aggregated_status.as_str();
                if aggregate == "SENT" {
                    let Some(updated) = service.update_draft(player_uuid, MinecraftDraft::clear)
                    else {
                        return Ok((Vec::new(), false));
                    };
                    *draft = updated;
                    let mut packets = vec![
                        chat_packet("§a§l✓ Email sent successfully!", Some("green"))?,
                        chat_packet(
                            &format!(
                                "§7Message ID: {}",
                                pending.message_id.as_deref().unwrap_or_default()
                            ),
                            Some("gray"),
                        )?,
                    ];
                    packets.extend(draft_sign_packets(draft)?);
                    packets.push(draft_book_packet_for(draft)?);
                    return Ok((packets, false));
                }
                if aggregate == "FAILED" {
                    let mut packets =
                        vec![chat_packet("§c§l✗ Email delivery failed!", Some("red"))?];
                    if let Some(error) = status.last_error {
                        packets.push(chat_packet(&format!("§c{error}"), Some("red"))?);
                    }
                    packets.push(chat_packet(
                        "§7Your draft is preserved. Fix and retry.",
                        Some("gray"),
                    )?);
                    return Ok((packets, false));
                }
                if aggregate == "PARTIAL_SUCCESS" {
                    let Some(updated) = service.update_draft(player_uuid, MinecraftDraft::clear)
                    else {
                        return Ok((Vec::new(), false));
                    };
                    *draft = updated;
                    let mut packets =
                        vec![chat_packet("§6⚠ Email partially delivered", Some("gold"))?];
                    packets.extend(draft_sign_packets(draft)?);
                    packets.push(draft_book_packet_for(draft)?);
                    return Ok((packets, false));
                }
            }

            match advance_outbound_poll(&mut pending.fast_polls, &mut pending.background_polls) {
                OutboundPollTransition::ContinueFast => {
                    pending.schedule_status(outbound, OUTBOUND_FAST_POLL_INTERVAL);
                    Ok((Vec::new(), true))
                }
                OutboundPollTransition::EnterBackground => {
                    pending.schedule_status(outbound, OUTBOUND_BACKGROUND_POLL_INTERVAL);
                    Ok((
                        vec![
                            chat_packet(
                                "§6Email is still being delivered (greylisting/retry)...",
                                Some("gold"),
                            )?,
                            chat_packet("§7You'll be notified when it completes.", Some("gray"))?,
                        ],
                        true,
                    ))
                }
                OutboundPollTransition::ContinueBackground => {
                    pending.schedule_status(outbound, OUTBOUND_BACKGROUND_POLL_INTERVAL);
                    Ok((Vec::new(), true))
                }
                OutboundPollTransition::Exhausted => Ok((
                    vec![chat_packet(
                        &format!(
                            "§6Email delivery taking long. Queue ID: {}",
                            pending.queue_id.unwrap_or_default()
                        ),
                        Some("gold"),
                    )?],
                    false,
                )),
            }
        }
    }
}

fn authenticated_command_packets(
    message: &str,
    config: &MinecraftConfig,
    draft: &mut MinecraftDraft,
    menu_window_id: Option<u8>,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let command = java_trim(message);
    if !command.starts_with('/') {
        return Ok(Vec::new());
    }
    let split = command.find(java_regex_space).unwrap_or(command.len());
    let name = command[..split].to_ascii_lowercase();
    let has_arguments = split < command.len();
    match name.as_str() {
        "/help" => email_instruction_packets(),
        "/stuck" => stuck_command_packets(config),
        "/skibidi" => Ok(vec![chat_packet(
            "Brrrrrr Skibidi dop dop dop yes yes!",
            None,
        )?]),
        "/video" if !has_arguments => Ok(vec![
            chat_packet(
                "\u{00a7}cUsage: /video play map [width=5] [fps=10] [dither=1]",
                Some("red"),
            )?,
            chat_packet(
                "\u{00a7}c       /video play [width=48] [fps=6]",
                Some("red"),
            )?,
            chat_packet("\u{00a7}c       /video stop | /video pause", Some("red"))?,
        ]),
        "/draft" => draft_summary_packets(draft),
        "/clear" => {
            draft.clear();
            let mut packets = vec![chat_packet("\u{00a7}aDraft cleared!", Some("green"))?];
            packets.extend(empty_draft_sign_packets()?);
            packets.push(draft_book_packet()?);
            Ok(packets)
        }
        "/menu" => menu_window_id.map_or_else(
            || Ok(Vec::new()),
            |window_id| main_menu_packets(window_id, render_settings),
        ),
        "/mail" | "/video" => Ok(Vec::new()),
        _ => Ok(vec![chat_packet(
            "\u{00a7}cUnknown command. Use /help",
            Some("red"),
        )?]),
    }
}

fn render_size_command_packets(
    message: &str,
    render_settings: &mut RenderSettings,
    username: &str,
    email: &str,
) -> io::Result<Option<(Vec<Vec<u8>>, bool)>> {
    let command = java_trim(message);
    let parts = command
        .split(java_regex_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts
        .first()
        .is_none_or(|name| !name.eq_ignore_ascii_case("/mail"))
        || parts.get(1).is_none_or(|subcommand| {
            !subcommand.eq_ignore_ascii_case("rendersize") && !subcommand.eq_ignore_ascii_case("rs")
        })
    {
        return Ok(None);
    }
    if parts.len() < 4 {
        return Ok(Some((
            render_settings_editor_packets(*render_settings)?,
            true,
        )));
    }

    let width = parts[2].parse::<i32>();
    let height = parts[3].parse::<i32>();
    let (Ok(width), Ok(height)) = (width, height) else {
        return Ok(Some((
            vec![chat_packet(
                "\u{00a7}cUsage: /mail rendersize <width> <height>",
                Some("red"),
            )?],
            false,
        )));
    };
    if !(RENDER_MAPS_X_MIN..=RENDER_MAPS_X_MAX).contains(&width) {
        return Ok(Some((
            vec![chat_packet(
                "\u{00a7}cWidth must be 2-24 maps",
                Some("red"),
            )?],
            false,
        )));
    }
    if !(RENDER_MAPS_Y_MIN..=RENDER_MAPS_Y_MAX).contains(&height) {
        return Ok(Some((
            vec![chat_packet(
                "\u{00a7}cHeight must be 2-20 maps",
                Some("red"),
            )?],
            false,
        )));
    }

    render_settings.maps_x = width;
    render_settings.maps_y = height;
    if let Some(font) = parts.get(4).and_then(|font| font.parse::<i32>().ok())
        && (RENDER_FONT_SIZE_MIN..=RENDER_FONT_SIZE_MAX).contains(&font)
    {
        render_settings.font_size = font;
    }
    let mut packets = authenticated_scoreboard_packets(username, email, *render_settings)?;
    packets.push(chat_packet(
        &format!(
            "\u{00a7}aRender: \u{00a7}f{}\u{00d7}{} \u{00a7}amaps, font \u{00a7}f{}px",
            render_settings.maps_x, render_settings.maps_y, render_settings.font_size
        ),
        Some("green"),
    )?);
    Ok(Some((packets, false)))
}

fn draft_summary_packets(draft: &MinecraftDraft) -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}lCurrent Draft:".to_owned(),
        format!("\u{00a7}7To: \u{00a7}f{}", draft_display(&draft.to)),
        format!("\u{00a7}7CC: \u{00a7}f{}", draft_display(&draft.cc)),
        format!("\u{00a7}7BCC: \u{00a7}f{}", draft_display(&draft.bcc)),
        format!(
            "\u{00a7}7Subject: \u{00a7}f{}",
            draft_display(&draft.subject)
        ),
        format!("\u{00a7}7Body: \u{00a7}f{} page(s)", draft.body_pages.len()),
    ]
    .into_iter()
    .map(|text| chat_packet(&text, None))
    .collect()
}

fn draft_display(value: &str) -> &str {
    if value.chars().all(char::is_whitespace) {
        "(empty)"
    } else {
        value
    }
}

fn main_menu_packets(window_id: u8, render_settings: RenderSettings) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, window_id];
    write_string(&mut open, "minecraft:chest")?;
    write_string(&mut open, &chat_json("\u{00a7}8LMYZMAIL Menu", None))?;
    open.push(54);

    Ok(vec![
        open,
        main_menu_contents_packet(window_id, render_settings)?,
    ])
}

fn main_menu_contents_packet(
    window_id: u8,
    render_settings: RenderSettings,
) -> io::Result<Vec<u8>> {
    let filler = gui_slot(160, 15, " ", &[], false);
    let mut slots = vec![filler; 54];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));
    slots[4] = gui_slot(
        399,
        0,
        "\u{00a7}6\u{00a7}lLMYZMAIL",
        &[
            "\u{00a7}7Minecraft Mail Server",
            "\u{00a7}7Skibidi dop dop yes yes!",
        ],
        true,
    );
    slots[10] = gui_slot(
        54,
        0,
        "\u{00a7}a\u{00a7}lInbox",
        &[
            "\u{00a7}7View received emails",
            "",
            "\u{00a7}eClick to open",
        ],
        false,
    );
    slots[12] = gui_slot(
        262,
        0,
        "\u{00a7}b\u{00a7}lSent",
        &["\u{00a7}7View sent emails", "", "\u{00a7}eClick to open"],
        false,
    );
    slots[14] = gui_slot(
        327,
        0,
        "\u{00a7}c\u{00a7}lTrash",
        &["\u{00a7}7View deleted emails", "", "\u{00a7}eClick to open"],
        false,
    );
    slots[16] = gui_slot(
        367,
        0,
        "\u{00a7}4\u{00a7}lSpam",
        &["\u{00a7}7View spam emails", "", "\u{00a7}eClick to open"],
        false,
    );
    let render_current = format!(
        "\u{00a7}7Current: \u{00a7}f{}\u{00d7}{} \u{00a7}7maps",
        render_settings.maps_x, render_settings.maps_y
    );
    let render_pixels = format!(
        "\u{00a7}7({}\u{00d7}{} px)",
        render_settings.maps_x * 128,
        render_settings.maps_y * 128
    );
    let render_font = format!("\u{00a7}7Font: \u{00a7}f{}px", render_settings.font_size);
    slots[22] = gui_slot(
        323,
        0,
        "\u{00a7}e\u{00a7}lRender Settings",
        &[
            "\u{00a7}7Mail render dimensions",
            &render_current,
            &render_pixels,
            &render_font,
            "",
            "\u{00a7}eClick to change",
        ],
        false,
    );
    slots[28] = gui_slot(
        49,
        0,
        "\u{00a7}c\u{00a7}lVideo Player",
        &[
            "\u{00a7}7Watch Skibidi Toilet EP.1",
            "\u{00a7}7in Minecraft!",
            "",
            "\u{00a7}eClick to choose mode",
        ],
        false,
    );
    slots[30] = gui_slot(
        340,
        0,
        "\u{00a7}f\u{00a7}lHelp",
        &["\u{00a7}7Show command help", "", "\u{00a7}eClick for help"],
        false,
    );
    slots[32] = gui_slot(
        345,
        0,
        "\u{00a7}e\u{00a7}lSwitch Account",
        &[
            "\u{00a7}7Log out and sign in",
            "\u{00a7}7with a different email",
            "",
            "\u{00a7}eClick to switch",
        ],
        false,
    );
    slots[34] = gui_slot(
        166,
        0,
        "\u{00a7}c\u{00a7}lLogout",
        &[
            "\u{00a7}7Disconnect from LMYZMAIL",
            "",
            "\u{00a7}eClick to logout",
        ],
        false,
    );
    slots[49] = gui_slot(
        331,
        0,
        "\u{00a7}7Close Menu",
        &["\u{00a7}8Click to close"],
        false,
    );
    slots[81] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[89] = MinecraftSlot::item(399, 0, menu_star_nbt());

    let mut contents = vec![0x30, window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

fn video_menu_packets(window_id: u8, config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, window_id];
    write_string(&mut open, "minecraft:chest")?;
    write_string(&mut open, &chat_json("\u{00a7}8Video Player", None))?;
    open.push(27);
    Ok(vec![open, video_menu_contents_packet(window_id, config)?])
}

fn video_menu_contents_packet(window_id: u8, config: &MinecraftConfig) -> io::Result<Vec<u8>> {
    let filler = gui_slot(160, 15, " ", &[], false);
    let mut slots = vec![filler; 27];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));
    slots[4] = gui_slot(
        399,
        0,
        "\u{00a7}c\u{00a7}lSkibidi Toilet \u{00a7}7EP.1",
        &["\u{00a7}7Choose playback mode"],
        true,
    );
    slots[11] = gui_slot(
        49,
        0,
        "\u{00a7}e\u{00a7}lBlock Art Mode",
        &[
            "\u{00a7}7Renders video as Minecraft blocks",
            "\u{00a7}7on the world wall.",
            "",
            &format!(
                "\u{00a7}fWidth: \u{00a7}7{} blocks",
                config.video.default_width
            ),
            &format!("\u{00a7}fFPS: \u{00a7}7{}", config.video.default_fps),
            "",
            "\u{00a7}eClick to start",
        ],
        false,
    );
    slots[15] = gui_slot(
        395,
        0,
        "\u{00a7}b\u{00a7}lMap Video Mode",
        &[
            "\u{00a7}7Renders video on item-frame maps.",
            "\u{00a7}7Higher resolution, smoother FPS.",
            "",
            &format!(
                "\u{00a7}fMaps: \u{00a7}7{} wide",
                config.video.map_default_maps_x
            ),
            &format!("\u{00a7}fFPS: \u{00a7}7{}", config.video.map_default_fps),
            "",
            "\u{00a7}eClick to start",
        ],
        false,
    );
    slots[22] = gui_slot(
        262,
        0,
        "\u{00a7}c\u{2190} Back",
        &["\u{00a7}7Return to main menu"],
        false,
    );
    slots[54] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[62] = MinecraftSlot::item(399, 0, menu_star_nbt());
    let mut contents = vec![0x30, window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VideoMenuEffect {
    None,
    Back(u8),
    StartMap,
    StartBlock,
}

fn video_menu_click_packets(
    click: WindowClick,
    main_window_id: Option<u8>,
    render_settings: RenderSettings,
    config: &MinecraftConfig,
) -> io::Result<(Vec<Vec<u8>>, VideoMenuEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);
    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    let mut packets = vec![
        confirmation,
        clear_cursor,
        video_menu_contents_packet(click.window_id, config)?,
    ];
    let effect = if click.mode != 0 || !(0..27).contains(&click.slot) {
        VideoMenuEffect::None
    } else {
        match click.slot {
            11 => {
                packets.push(vec![0x2e, click.window_id]);
                VideoMenuEffect::StartBlock
            }
            15 => {
                packets.push(vec![0x2e, click.window_id]);
                VideoMenuEffect::StartMap
            }
            22 => {
                let Some(window_id) = main_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft video menu return window ID is missing",
                    ));
                };
                packets.push(vec![0x2e, click.window_id]);
                packets.extend(main_menu_packets(window_id, render_settings)?);
                VideoMenuEffect::Back(window_id)
            }
            _ => VideoMenuEffect::None,
        }
    };
    Ok((packets, effect))
}

#[cfg(test)]
fn main_menu_click_packets(
    click: WindowClick,
    logout_window_id: Option<u8>,
    render_settings: RenderSettings,
    mail_view_active: bool,
) -> io::Result<(Vec<Vec<u8>>, MainMenuEffect)> {
    main_menu_click_packets_with_video(
        click,
        logout_window_id,
        None,
        render_settings,
        mail_view_active,
    )
}

fn main_menu_click_packets_with_video(
    click: WindowClick,
    logout_window_id: Option<u8>,
    video_menu: Option<(u8, &MinecraftConfig)>,
    render_settings: RenderSettings,
    mail_view_active: bool,
) -> io::Result<(Vec<Vec<u8>>, MainMenuEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);

    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());

    let mut packets = vec![
        confirmation,
        clear_cursor,
        main_menu_contents_packet(click.window_id, render_settings)?,
    ];
    let effect = if click.mode != 0 || !(0..54).contains(&click.slot) {
        MainMenuEffect::None
    } else {
        match click.slot {
            10 | 12 | 14 | 16 => {
                let folder = match click.slot {
                    10 => "inbox",
                    12 => "sent",
                    14 => "trash",
                    16 => "spam",
                    _ => unreachable!(),
                };
                packets.push(chat_packet(
                    &format!("\u{00a7}7Loading {folder}..."),
                    Some("gray"),
                )?);
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                MainMenuEffect::OpenFolder(folder)
            }
            22 => {
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.extend(render_settings_editor_packets(render_settings)?);
                MainMenuEffect::OpenRenderSettings
            }
            28 => {
                let Some((window_id, config)) = video_menu else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft video menu window ID is missing",
                    ));
                };
                packets.extend(restore_gui_hotbar_packets(mail_view_active)?);
                packets.extend(video_menu_packets(window_id, config)?);
                MainMenuEffect::OpenVideoMenu(window_id)
            }
            30 => {
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.extend(help_menu_packets()?);
                MainMenuEffect::Close
            }
            32 => {
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.push(chat_packet(
                    "\u{00a7}aPlease enter your new email address:",
                    Some("green"),
                )?);
                MainMenuEffect::SwitchAccount
            }
            34 => {
                let Some(window_id) = logout_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft logout confirmation window ID is missing",
                    ));
                };
                packets.extend(restore_gui_hotbar_packets(mail_view_active)?);
                packets.extend(logout_confirmation_packets(window_id)?);
                MainMenuEffect::OpenLogoutConfirm(window_id)
            }
            49 => {
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                MainMenuEffect::Close
            }
            _ => MainMenuEffect::None,
        }
    };
    Ok((packets, effect))
}

fn start_folder_load(
    service: &StatusService,
    email: &str,
    folder: &str,
    page: i32,
    action: FolderLoadAction,
    connection_deadline: Instant,
) -> io::Result<PendingFolderLoad> {
    let mailbox = service.mailbox.as_ref().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "Minecraft mailbox service is unavailable",
        )
    })?;
    let email = email.to_owned();
    let folder = folder.to_owned();
    let load_deadline = connection_deadline.min(Instant::now() + FOLDER_LOAD_TIMEOUT);
    let future = Box::pin(async move {
        match timeout_at(
            load_deadline,
            mailbox.list_folder(&email, &folder, page, FOLDER_PAGE_SIZE, false),
        )
        .await
        {
            Ok(Ok(page)) => Ok(page),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("mailbox backend unavailable".to_owned()),
        }
    });
    Ok(PendingFolderLoad { action, future })
}

fn start_mail_render(
    service: Arc<StatusService>,
    email: &str,
    folder: String,
    file_name: String,
    settings: RenderSettings,
    connection_deadline: Instant,
) -> io::Result<PendingMailRender> {
    let mailbox = service.mailbox.as_ref().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "Minecraft mailbox service is unavailable",
        )
    })?;
    let email = email.to_owned();
    let cancellation = CancellationToken::new();
    let simd_mode = service.mail_render_simd_mode;
    let future_cancellation = cancellation.clone();
    let render_deadline = connection_deadline.min(Instant::now() + MAIL_RENDER_TIMEOUT);
    let future = Box::pin(async move {
        let detail = tokio::select! {
            biased;
            _ = future_cancellation.cancelled() => return Err(MailRenderFailure::Cancelled),
            result = timeout_at(
                render_deadline,
                mailbox.read_detail(&email, &folder, &file_name),
            ) => match result {
                Ok(Ok(detail)) => detail,
                Ok(Err(error)) => return Err(MailRenderFailure::Read(error.to_string())),
                Err(_) => return Err(MailRenderFailure::Read("mailbox backend unavailable".to_owned())),
            },
        };
        if future_cancellation.is_cancelled() {
            return Err(MailRenderFailure::Cancelled);
        }

        let preparation_receiver = service
            .mail_render_pool
            .submit(move || prepare_mail_render(detail))
            .map_err(|error| match error {
                SubmitError::Full => MailRenderFailure::Busy,
                SubmitError::Closed => MailRenderFailure::Unavailable,
            })?;
        let mut preparation = tokio::select! {
            biased;
            _ = future_cancellation.cancelled() => return Err(MailRenderFailure::Cancelled),
            result = timeout_at(render_deadline, preparation_receiver) => match result {
                Ok(Ok(Ok(preparation))) => preparation,
                Ok(Ok(Err(error))) => return Err(MailRenderFailure::Render(error)),
                Ok(Err(_)) => return Err(MailRenderFailure::Unavailable),
                Err(_) => {
                    future_cancellation.cancel();
                    return Err(MailRenderFailure::Render(
                        "mail rendering deadline exceeded".to_owned(),
                    ));
                }
            },
        };

        let mut resources = Vec::with_capacity(
            preparation
                .cid_targets
                .len()
                .saturating_add(preparation.external_targets.len()),
        );
        let mut total_resource_bytes = 0usize;
        for target in preparation.cid_targets.drain(..) {
            let attachment = tokio::select! {
                biased;
                _ = future_cancellation.cancelled() => {
                    return Err(MailRenderFailure::Cancelled);
                }
                result = timeout_at(
                    render_deadline,
                    mailbox.read_attachment(&email, &folder, &file_name, target.index),
                ) => match result {
                    Ok(Ok(attachment)) => attachment,
                    Ok(Err(_)) => continue,
                    Err(_) => {
                        future_cancellation.cancel();
                        return Err(MailRenderFailure::Render(
                            "mail rendering deadline exceeded".to_owned(),
                        ));
                    }
                },
            };
            let body_len = attachment.body.len();
            if body_len == 0
                || body_len > mail_render::MAX_CID_RESOURCE_BYTES
                || !mail_render::is_safe_cid_image_type(attachment.content_type.as_deref())
            {
                continue;
            }
            let Some(next_total) = total_resource_bytes.checked_add(body_len) else {
                return Err(MailRenderFailure::Render(
                    "mail image resource budget overflowed".to_owned(),
                ));
            };
            if next_total > mail_render::MAX_TOTAL_RESOURCE_BYTES {
                break;
            }
            total_resource_bytes = next_total;
            resources.push(mail_render::EmbeddedResource::new(
                target.content_id,
                attachment.body,
                target.mime_type,
            ));
        }

        let mut successful_replacements = Vec::new();
        if let Some(image_http) = service.image_http.clone() {
            for target in preparation.external_targets.drain(..) {
                if resources.len() >= mail_render::MAX_IMAGE_RESOURCES {
                    break;
                }
                let downloaded = match image_http
                    .get(&target.url, render_deadline, &future_cancellation)
                    .await
                {
                    Ok(Some(downloaded)) => downloaded,
                    Ok(None) => continue,
                    Err(_) if future_cancellation.is_cancelled() => {
                        return Err(MailRenderFailure::Cancelled);
                    }
                    Err(_) if Instant::now() >= render_deadline => {
                        future_cancellation.cancel();
                        return Err(MailRenderFailure::Render(
                            "mail rendering deadline exceeded".to_owned(),
                        ));
                    }
                    Err(_) => continue,
                };
                let Some(next_total) = total_resource_bytes.checked_add(downloaded.body.len())
                else {
                    return Err(MailRenderFailure::Render(
                        "mail image resource budget overflowed".to_owned(),
                    ));
                };
                if next_total > mail_render::MAX_TOTAL_RESOURCE_BYTES {
                    break;
                }
                total_resource_bytes = next_total;
                successful_replacements.push((target.source, format!("cid:{}", target.content_id)));
                resources.push(mail_render::EmbeddedResource::new(
                    target.content_id,
                    downloaded.body,
                    downloaded.mime_type,
                ));
            }
        }

        let worker_cancellation = future_cancellation.clone();
        let receiver = service
            .mail_render_pool
            .submit(move || {
                let mut request = match &mut preparation.document {
                    mail_render::PreparedDocument::PlainText(plain_text) => {
                        mail_render::RenderRequest::plain_text(
                            plain_text,
                            settings.maps_x as u8,
                            settings.maps_y as u8,
                            &worker_cancellation,
                            render_deadline.into_std(),
                        )
                    }
                    mail_render::PreparedDocument::Html(html) => {
                        for (source, replacement) in successful_replacements {
                            *html = html.replace(&source, &replacement);
                        }
                        *html = mail_render::preprocess_html(html);
                        mail_render::RenderRequest::html(
                            html,
                            &resources,
                            settings.maps_x as u8,
                            settings.maps_y as u8,
                            &worker_cancellation,
                            render_deadline.into_std(),
                        )
                    }
                };
                request.simd_mode = simd_mode;
                request.style.font_size_px = f64::from(settings.font_size);
                mail_render::render(&request)
            })
            .map_err(|error| match error {
                SubmitError::Full => MailRenderFailure::Busy,
                SubmitError::Closed => MailRenderFailure::Unavailable,
            })?;
        tokio::select! {
            biased;
            _ = future_cancellation.cancelled() => Err(MailRenderFailure::Cancelled),
            result = timeout_at(render_deadline, receiver) => match result {
                Ok(Ok(Ok(result))) => Ok(result),
                Ok(Ok(Err(error))) => Err(MailRenderFailure::Render(error.to_string())),
                Ok(Err(_)) => Err(MailRenderFailure::Unavailable),
                Err(_) => {
                    future_cancellation.cancel();
                    Err(MailRenderFailure::Render("mail rendering deadline exceeded".to_owned()))
                }
            },
        }
    });
    Ok(PendingMailRender {
        cancellation,
        future,
    })
}

impl MapWallFacing {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "WEST" => Self::West,
            "NORTH" => Self::North,
            "EAST" => Self::East,
            _ => Self::South,
        }
    }

    fn frame_direction(self) -> i32 {
        match self {
            Self::South => 0,
            Self::West => 1,
            Self::North => 2,
            Self::East => 3,
        }
    }
}

impl MapWall {
    fn new(service: &StatusService, maps_x: usize, maps_y: usize) -> io::Result<Self> {
        if maps_x == 0
            || maps_y == 0
            || maps_x > RENDER_MAPS_X_MAX as usize
            || maps_y > RENDER_MAPS_Y_MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Minecraft map wall dimensions are out of bounds",
            ));
        }
        let total = maps_x
            .checked_mul(maps_y)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| io::Error::other("Minecraft map wall size overflow"))?;
        let (map_base, entity_base) = service.reserve_map_wall_ids(total)?;
        let map_ids = (0..total)
            .map(|offset| map_base + offset)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let entity_ids = (0..total)
            .map(|offset| entity_base + offset)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            maps_x,
            maps_y,
            facing: MapWallFacing::parse(&service.config.video.map_facing),
            center_x: service.config.video.map_center_x,
            center_y: service.config.video.map_center_y,
            center_z: service.config.video.map_center_z,
            map_ids,
            entity_ids,
            saved_blocks: Vec::with_capacity(total as usize * 2),
        })
    }

    fn map_id(&self, col: usize, row: usize) -> io::Result<i32> {
        self.map_ids
            .get(row.saturating_mul(self.maps_x).saturating_add(col))
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "map tile is out of range"))
    }

    fn support_position(&self, col: usize, y: i32) -> (i32, i32, i32) {
        let col = col as i32;
        let maps_x = self.maps_x as i32;
        match self.facing {
            MapWallFacing::South => {
                let start_x = self.center_x - (maps_x - 1) / 2;
                (start_x + col, y, self.center_z)
            }
            MapWallFacing::North => {
                let start_x = self.center_x + (maps_x - 1) / 2;
                (start_x - col, y, self.center_z)
            }
            MapWallFacing::East => {
                let start_z = self.center_z + (maps_x - 1) / 2;
                (self.center_x, y, start_z - col)
            }
            MapWallFacing::West => {
                let start_z = self.center_z - (maps_x - 1) / 2;
                (self.center_x, y, start_z + col)
            }
        }
    }

    fn air_position(&self, support: (i32, i32, i32)) -> (i32, i32, i32) {
        let (x, y, z) = support;
        match self.facing {
            MapWallFacing::South => (x, y, z + 1),
            MapWallFacing::North => (x, y, z - 1),
            MapWallFacing::East => (x + 1, y, z),
            MapWallFacing::West => (x - 1, y, z),
        }
    }

    fn fixed_entity_position(&self, air: (i32, i32, i32)) -> (i32, i32, i32) {
        let (x, y, z) = air;
        match self.facing {
            MapWallFacing::South => (x * 32 + 16, y * 32 + 16, z * 32 + 1),
            MapWallFacing::North => (x * 32 + 16, y * 32 + 16, z * 32 + 31),
            MapWallFacing::East => (x * 32 + 1, y * 32 + 16, z * 32 + 16),
            MapWallFacing::West => (x * 32 + 31, y * 32 + 16, z * 32 + 16),
        }
    }

    fn setup_packets(&mut self, world: &WorldTemplate) -> io::Result<Vec<Vec<u8>>> {
        let total = self.maps_x * self.maps_y;
        let mut packets = Vec::with_capacity(total * 5);
        let mut saved = HashSet::with_capacity(total * 2);
        let blank = [MAP_BLANK_COLOR; MAP_TILE_PIXELS];
        let max_y = self.center_y + (self.maps_y as i32 - 1) / 2;
        for row in 0..self.maps_y {
            let y = max_y - row as i32;
            for col in 0..self.maps_x {
                let index = row * self.maps_x + col;
                let support = self.support_position(col, y);
                let air = self.air_position(support);
                for position in [support, air] {
                    if saved.insert(position) {
                        self.saved_blocks.push((
                            position,
                            world.block_state_at(position.0, position.1, position.2),
                        ));
                    }
                }
                packets.push(block_change_packet(support, MAP_SUPPORT_BLOCK_STATE));
                packets.push(block_change_packet(air, 0));
                packets.push(spawn_object_packet(
                    self.entity_ids[index],
                    self.fixed_entity_position(air),
                    self.facing.frame_direction(),
                ));
                packets.push(entity_metadata_map_packet(
                    self.entity_ids[index],
                    self.map_ids[index],
                ));
                packets.push(map_data_packet(self.map_ids[index], &blank)?);
            }
        }
        Ok(packets)
    }

    fn teardown_packets(self) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(self.saved_blocks.len() + 1);
        packets.push(destroy_entities_packet(&self.entity_ids));
        packets.extend(
            self.saved_blocks
                .into_iter()
                .map(|(position, state)| block_change_packet(position, state)),
        );
        packets
    }
}

fn block_change_packet(position: (i32, i32, i32), block_state: i32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(14);
    packet.push(0x23);
    write_block_position(&mut packet, position.0, position.1, position.2);
    write_varint(&mut packet, block_state as u32);
    packet
}

fn spawn_object_packet(
    entity_id: i32,
    fixed_position: (i32, i32, i32),
    object_data: i32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32);
    packet.push(0x0e);
    write_varint(&mut packet, entity_id as u32);
    packet.push(71);
    packet.extend_from_slice(&fixed_position.0.to_be_bytes());
    packet.extend_from_slice(&fixed_position.1.to_be_bytes());
    packet.extend_from_slice(&fixed_position.2.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&object_data.to_be_bytes());
    if object_data > 0 {
        packet.extend_from_slice(&[0; 6]);
    }
    packet
}

fn entity_metadata_map_packet(entity_id: i32, map_id: i32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(16);
    packet.push(0x1c);
    write_varint(&mut packet, entity_id as u32);
    packet.push(0xa8);
    packet.extend_from_slice(&358_i16.to_be_bytes());
    packet.push(1);
    packet.extend_from_slice(&(map_id as i16).to_be_bytes());
    packet.extend_from_slice(&[0, 0x7f]);
    packet
}

fn map_data_packet(map_id: i32, pixels: &[u8]) -> io::Result<Vec<u8>> {
    if pixels.len() != MAP_TILE_PIXELS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Minecraft map tile must contain exactly 16384 pixels",
        ));
    }
    let mut packet = Vec::with_capacity(MAP_TILE_PIXELS + 16);
    packet.push(0x34);
    write_varint(&mut packet, map_id as u32);
    packet.push(0);
    write_varint(&mut packet, 0);
    packet.extend_from_slice(&[128, 128, 0, 0]);
    write_varint(&mut packet, MAP_TILE_PIXELS as u32);
    packet.extend_from_slice(pixels);
    Ok(packet)
}

fn map_data_rect_packet(
    map_id: i32,
    x_offset: usize,
    z_offset: usize,
    columns: usize,
    rows: usize,
    pixels: &[u8],
) -> io::Result<Vec<u8>> {
    if columns == 0
        || rows == 0
        || x_offset >= 128
        || z_offset >= 128
        || x_offset + columns > 128
        || z_offset + rows > 128
        || pixels.len() != columns * rows
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Minecraft map delta is outside the tile",
        ));
    }
    let mut packet = Vec::with_capacity(pixels.len() + 16);
    packet.push(0x34);
    write_varint(&mut packet, map_id as u32);
    packet.push(0);
    write_varint(&mut packet, 0);
    packet.extend_from_slice(&[
        u8::try_from(columns).expect("bounded map columns"),
        u8::try_from(rows).expect("bounded map rows"),
        u8::try_from(x_offset).expect("bounded map x offset"),
        u8::try_from(z_offset).expect("bounded map z offset"),
    ]);
    write_varint(
        &mut packet,
        u32::try_from(pixels.len()).expect("bounded map delta bytes"),
    );
    packet.extend_from_slice(pixels);
    Ok(packet)
}

fn video_frame_packets(
    wall: &MapWall,
    map_colors: &[u8],
    previous_frame: &mut Option<Vec<u8>>,
) -> io::Result<Vec<Vec<u8>>> {
    let width = wall
        .maps_x
        .checked_mul(128)
        .ok_or_else(|| io::Error::other("video frame width overflow"))?;
    let height = wall
        .maps_y
        .checked_mul(128)
        .ok_or_else(|| io::Error::other("video frame height overflow"))?;
    if map_colors.len() != width * height {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "video frame dimensions do not match the map wall",
        ));
    }
    let old = previous_frame.as_deref();
    let mut packets = Vec::with_capacity(wall.maps_x * wall.maps_y);
    for row in 0..wall.maps_y {
        for col in 0..wall.maps_x {
            let mut x_min = 128;
            let mut z_min = 128;
            let mut x_max = 0_usize;
            let mut z_max = 0_usize;
            let mut changed = old.is_none();
            for z in 0..128 {
                let source_row = (row * 128 + z) * width + col * 128;
                for x in 0..128 {
                    let index = source_row + x;
                    if old.is_none_or(|previous| previous[index] != map_colors[index]) {
                        changed = true;
                        x_min = x_min.min(x);
                        x_max = x_max.max(x);
                        z_min = z_min.min(z);
                        z_max = z_max.max(z);
                    }
                }
            }
            if !changed {
                continue;
            }
            let columns = x_max - x_min + 1;
            let rows = z_max - z_min + 1;
            let mut pixels = Vec::with_capacity(columns * rows);
            for z in z_min..=z_max {
                let start = (row * 128 + z) * width + col * 128 + x_min;
                pixels.extend_from_slice(&map_colors[start..start + columns]);
            }
            packets.push(map_data_rect_packet(
                wall.map_id(col, row)?,
                x_min,
                z_min,
                columns,
                rows,
                &pixels,
            )?);
        }
    }
    *previous_frame = Some(map_colors.to_vec());
    Ok(packets)
}

fn destroy_entities_packet(entity_ids: &[i32]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(entity_ids.len() * 5 + 6);
    packet.push(0x13);
    write_varint(&mut packet, entity_ids.len() as u32);
    for &entity_id in entity_ids {
        write_varint(&mut packet, entity_id as u32);
    }
    packet
}

fn mail_view_page_packets(wall: &MapWall, page: &mail_render::Page) -> io::Result<Vec<Vec<u8>>> {
    if usize::from(page.maps_x()) != wall.maps_x || usize::from(page.maps_y()) > wall.maps_y {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rendered page dimensions do not fit the map wall",
        ));
    }
    let mut packets = Vec::with_capacity(wall.maps_x * wall.maps_y);
    let mut tile_pixels = [0_u8; MAP_TILE_PIXELS];
    for row in 0..usize::from(page.maps_y()) {
        for col in 0..wall.maps_x {
            page.tile_at(col, row)
                .ok_or_else(|| io::Error::other("rendered map tile is missing"))?
                .copy_into(&mut tile_pixels);
            packets.push(map_data_packet(wall.map_id(col, row)?, &tile_pixels)?);
        }
    }
    tile_pixels.fill(MAP_BLANK_COLOR);
    for row in usize::from(page.maps_y())..wall.maps_y {
        for col in 0..wall.maps_x {
            packets.push(map_data_packet(wall.map_id(col, row)?, &tile_pixels)?);
        }
    }
    Ok(packets)
}

fn hotbar_skull_nbt(texture_url: &str, name: &str, lore: &str) -> NbtValue {
    let texture_json = serde_json::json!({
        "textures": {"SKIN": {"url": texture_url}}
    })
    .to_string();
    let skull_owner = NbtValue::Compound(vec![
        (
            "Id".to_owned(),
            NbtValue::String(java_name_uuid(texture_url.as_bytes())),
        ),
        (
            "Properties".to_owned(),
            NbtValue::Compound(vec![(
                "textures".to_owned(),
                NbtValue::List {
                    element_type: 10,
                    values: vec![NbtValue::Compound(vec![(
                        "Value".to_owned(),
                        NbtValue::String(STANDARD.encode(texture_json.as_bytes())),
                    )])],
                },
            )]),
        ),
    ]);
    let display = NbtValue::Compound(vec![
        ("Name".to_owned(), NbtValue::String(name.to_owned())),
        (
            "Lore".to_owned(),
            NbtValue::List {
                element_type: 8,
                values: vec![NbtValue::String(lore.to_owned())],
            },
        ),
    ]);
    NbtValue::Compound(vec![
        ("SkullOwner".to_owned(), skull_owner),
        ("display".to_owned(), display),
    ])
}

fn hotbar_display_nbt(name: &str, lore: &str) -> NbtValue {
    NbtValue::Compound(vec![(
        "display".to_owned(),
        NbtValue::Compound(vec![
            ("Name".to_owned(), NbtValue::String(name.to_owned())),
            (
                "Lore".to_owned(),
                NbtValue::List {
                    element_type: 8,
                    values: vec![NbtValue::String(lore.to_owned())],
                },
            ),
        ]),
    )])
}

fn set_slot_packet(slot: i16, item: &MinecraftSlot) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x2f, 0];
    packet.extend_from_slice(&slot.to_be_bytes());
    write_slot(&mut packet, item)?;
    Ok(packet)
}

fn mail_view_hotbar_packets() -> io::Result<Vec<Vec<u8>>> {
    Ok(vec![
        set_slot_packet(
            39,
            &MinecraftSlot::item(
                397,
                3,
                hotbar_skull_nbt(
                    TEXTURE_ARROW_LEFT,
                    "\u{00a7}a\u{25c0} Previous Page",
                    "\u{00a7}7Right-click to go back",
                ),
            ),
        )?,
        set_slot_packet(
            40,
            &MinecraftSlot::item(
                166,
                0,
                hotbar_display_nbt(
                    "\u{00a7}c\u{2716} Close View",
                    "\u{00a7}7Right-click to close",
                ),
            ),
        )?,
        set_slot_packet(
            41,
            &MinecraftSlot::item(
                397,
                3,
                hotbar_skull_nbt(
                    TEXTURE_ARROW_RIGHT,
                    "\u{00a7}aNext Page \u{25b6}",
                    "\u{00a7}7Right-click to advance",
                ),
            ),
        )?,
        vec![0x09, 4],
    ])
}

fn restore_default_hotbar_packets() -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(10);
    for slot in 37_i16..=43 {
        packets.push(set_slot_packet(slot, &MinecraftSlot::empty())?);
    }
    packets.push(draft_book_packet()?);
    let mut menu_star = vec![0x2f, 0];
    menu_star.extend_from_slice(&44_i16.to_be_bytes());
    write_slot(
        &mut menu_star,
        &MinecraftSlot::item(399, 0, menu_star_nbt()),
    )?;
    packets.push(menu_star);
    packets.push(vec![0x09, 0]);
    Ok(packets)
}

fn video_hotbar_packets() -> io::Result<Vec<Vec<u8>>> {
    Ok(vec![
        set_slot_packet(
            39,
            &MinecraftSlot::item(
                397,
                3,
                hotbar_skull_nbt(
                    TEXTURE_PLAY_BUTTON,
                    "\u{00a7}e\u{23ef} Pause / Resume",
                    "\u{00a7}7Right-click to toggle",
                ),
            ),
        )?,
        set_slot_packet(
            40,
            &MinecraftSlot::item(
                166,
                0,
                hotbar_display_nbt(
                    "\u{00a7}c\u{23f9} Stop Video",
                    "\u{00a7}7Right-click to stop",
                ),
            ),
        )?,
        vec![0x09, 4],
    ])
}

fn scoreboard_packets(lines: &[String]) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(lines.len() + 3);
    let mut remove = vec![0x3b];
    write_string(&mut remove, "lmyz")?;
    remove.push(1);
    packets.push(remove);

    let mut create = vec![0x3b];
    write_string(&mut create, "lmyz")?;
    create.push(0);
    write_string(&mut create, "\u{00a7}6\u{00a7}lLMYZMAIL")?;
    write_string(&mut create, "dummy")?;
    packets.push(create);

    let mut display = vec![0x3d, 1];
    write_string(&mut display, "lmyz")?;
    packets.push(display);

    for (index, line) in lines.iter().enumerate() {
        let prefix = char::from_digit(index as u32, 16).unwrap_or('f');
        let score_name = truncate_utf16(&format!("\u{00a7}{prefix}\u{00a7}r{line}"), 40);
        let mut score = vec![0x3c];
        write_string(&mut score, &score_name)?;
        score.push(0);
        write_string(&mut score, "lmyz")?;
        write_varint(&mut score, (lines.len() - index) as u32);
        packets.push(score);
    }
    Ok(packets)
}

fn email_view_scoreboard_packets(page: usize, total_pages: usize) -> io::Result<Vec<Vec<u8>>> {
    let divider = format!("\u{00a7}7{}", "\u{2501}".repeat(13));
    scoreboard_packets(&[
        divider.clone(),
        "\u{00a7}bViewing Email".to_owned(),
        format!(
            "\u{00a7}fPage: \u{00a7}a{}\u{00a7}7/\u{00a7}f{total_pages}",
            page + 1
        ),
        String::new(),
        "\u{00a7}f\u{25c0} \u{00a7}7Prev  \u{00a7}f\u{2716} \u{00a7}7Close  \u{00a7}f\u{25b6} \u{00a7}7Next"
            .to_owned(),
        divider,
        "\u{00a7}email.lmyz.net".to_owned(),
    ])
}

fn video_scoreboard_packets(mode: &str, fps: u32) -> io::Result<Vec<Vec<u8>>> {
    let divider = format!("\u{00a7}7{}", "\u{2501}".repeat(13));
    scoreboard_packets(&[
        divider.clone(),
        "\u{00a7}cVideo Playing".to_owned(),
        format!("\u{00a7}fMode: \u{00a7}a{mode}"),
        format!("\u{00a7}fFPS: \u{00a7}a{fps}"),
        String::new(),
        "\u{00a7}f\u{23ef} \u{00a7}7Pause  \u{00a7}f\u{23f9} \u{00a7}7Stop".to_owned(),
        divider,
        "\u{00a7}email.lmyz.net".to_owned(),
    ])
}

fn positioned_chat_packet(text: &str, position: u8) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x02];
    write_string(&mut packet, &chat_json(text, None))?;
    packet.push(position);
    Ok(packet)
}

fn mail_view_actionbar_packet(page: usize, total_pages: usize) -> io::Result<Vec<u8>> {
    positioned_chat_packet(
        &format!(
            "\u{00a7}7\u{1f4e7} Page \u{00a7}f{}\u{00a7}7/\u{00a7}f{total_pages} \u{00a7}8| \u{00a7}f\u{25c0} Prev \u{00a7}8| \u{00a7}f\u{2716} Close \u{00a7}8| \u{00a7}fNext \u{25b6}",
            page + 1
        ),
        2,
    )
}

fn mail_view_started_packets(total_pages: usize) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = mail_view_hotbar_packets()?;
    packets.extend(email_view_scoreboard_packets(0, total_pages)?);
    packets.push(mail_view_actionbar_packet(0, total_pages)?);
    packets.push(chat_packet(
        "\u{00a7}a\u{00a7}lEmail rendered on map wall!",
        Some("green"),
    )?);
    if total_pages > 1 {
        packets.push(chat_packet(
            &format!(
                "\u{00a7}7Page \u{00a7}f1\u{00a7}7/\u{00a7}f{total_pages} \u{00a7}7\u{2014} Use hotbar arrows or \u{00a7}f/mail next\u{00a7}7/\u{00a7}fprev"
            ),
            Some("gray"),
        )?);
    }
    packets.push(chat_packet(
        "\u{00a7}7Use \u{00a7}fbarrier item \u{00a7}7or \u{00a7}f/mail close \u{00a7}7to close",
        Some("gray"),
    )?);
    Ok(packets)
}

fn mail_view_navigation_packets(
    view: &mut ActiveMailView,
    direction: i32,
) -> io::Result<Vec<Vec<u8>>> {
    let total_pages = view.result.pages().len();
    let next = view.current_page as i32 + direction;
    if next < 0 {
        return Ok(vec![chat_packet(
            "\u{00a7}cAlready on the first page",
            Some("red"),
        )?]);
    }
    let next = next as usize;
    if next >= total_pages {
        return Ok(vec![chat_packet(
            "\u{00a7}cAlready on the last page",
            Some("red"),
        )?]);
    }
    view.current_page = next;
    let mut packets = mail_view_page_packets(&view.wall, &view.result.pages()[next])?;
    packets.extend(email_view_scoreboard_packets(next, total_pages)?);
    packets.push(mail_view_actionbar_packet(next, total_pages)?);
    packets.push(chat_packet(
        &format!(
            "\u{00a7}7Page \u{00a7}f{}\u{00a7}7/\u{00a7}f{total_pages}",
            next + 1
        ),
        Some("gray"),
    )?);
    Ok(packets)
}

fn mail_view_close_packets(
    view: ActiveMailView,
    username: &str,
    email: &str,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = view.wall.teardown_packets();
    packets.extend(restore_default_hotbar_packets()?);
    packets.extend(authenticated_scoreboard_packets(
        username,
        email,
        render_settings,
    )?);
    packets.push(chat_packet("\u{00a7}aMail view closed.", Some("green"))?);
    Ok(packets)
}

fn folder_gui_packets(gui: &FolderGui) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, gui.window_id];
    write_string(&mut open, "minecraft:chest")?;
    let label = match gui.folder.as_str() {
        "inbox" => "\u{00a7}9Inbox".to_owned(),
        "sent" => "\u{00a7}bSent".to_owned(),
        "trash" => "\u{00a7}cTrash".to_owned(),
        "spam" => "\u{00a7}4Spam".to_owned(),
        folder => format!("\u{00a7}8{folder}"),
    };
    let title = format!(
        "{label} \u{00a7}8(Page {}/{})",
        gui.page.current_page + 1,
        gui.page.total_pages.max(1)
    );
    write_string(&mut open, &chat_json(&title, None))?;
    open.push(54);
    Ok(vec![open, folder_contents_packet(gui)?])
}

fn folder_contents_packet(gui: &FolderGui) -> io::Result<Vec<u8>> {
    let mut slots = vec![MinecraftSlot::empty(); 54];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));

    for (index, item) in gui
        .page
        .content
        .iter()
        .take(FOLDER_PAGE_SIZE as usize)
        .enumerate()
    {
        slots[index] = folder_email_slot(item);
    }

    let separator = gui_slot(160, 7, " ", &[], false);
    for slot in &mut slots[36..45] {
        *slot = separator.clone();
    }
    let page_name = format!(
        "\u{00a7}ePage {}/{}",
        gui.page.current_page + 1,
        gui.page.total_pages.max(1)
    );
    let page_lore = format!("\u{00a7}7{} email(s) total", gui.page.total_elements);
    slots[40] = gui_slot(339, 0, &page_name, &[&page_lore], false);

    let filler = gui_slot(160, 15, " ", &[], false);
    for slot in &mut slots[45..54] {
        *slot = filler.clone();
    }
    if gui.page.current_page > 0 {
        let lore = format!("\u{00a7}7Page {}", gui.page.current_page);
        slots[46] = skull_gui_slot(
            TEXTURE_ARROW_LEFT,
            "\u{00a7}a\u{25c0} Previous Page",
            &[&lore],
        );
    }
    slots[49] = gui_slot(
        262,
        0,
        "\u{00a7}c\u{2190} Back to Menu",
        &["\u{00a7}7Return to main menu"],
        false,
    );
    if gui.page.current_page < gui.page.total_pages - 1 {
        let lore = format!("\u{00a7}7Page {}", gui.page.current_page + 2);
        slots[52] = skull_gui_slot(TEXTURE_ARROW_RIGHT, "\u{00a7}aNext Page \u{25b6}", &[&lore]);
    }

    slots[81] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[89] = MinecraftSlot::item(399, 0, menu_star_nbt());
    let mut contents = vec![0x30, gui.window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

fn folder_email_slot(item: &EmailListItem) -> MinecraftSlot {
    let subject = java_truncated_nbt_line("\u{00a7}f", item.subject.as_deref(), 32);
    let sender = java_truncated_nbt_line("\u{00a7}7From: \u{00a7}f", item.from.as_deref(), 28);
    let date = format!("\u{00a7}7Date: \u{00a7}f{}", folder_date(&item.received_at));
    let display = NbtValue::Compound(vec![
        ("Name".to_owned(), NbtValue::Utf16String(subject)),
        (
            "Lore".to_owned(),
            NbtValue::List {
                element_type: 8,
                values: vec![
                    NbtValue::Utf16String(sender),
                    NbtValue::String(date),
                    NbtValue::String(String::new()),
                    NbtValue::String("\u{00a7}eClick to view on map wall".to_owned()),
                ],
            },
        ),
    ]);
    let mut root = vec![("display".to_owned(), display)];
    if item.has_attachments {
        root.push((
            "ench".to_owned(),
            NbtValue::List {
                element_type: 10,
                values: vec![NbtValue::Compound(vec![
                    ("id".to_owned(), NbtValue::Short(0)),
                    ("lvl".to_owned(), NbtValue::Short(1)),
                ])],
            },
        ));
        root.push(("HideFlags".to_owned(), NbtValue::Int(63)));
    }
    MinecraftSlot::item(339, 0, NbtValue::Compound(root))
}

const TEXTURE_ARROW_LEFT: &str = "http://textures.minecraft.net/texture/de1dfc11a837111d22b001a14461f9a7fc093522f88c58faefd6adeffcd4e9ab";
const TEXTURE_ARROW_RIGHT: &str = "http://textures.minecraft.net/texture/7c69d41076a8dea4f06d3f1a9ac47cc996988b74a0913ab2ac1a74caf7081918";
const TEXTURE_PLAY_BUTTON: &str = "http://textures.minecraft.net/texture/384e46a4e1ae05b932a8c6601a7d36fa3d5fb7919d82f7d170ff745317c2abe2";

fn skull_gui_slot(texture_url: &str, name: &str, lore: &[&str]) -> MinecraftSlot {
    let display = vec![
        ("Name".to_owned(), NbtValue::String(name.to_owned())),
        (
            "Lore".to_owned(),
            NbtValue::List {
                element_type: 8,
                values: lore
                    .iter()
                    .map(|line| NbtValue::String((*line).to_owned()))
                    .collect(),
            },
        ),
    ];
    let texture_json = serde_json::json!({
        "textures": {"SKIN": {"url": texture_url}}
    })
    .to_string();
    let texture_value = STANDARD.encode(texture_json.as_bytes());
    let skull_owner = NbtValue::Compound(vec![
        (
            "Id".to_owned(),
            NbtValue::String(java_name_uuid(texture_url.as_bytes())),
        ),
        (
            "Properties".to_owned(),
            NbtValue::Compound(vec![(
                "textures".to_owned(),
                NbtValue::List {
                    element_type: 10,
                    values: vec![NbtValue::Compound(vec![(
                        "Value".to_owned(),
                        NbtValue::String(texture_value),
                    )])],
                },
            )]),
        ),
    ]);
    MinecraftSlot::item(
        397,
        3,
        NbtValue::Compound(vec![
            ("display".to_owned(), NbtValue::Compound(display)),
            ("SkullOwner".to_owned(), skull_owner),
        ]),
    )
}

fn java_truncated_nbt_line(prefix: &str, value: Option<&str>, max_utf16_units: usize) -> Vec<u16> {
    let encoded = value.unwrap_or("(none)").encode_utf16().collect::<Vec<_>>();
    let mut output = prefix.encode_utf16().collect::<Vec<_>>();
    if encoded.len() > max_utf16_units {
        output.extend_from_slice(&encoded[..max_utf16_units]);
        output.extend("...".encode_utf16());
    } else {
        output.extend_from_slice(&encoded);
    }
    output
}

fn folder_date(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value).map_or_else(
        |_| "?".to_owned(),
        |date| {
            date.with_timezone(&chrono::Local)
                .format("%m/%d %H:%M")
                .to_string()
        },
    )
}

fn folder_gui_click_packets(
    click: WindowClick,
    gui: &FolderGui,
    main_window_id: Option<u8>,
    render_settings: RenderSettings,
    mail_view_active: bool,
) -> io::Result<(Vec<Vec<u8>>, FolderGuiEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);
    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    let mut packets = vec![confirmation, clear_cursor, folder_contents_packet(gui)?];
    let effect = if click.mode != 0 || !(0..54).contains(&click.slot) {
        FolderGuiEffect::None
    } else {
        match click.slot {
            slot @ 0..36 if (slot as usize) < gui.page.content.len() => {
                let item = &gui.page.content[slot as usize];
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.push(chat_packet("\u{00a7}7Rendering email...", Some("gray"))?);
                FolderGuiEffect::OpenMail {
                    folder: gui.folder.clone(),
                    file_name: item.file_name.clone(),
                }
            }
            46 if gui.page.current_page > 0 => FolderGuiEffect::LoadPage(gui.page.current_page - 1),
            49 => {
                let Some(window_id) = main_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft main-menu window ID is missing",
                    ));
                };
                packets.extend(restore_gui_hotbar_packets(mail_view_active)?);
                packets.extend(main_menu_packets(window_id, render_settings)?);
                FolderGuiEffect::OpenMainMenu(window_id)
            }
            52 if gui.page.current_page < gui.page.total_pages - 1 => {
                FolderGuiEffect::LoadPage(gui.page.current_page + 1)
            }
            _ => FolderGuiEffect::None,
        }
    };
    Ok((packets, effect))
}

fn render_settings_editor_packets(render_settings: RenderSettings) -> io::Result<Vec<Vec<u8>>> {
    let sign_nbt = NbtValue::Compound(vec![
        ("id".to_owned(), NbtValue::String("Sign".to_owned())),
        ("x".to_owned(), NbtValue::Int(0)),
        ("y".to_owned(), NbtValue::Int(0)),
        ("z".to_owned(), NbtValue::Int(0)),
        (
            "Text1".to_owned(),
            NbtValue::String(chat_json(&render_settings.maps_x.to_string(), None)),
        ),
        (
            "Text2".to_owned(),
            NbtValue::String(chat_json(&render_settings.maps_y.to_string(), None)),
        ),
        (
            "Text3".to_owned(),
            NbtValue::String(chat_json(&render_settings.font_size.to_string(), None)),
        ),
        (
            "Text4".to_owned(),
            NbtValue::String(chat_json("\u{00a7}oW H Font", None)),
        ),
    ]);
    let mut update = vec![0x35];
    write_block_position(&mut update, 0, 0, 0);
    update.push(9);
    minecraft_world::write_nbt(Some(&sign_nbt), &mut update)?;

    let mut editor = vec![0x36];
    write_block_position(&mut editor, 0, 0, 0);

    Ok(vec![
        update,
        editor,
        chat_packet(
            "\u{00a7}7Enter render dimensions in the sign:",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 1: Width in maps \u{00a7}f(2-24)",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 2: Height in maps \u{00a7}f(2-20)",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 3: Font size in px \u{00a7}f(8-48, default 20)",
            Some("gray"),
        )?,
    ])
}

fn render_settings_update_packets(
    update: UpdateSign,
    render_settings: &mut RenderSettings,
    username: &str,
    email: &str,
    draft: &MinecraftDraft,
) -> io::Result<Vec<Vec<u8>>> {
    let width_text = clean_sign_text(&strip_chat_json(&update.lines[0]));
    let height_text = clean_sign_text(&strip_chat_json(&update.lines[1]));
    let font_text = clean_sign_text(&strip_chat_json(&update.lines[2]));
    let width = width_text.parse::<i32>();
    let height = height_text.parse::<i32>();

    let (Ok(width), Ok(height)) = (width, height) else {
        let mut packets = vec![chat_packet(
            "\u{00a7}cWidth and height must be integers.",
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    };
    if !(RENDER_MAPS_X_MIN..=RENDER_MAPS_X_MAX).contains(&width) {
        let mut packets = vec![chat_packet(
            &format!("\u{00a7}cWidth must be 2-24 maps (got {width})"),
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    }
    if !(RENDER_MAPS_Y_MIN..=RENDER_MAPS_Y_MAX).contains(&height) {
        let mut packets = vec![chat_packet(
            &format!("\u{00a7}cHeight must be 2-20 maps (got {height})"),
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    }

    render_settings.maps_x = width;
    render_settings.maps_y = height;
    let mut packets = Vec::new();
    if !font_text.is_empty()
        && let Ok(font_size) = font_text.parse::<i32>()
    {
        if (RENDER_FONT_SIZE_MIN..=RENDER_FONT_SIZE_MAX).contains(&font_size) {
            render_settings.font_size = font_size;
        } else {
            packets.push(chat_packet(
                "\u{00a7}cFont size must be 8-48px",
                Some("red"),
            )?);
        }
    }
    packets.push(chat_packet(
        &format!(
            "\u{00a7}aRender: \u{00a7}f{}\u{00d7}{} \u{00a7}amaps, font \u{00a7}f{}px",
            render_settings.maps_x, render_settings.maps_y, render_settings.font_size
        ),
        Some("green"),
    )?);
    packets.extend(authenticated_scoreboard_packets(
        username,
        email,
        *render_settings,
    )?);
    packets.extend(draft_sign_packets(draft)?);
    Ok(packets)
}

fn strip_chat_json(value: &str) -> String {
    let value = java_trim(value);
    if value.starts_with('{') {
        let Some(text_index) = value.find("\"text\"") else {
            return String::new();
        };
        let after_key = &value[text_index + 6..];
        let Some(open_quote) = after_key.find('"') else {
            return String::new();
        };
        let text_start = text_index + 6 + open_quote + 1;
        let Some(close_quote) = value[text_start..].find('"') else {
            return String::new();
        };
        return value[text_start..text_start + close_quote]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        return value[1..value.len() - 1].to_owned();
    }
    value.to_owned()
}

fn clean_sign_text(value: &str) -> String {
    let mut without_formatting = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\u{00a7}' {
            let _ = characters.next();
        } else {
            without_formatting.push(character);
        }
    }
    for label in ["[To]", "[CC]", "[BCC]", "[Subject]", "[Status]"] {
        without_formatting = without_formatting.replace(label, "");
    }
    without_formatting.retain(
        |character| !matches!(character, '\0'..='\u{001f}' | '\u{007f}'..='\u{009f}' | '\u{00a7}'),
    );
    java_trim(&without_formatting).to_owned()
}

fn draft_update_packets(
    update: UpdateSign,
    draft: &mut MinecraftDraft,
) -> io::Result<Vec<Vec<u8>>> {
    let (label, combined) = apply_draft_update(&update, draft);

    let mut packets = Vec::with_capacity(2);
    if !label.is_empty() {
        packets.push(chat_packet(
            &format!("\u{00a7}7{label} set to: \u{00a7}f{combined}"),
            None,
        )?);
    }
    let mut sign = vec![0x33];
    write_block_position(&mut sign, update.x, update.y, update.z);
    for line in update.lines {
        write_string(&mut sign, &chat_json(&strip_chat_json(&line), None))?;
    }
    packets.push(sign);
    Ok(packets)
}

fn apply_draft_update(update: &UpdateSign, draft: &mut MinecraftDraft) -> (&'static str, String) {
    let mut combined = String::new();
    for line in &update.lines {
        combined.push_str(&clean_sign_text(&strip_chat_json(line)));
    }
    let combined = java_trim(&combined).to_owned();
    let label = match (update.x, update.y, update.z) {
        (2, 161, 3) => {
            draft.to.clone_from(&combined);
            "To"
        }
        (4, 161, 3) => {
            draft.cc.clone_from(&combined);
            "CC"
        }
        (6, 161, 3) => {
            draft.bcc.clone_from(&combined);
            "BCC"
        }
        (8, 161, 3) => {
            draft.subject.clone_from(&combined);
            "Subject"
        }
        _ => "",
    };
    (label, combined)
}

fn logout_confirmation_packets(window_id: u8) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, window_id];
    write_string(&mut open, "minecraft:chest")?;
    write_string(&mut open, &chat_json("\u{00a7}cConfirm Logout", None))?;
    open.push(27);
    Ok(vec![open, logout_confirmation_contents_packet(window_id)?])
}

fn logout_confirmation_contents_packet(window_id: u8) -> io::Result<Vec<u8>> {
    let filler = gui_slot(160, 15, " ", &[], false);
    let mut slots = vec![filler; 27];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));
    slots[11] = gui_slot(
        35,
        5,
        "\u{00a7}a\u{00a7}lConfirm",
        &[
            "\u{00a7}7You will be disconnected.",
            "",
            "\u{00a7}aClick to confirm",
        ],
        false,
    );
    slots[15] = gui_slot(
        35,
        14,
        "\u{00a7}c\u{00a7}lCancel",
        &["\u{00a7}7Go back"],
        false,
    );
    slots[54] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[62] = MinecraftSlot::item(399, 0, menu_star_nbt());

    let mut contents = vec![0x30, window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

fn logout_confirmation_click_packets(
    click: WindowClick,
    main_window_id: Option<u8>,
    render_settings: RenderSettings,
    mail_view_active: bool,
) -> io::Result<(Vec<Vec<u8>>, LogoutConfirmEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);

    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());

    let mut packets = vec![
        confirmation,
        clear_cursor,
        logout_confirmation_contents_packet(click.window_id)?,
    ];
    let effect = if click.mode != 0 || !(0..27).contains(&click.slot) {
        LogoutConfirmEffect::None
    } else {
        match click.slot {
            11 => {
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.push(disconnect_play_packet("\u{00a7}aLogged out. See you!")?);
                LogoutConfirmEffect::Disconnect
            }
            15 => {
                let Some(window_id) = main_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft main-menu return window ID is missing",
                    ));
                };
                packets.extend(close_menu_packets(click.window_id, mail_view_active)?);
                packets.extend(main_menu_packets(window_id, render_settings)?);
                LogoutConfirmEffect::OpenMainMenu(window_id)
            }
            _ => LogoutConfirmEffect::None,
        }
    };
    Ok((packets, effect))
}

fn close_menu_packets(window_id: u8, mail_view_active: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = vec![vec![0x2e, window_id]];
    packets.extend(restore_gui_hotbar_packets(mail_view_active)?);
    Ok(packets)
}

fn help_menu_packets() -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}l=== Help ===",
        "\u{00a7}7Hold \u{00a7}f\u{2605} Nether Star \u{00a7}7and right-click \u{2192} Open menu",
        "\u{00a7}7/mail close \u{00a7}7\u{2192} Close email view",
        "\u{00a7}7/mail next/prev \u{00a7}7\u{2192} Navigate pages",
        "\u{00a7}7/video play map \u{00a7}7\u{2192} Play video",
        "\u{00a7}7/draft, /clear, /stuck, /help",
    ]
    .into_iter()
    .map(|text| chat_packet(text, None))
    .collect()
}

fn gui_slot(item_id: i16, damage: i16, name: &str, lore: &[&str], glow: bool) -> MinecraftSlot {
    let mut display = vec![("Name".to_owned(), NbtValue::String(name.to_owned()))];
    if !lore.is_empty() {
        display.push((
            "Lore".to_owned(),
            NbtValue::List {
                element_type: 8,
                values: lore
                    .iter()
                    .map(|line| NbtValue::String((*line).to_owned()))
                    .collect(),
            },
        ));
    }
    let mut root = vec![("display".to_owned(), NbtValue::Compound(display))];
    if glow {
        root.push((
            "ench".to_owned(),
            NbtValue::List {
                element_type: 10,
                values: vec![NbtValue::Compound(vec![
                    ("id".to_owned(), NbtValue::Short(0)),
                    ("lvl".to_owned(), NbtValue::Short(1)),
                ])],
            },
        ));
        root.push(("HideFlags".to_owned(), NbtValue::Int(63)));
    }
    MinecraftSlot::item(item_id, damage, NbtValue::Compound(root))
}

fn write_slot(output: &mut Vec<u8>, slot: &MinecraftSlot) -> io::Result<()> {
    output.extend_from_slice(&slot.item_id.to_be_bytes());
    if slot.item_id >= 0 {
        output.push(slot.count);
        output.extend_from_slice(&slot.damage.to_be_bytes());
        minecraft_world::write_nbt(slot.nbt.as_ref(), output)?;
    }
    Ok(())
}

fn stuck_command_packets(config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut position = vec![0x08];
    position.extend_from_slice(&config.spawn.x.to_be_bytes());
    position.extend_from_slice(&config.spawn.y.to_be_bytes());
    position.extend_from_slice(&config.spawn.z.to_be_bytes());
    position.extend_from_slice(&config.spawn.yaw.to_be_bytes());
    position.extend_from_slice(&config.spawn.pitch.to_be_bytes());
    position.push(0);
    Ok(vec![
        position,
        chat_packet("\u{00a7}aTeleported to spawn!", Some("green"))?,
    ])
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| character <= '\u{20}')
}

fn java_regex_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r')
}

fn empty_draft_sign_packets() -> io::Result<Vec<Vec<u8>>> {
    draft_sign_packets(&MinecraftDraft::default())
}

fn draft_sign_packets(draft: &MinecraftDraft) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(4);
    for (x, label, content) in [
        (2, "\u{00a7}1[To]", draft.to.as_str()),
        (4, "\u{00a7}1[CC]", draft.cc.as_str()),
        (6, "\u{00a7}1[BCC]", draft.bcc.as_str()),
        (8, "\u{00a7}1[Subject]", draft.subject.as_str()),
    ] {
        let lines = split_sign_lines(content);
        let mut sign = vec![0x33];
        write_block_position(&mut sign, x, 161, 3);
        for text in [label, &lines[0], &lines[1], &lines[2]] {
            write_string(&mut sign, &chat_json(text, None))?;
        }
        packets.push(sign);
    }
    Ok(packets)
}

fn split_sign_lines(value: &str) -> [String; 3] {
    let mut lines = std::array::from_fn(|_| String::new());
    let encoded = value.encode_utf16().collect::<Vec<_>>();
    for (line, units) in lines.iter_mut().zip(encoded.chunks(15)) {
        *line = java_utf16_slice_to_string(units);
    }
    lines
}

fn java_utf16_slice_to_string(units: &[u16]) -> String {
    let mut output = String::with_capacity(units.len());
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit)
            && let Some(&low) = units.get(index + 1)
            && (0xdc00..=0xdfff).contains(&low)
        {
            let code_point =
                0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
            output.push(char::from_u32(code_point).expect("valid UTF-16 surrogate pair"));
            index += 2;
            continue;
        }
        if (0xd800..=0xdfff).contains(&unit) {
            output.push('?');
        } else {
            output.push(char::from_u32(u32::from(unit)).expect("valid UTF-16 BMP scalar"));
        }
        index += 1;
    }
    output
}

fn draft_book_packet() -> io::Result<Vec<u8>> {
    draft_book_packet_for(&MinecraftDraft::default())
}

fn draft_book_packet_for(draft: &MinecraftDraft) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x2f, 0];
    packet.extend_from_slice(&36_i16.to_be_bytes());
    packet.extend_from_slice(&386_i16.to_be_bytes());
    packet.push(1);
    packet.extend_from_slice(&0_i16.to_be_bytes());
    minecraft_world::write_nbt(Some(&draft_book_nbt(draft)), &mut packet)?;
    Ok(packet)
}

fn restore_hotbar_packets() -> io::Result<Vec<Vec<u8>>> {
    let mut menu_star = vec![0x2f, 0];
    menu_star.extend_from_slice(&44_i16.to_be_bytes());
    menu_star.extend_from_slice(&399_i16.to_be_bytes());
    menu_star.push(1);
    menu_star.extend_from_slice(&0_i16.to_be_bytes());
    minecraft_world::write_nbt(Some(&menu_star_nbt()), &mut menu_star)?;
    Ok(vec![draft_book_packet()?, menu_star])
}

fn restore_gui_hotbar_packets(mail_view_active: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = restore_hotbar_packets()?;
    if mail_view_active {
        packets.extend(mail_view_hotbar_packets()?);
    }
    Ok(packets)
}

fn authenticated_scoreboard_packets(
    username: &str,
    email: &str,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let email = if email.encode_utf16().count() > 20 {
        format!("{}...", truncate_utf16(email, 17))
    } else {
        email.to_owned()
    };
    let divider = format!("\u{00a7}7{}", "\u{2501}".repeat(13));
    let lines = [
        divider.clone(),
        format!("\u{00a7}fPlayer: \u{00a7}a{username}"),
        format!("\u{00a7}fEmail: \u{00a7}b{email}"),
        String::new(),
        format!(
            "\u{00a7}fRender: \u{00a7}e{}\u{00d7}{} maps",
            render_settings.maps_x, render_settings.maps_y
        ),
        format!("\u{00a7}fFont: \u{00a7}e{}px", render_settings.font_size),
        String::new(),
        "\u{00a7}f/menu \u{00a7}7\u{2192} Open menu".to_owned(),
        divider,
        "\u{00a7}email.lmyz.net".to_owned(),
    ];
    let mut packets = Vec::with_capacity(13);
    let mut remove = vec![0x3b];
    write_string(&mut remove, "lmyz")?;
    remove.push(1);
    packets.push(remove);

    let mut create = vec![0x3b];
    write_string(&mut create, "lmyz")?;
    create.push(0);
    write_string(&mut create, "\u{00a7}6\u{00a7}lLMYZMAIL")?;
    write_string(&mut create, "dummy")?;
    packets.push(create);

    let mut display = vec![0x3d, 1];
    write_string(&mut display, "lmyz")?;
    packets.push(display);

    let line_count = lines.len();
    for (index, line) in lines.into_iter().enumerate() {
        let prefix = char::from_digit(index as u32, 16).unwrap_or('f');
        let score_name = truncate_utf16(&format!("\u{00a7}{prefix}\u{00a7}r{line}"), 40);
        let mut score = vec![0x3c];
        write_string(&mut score, &score_name)?;
        score.push(0);
        write_string(&mut score, "lmyz")?;
        write_varint(&mut score, (line_count - index) as u32);
        packets.push(score);
    }
    Ok(packets)
}

fn truncate_utf16(value: &str, max_units: usize) -> String {
    let mut output = String::new();
    let mut units = 0;
    for character in value.chars() {
        let character_units = character.len_utf16();
        if units + character_units > max_units {
            break;
        }
        output.push(character);
        units += character_units;
    }
    output
}

fn chat_json(text: &str, color: Option<&str>) -> String {
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    match color {
        Some(color) => format!(r#"{{"text":"{escaped}","color":"{color}"}}"#),
        None => format!(r#"{{"text":"{escaped}"}}"#),
    }
}

fn parse_uuid_bytes(value: &str) -> Option<[u8; 16]> {
    let compact = value.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(compact.as_bytes()[index * 2])? << 4)
            | hex_nibble(compact.as_bytes()[index * 2 + 1])?;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn book_item_nbt() -> NbtValue {
    draft_book_nbt(&MinecraftDraft::default())
}

fn draft_book_nbt(draft: &MinecraftDraft) -> NbtValue {
    let values = if draft.body_pages.is_empty() {
        vec![NbtValue::String(String::new())]
    } else {
        draft
            .body_pages
            .iter()
            .cloned()
            .map(NbtValue::String)
            .collect()
    };
    NbtValue::Compound(vec![(
        "pages".to_owned(),
        NbtValue::List {
            element_type: 8,
            values,
        },
    )])
}

fn menu_star_nbt() -> NbtValue {
    NbtValue::Compound(vec![
        (
            "display".to_owned(),
            NbtValue::Compound(vec![
                (
                    "Name".to_owned(),
                    NbtValue::String("\u{00a7}6\u{00a7}lMenu \u{00a7}7(Right Click)".to_owned()),
                ),
                (
                    "Lore".to_owned(),
                    NbtValue::List {
                        element_type: 8,
                        values: vec![NbtValue::String("\u{00a7}7Open the main menu".to_owned())],
                    },
                ),
            ]),
        ),
        (
            "ench".to_owned(),
            NbtValue::List {
                element_type: 10,
                values: vec![NbtValue::Compound(vec![
                    ("id".to_owned(), NbtValue::Short(0)),
                    ("lvl".to_owned(), NbtValue::Short(1)),
                ])],
            },
        ),
        ("HideFlags".to_owned(), NbtValue::Int(63)),
    ])
}

async fn write_packet<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    packet: Vec<u8>,
    compression: Option<i32>,
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let frame = encode_packet_frame(service, packet, compression, deadline, cancellation).await?;
    write_bytes(stream, &frame, cipher, deadline, cancellation).await
}

async fn write_packet_list<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    packets: Vec<Vec<u8>>,
    compression: Option<i32>,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    for packet in packets {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    Ok(())
}

async fn encode_packet_frame(
    service: &StatusService,
    packet: Vec<u8>,
    compression: Option<i32>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProtocolError> {
    let Some(threshold) = compression else {
        return encode_frame(&packet).map_err(ProtocolError::Io);
    };
    let mut envelope = Vec::new();
    if packet.len() < threshold as usize {
        envelope
            .try_reserve_exact(packet.len() + 1)
            .map_err(|error| {
                ProtocolError::Io(io::Error::other(format!(
                    "Minecraft packet allocation failed: {error}"
                )))
            })?;
        envelope.push(0);
        envelope.extend_from_slice(&packet);
    } else {
        let uncompressed_length =
            u32::try_from(packet.len()).map_err(|_| ProtocolError::Malformed)?;
        let worker_cancellation = cancellation.clone();
        let receiver = service
            .compression_pool
            .submit(move || compress_packet(packet, &worker_cancellation, deadline))
            .map_err(submit_error)?;
        let compressed = await_compression(receiver, deadline, cancellation).await??;
        envelope
            .try_reserve_exact(compressed.len() + 5)
            .map_err(|error| {
                ProtocolError::Io(io::Error::other(format!(
                    "Minecraft packet allocation failed: {error}"
                )))
            })?;
        write_varint(&mut envelope, uncompressed_length);
        envelope.extend_from_slice(&compressed);
    }
    encode_frame(&envelope).map_err(ProtocolError::Io)
}

async fn decode_compression_envelope(
    service: &StatusService,
    mut frame: Vec<u8>,
    threshold: i32,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProtocolError> {
    let mut reader = PacketReader::new(&frame);
    let data_length = reader
        .read_varint()
        .map_err(|()| ProtocolError::Malformed)?;
    if data_length < 0 {
        return Err(ProtocolError::Malformed);
    }
    let cursor = reader.cursor;
    if cursor == frame.len() {
        return Err(ProtocolError::Malformed);
    }
    if data_length == 0 {
        let packet_length = frame.len() - cursor;
        if packet_length >= threshold as usize {
            return Err(ProtocolError::Malformed);
        }
        frame.copy_within(cursor.., 0);
        frame.truncate(packet_length);
        return Ok(frame);
    }

    let expected = data_length as usize;
    if expected > MAX_FRAME_LENGTH || expected < threshold as usize {
        return Err(ProtocolError::Malformed);
    }
    let receiver = service
        .compression_pool
        .submit({
            let worker_cancellation = cancellation.clone();
            move || decompress_packet(frame, cursor, expected, &worker_cancellation, deadline)
        })
        .map_err(submit_error)?;
    await_compression(receiver, deadline, cancellation).await?
}

fn submit_error(error: SubmitError) -> ProtocolError {
    match error {
        SubmitError::Closed | SubmitError::Full => ProtocolError::Malformed,
    }
}

async fn await_compression<T>(
    receiver: tokio::sync::oneshot::Receiver<T>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, ProtocolError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, receiver) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(ProtocolError::Io(io::Error::other(
                "Minecraft compression worker stopped",
            ))),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

fn compression_budget(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    if cancellation.is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(ProtocolError::TimedOut)
    } else {
        Ok(())
    }
}

fn compress_packet(
    packet: Vec<u8>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    for chunk in packet.chunks(COMPRESSION_CHUNK_BYTES) {
        compression_budget(cancellation, deadline)?;
        encoder.write_all(chunk).map_err(ProtocolError::Io)?;
    }
    compression_budget(cancellation, deadline)?;
    let output = encoder.finish().map_err(ProtocolError::Io)?;
    compression_budget(cancellation, deadline)?;
    Ok(output)
}

fn decompress_packet(
    frame: Vec<u8>,
    cursor: usize,
    expected: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, ProtocolError> {
    let mut decoder = flate2::Decompress::new(true);
    let mut output = vec![0_u8; expected];
    let input = &frame[cursor..];
    let mut input_cursor = 0;
    let mut output_cursor: usize = 0;
    let mut overflow_probe = [0_u8; 1];
    loop {
        compression_budget(cancellation, deadline)?;
        let output_end = output_cursor
            .saturating_add(COMPRESSION_CHUNK_BYTES)
            .min(output.len());
        let output_chunk = if output_cursor < output.len() {
            &mut output[output_cursor..output_end]
        } else {
            &mut overflow_probe[..]
        };
        let input_before = decoder.total_in();
        let output_before = decoder.total_out();
        let status = decoder
            .decompress(
                &input[input_cursor..],
                output_chunk,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|_| ProtocolError::Malformed)?;
        let consumed = (decoder.total_in() - input_before) as usize;
        let produced = (decoder.total_out() - output_before) as usize;
        input_cursor += consumed;
        if output_cursor == output.len() && produced != 0 {
            return Err(ProtocolError::Malformed);
        }
        output_cursor += produced;
        if status == flate2::Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Err(ProtocolError::Malformed);
        }
    }
    compression_budget(cancellation, deadline)?;
    if input_cursor != input.len() || output_cursor != expected {
        return Err(ProtocolError::Malformed);
    }
    Ok(output)
}

fn offline_uuid(username: &str) -> io::Result<String> {
    let input = format!("OfflinePlayer:{username}");
    Ok(java_name_uuid(input.as_bytes()))
}

fn java_name_uuid(input: &[u8]) -> String {
    let mut bytes: [u8; 16] = Md5::digest(input).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut value = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    value
}

fn write_string(output: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > 32_767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft outbound string exceeded 32767 bytes",
        ));
    }
    output.try_reserve_exact(bytes.len() + 5).map_err(|error| {
        io::Error::other(format!("Minecraft string allocation failed: {error}"))
    })?;
    write_varint(output, bytes.len() as u32);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_byte_array(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft byte array exceeded the protocol range",
        )
    })?;
    output.try_reserve_exact(value.len() + 5).map_err(|error| {
        io::Error::other(format!("Minecraft byte array allocation failed: {error}"))
    })?;
    write_varint(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn initial_play_packets(entity_id: i32, config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut join_game = vec![0x01];
    join_game.extend_from_slice(&entity_id.to_be_bytes());
    join_game.extend_from_slice(&[0x02, 0x00, 0x00, config.max_players as u8]);
    write_string(&mut join_game, "default")?;
    join_game.push(0);

    let mut spawn = vec![0x05];
    let spawn_x = config.spawn.x as i32;
    let spawn_y = config.spawn.y as i32;
    let spawn_z = config.spawn.z as i32;
    let packed_spawn = ((i64::from(spawn_x) & 0x3ff_ffff) << 38)
        | ((i64::from(spawn_y) & 0xfff) << 26)
        | (i64::from(spawn_z) & 0x3ff_ffff);
    spawn.extend_from_slice(&packed_spawn.to_be_bytes());

    let mut abilities = vec![0x39, 0x05];
    abilities.extend_from_slice(&0.05_f32.to_be_bytes());
    abilities.extend_from_slice(&0.1_f32.to_be_bytes());

    let mut time = vec![0x03];
    time.extend_from_slice(&0_i64.to_be_bytes());
    time.extend_from_slice(&(-6000_i64).to_be_bytes());

    let mut health = vec![0x06];
    health.extend_from_slice(&20.0_f32.to_be_bytes());
    write_varint(&mut health, 20);
    health.extend_from_slice(&5.0_f32.to_be_bytes());

    Ok(vec![
        join_game,
        vec![0x41, 0x00],
        spawn,
        abilities,
        time,
        health,
        vec![0x09, 0x00],
    ])
}

async fn read_connection_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    cipher: Option<&mut MinecraftCipher>,
    state: ConnectionState,
    deadline: Instant,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> (Result<Option<Vec<u8>>, ProtocolError>, Instant) {
    let result = read_frame(stream, cipher, deadline, cancellation).await;
    let next_deadline = if state == ConnectionState::Play && matches!(result, Ok(Some(_))) {
        Instant::now() + idle_timeout
    } else {
        deadline
    };
    (result, next_deadline)
}

async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    loop {
        let mut encoded_length = [0_u8; 5];
        let mut value = 0_u32;
        for index in 0..encoded_length.len() {
            let read = read_with_deadline(
                stream,
                &mut encoded_length[index..=index],
                cipher.as_deref_mut(),
                deadline,
                cancellation,
            )
            .await?;
            if read == 0 {
                return if index == 0 {
                    Ok(None)
                } else {
                    Err(ProtocolError::Malformed)
                };
            }
            let byte = encoded_length[index];
            if index == 4 && byte & 0xf0 != 0 {
                return Err(ProtocolError::Malformed);
            }
            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let length = value as i32;
                if length < 0 || length as usize > MAX_FRAME_LENGTH {
                    return Err(ProtocolError::Malformed);
                }
                if length == 0 {
                    break;
                }
                let length = length as usize;
                let mut frame = Vec::new();
                frame.try_reserve_exact(length).map_err(|error| {
                    ProtocolError::Io(io::Error::other(format!(
                        "Minecraft frame allocation failed: {error}"
                    )))
                })?;
                frame.resize(length, 0);
                let mut cursor = 0;
                while cursor < frame.len() {
                    let read = read_with_deadline(
                        stream,
                        &mut frame[cursor..],
                        cipher.as_deref_mut(),
                        deadline,
                        cancellation,
                    )
                    .await?;
                    if read == 0 {
                        return Err(ProtocolError::Malformed);
                    }
                    cursor += read;
                }
                return Ok(Some(frame));
            }
            if index == 4 {
                return Err(ProtocolError::Malformed);
            }
        }
    }
}

async fn read_with_deadline<R: AsyncRead + Unpin>(
    stream: &mut R,
    buffer: &mut [u8],
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<usize, ProtocolError> {
    let read = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.read(buffer)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }?;
    if let Some(cipher) = cipher {
        cipher.decrypt_in_place(&mut buffer[..read])?;
    }
    Ok(read)
}

async fn write_bytes<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let encrypted;
    let bytes = if let Some(cipher) = cipher {
        encrypted = cipher.encrypt(bytes)?;
        encrypted
    } else {
        bytes
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.write_all(bytes)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

fn transform_in_place(
    crypter: &mut Crypter,
    scratch: &mut Vec<u8>,
    bytes: &mut [u8],
) -> Result<(), ProtocolError> {
    let transformed = transform_to_scratch(crypter, scratch, bytes)?;
    bytes.copy_from_slice(transformed);
    Ok(())
}

fn transform_to_scratch<'a>(
    crypter: &mut Crypter,
    scratch: &'a mut Vec<u8>,
    bytes: &[u8],
) -> Result<&'a [u8], ProtocolError> {
    let capacity = bytes
        .len()
        .checked_add(Cipher::aes_128_cfb8().block_size())
        .ok_or(ProtocolError::Malformed)?;
    scratch.resize(capacity, 0);
    let written = crypter.update(bytes, scratch).map_err(crypto_protocol)?;
    if written != bytes.len() {
        return Err(ProtocolError::Malformed);
    }
    scratch.truncate(written);
    Ok(scratch)
}

fn crypto_io(error: openssl::error::ErrorStack) -> io::Error {
    io::Error::other(format!("Minecraft crypto initialization failed: {error}"))
}

fn crypto_protocol(_error: openssl::error::ErrorStack) -> ProtocolError {
    ProtocolError::Malformed
}

#[cfg(test)]
fn status_json(config: &MinecraftConfig) -> String {
    status_json_with_online(config, 0)
}

fn status_json_with_online(config: &MinecraftConfig, online: u32) -> String {
    let motd = config.motd.replace('\\', "\\\\").replace('"', "\\\"");
    let favicon = if config.favicon.trim().is_empty() {
        String::new()
    } else {
        format!(
            ",\"favicon\":\"data:image/png;base64,{}\"",
            config.favicon.trim()
        )
    };
    format!(
        "{{\"version\":{{\"name\":\"1.8.9\",\"protocol\":47}},\"players\":{{\"max\":{},\"online\":{},\"sample\":[]}},\"description\":{{\"text\":\"{}\"}}{}}}",
        config.max_players, online, motd, favicon
    )
}

fn build_status_frame(config: &MinecraftConfig, online: u32) -> io::Result<Vec<u8>> {
    let json = status_json_with_online(config, online);
    let mut payload = Vec::new();
    payload.try_reserve_exact(json.len() + 6).map_err(|error| {
        io::Error::other(format!("Minecraft status allocation failed: {error}"))
    })?;
    write_varint(&mut payload, 0);
    write_varint(&mut payload, json.len() as u32);
    payload.extend_from_slice(json.as_bytes());
    encode_frame(&payload)
}

fn login_disconnect_frame(reason_json: &str) -> io::Result<Vec<u8>> {
    encode_frame(&login_disconnect_packet(reason_json)?)
}

fn login_disconnect_packet(reason_json: &str) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(reason_json.len() + 6)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    write_varint(&mut payload, 0);
    write_varint(&mut payload, reason_json.len() as u32);
    payload.extend_from_slice(reason_json.as_bytes());
    Ok(payload)
}

fn contains_player(players: &[String], username: &str) -> bool {
    players
        .iter()
        .any(|player| java_equals_ignore_case(player, username))
}

fn java_equals_ignore_case(left: &str, right: &str) -> bool {
    if left.encode_utf16().count() != right.encode_utf16().count() {
        return false;
    }
    // JDK 22 uses Unicode 15.1; Cargo pins the matching ICU4X data generation.
    let case_mapper = CaseMapper::new();
    let mut left = left.chars();
    let mut right = right.chars();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) => {
                if left == right {
                    continue;
                }
                let left_upper = case_mapper.simple_uppercase(left);
                let right_upper = case_mapper.simple_uppercase(right);
                if left_upper != right_upper
                    && case_mapper.simple_lowercase(left_upper)
                        != case_mapper.simple_lowercase(right_upper)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn encode_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft outbound frame is outside the protocol budget",
        ));
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(payload.len() + 5)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    write_varint(&mut frame, payload.len() as u32);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn write_varint(output: &mut Vec<u8>, mut value: u32) {
    loop {
        if value & !0x7f == 0 {
            output.push(value as u8);
            return;
        }
        output.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
}

fn decode_java_utf8(bytes: &[u8]) -> Result<String, ()> {
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len().saturating_mul(3))
        .map_err(|_| ())?;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let b1 = bytes[cursor];
        if b1 < 0x80 {
            output.push(char::from(b1));
            cursor += 1;
            continue;
        }
        if (0xc2..=0xdf).contains(&b1) {
            if cursor + 1 < bytes.len() && is_utf8_continuation(bytes[cursor + 1]) {
                let codepoint = (u32::from(b1 & 0x1f) << 6) | u32::from(bytes[cursor + 1] & 0x3f);
                output.push(char::from_u32(codepoint).ok_or(())?);
                cursor += 2;
            } else {
                output.push('\u{fffd}');
                cursor += 1;
            }
            continue;
        }
        if (0xe0..=0xef).contains(&b1) {
            let remaining = bytes.len() - cursor;
            if remaining < 3 {
                if remaining > 1
                    && ((b1 == 0xe0 && bytes[cursor + 1] & 0xe0 == 0x80)
                        || !is_utf8_continuation(bytes[cursor + 1]))
                {
                    output.push('\u{fffd}');
                    cursor += 1;
                } else {
                    output.push('\u{fffd}');
                    cursor = bytes.len();
                }
                continue;
            }
            let b2 = bytes[cursor + 1];
            let b3 = bytes[cursor + 2];
            if (b1 == 0xe0 && b2 & 0xe0 == 0x80)
                || !is_utf8_continuation(b2)
                || !is_utf8_continuation(b3)
            {
                let malformed_length =
                    if (b1 == 0xe0 && b2 & 0xe0 == 0x80) || !is_utf8_continuation(b2) {
                        1
                    } else {
                        2
                    };
                output.push('\u{fffd}');
                cursor += malformed_length;
                continue;
            }
            let codepoint =
                (u32::from(b1 & 0x0f) << 12) | (u32::from(b2 & 0x3f) << 6) | u32::from(b3 & 0x3f);
            if (0xd800..=0xdfff).contains(&codepoint) {
                output.push('\u{fffd}');
            } else {
                output.push(char::from_u32(codepoint).ok_or(())?);
            }
            cursor += 3;
            continue;
        }
        if (0xf0..=0xf7).contains(&b1) {
            let remaining = bytes.len() - cursor;
            if remaining < 4 {
                if b1 > 0xf4
                    || (remaining > 1 && invalid_java_utf8_four_byte_second(b1, bytes[cursor + 1]))
                {
                    output.push('\u{fffd}');
                    cursor += 1;
                } else if remaining > 2 && !is_utf8_continuation(bytes[cursor + 2]) {
                    output.push('\u{fffd}');
                    cursor += 2;
                } else {
                    output.push('\u{fffd}');
                    cursor = bytes.len();
                }
                continue;
            }
            let b2 = bytes[cursor + 1];
            let b3 = bytes[cursor + 2];
            let b4 = bytes[cursor + 3];
            let codepoint = (u32::from(b1 & 0x07) << 18)
                | (u32::from(b2 & 0x3f) << 12)
                | (u32::from(b3 & 0x3f) << 6)
                | u32::from(b4 & 0x3f);
            if !is_utf8_continuation(b2)
                || !is_utf8_continuation(b3)
                || !is_utf8_continuation(b4)
                || !(0x1_0000..=0x10_ffff).contains(&codepoint)
            {
                let malformed_length = if invalid_java_utf8_four_byte_second(b1, b2) {
                    1
                } else if !is_utf8_continuation(b3) {
                    2
                } else {
                    3
                };
                output.push('\u{fffd}');
                cursor += malformed_length;
                continue;
            }
            output.push(char::from_u32(codepoint).ok_or(())?);
            cursor += 4;
            continue;
        }
        output.push('\u{fffd}');
        cursor += 1;
    }
    Ok(output)
}

const fn is_utf8_continuation(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

const fn invalid_java_utf8_four_byte_second(first: u8, second: u8) -> bool {
    first > 0xf4
        || (first == 0xf0 && (second < 0x90 || second > 0xbf))
        || (first == 0xf4 && second & 0xf0 != 0x80)
        || !is_utf8_continuation(second)
}

struct PacketReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> PacketReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.cursor..).unwrap_or_default()
    }

    fn advance(&mut self, length: usize) -> Result<(), ()> {
        let end = self.cursor.checked_add(length).ok_or(())?;
        if end > self.bytes.len() {
            return Err(());
        }
        self.cursor = end;
        Ok(())
    }

    fn read_varint(&mut self) -> Result<i32, ()> {
        let mut value = 0_u32;
        for index in 0..5 {
            let byte = *self.bytes.get(self.cursor).ok_or(())?;
            self.cursor += 1;
            if index == 4 && byte & 0xf0 != 0 {
                return Err(());
            }
            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value as i32);
            }
        }
        Err(())
    }

    fn read_string(&mut self, max_utf16_units: usize) -> Result<String, ()> {
        let length = self.read_varint()?;
        if length < 0 || length as usize > max_utf16_units.saturating_mul(4) {
            return Err(());
        }
        let length = length as usize;
        let end = self.cursor.checked_add(length).ok_or(())?;
        let bytes = self.bytes.get(self.cursor..end).ok_or(())?;
        self.cursor = end;
        let value = decode_java_utf8(bytes)?;
        if value.encode_utf16().count() > max_utf16_units {
            return Err(());
        }
        Ok(value)
    }

    fn read_byte_array(&mut self, max_bytes: usize) -> Result<Vec<u8>, ()> {
        let length = self.read_varint()?;
        if length < 0 || length as usize > max_bytes {
            return Err(());
        }
        let length = length as usize;
        let end = self.cursor.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.cursor..end).ok_or(())?.to_vec();
        self.cursor = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        let end = self.cursor.checked_add(2).ok_or(())?;
        let bytes: [u8; 2] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_i16(&mut self) -> Result<i16, ()> {
        Ok(self.read_u16()? as i16)
    }

    fn read_u8(&mut self) -> Result<u8, ()> {
        let value = *self.bytes.get(self.cursor).ok_or(())?;
        self.cursor += 1;
        Ok(value)
    }

    fn skip_slot(&mut self) -> Result<(), ()> {
        let item_id = self.read_i16()?;
        if item_id >= 0 {
            self.read_u8()?;
            self.read_i16()?;
            let encoded = self.bytes.get(self.cursor..).ok_or(())?;
            let length = minecraft_world::network_nbt_len(encoded).map_err(|_| ())?;
            self.cursor = self.cursor.checked_add(length).ok_or(())?;
        }
        Ok(())
    }

    fn read_i64(&mut self) -> Result<i64, ()> {
        let end = self.cursor.checked_add(8).ok_or(())?;
        let bytes: [u8; 8] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, ()> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    fn read_f32(&mut self) -> Result<f32, ()> {
        let end = self.cursor.checked_add(4).ok_or(())?;
        let bytes: [u8; 4] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(f32::from_be_bytes(bytes))
    }
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn retryable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) || (cfg!(target_os = "linux")
        && matches!(
            error.raw_os_error(),
            Some(1 | 4 | 11 | 12 | 23 | 24 | 64 | 71 | 92 | 95 | 100 | 101 | 103 | 105 | 112 | 113)
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sha2::Sha256;
    use std::future::pending;
    use tokio::sync::oneshot;
    use tokio::time::{advance, sleep};

    const FROZEN_STATUS_FRAME: &str = "nAEAmQF7InZlcnNpb24iOnsibmFtZSI6IjEuOC45IiwicHJvdG9jb2wiOjQ3fSwicGxheWVycyI6eyJtYXgiOjIwLCJvbmxpbmUiOjAsInNhbXBsZSI6W119LCJkZXNjcmlwdGlvbiI6eyJ0ZXh0Ijoiwqc2TE1ZWk1BSUwgwqc3LSBTZW5kIGVtYWlscyBpbiBNaW5lY3JhZnQifX0=";

    fn config(timeout: Duration) -> MinecraftConfig {
        MinecraftConfig {
            enabled: true,
            online_mode: false,
            compression_threshold: 256,
            max_players: 20,
            motd: "§6LMYZMAIL §7- Send emails in Minecraft".to_owned(),
            favicon: String::new(),
            read_timeout_seconds: timeout.as_secs().max(1),
            session_server_url: "https://sessionserver.mojang.com/session/minecraft/hasJoined"
                .to_owned(),
            world_template: "worlds/mailroom".to_owned(),
            view_distance: 32,
            max_concurrent_videos: 2,
            spawn: crate::config::MinecraftSpawnConfig {
                x: 0.5,
                y: 160.0,
                z: 0.5,
                yaw: 0.0,
                pitch: 0.0,
            },
            video: crate::config::MinecraftVideoConfig {
                center_x: 0,
                center_y: 180,
                wall_z: -20,
                max_width: 64,
                max_fps: 20,
                default_width: 32,
                default_fps: 10,
                default_contrast: 1.2,
                spawn_protect_radius: 8,
                clear_margin: 2,
                map_center_x: 0,
                map_center_y: 180,
                map_center_z: -20,
                map_facing: "SOUTH".to_owned(),
                map_max_maps_x: 10,
                map_max_maps_y: 10,
                map_max_fps: 20,
                map_default_maps_x: 5,
                map_default_fps: 10,
                map_default_contrast: 1.2,
                base_map_id: 10_000,
                base_entity_id: 100_000,
            },
            whitelist_enabled: false,
            whitelist_players: Vec::new(),
            blacklist_players: Vec::new(),
            auth_max_attempts: 5,
            auth_lockout_seconds: 300,
            auth_window_seconds: 600,
        }
    }

    #[test]
    fn external_image_targets_match_java_quoted_src_and_uri_policy() {
        let html = concat!(
            "<img src=\"https://example.test/a.png\">",
            "<img SRC = 'http://8.8.8.8/b.jpg?x=1'>",
            "<img src=\"https://example.test/a.png\">",
            "<img src=https://example.test/unquoted.png>",
            "<img src=\"https://user@example.test/no.png\">",
            "<img src=\"https://example.test:444/no.png\">",
            "<img src=\"https://example.test/no.png#fragment\">"
        );
        let targets = collect_external_image_targets(html, 0);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].source, "https://example.test/a.png");
        assert_eq!(targets[0].content_id, "__http_0");
        assert_eq!(targets[1].source, "http://8.8.8.8/b.jpg?x=1");
        assert_eq!(targets[1].content_id, "__http_1");

        let one_slot = collect_external_image_targets(html, mail_render::MAX_IMAGE_RESOURCES - 1);
        assert_eq!(one_slot.len(), 1);
    }

    #[test]
    fn external_image_uri_policy_accepts_only_default_http_ports() {
        assert!(parse_allowed_external_image_url("https://8.8.8.8/a.png").is_some());
        assert!(parse_allowed_external_image_url("http://example.test:80/a.png").is_some());
        for value in [
            "file:///etc/passwd",
            "http://8.8.8.8:22/a.png",
            "https://user@example.test/a.png",
            "https://example.test/a.png#fragment",
        ] {
            assert!(
                parse_allowed_external_image_url(value).is_none(),
                "accepted {value}"
            );
        }
    }

    fn handshake(port: u16, next_state: i32) -> Vec<u8> {
        let mut packet = vec![0];
        write_varint(&mut packet, 47);
        write_varint(&mut packet, 9);
        packet.extend_from_slice(b"127.0.0.1");
        packet.extend_from_slice(&port.to_be_bytes());
        write_varint(&mut packet, next_state as u32);
        encode_frame(&packet).unwrap()
    }

    async fn start_server(
        max_connections: usize,
        timeout: Duration,
    ) -> (
        std::net::SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = Arc::new(StatusService::new(&config(timeout)).unwrap());
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task =
            tokio::spawn(
                async move { serve_listener(listener, service, child, max_connections).await },
            );
        (address, cancellation, task)
    }

    async fn start_server_with_config(
        max_connections: usize,
        config: MinecraftConfig,
    ) -> (
        std::net::SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = Arc::new(StatusService::new(&config).unwrap());
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task =
            tokio::spawn(
                async move { serve_listener(listener, service, child, max_connections).await },
            );
        (address, cancellation, task)
    }

    async fn start_session_fixture(
        status: u16,
        body: String,
        response_delay: Duration,
    ) -> (
        std::net::SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "fixture client closed before HTTP headers");
                assert!(request.len() + read <= 8 * 1024);
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = request_sender.send(request);
            if !response_delay.is_zero() {
                sleep(response_delay).await;
            }
            let reason = match status {
                200 => "OK",
                204 => "No Content",
                _ => "Fixture",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, request_receiver, task)
    }

    fn rsa_encrypt(public_key_der: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let public_key = PKey::public_key_from_der(public_key_der)
            .unwrap()
            .rsa()
            .unwrap();
        let mut encrypted = vec![0_u8; public_key.size() as usize];
        let written = public_key
            .public_encrypt(plaintext, &mut encrypted, Padding::PKCS1)
            .unwrap();
        encrypted.truncate(written);
        encrypted
    }

    fn login_start(username: &[u8]) -> Vec<u8> {
        let mut packet = vec![0];
        write_varint(&mut packet, username.len() as u32);
        packet.extend_from_slice(username);
        encode_frame(&packet).unwrap()
    }

    async fn assert_closed_without_response(address: std::net::SocketAddr, payload: &[u8]) {
        let mut client = TcpStream::connect(address).await.unwrap();
        let _ = client.write_all(payload).await;
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("server did not reject malformed frame");
        assert!(
            matches!(result, Ok(0))
                || matches!(
                    result,
                    Err(ref error) if connection_ended(error)
                ),
            "unexpected rejection result: {result:?}"
        );
    }

    #[test]
    fn default_status_frame_matches_frozen_java_wire() {
        assert_eq!(MAX_CONNECTIONS, 64);
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        assert_eq!(
            service.status_frame.as_ref(),
            STANDARD.decode(FROZEN_STATUS_FRAME).unwrap()
        );
    }

    #[test]
    fn minecraft_auth_limiter_matches_java_window_lockout_and_clear() {
        let limiter = MinecraftAuthLimiter {
            max_attempts: 3,
            lockout: Duration::from_secs(30),
            window: Duration::from_secs(10),
            records: Mutex::new(HashMap::new()),
        };
        let start = StdInstant::now();
        assert_eq!(limiter.record_failure_at("192.0.2.1", start), (false, 2));
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(10)),
            (false, 1)
        );
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(11)),
            (false, 1)
        );
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(12)),
            (true, 0)
        );
        assert_eq!(
            limiter.locked_remaining_at("192.0.2.1", start + Duration::from_secs(13)),
            Some(29)
        );
        assert_eq!(
            limiter.locked_remaining_at("192.0.2.1", start + Duration::from_secs(42)),
            None
        );
        assert_eq!(
            limiter
                .records
                .lock()
                .unwrap()
                .get("192.0.2.1")
                .unwrap()
                .failures
                .len(),
            0
        );
        limiter.clear("192.0.2.1");
        assert!(limiter.records.lock().unwrap().is_empty());
    }

    #[test]
    fn minecraft_auth_limiter_fails_closed_at_record_capacity_and_reclaims_stale_entries() {
        let limiter = MinecraftAuthLimiter {
            max_attempts: 3,
            lockout: Duration::from_secs(30),
            window: Duration::from_secs(10),
            records: Mutex::new(HashMap::new()),
        };
        let start = StdInstant::now();
        {
            let mut records = limiter.records.lock().unwrap();
            for index in 0..MAX_MINECRAFT_AUTH_RECORDS {
                records.insert(
                    format!("198.51.100.{index}"),
                    MinecraftAuthAttempt {
                        failures: VecDeque::from([start + Duration::from_secs(1)]),
                        locked_until: None,
                    },
                );
            }
        }
        assert_eq!(
            limiter.record_failure_at("203.0.113.1", start + Duration::from_secs(2)),
            (true, 0)
        );
        assert_eq!(
            limiter.records.lock().unwrap().len(),
            MAX_MINECRAFT_AUTH_RECORDS
        );

        limiter.records.lock().unwrap().clear();
        {
            let mut records = limiter.records.lock().unwrap();
            for index in 0..MAX_MINECRAFT_AUTH_RECORDS {
                records.insert(
                    format!("stale-{index}"),
                    MinecraftAuthAttempt {
                        failures: VecDeque::from([start]),
                        locked_until: None,
                    },
                );
            }
        }
        assert_eq!(
            limiter.record_failure_at("203.0.113.1", start + Duration::from_secs(11)),
            (false, 2)
        );
        assert_eq!(limiter.records.lock().unwrap().len(), 1);
    }

    #[test]
    fn mail_view_serverbound_parsers_are_bounded_and_match_protocol_47() {
        for (encoded, expected) in [
            ([0x00, 0x00], 0),
            ([0x00, 0x03], 3),
            ([0x00, 0x08], 8),
            ([0x12, 0x3f], 15),
        ] {
            let mut reader = PacketReader::new(&encoded);
            assert_eq!(read_held_item_change(&mut reader), Ok(expected));
            assert_eq!(reader.cursor, encoded.len());
        }
        assert!(read_held_item_change(&mut PacketReader::new(&[0])).is_err());

        let mut interact = PacketReader::new(&[0xac, 0x02, 0]);
        assert_eq!(read_use_entity(&mut interact), Ok((300, 0)));
        assert_eq!(interact.cursor, 3);

        let mut interact_at = vec![7, 2];
        interact_at.extend_from_slice(&1.25_f32.to_be_bytes());
        interact_at.extend_from_slice(&(-2.5_f32).to_be_bytes());
        interact_at.extend_from_slice(&3.75_f32.to_be_bytes());
        let mut reader = PacketReader::new(&interact_at);
        assert_eq!(read_use_entity(&mut reader), Ok((7, 2)));
        assert_eq!(reader.cursor, 2);
        assert_eq!(
            read_use_entity(&mut PacketReader::new(&interact_at[..2])),
            Ok((7, 2))
        );
        assert!(read_use_entity(&mut PacketReader::new(&[7])).is_err());

        let mut placement = Vec::new();
        write_block_position(&mut placement, -12, 4095, -33_554_432);
        placement.push(0xff);
        write_slot(&mut placement, &MinecraftSlot::empty()).unwrap();
        placement.extend_from_slice(&[1, 2, 3]);
        let mut reader = PacketReader::new(&placement);
        assert_eq!(
            read_player_block_placement(&mut reader),
            Ok((-12, 4095, -33_554_432, -1))
        );
        assert_eq!(reader.cursor, placement.len());

        let mut placement_with_item = Vec::new();
        write_block_position(&mut placement_with_item, 33_554_431, 0, 17);
        placement_with_item.push(5);
        write_slot(
            &mut placement_with_item,
            &MinecraftSlot::item(399, 0, menu_star_nbt()),
        )
        .unwrap();
        placement_with_item.extend_from_slice(&[0, 8, 15]);
        let mut reader = PacketReader::new(&placement_with_item);
        assert_eq!(
            read_player_block_placement(&mut reader),
            Ok((33_554_431, 0, 17, 5))
        );
        assert_eq!(reader.cursor, placement_with_item.len());
        for length in 0..placement_with_item.len() {
            assert!(
                read_player_block_placement(&mut PacketReader::new(&placement_with_item[..length]))
                    .is_err(),
                "truncated placement of length {length} was accepted"
            );
        }
    }

    #[test]
    fn draft_sign_updates_match_java_cleaning_assignment_and_echo() {
        let mut draft = MinecraftDraft::default();
        for (position, lines, expected_field, expected_value) in [
            (
                (2, 161, 3),
                [r#"{"text":" to@"}"#, r#"{"text":"example.test "}"#, "", ""],
                "to",
                "to@example.test",
            ),
            (
                (4, 161, 3),
                [r#"{"text":"[CC] cc@"}"#, "example.test", "", ""],
                "cc",
                "cc@example.test",
            ),
            (
                (6, 161, 3),
                ["\u{00a7}4bcc@", "example.test", "", ""],
                "bcc",
                "bcc@example.test",
            ),
            (
                (8, 161, 3),
                [r#"{"text":" Subject "}"#, "two", " lines ", ""],
                "subject",
                "Subjecttwolines",
            ),
        ] {
            let update = UpdateSign {
                x: position.0,
                y: position.1,
                z: position.2,
                lines: lines.map(str::to_owned),
            };
            let packets = draft_update_packets(update, &mut draft).unwrap();
            assert_eq!(
                packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
                [0x02, 0x33]
            );
            assert_eq!(
                &packets[1][1..9],
                &pack_block_position(position.0, position.1, position.2).to_be_bytes()
            );
            assert_eq!(
                match expected_field {
                    "to" => &draft.to,
                    "cc" => &draft.cc,
                    "bcc" => &draft.bcc,
                    "subject" => &draft.subject,
                    _ => unreachable!(),
                },
                expected_value
            );
        }

        let packets = draft_update_packets(
            UpdateSign {
                x: 100,
                y: 64,
                z: -100,
                lines: ["ignored", "", "", ""].map(str::to_owned),
            },
            &mut draft,
        )
        .unwrap();
        assert_eq!(
            packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x33]
        );
    }

    #[test]
    fn book_edit_parser_accepts_string_pages_and_rejects_bounded_invalid_slots() {
        fn encoded_book(item_id: i16, pages: NbtValue) -> Vec<u8> {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&item_id.to_be_bytes());
            encoded.push(1);
            encoded.extend_from_slice(&0_i16.to_be_bytes());
            minecraft_world::write_nbt(
                Some(&NbtValue::Compound(vec![("pages".to_owned(), pages)])),
                &mut encoded,
            )
            .unwrap();
            encoded
        }

        let pages = NbtValue::List {
            element_type: 8,
            values: vec![
                NbtValue::String("First page".to_owned()),
                NbtValue::String("Second page \u{2603}".to_owned()),
            ],
        };
        let encoded = encoded_book(386, pages.clone());
        let mut reader = PacketReader::new(&encoded);
        assert_eq!(
            read_book_edit(&mut reader),
            Some(vec![
                "First page".to_owned(),
                "Second page \u{2603}".to_owned()
            ])
        );
        assert_eq!(reader.cursor, encoded.len());

        assert!(read_book_edit(&mut PacketReader::new(&encoded_book(387, pages))).is_none());
        assert!(
            read_book_edit(&mut PacketReader::new(&encoded_book(
                386,
                NbtValue::List {
                    element_type: 3,
                    values: vec![NbtValue::Int(1)],
                },
            )))
            .is_none()
        );
        assert!(
            read_book_edit(&mut PacketReader::new(&encoded_book(
                386,
                NbtValue::List {
                    element_type: 8,
                    values: (0..=MAX_DRAFT_PAGES)
                        .map(|_| NbtValue::String(String::new()))
                        .collect(),
                },
            )))
            .is_none()
        );
    }

    #[test]
    fn draft_store_is_bounded_and_only_evicts_the_oldest_offline_player() {
        let mut store = MinecraftDraftStore::default();
        let active = HashSet::new();
        for index in 0..MAX_MINECRAFT_DRAFTS {
            let player = format!("player-{index}");
            assert!(store.get_or_create(&player, &active).is_some());
        }
        assert_eq!(store.drafts.len(), MAX_MINECRAFT_DRAFTS);

        let all_active = store.drafts.keys().cloned().collect::<HashSet<_>>();
        assert!(
            store
                .get_or_create("capacity-rejected", &all_active)
                .is_none()
        );
        assert_eq!(store.drafts.len(), MAX_MINECRAFT_DRAFTS);

        let active = HashSet::from(["player-0".to_owned()]);
        assert!(store.get_or_create("replacement", &active).is_some());
        assert!(store.drafts.contains_key("player-0"));
        assert!(!store.drafts.contains_key("player-1"));
        assert!(store.drafts.contains_key("replacement"));
        assert_eq!(store.drafts.len(), MAX_MINECRAFT_DRAFTS);
    }

    #[test]
    fn draft_store_rejects_over_budget_updates_atomically() {
        let mut store = MinecraftDraftStore::default();
        let active = HashSet::new();
        store.get_or_create("current", &active).unwrap();
        store
            .update_with_budget("current", &active, 4, |draft| {
                draft.to = "1234".to_owned();
            })
            .unwrap();
        let sequence = store.drafts["current"].sequence;
        let next_sequence = store.next_sequence;

        assert!(
            store
                .update_with_budget("current", &active, 4, |draft| {
                    draft.subject = "x".to_owned();
                })
                .is_none()
        );
        assert_eq!(store.drafts["current"].draft.to, "1234");
        assert!(store.drafts["current"].draft.subject.is_empty());
        assert_eq!(store.drafts["current"].sequence, sequence);
        assert_eq!(store.next_sequence, next_sequence);
        assert_eq!(store.content_bytes, 4);
    }

    #[test]
    fn draft_store_reclaims_the_oldest_offline_content_for_an_update() {
        let mut store = MinecraftDraftStore::default();
        let active = HashSet::new();
        for (player, value) in [("old", "aaaa"), ("newer", "bbbb")] {
            store.get_or_create(player, &active).unwrap();
            store
                .update_with_budget(player, &active, 16, |draft| {
                    draft.to = value.to_owned();
                })
                .unwrap();
        }
        store.get_or_create("current", &active).unwrap();

        store
            .update_with_budget("current", &active, 12, |draft| {
                draft.to = "12345678".to_owned();
            })
            .unwrap();

        assert!(!store.drafts.contains_key("old"));
        assert!(store.drafts.contains_key("newer"));
        assert_eq!(store.drafts["current"].draft.to, "12345678");
        assert_eq!(store.content_bytes, 12);
    }

    #[test]
    fn draft_store_never_reclaims_online_player_content() {
        let mut store = MinecraftDraftStore::default();
        let no_active_players = HashSet::new();
        for (player, value) in [("protected", "aaaa"), ("offline", "bbbb")] {
            store.get_or_create(player, &no_active_players).unwrap();
            store
                .update_with_budget(player, &no_active_players, 16, |draft| {
                    draft.to = value.to_owned();
                })
                .unwrap();
        }
        store.get_or_create("current", &no_active_players).unwrap();
        let active = HashSet::from(["protected".to_owned(), "current".to_owned()]);

        store
            .update_with_budget("current", &active, 12, |draft| {
                draft.to = "12345678".to_owned();
            })
            .unwrap();

        assert!(store.drafts.contains_key("protected"));
        assert!(!store.drafts.contains_key("offline"));
        assert!(store.drafts.contains_key("current"));
        assert_eq!(store.content_bytes, 12);
    }

    #[test]
    fn draft_store_content_accounting_matches_all_stored_drafts() {
        fn actual_content_bytes(store: &MinecraftDraftStore) -> usize {
            store
                .drafts
                .values()
                .map(|stored| draft_content_bytes(&stored.draft))
                .sum()
        }

        let mut store = MinecraftDraftStore::default();
        let active = HashSet::new();
        for player in ["first", "second", "current"] {
            store.get_or_create(player, &active).unwrap();
        }
        store
            .update_with_budget("first", &active, 128, |draft| {
                draft.to = "first@example.test".to_owned();
                draft.body_pages = vec!["one".to_owned(), "two".to_owned()];
            })
            .unwrap();
        store
            .update_with_budget("second", &active, 128, |draft| {
                draft.subject = "subject".to_owned();
            })
            .unwrap();
        assert_eq!(store.content_bytes, actual_content_bytes(&store));

        store
            .update_with_budget("first", &active, 128, MinecraftDraft::clear)
            .unwrap();
        assert_eq!(store.content_bytes, actual_content_bytes(&store));

        store
            .update_with_budget("current", &active, 8, |draft| {
                draft.to = "12345678".to_owned();
            })
            .unwrap();
        assert_eq!(store.content_bytes, actual_content_bytes(&store));
        assert_eq!(store.content_bytes, 8);
    }

    #[test]
    fn mail_view_hotbar_actions_match_java_slots_and_cooldown() {
        let start = Instant::now();
        let mut last_click = None;
        assert_eq!(
            hotbar_action(true, true, 3, true, start, &mut last_click),
            HotbarAction::PreviousPage
        );
        assert_eq!(last_click, Some(start));
        assert_eq!(
            hotbar_action(
                true,
                true,
                5,
                true,
                start + Duration::from_millis(399),
                &mut last_click,
            ),
            HotbarAction::None
        );
        assert_eq!(last_click, Some(start));
        assert_eq!(
            hotbar_action(
                true,
                true,
                5,
                true,
                start + HOTBAR_CLICK_COOLDOWN,
                &mut last_click,
            ),
            HotbarAction::NextPage
        );
        assert_eq!(
            hotbar_action(
                true,
                true,
                4,
                true,
                start + HOTBAR_CLICK_COOLDOWN * 2,
                &mut last_click,
            ),
            HotbarAction::CloseMailView
        );
        assert_eq!(
            hotbar_action(
                true,
                true,
                8,
                true,
                start + HOTBAR_CLICK_COOLDOWN * 2,
                &mut last_click,
            ),
            HotbarAction::OpenMainMenu
        );
        assert_eq!(
            hotbar_action(
                false,
                true,
                8,
                true,
                start + HOTBAR_CLICK_COOLDOWN * 2,
                &mut last_click,
            ),
            HotbarAction::OpenMainMenu
        );
        for (active, authenticated, slot, primary) in [
            (false, true, 3, true),
            (true, false, 3, true),
            (true, true, 3, false),
            (true, true, 2, true),
            (true, true, 15, true),
        ] {
            assert_eq!(
                hotbar_action(
                    active,
                    authenticated,
                    slot,
                    primary,
                    start + Duration::from_secs(2),
                    &mut last_click,
                ),
                HotbarAction::None
            );
        }
    }

    #[test]
    fn map_wall_teardown_restores_every_saved_block_and_entity() {
        let wall = MapWall {
            maps_x: 2,
            maps_y: 2,
            facing: MapWallFacing::South,
            center_x: 0,
            center_y: 180,
            center_z: -20,
            map_ids: vec![10_000, 10_001, 10_002, 10_003].into_boxed_slice(),
            entity_ids: vec![100_000, 100_001, 100_002, 100_003].into_boxed_slice(),
            saved_blocks: vec![((-1, 180, -20), 16), ((-1, 180, -19), 0)],
        };
        let packets = wall.teardown_packets();
        assert_eq!(packets.len(), 3);
        assert_eq!(
            packets[0],
            destroy_entities_packet(&[100_000, 100_001, 100_002, 100_003])
        );
        assert_eq!(packets[1], block_change_packet((-1, 180, -20), 16));
        assert_eq!(packets[2], block_change_packet((-1, 180, -19), 0));
    }

    #[test]
    fn one_row_mail_page_overwrites_the_full_wall_with_blank_lower_maps() {
        let cancellation = CancellationToken::new();
        let result = mail_render::render(&mail_render::RenderRequest::plain_text(
            "short page",
            2,
            2,
            &cancellation,
            StdInstant::now() + Duration::from_secs(5),
        ))
        .unwrap();
        assert_eq!(result.pages().len(), 1);
        assert_eq!(result.pages()[0].maps_y(), 1);
        assert_eq!(result.pages()[0].pixel_height(), 128);

        let wall = MapWall {
            maps_x: 2,
            maps_y: 2,
            facing: MapWallFacing::South,
            center_x: 0,
            center_y: 180,
            center_z: -20,
            map_ids: vec![10, 11, 12, 13].into_boxed_slice(),
            entity_ids: vec![100, 101, 102, 103].into_boxed_slice(),
            saved_blocks: Vec::new(),
        };
        let packets = mail_view_page_packets(&wall, &result.pages()[0]).unwrap();
        assert_eq!(packets.len(), 4);
        assert_eq!(
            mail_view_page_packets(&wall, &result.pages()[0]).unwrap(),
            packets
        );
        assert_eq!(
            packets.iter().map(|packet| packet[1]).collect::<Vec<_>>(),
            [10, 11, 12, 13]
        );
        let blank = [MAP_BLANK_COLOR; MAP_TILE_PIXELS];
        for packet in &packets[2..] {
            assert_eq!(&packet[packet.len() - MAP_TILE_PIXELS..], &blank);
        }
    }

    #[test]
    fn gui_close_restores_the_java_mail_view_hotbar_order() {
        let packets = restore_gui_hotbar_packets(true).unwrap();
        let digest = Sha256::digest(packets.concat())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "8349f0f3eaf435a751e244edcbd17885d746e10550f61cd719de75b2226c5292"
        );
        assert_eq!(packets.len(), 6);
        assert_eq!(
            packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x09]
        );
        assert_eq!(
            packets[..5]
                .iter()
                .map(|packet| i16::from_be_bytes([packet[2], packet[3]]))
                .collect::<Vec<_>>(),
            [36, 44, 39, 40, 41]
        );
        assert_eq!(packets[5], [0x09, 4]);

        let base_only = restore_gui_hotbar_packets(false).unwrap();
        assert_eq!(base_only, restore_hotbar_packets().unwrap());

        let (close, effect) = main_menu_click_packets(
            WindowClick {
                window_id: 7,
                slot: 49,
                action_number: 15,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            true,
        )
        .unwrap();
        assert_eq!(effect, MainMenuEffect::Close);
        assert_eq!(
            close.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x09]
        );
        assert_eq!(close.last().unwrap(), &[0x09, 4]);
    }

    #[test]
    fn authenticated_basic_commands_match_java_trim_case_and_packet_order() {
        let configured = config(Duration::from_secs(30));
        let mut draft = MinecraftDraft::default();
        let render_settings = RenderSettings::default();
        let help = authenticated_command_packets(
            "  /HeLp  ",
            &configured,
            &mut draft,
            None,
            render_settings,
        )
        .unwrap();
        assert_eq!(help, email_instruction_packets().unwrap());
        assert_eq!(help.len(), 8);
        assert!(help.iter().all(|packet| packet[0] == 0x02));

        let stuck =
            authenticated_command_packets("/stuck", &configured, &mut draft, None, render_settings)
                .unwrap();
        assert_eq!(stuck.len(), 2);
        assert_eq!(stuck[0][0], 0x08);
        assert_eq!(stuck[1][0], 0x02);
        assert_eq!(
            authenticated_command_packets(
                "/skibidi",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()[0],
            chat_packet("Brrrrrr Skibidi dop dop dop yes yes!", None).unwrap()
        );
        assert_eq!(
            authenticated_command_packets(
                "/video",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            authenticated_command_packets(
                "/definitely-unknown",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()[0],
            chat_packet("\u{00a7}cUnknown command. Use /help", Some("red")).unwrap()
        );
        assert!(
            authenticated_command_packets(
                "plain chat",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn render_size_commands_match_direct_validation_and_sign_alias() {
        let mut settings = RenderSettings::default();
        let (valid, opens_editor) = render_size_command_packets(
            "/MAIL RenderSize 24 20 48",
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
        )
        .unwrap()
        .unwrap();
        assert!(!opens_editor);
        assert_eq!(
            settings,
            RenderSettings {
                maps_x: 24,
                maps_y: 20,
                font_size: 48,
            }
        );
        assert_eq!(
            valid.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x3b, 0x3b, 0x3d, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x02
            ]
        );

        let (invalid_font, opens_editor) = render_size_command_packets(
            "/mail rs 12 8 49",
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
        )
        .unwrap()
        .unwrap();
        assert!(!opens_editor);
        assert_eq!(settings.maps_x, 12);
        assert_eq!(settings.maps_y, 8);
        assert_eq!(settings.font_size, 48);
        assert_eq!(invalid_font.len(), 14);

        let (editor, opens_editor) = render_size_command_packets(
            "/mail rs 12",
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
        )
        .unwrap()
        .unwrap();
        assert!(opens_editor);
        assert_eq!(
            editor.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x35, 0x36, 0x02, 0x02, 0x02, 0x02]
        );
        assert!(
            render_size_command_packets(
                "/mail close",
                &mut settings,
                "BlackboxLogin",
                "qa@example.test",
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn draft_commands_inspect_and_clear_the_session_state() {
        let configured = config(Duration::from_secs(30));
        let mut draft = MinecraftDraft {
            to: "to@example.test".to_owned(),
            cc: "cc@example.test".to_owned(),
            bcc: "bcc@example.test".to_owned(),
            subject: "subject".to_owned(),
            body_pages: vec!["page one".to_owned(), "page two".to_owned()],
        };
        let summary = authenticated_command_packets(
            "/draft",
            &configured,
            &mut draft,
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(summary.len(), 6);
        assert_eq!(
            summary[1],
            chat_packet("\u{00a7}7To: \u{00a7}fto@example.test", None).unwrap()
        );
        assert_eq!(
            summary[5],
            chat_packet("\u{00a7}7Body: \u{00a7}f2 page(s)", None).unwrap()
        );

        let clear = authenticated_command_packets(
            "/clear",
            &configured,
            &mut draft,
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(
            clear.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x02, 0x33, 0x33, 0x33, 0x33, 0x2f]
        );
        assert!(draft.to.is_empty());
        assert!(draft.cc.is_empty());
        assert!(draft.bcc.is_empty());
        assert!(draft.subject.is_empty());
        assert!(draft.body_pages.is_empty());
    }

    #[test]
    fn main_menu_payload_and_window_id_cycle_are_bounded() {
        let packets = main_menu_packets(1, RenderSettings::default()).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0][0], 0x2d);
        assert_eq!(packets[0].len(), 47);
        assert_eq!(packets[1][0], 0x30);
        assert_eq!(packets[1][1], 1);
        assert_eq!(i16::from_be_bytes([packets[1][2], packets[1][3]]), 90);
        assert_eq!(packets[1].len(), 2771);

        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        for expected in 1..=100 {
            assert_eq!(service.next_window_id(), expected);
        }
        assert_eq!(service.next_window_id(), 1);
    }

    #[test]
    fn folder_gui_builds_java_navigation_and_utf16_nbt_boundaries() {
        let (opening, opening_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 10,
                action_number: 7,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(opening_effect, MainMenuEffect::OpenFolder("inbox"));
        assert_eq!(
            opening.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x02, 0x2e, 0x2f, 0x2f]
        );

        let subject = "Unicode subject xxxxxxxxxxxxxxx\u{1f4e7}tail";
        let item = EmailListItem {
            file_name: "folder.eml".to_owned(),
            subject: Some(subject.to_owned()),
            from: Some("sender@example.test".to_owned()),
            to: vec!["qa@example.test".to_owned()],
            received_at: "2024-02-02T10:00:00Z".to_owned(),
            starred: false,
            has_attachments: true,
            labels: Vec::new(),
            send_status: None,
            send_status_description: None,
            retry_count: None,
            last_error: None,
        };
        let gui = FolderGui {
            window_id: 2,
            folder: "inbox".to_owned(),
            page: EmailListPage {
                content: vec![item],
                current_page: 0,
                page_size: 36,
                total_elements: 37,
                total_pages: 2,
                has_next: true,
                has_previous: false,
            },
        };
        let packets = folder_gui_packets(&gui).unwrap();
        assert_eq!(packets[0][0], 0x2d);
        assert_eq!(packets[1][0], 0x30);
        assert!(
            packets[1]
                .windows(3)
                .any(|window| window == [0xed, 0xa0, 0xbd])
        );

        let (next, next_effect) = folder_gui_click_packets(
            WindowClick {
                window_id: 2,
                slot: 52,
                action_number: 8,
                mode: 0,
            },
            &gui,
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(next_effect, FolderGuiEffect::LoadPage(1));
        assert_eq!(
            next.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30]
        );

        let (back, back_effect) = folder_gui_click_packets(
            WindowClick {
                window_id: 2,
                slot: 49,
                action_number: 9,
                mode: 0,
            },
            &gui,
            Some(3),
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(back_effect, FolderGuiEffect::OpenMainMenu(3));
        assert_eq!(
            back.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2f, 0x2f, 0x2d, 0x30]
        );
    }

    #[test]
    fn main_menu_click_and_close_packets_match_the_protocol_lifecycle() {
        let mut encoded_click = vec![1];
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&7_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&(-1_i16).to_be_bytes());
        let mut reader = PacketReader::new(&encoded_click);
        let click = read_window_click(&mut reader).unwrap();
        assert_eq!(click.window_id, 1);
        assert_eq!(click.slot, 0);
        assert_eq!(click.action_number, 7);
        assert_eq!(click.mode, 0);
        assert_eq!(reader.cursor, encoded_click.len());

        let (responses, effect) =
            main_menu_click_packets(click, None, RenderSettings::default(), false).unwrap();
        assert_eq!(effect, MainMenuEffect::None);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0], [0x32, 1, 0, 7, 0]);
        assert_eq!(responses[1], [0x2f, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            responses[2],
            main_menu_contents_packet(1, RenderSettings::default()).unwrap()
        );

        let restored = restore_hotbar_packets().unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0][..6], [0x2f, 0, 0, 36, 1, 130]);
        assert_eq!(restored[1][..6], [0x2f, 0, 0, 44, 1, 143]);
    }

    #[test]
    fn synchronous_main_menu_actions_close_or_switch_state_after_base_refresh() {
        let (help, help_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 30,
                action_number: 11,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(help_effect, MainMenuEffect::Close);
        assert_eq!(
            help.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            ]
        );

        let (close, close_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 2,
                slot: 49,
                action_number: 12,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(close_effect, MainMenuEffect::Close);
        assert_eq!(close.len(), 6);

        let (switch, switch_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 3,
                slot: 32,
                action_number: 13,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(switch_effect, MainMenuEffect::SwitchAccount);
        assert_eq!(switch.len(), 7);
        assert_eq!(switch[6][0], 0x02);

        let (mode_only, mode_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 4,
                slot: 30,
                action_number: 14,
                mode: 1,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(mode_effect, MainMenuEffect::None);
        assert_eq!(mode_only.len(), 3);
    }

    #[test]
    fn logout_confirmation_cancel_and_confirm_have_complete_bounded_flows() {
        let (open, open_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 34,
                action_number: 21,
                mode: 0,
            },
            Some(2),
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(open_effect, MainMenuEffect::OpenLogoutConfirm(2));
        assert_eq!(
            open.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2f, 0x2f, 0x2d, 0x30]
        );
        assert_eq!(open[6], logout_confirmation_contents_packet(2).unwrap());

        let (cancel, cancel_effect) = logout_confirmation_click_packets(
            WindowClick {
                window_id: 2,
                slot: 15,
                action_number: 22,
                mode: 0,
            },
            Some(3),
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(cancel_effect, LogoutConfirmEffect::OpenMainMenu(3));
        assert_eq!(
            cancel.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x2d, 0x30]
        );

        let (confirm, confirm_effect) = logout_confirmation_click_packets(
            WindowClick {
                window_id: 4,
                slot: 11,
                action_number: 24,
                mode: 0,
            },
            None,
            RenderSettings::default(),
            false,
        )
        .unwrap();
        assert_eq!(confirm_effect, LogoutConfirmEffect::Disconnect);
        assert_eq!(
            confirm.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x40]
        );
        assert_eq!(
            confirm[6],
            disconnect_play_packet("\u{00a7}aLogged out. See you!").unwrap()
        );
    }

    #[test]
    fn render_settings_menu_and_editor_have_the_complete_protocol_flow() {
        let settings = RenderSettings::default();
        let (packets, effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 22,
                action_number: 31,
                mode: 0,
            },
            None,
            settings,
            false,
        )
        .unwrap();
        assert_eq!(effect, MainMenuEffect::OpenRenderSettings);
        assert_eq!(
            packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x35, 0x36, 0x02, 0x02, 0x02, 0x02
            ]
        );
        assert_eq!(packets[2], main_menu_contents_packet(1, settings).unwrap());
        assert_eq!(&packets[6][..10], &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(packets[7], [0x36, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn render_settings_updates_match_java_validation_and_partial_font_commit() {
        let draft = MinecraftDraft::default();
        let mut settings = RenderSettings::default();
        let update = |lines: [&str; 4]| UpdateSign {
            x: 0,
            y: 0,
            z: 0,
            lines: lines.map(str::to_owned),
        };

        let valid = render_settings_update_packets(
            update([
                r#"{"text":"24"}"#,
                r#"{"text":"20"}"#,
                r#"{"text":"48"}"#,
                r#"{"text":"W H Font"}"#,
            ]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(
            settings,
            RenderSettings {
                maps_x: 24,
                maps_y: 20,
                font_size: 48,
            }
        );
        assert_eq!(
            valid.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x02, 0x3b, 0x3b, 0x3d, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
                0x33, 0x33, 0x33, 0x33
            ]
        );

        let invalid_width = render_settings_update_packets(
            update(["1", "20", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_x, 24);
        assert_eq!(
            invalid_width
                .iter()
                .map(|packet| packet[0])
                .collect::<Vec<_>>(),
            [0x02, 0x33, 0x33, 0x33, 0x33]
        );

        let invalid_height = render_settings_update_packets(
            update(["24", "21", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_y, 20);
        assert_eq!(invalid_height.len(), 5);

        let invalid_font = render_settings_update_packets(
            update(["12", "8", "49", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(
            settings,
            RenderSettings {
                maps_x: 12,
                maps_y: 8,
                font_size: 48,
            }
        );
        assert_eq!(invalid_font[0][0], 0x02);
        assert_eq!(invalid_font[1][0], 0x02);
        assert_eq!(invalid_font.len(), 19);

        let non_integer = render_settings_update_packets(
            update(["twelve", "8", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_x, 12);
        assert_eq!(non_integer.len(), 5);
    }

    #[test]
    fn update_sign_parser_enforces_four_bounded_utf16_lines() {
        fn encoded(lines: [&str; 4]) -> Vec<u8> {
            let mut packet = 0_i64.to_be_bytes().to_vec();
            for line in lines {
                write_string(&mut packet, line).unwrap();
            }
            packet
        }

        let ascii_limit = "a".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS);
        let within = encoded([&ascii_limit, "", "", ""]);
        let mut reader = PacketReader::new(&within);
        assert!(read_update_sign(&mut reader).is_ok());
        assert_eq!(reader.cursor, within.len());

        let ascii_over = "a".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS + 1);
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([&ascii_over, "", "", ""]))).is_err()
        );

        let supplementary_limit = "\u{1f600}".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS / 2);
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([
                &supplementary_limit,
                "",
                "",
                ""
            ])))
            .is_ok()
        );
        let supplementary_over = format!("{supplementary_limit}\u{1f600}");
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([
                &supplementary_over,
                "",
                "",
                ""
            ])))
            .is_err()
        );

        let mut truncated = encoded(["24", "20", "48", ""]);
        truncated.pop();
        assert!(read_update_sign(&mut PacketReader::new(&truncated)).is_err());
    }

    #[test]
    fn draft_sign_lines_match_java_utf16_substring_replacement() {
        let split_pair = format!("{}\u{1f600}x", "a".repeat(14));
        assert_eq!(
            split_sign_lines(&split_pair),
            [
                format!("{}?", "a".repeat(14)),
                "?x".to_owned(),
                String::new()
            ]
        );
        assert_eq!(
            split_sign_lines(&"b".repeat(46)),
            ["b".repeat(15), "b".repeat(15), "b".repeat(15)]
        );
    }

    #[test]
    fn click_slot_parser_skips_bounded_nbt_and_rejects_truncation() {
        let mut encoded_click = vec![1];
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&7_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&386_i16.to_be_bytes());
        encoded_click.push(1);
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        minecraft_world::write_nbt(Some(&book_item_nbt()), &mut encoded_click).unwrap();

        let mut reader = PacketReader::new(&encoded_click);
        let click = read_window_click(&mut reader).unwrap();
        assert_eq!(click.window_id, 1);
        assert_eq!(reader.cursor, encoded_click.len());

        encoded_click.pop();
        assert!(read_window_click(&mut PacketReader::new(&encoded_click)).is_err());
    }

    #[test]
    fn configured_status_preserves_java_motd_and_favicon_rules() {
        let mut configured = config(Duration::from_secs(30));
        configured.max_players = 42;
        configured.motd = "quoted \\\"status\\\"".to_owned();
        configured.favicon = "  cGl4ZWw=  ".to_owned();
        assert_eq!(
            status_json(&configured),
            "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":42,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"quoted \\\\\\\"status\\\\\\\"\"},\"favicon\":\"data:image/png;base64,cGl4ZWw=\"}"
        );
    }

    #[test]
    fn login_rejection_frames_match_frozen_java_wire() {
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        assert_eq!(
            service.blacklist_frame.as_ref(),
            STANDARD
                .decode("OwA5eyJ0ZXh0IjoiWW91IGFyZSBiYW5uZWQgZnJvbSB0aGlzIHNlcnZlci4iLCJjb2xvciI6InJlZCJ9")
                .unwrap()
        );
        assert_eq!(
            service.whitelist_frame.as_ref(),
            STANDARD
                .decode("MwAxeyJ0ZXh0IjoiWW91IGFyZSBub3Qgd2hpdGVsaXN0ZWQuIiwiY29sb3IiOiJyZWQifQ==")
                .unwrap()
        );
    }

    #[test]
    fn admission_uses_java_unicode_simple_case_comparison() {
        assert!(java_equals_ignore_case("\u{c4}User", "\u{e4}user"));
        assert!(java_equals_ignore_case("\u{130}", "i"));
        assert!(java_equals_ignore_case("\u{3a3}", "\u{3c2}"));
        assert!(!java_equals_ignore_case("\u{df}", "ss"));
    }

    #[test]
    fn encryption_request_uses_protocol_47_x509_and_four_byte_token() {
        let mut configured = config(Duration::from_secs(3));
        configured.online_mode = true;
        let online = OnlineModeService::new(&configured).unwrap();
        let token = [1, 2, 3, 4];
        let frame = encryption_request_frame(&online.public_key_der, &token).unwrap();
        let mut outer = PacketReader::new(&frame);
        let length = outer.read_varint().unwrap() as usize;
        assert_eq!(length, frame.len() - outer.cursor);
        let mut packet = PacketReader::new(&frame[outer.cursor..]);
        assert_eq!(packet.read_varint().unwrap(), 1);
        assert_eq!(packet.read_string(20).unwrap(), "");
        let der = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        assert_eq!(der.as_slice(), online.public_key_der.as_ref());
        assert!(PKey::public_key_from_der(&der).is_ok());
        assert_eq!(
            packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap(),
            token
        );
        assert_eq!(packet.cursor, packet.bytes.len());
    }

    #[tokio::test]
    async fn rsa_response_requires_matching_token_and_aes_128_secret() {
        let mut configured = config(Duration::from_secs(3));
        configured.online_mode = true;
        let online = OnlineModeService::new(&configured).unwrap();
        let public_key = PKey::public_key_from_der(&online.public_key_der)
            .unwrap()
            .rsa()
            .unwrap();
        let secret = *b"0123456789abcdef";
        let token = [9, 8, 7, 6];
        let mut encrypted_secret = vec![0_u8; public_key.size() as usize];
        let secret_len = public_key
            .public_encrypt(&secret, &mut encrypted_secret, Padding::PKCS1)
            .unwrap();
        encrypted_secret.truncate(secret_len);
        let mut encrypted_token = vec![0_u8; public_key.size() as usize];
        let token_len = public_key
            .public_encrypt(&token, &mut encrypted_token, Padding::PKCS1)
            .unwrap();
        encrypted_token.truncate(token_len);
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        assert_eq!(
            decrypt_online_response(
                &online,
                encrypted_secret.clone(),
                encrypted_token.clone(),
                token,
                deadline,
                &cancellation,
            )
            .await
            .unwrap(),
            secret
        );
        assert!(matches!(
            decrypt_online_response(
                &online,
                encrypted_secret,
                encrypted_token,
                [0; VERIFY_TOKEN_BYTES],
                deadline,
                &cancellation,
            )
            .await,
            Err(ProtocolError::Malformed)
        ));
    }

    #[tokio::test]
    async fn online_login_switches_to_aes_and_uses_bounded_session_fixture() {
        let profile_uuid = "0123456789abcdef0123456789abcdef";
        let profile_body = format!(r#"{{"id":"{profile_uuid}","name":"OnlineUser"}}"#);
        let (fixture_address, request_receiver, fixture_task) =
            start_session_fixture(200, profile_body, Duration::ZERO).await;
        let mut configured = config(Duration::from_secs(5));
        configured.online_mode = true;
        configured.session_server_url =
            format!("http://{fixture_address}/session/minecraft/hasJoined");
        let (address, cancellation, server_task) = start_server_with_config(8, configured).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&handshake(address.port(), 2))
            .await
            .unwrap();
        client.write_all(&login_start(b"OnlineUser")).await.unwrap();

        let io_cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let request = read_frame(&mut client, None, deadline, &io_cancellation)
            .await
            .unwrap()
            .unwrap();
        let mut request = PacketReader::new(&request);
        assert_eq!(request.read_varint().unwrap(), 1);
        assert_eq!(request.read_string(20).unwrap(), "");
        let public_key_der = request.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        let verify_token = request.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        assert_eq!(verify_token.len(), VERIFY_TOKEN_BYTES);

        let secret = *b"0123456789abcdef";
        let mut response = vec![0x01];
        write_byte_array(&mut response, &rsa_encrypt(&public_key_der, &secret)).unwrap();
        write_byte_array(&mut response, &rsa_encrypt(&public_key_der, &verify_token)).unwrap();
        client
            .write_all(&encode_frame(&response).unwrap())
            .await
            .unwrap();

        let mut client_cipher = MinecraftCipher::new(&secret).unwrap();
        let set_compression = read_frame(
            &mut client,
            Some(&mut client_cipher),
            deadline,
            &io_cancellation,
        )
        .await
        .unwrap()
        .unwrap();
        let mut set_compression = PacketReader::new(&set_compression);
        assert_eq!(set_compression.read_varint().unwrap(), 3);
        assert_eq!(set_compression.read_varint().unwrap(), 256);

        let login_success = read_frame(
            &mut client,
            Some(&mut client_cipher),
            deadline,
            &io_cancellation,
        )
        .await
        .unwrap()
        .unwrap();
        let mut envelope = PacketReader::new(&login_success);
        assert_eq!(envelope.read_varint().unwrap(), 0);
        let mut login_success = PacketReader::new(&login_success[envelope.cursor..]);
        assert_eq!(login_success.read_varint().unwrap(), 2);
        assert_eq!(
            login_success.read_string(36).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        assert_eq!(login_success.read_string(16).unwrap(), "OnlineUser");

        let request = request_receiver.await.unwrap();
        let request = String::from_utf8(request).unwrap();
        let request_line = request.lines().next().unwrap();
        assert!(
            request_line
                .starts_with("GET /session/minecraft/hasJoined?username=OnlineUser&serverId=")
        );
        let hash = request_line
            .split("serverId=")
            .nth(1)
            .unwrap()
            .split_ascii_whitespace()
            .next()
            .unwrap();
        assert!(!hash.is_empty());
        assert!(
            hash.bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_hexdigit())
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fixture_task.await.unwrap();
    }

    #[tokio::test]
    async fn session_fixture_errors_are_bounded_and_stable() {
        async fn run_case(
            status: u16,
            body: String,
            response_delay: Duration,
            request_budget: Duration,
        ) -> String {
            let (fixture_address, request_receiver, fixture_task) =
                start_session_fixture(status, body, response_delay).await;
            let mut configured = config(Duration::from_secs(5));
            configured.online_mode = true;
            configured.session_server_url = format!("http://{fixture_address}/hasJoined");
            let online = OnlineModeService::new(&configured).unwrap();
            let cancellation = CancellationToken::new();
            let error = authenticate_online(
                &online,
                "OnlineUser",
                b"0123456789abcdef",
                Instant::now() + request_budget,
                &cancellation,
            )
            .await
            .unwrap_err();
            request_receiver.await.unwrap();
            fixture_task.await.unwrap();
            error.message
        }

        assert_eq!(
            run_case(204, String::new(), Duration::ZERO, Duration::from_secs(2)).await,
            "Session not found"
        );
        assert_eq!(
            run_case(200, "{}".to_owned(), Duration::ZERO, Duration::from_secs(2)).await,
            "Auth server error: invalid response"
        );
        assert_eq!(
            run_case(
                200,
                "x".repeat(MAX_AUTH_RESPONSE_BYTES + 1),
                Duration::ZERO,
                Duration::from_secs(2)
            )
            .await,
            "Auth server error: response exceeded byte limit"
        );
        assert_eq!(
            run_case(
                200,
                r#"{"id":"0123456789abcdef0123456789abcdef","name":"OnlineUser"}"#.to_owned(),
                Duration::from_millis(200),
                Duration::from_millis(40)
            )
            .await,
            "Auth server error: request timed out"
        );
    }

    #[test]
    fn aes_cfb8_stream_state_survives_fragmentation() {
        let secret = *b"0123456789abcdef";
        let mut sender = MinecraftCipher::new(&secret).unwrap();
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(sender.encrypt(b"first-").unwrap());
        ciphertext.extend_from_slice(sender.encrypt(b"second-payload").unwrap());

        let mut receiver = MinecraftCipher::new(&secret).unwrap();
        let mut first = ciphertext[..3].to_vec();
        let mut second = ciphertext[3..11].to_vec();
        let mut third = ciphertext[11..].to_vec();
        receiver.decrypt_in_place(&mut first).unwrap();
        receiver.decrypt_in_place(&mut second).unwrap();
        receiver.decrypt_in_place(&mut third).unwrap();
        first.extend_from_slice(&second);
        first.extend_from_slice(&third);
        assert_eq!(first, b"first-second-payload");
    }

    #[test]
    fn signed_server_hash_matches_java_big_integer_hex_rules() {
        assert_eq!(signed_hex(&[0]), "0");
        assert_eq!(signed_hex(&[0, 0x0f]), "f");
        assert_eq!(signed_hex(&[0x7f]), "7f");
        assert_eq!(signed_hex(&[0x80]), "-80");
        assert_eq!(signed_hex(&[0xff]), "-1");
        assert_eq!(signed_hex(&[0xff, 0]), "-100");
    }

    #[test]
    fn joined_profile_validation_is_strict_and_canonical() {
        assert_eq!(
            normalize_joined_uuid("0123456789ABCDEF0123456789ABCDEF").as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert_eq!(
            normalize_joined_uuid("01234567-89ab-cdef-0123-456789abcdef").as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert!(normalize_joined_uuid("--0123456789abcdef0123456789abcdef").is_none());
        assert!(valid_online_name("Player_1"));
        assert!(!valid_online_name("player-name"));
        assert!(!valid_online_name("12345678901234567"));
    }

    #[test]
    fn java_utf8_replacement_consumes_the_frozen_malformed_lengths() {
        assert_eq!(decode_java_utf8(b"valid").unwrap(), "valid");
        assert_eq!(decode_java_utf8(&[0xed, 0xa0, 0x80]).unwrap(), "\u{fffd}");
        assert_eq!(decode_java_utf8(&[0xe2, 0x82, b'A']).unwrap(), "\u{fffd}A");
        assert_eq!(
            decode_java_utf8(&[0xe0, 0x80, 0x80]).unwrap(),
            "\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x80, 0x80, 0x80]).unwrap(),
            "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x90, 0x80, b'A']).unwrap(),
            "\u{fffd}A"
        );
        assert_eq!(decode_java_utf8(&[0xe2, 0x82]).unwrap(), "\u{fffd}");
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x9f, 0x92, 0xa9]).unwrap(),
            "\u{1f4a9}"
        );
    }

    #[test]
    fn duplicate_uuid_status_is_unique_and_old_disconnect_is_fenced() {
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        let old = service.register_online("same-uuid".to_owned());
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        let current = service.register_online("same-uuid".to_owned());
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        drop(old);
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        drop(current);
        assert!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn login_admission_matches_frozen_rejections_and_username_bound() {
        let mut configured = config(Duration::from_secs(3));
        configured.whitelist_enabled = true;
        configured.whitelist_players = vec!["AllowedUser".to_owned(), "BlockedUser".to_owned()];
        configured.blacklist_players = vec!["BlockedUser".to_owned()];
        let (address, cancellation, task) = start_server_with_config(8, configured).await;

        for (username, expected) in [
            (
                b"blockeduser".as_slice(),
                "OwA5eyJ0ZXh0IjoiWW91IGFyZSBiYW5uZWQgZnJvbSB0aGlzIHNlcnZlci4iLCJjb2xvciI6InJlZCJ9",
            ),
            (
                b"OtherUser".as_slice(),
                "MwAxeyJ0ZXh0IjoiWW91IGFyZSBub3Qgd2hpdGVsaXN0ZWQuIiwiY29sb3IiOiJyZWQifQ==",
            ),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(&handshake(address.port(), 2))
                .await
                .unwrap();
            client.write_all(&login_start(username)).await.unwrap();
            let expected = STANDARD.decode(expected).unwrap();
            let mut actual = vec![0_u8; expected.len()];
            client.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
            let mut trailing = [0_u8; 1];
            assert_eq!(client.read(&mut trailing).await.unwrap(), 0);
        }

        let mut allowed = TcpStream::connect(address).await.unwrap();
        allowed
            .write_all(&handshake(address.port(), 2))
            .await
            .unwrap();
        allowed
            .write_all(&login_start(b"alloweduser"))
            .await
            .unwrap();
        let mut compression_prefix = [0_u8; 4];
        allowed.read_exact(&mut compression_prefix).await.unwrap();
        assert_eq!(compression_prefix, [3, 3, 0x80, 2]);

        let mut overlong = Vec::new();
        overlong.extend_from_slice(&handshake(address.port(), 2));
        overlong.extend_from_slice(&login_start(b"12345678901234567"));
        assert_closed_without_response(address, &overlong).await;

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fragmented_handshake_status_and_ping_match_protocol_47() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        for byte in handshake(address.port(), 1) {
            client.write_all(&[byte]).await.unwrap();
        }
        client.write_all(&[1, 0]).await.unwrap();
        let expected = STANDARD.decode(FROZEN_STATUS_FRAME).unwrap();
        let mut actual = vec![0_u8; expected.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        client
            .write_all(&[9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
            .await
            .unwrap();
        let mut pong = [0_u8; 10];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let mut trailing = [0_u8; 1];
        assert_eq!(client.read(&mut trailing).await.unwrap(), 0);

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_lengths_and_invalid_state_close_silently() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        for payload in [
            handshake(address.port(), 3),
            vec![0xff, 0xff, 0xff, 0xff, 0x0f],
            {
                let mut value = Vec::new();
                write_varint(&mut value, MAX_FRAME_LENGTH as u32 + 1);
                value
            },
            vec![0x80, 0x80, 0x80, 0x80, 0x80],
        ] {
            assert_closed_without_response(address, &payload).await;
        }
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn empty_frames_unknown_packets_and_trailing_bytes_are_ignored() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0]).await.unwrap();
        client
            .write_all(&encode_frame(&[7]).unwrap())
            .await
            .unwrap();
        client
            .write_all(&handshake(address.port(), 1))
            .await
            .unwrap();
        client
            .write_all(&encode_frame(&[2, 0xaa, 0xbb]).unwrap())
            .await
            .unwrap();
        client
            .write_all(&encode_frame(&[0, 0xcc]).unwrap())
            .await
            .unwrap();

        let expected = STANDARD.decode(FROZEN_STATUS_FRAME).unwrap();
        let mut actual = vec![0_u8; expected.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        let ping = [1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xdd];
        client
            .write_all(&encode_frame(&ping).unwrap())
            .await
            .unwrap();
        let mut pong = [0_u8; 10];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn admission_is_bounded_and_cancellation_drains_partial_reads() {
        let (address, cancellation, task) = start_server(1, Duration::from_secs(30)).await;
        let mut admitted = TcpStream::connect(address).await.unwrap();
        admitted.write_all(&[0x80]).await.unwrap();
        sleep(Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(address).await.unwrap();
        let _ = rejected.write_all(&handshake(address.port(), 1)).await;
        let mut byte = [0_u8; 1];
        let rejected_read = timeout(Duration::from_secs(1), rejected.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(rejected_read, Ok(0))
                || matches!(rejected_read, Err(ref error) if connection_ended(error))
        );

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("Minecraft listener did not drain after cancellation")
            .unwrap()
            .unwrap();
        let admitted_read = timeout(Duration::from_secs(1), admitted.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(admitted_read, Ok(0))
                || matches!(admitted_read, Err(ref error) if connection_ended(error))
        );
    }

    #[tokio::test]
    async fn connection_deadline_is_absolute_across_fragmented_input() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let server_cancellation = cancellation.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut service = StatusService::new(&config(Duration::from_secs(1))).unwrap();
            service.connection_timeout = Duration::from_millis(150);
            handle_connection(
                stream,
                Arc::new(service),
                server_cancellation,
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                Instant::now() + Duration::from_millis(150),
            )
            .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x80]).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        let _ = client.write_all(&[0x80]).await;
        let started = Instant::now();
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_millis(500), client.read(&mut byte))
            .await
            .expect("absolute Minecraft deadline was extended by partial reads");
        assert!(
            matches!(result, Ok(0)) || matches!(result, Err(ref error) if connection_ended(error))
        );
        assert!(started.elapsed() < Duration::from_millis(350));
        server.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn play_complete_frames_refresh_the_idle_deadline() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cancellation = CancellationToken::new();
        let idle_timeout = Duration::from_millis(100);
        let initial_deadline = Instant::now() + idle_timeout;
        client
            .write_all(&encode_frame(&[0]).unwrap())
            .await
            .unwrap();

        advance(Duration::from_millis(90)).await;
        let (first, refreshed_deadline) = read_connection_frame(
            &mut server,
            None,
            ConnectionState::Play,
            initial_deadline,
            idle_timeout,
            &cancellation,
        )
        .await;
        assert_eq!(first.unwrap(), Some(vec![0]));
        assert_eq!(refreshed_deadline, Instant::now() + idle_timeout);
        assert!(refreshed_deadline > initial_deadline);

        client
            .write_all(&encode_frame(&[1]).unwrap())
            .await
            .unwrap();
        advance(Duration::from_millis(90)).await;
        let (second, second_deadline) = read_connection_frame(
            &mut server,
            None,
            ConnectionState::Play,
            refreshed_deadline,
            idle_timeout,
            &cancellation,
        )
        .await;
        assert_eq!(second.unwrap(), Some(vec![1]));
        assert_eq!(second_deadline, Instant::now() + idle_timeout);

        let (idle_result, unchanged_deadline) = read_connection_frame(
            &mut server,
            None,
            ConnectionState::Play,
            second_deadline,
            idle_timeout,
            &cancellation,
        )
        .await;
        assert!(matches!(idle_result, Err(ProtocolError::TimedOut)));
        assert_eq!(unchanged_deadline, second_deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn complete_login_frames_do_not_extend_the_absolute_deadline() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let cancellation = CancellationToken::new();
        let initial_deadline = Instant::now() + Duration::from_millis(100);
        client
            .write_all(&encode_frame(&[0]).unwrap())
            .await
            .unwrap();
        advance(Duration::from_millis(90)).await;

        let (result, next_deadline) = read_connection_frame(
            &mut server,
            None,
            ConnectionState::Login,
            initial_deadline,
            Duration::from_millis(100),
            &cancellation,
        )
        .await;
        assert_eq!(result.unwrap(), Some(vec![0]));
        assert_eq!(next_deadline, initial_deadline);

        let (timed_out, unchanged_deadline) = read_connection_frame(
            &mut server,
            None,
            ConnectionState::Login,
            next_deadline,
            Duration::from_millis(100),
            &cancellation,
        )
        .await;
        assert!(matches!(timed_out, Err(ProtocolError::TimedOut)));
        assert_eq!(unchanged_deadline, initial_deadline);
    }

    #[test]
    fn outbound_poll_state_has_exact_fast_and_background_limits() {
        let mut fast_polls = 0;
        let mut background_polls = 0;
        for completed in 1..OUTBOUND_FAST_POLLS {
            assert_eq!(
                advance_outbound_poll(&mut fast_polls, &mut background_polls),
                OutboundPollTransition::ContinueFast,
                "fast poll {completed} changed phase early",
            );
        }
        assert_eq!(fast_polls, OUTBOUND_FAST_POLLS - 1);
        assert_eq!(
            advance_outbound_poll(&mut fast_polls, &mut background_polls),
            OutboundPollTransition::EnterBackground,
        );
        assert_eq!(fast_polls, OUTBOUND_FAST_POLLS);
        assert_eq!(background_polls, 0);

        for completed in 1..OUTBOUND_BACKGROUND_POLLS {
            assert_eq!(
                advance_outbound_poll(&mut fast_polls, &mut background_polls),
                OutboundPollTransition::ContinueBackground,
                "background poll {completed} stopped early",
            );
        }
        assert_eq!(background_polls, OUTBOUND_BACKGROUND_POLLS - 1);
        assert_eq!(
            advance_outbound_poll(&mut fast_polls, &mut background_polls),
            OutboundPollTransition::Exhausted,
        );
        assert_eq!(background_polls, OUTBOUND_BACKGROUND_POLLS);
    }

    #[tokio::test]
    async fn pending_outbound_drop_cancels_immediately_and_cancelled_step_stops() {
        let cancellation = CancellationToken::new();
        let observed = cancellation.clone();
        let pending_send = PendingOutboundSend {
            cancellation,
            sender: "qa@example.test".to_owned(),
            queue_id: Some(42),
            message_id: Some("message-id".to_owned()),
            fast_polls: 0,
            background_polls: 0,
            future: Box::pin(pending()),
        };
        assert!(!observed.is_cancelled());
        drop(pending_send);
        assert!(observed.is_cancelled());
        timeout(Duration::from_millis(50), observed.cancelled())
            .await
            .expect("outbound cancellation did not wake its waiter");

        let mut pending_send = PendingOutboundSend {
            cancellation: CancellationToken::new(),
            sender: "qa@example.test".to_owned(),
            queue_id: Some(42),
            message_id: Some("message-id".to_owned()),
            fast_polls: 7,
            background_polls: 11,
            future: Box::pin(pending()),
        };
        let service = StatusService::new(&config(Duration::from_secs(1))).unwrap();
        let mut draft = MinecraftDraft::default();
        let (packets, keep_pending) = outbound_step_packets(
            &service,
            &mut pending_send,
            OutboundStepResult::Cancelled,
            "player-uuid",
            &mut draft,
        )
        .unwrap();
        assert!(packets.is_empty());
        assert!(!keep_pending);
        assert_eq!(
            (pending_send.fast_polls, pending_send.background_polls),
            (7, 11)
        );
    }

    #[tokio::test]
    async fn disconnected_connection_owner_cancels_pending_outbound_and_drains() {
        let (client, mut server) = tokio::io::duplex(8);
        let cancellation = CancellationToken::new();
        let observed = cancellation.clone();
        let owner = tokio::spawn(async move {
            let _pending_send = PendingOutboundSend {
                cancellation,
                sender: "qa@example.test".to_owned(),
                queue_id: Some(42),
                message_id: Some("message-id".to_owned()),
                fast_polls: 0,
                background_polls: 0,
                future: Box::pin(pending()),
            };
            let mut byte = [0_u8; 1];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });
        drop(client);

        timeout(Duration::from_millis(100), owner)
            .await
            .expect("connection owner did not drain after peer disconnect")
            .unwrap();
        timeout(Duration::from_millis(100), observed.cancelled())
            .await
            .expect("pending outbound token survived its connection owner");
    }

    #[test]
    fn offline_uuid_matches_frozen_java_name_uuid() {
        assert_eq!(
            offline_uuid("BlackboxLogin").unwrap(),
            "fba9f5f2-955e-359f-ae31-9d00075473c2"
        );
        assert_eq!(
            offline_uuid("\u{fffd}").unwrap(),
            "7f21183c-0ff2-3465-9df0-9ca82956deb0"
        );
    }

    #[tokio::test]
    async fn offline_login_prefix_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let mut login_success = vec![0x02];
        write_string(&mut login_success, "fba9f5f2-955e-359f-ae31-9d00075473c2").unwrap();
        write_string(&mut login_success, "BlackboxLogin").unwrap();
        let login_frame =
            encode_packet_frame(&service, login_success, Some(256), deadline, &cancellation)
                .await
                .unwrap();
        assert_eq!(
            login_frame,
            STANDARD
                .decode("NQACJGZiYTlmNWYyLTk1NWUtMzU5Zi1hZTMxLTlkMDAwNzU0NzNjMg1CbGFja2JveExvZ2lu")
                .unwrap()
        );

        let expected = [
            "EwABAAAAAAIAABQHZGVmYXVsdAA=",
            "AwBBAA==",
            "CgAFAAAAAoAAAAA=",
            "CwA5BT1MzM09zMzN",
            "EgADAAAAAAAAAAD////////okA==",
            "CwAGQaAAABRAoAAA",
            "AwAJAA==",
        ];
        for (packet, frozen) in initial_play_packets(0, &config(Duration::from_secs(3)))
            .unwrap()
            .into_iter()
            .zip(expected)
        {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[tokio::test]
    async fn static_play_bootstrap_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let expected = [
            "KAA4AAGLpuWQOgE1I75xDynrcJc1D1N0YXRpY1BsYXlQcm9iZQACAAA=",
            "ewBHKHsidGV4dCI6IsKnNsKnbExNWVpNQUlMIiwiY29sb3IiOiJnb2xkIn1PeyJ0ZXh0Ijoiwqc3U2VuZCBlbWFpbHMgaW4gTWluZWNyYWZ0ISBTa2liaWRpIGRvcCBkb3AgeWVzIHllcyEiLCJjb2xvciI6ImdyYXkifQ==",
            "DwBFAgAAAAoAAAA8AAAAFA==",
            "GgBFABZ7InRleHQiOiLCpzZMTVlaTUFJTCJ9",
            "PwBFATt7InRleHQiOiLCpzdUeXBlIHlvdXIgZW1haWwgdG8gZ2V0IHN0YXJ0ZWQiLCJjb2xvciI6ImdyYXkifQ==",
            "UgACTnsidGV4dCI6IsKnZcKnbD09PSBXZWxjb21lIHRvIExNWVpNQUlMIE1pbmVjcmFmdCBTZXJ2ZXIgPT09IiwiY29sb3IiOiJ5ZWxsb3cifQA=",
            "RQACQXsidGV4dCI6IsKnN1NlbmQgZW1haWxzIGRpcmVjdGx5IGZyb20gTWluZWNyYWZ0ISIsImNvbG9yIjoiZ3JheSJ9AA==",
            "DwACC3sidGV4dCI6IiJ9AA==",
            "QgACPnsidGV4dCI6IsKnYVBsZWFzZSBlbnRlciB5b3VyIGVtYWlsIGFkZHJlc3M6IiwiY29sb3IiOiJncmVlbiJ9AA==",
            "HQAvAAAkAYIBAAAKAAAJAAVwYWdlcwgAAAABAAAA",
            "jAEALwAALAGPAQAACgAACgAHZGlzcGxheQgABE5hbWUAG8KnNsKnbE1lbnUgwqc3KFJpZ2h0IENsaWNrKQkABExvcmUIAAAAAQAVwqc3T3BlbiB0aGUgbWFpbiBtZW51AAkABGVuY2gKAAAAAQIAAmlkAAACAANsdmwAAQADAAlIaWRlRmxhZ3MAAAA/AA==",
        ];
        let packets =
            static_play_packets("8ba6e590-3a01-3523-be71-0f29eb709735", "StaticPlayProbe").unwrap();
        assert_eq!(packets.len(), expected.len());
        for (packet, frozen) in packets.into_iter().zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[tokio::test]
    async fn post_static_play_bootstrap_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let expected = [
            "QQAzAAAAgoQAAAMSeyJ0ZXh0IjoiwqcxW1RvXSJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9",
            "QQAzAAABAoQAAAMSeyJ0ZXh0IjoiwqcxW0NDXSJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9",
            "QgAzAAABgoQAAAMTeyJ0ZXh0IjoiwqcxW0JDQ10ifQt7InRleHQiOiIifQt7InRleHQiOiIifQt7InRleHQiOiIifQ==",
            "RgAzAAACAoQAAAMXeyJ0ZXh0IjoiwqcxW1N1YmplY3RdIn0LeyJ0ZXh0IjoiIn0LeyJ0ZXh0IjoiIn0LeyJ0ZXh0IjoiIn0=",
            "HQA7BGxteXoADsKnNsKnbExNWVpNQUlMBWR1bW15",
            "CAA9AQRsbXl6",
            "IAAPoPc2HgAAABAAABRgAAAAEAAAAAAAAAAAAAAgCgl/",
            "GAAcoPc2gg7CpzbCp2xMTVlaTUFJTAMBfw==",
            "IAAPofc2HgAAABAAABROAAAAEAAAAAAAAAAAAAAgCgl/",
            "KwAcofc2giHCpzdNaW5lY3JhZnQgU2tpYmlkaSBFbWFpbCBTZXJ2ZXIDAX8=",
            "IAAPovc2HgAAABAAABQ8AAAAEAAAAAAAAAAAAAAgCgl/",
            "NQAcovc2givCpzdieSDCp2VsbXl6enogdGhlIGdyZWF0IHNraWJpZGkgc2NpZW50aXN0AwF/",
            "IAAPo/c2HgAAABAAABQrAAAAEAAAAAAAAAAAAAAgCgl/",
            "CwAco/c2ggEgAwF/",
            "IAAPpPc2HgAAABAAABQZAAAAEAAAAAAAAAAAAAAgCgl/",
            "PAAcpPc2gjLCp2VIb2xkIMKnZk5ldGhlciBTdGFyIMKnZSsgUmlnaHQtY2xpY2sgLT4gwqdmTWVudQMBfw==",
            "IAAPpfc2HgAAABAAABQIAAAAEAAAAAAAAAAAAAAgCgl/",
            "NgAcpfc2gizCp2VXcml0ZSBpbiDCp2ZCb29rICYgUXVpbGwgwqdlLT4gRW1haWwgYm9keQMBfw==",
            "IAAPpvc2HgAAABAAABP2AAAAEAAAAAAAAAAAAAAgCgl/",
            "NwAcpvc2gi3Cp2VDbGljayDCp2ZTaWduIEJ1dHRvbnMgwqdlLT4gU2V0IFRvL1N1YmplY3QDAX8=",
        ];
        let packets = post_static_play_packets(900_000).unwrap();
        assert_eq!(packets.len(), expected.len());
        for (packet, frozen) in packets.into_iter().zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[test]
    fn scheduled_play_packets_match_protocol_fields() {
        let time_update = time_update_packet();
        let mut expected_time_update = vec![0x03];
        expected_time_update.extend_from_slice(&0_i64.to_be_bytes());
        expected_time_update.extend_from_slice(&(-6000_i64).to_be_bytes());
        assert_eq!(time_update, expected_time_update);

        let packets = hologram_teleport_packets(900_000);
        assert_eq!(packets.len(), 7);
        for (index, packet) in packets.into_iter().enumerate() {
            let mut expected = vec![0x18];
            write_varint(&mut expected, 900_000 + index as u32);
            expected.extend_from_slice(&16_i32.to_be_bytes());
            expected
                .extend_from_slice(&(((163.0 - index as f64 * 0.55) * 32.0) as i32).to_be_bytes());
            expected.extend_from_slice(&16_i32.to_be_bytes());
            expected.extend_from_slice(&[0, 0, 0]);
            assert_eq!(packet, expected);
        }

        let mut configured = config(Duration::from_secs(3));
        configured.spawn.x = -12.75;
        configured.spawn.y = 70.9;
        configured.spawn.z = 34.5;
        configured.spawn.yaw = 45.0;
        configured.spawn.pitch = -15.0;
        let packets = teleport_back_packets(&configured).unwrap();
        assert_eq!(packets.len(), 2);
        let mut expected_position = vec![0x08];
        expected_position.extend_from_slice(&configured.spawn.x.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.y.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.z.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.yaw.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.pitch.to_be_bytes());
        expected_position.push(0);
        assert_eq!(packets[0], expected_position);

        let mut expected_chat = vec![0x02];
        write_string(
            &mut expected_chat,
            &chat_json("\u{00a7}cYou were teleported back to spawn!", Some("red")),
        )
        .unwrap();
        expected_chat.push(0);
        assert_eq!(packets[1], expected_chat);
    }

    #[test]
    fn player_position_parser_rejects_truncated_packets() {
        let mut position = Vec::new();
        position.extend_from_slice(&1.0_f64.to_be_bytes());
        position.extend_from_slice(&2.0_f64.to_be_bytes());
        position.extend_from_slice(&3.0_f64.to_be_bytes());
        position.push(1);
        assert_eq!(
            read_player_position(&mut PacketReader::new(&position), 0x04).unwrap(),
            (1.0, 2.0, 3.0)
        );
        assert!(
            read_player_position(
                &mut PacketReader::new(&position[..position.len() - 1]),
                0x04
            )
            .is_err()
        );

        let mut position_and_look = position;
        position_and_look.pop();
        position_and_look.extend_from_slice(&45.0_f32.to_be_bytes());
        position_and_look.extend_from_slice(&(-15.0_f32).to_be_bytes());
        position_and_look.push(0);
        assert_eq!(
            read_player_position(&mut PacketReader::new(&position_and_look), 0x06).unwrap(),
            (1.0, 2.0, 3.0)
        );
        assert!(
            read_player_position(
                &mut PacketReader::new(&position_and_look[..position_and_look.len() - 1]),
                0x06
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn awaiting_email_prompts_match_frozen_java_frames_and_trim_rules() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let (email, invalid) = awaiting_email_responses("not-an-email").unwrap();
        assert_eq!(email, None);
        let (email, valid) = awaiting_email_responses("  qa@example.test  ").unwrap();
        assert_eq!(email.as_deref(), Some("qa@example.test"));

        let expected = [
            "RwACQ3sidGV4dCI6IsKnY0ludmFsaWQgZW1haWwgZm9ybWF0LiBQbGVhc2UgdHJ5IGFnYWluOiIsImNvbG9yIjoicmVkIn0A",
            "KwACJ3sidGV4dCI6IsKnYUVtYWlsOiDCp2ZxYUBleGFtcGxlLnRlc3QifQA=",
            "PQACOXsidGV4dCI6IsKnYVBsZWFzZSBlbnRlciB5b3VyIHBhc3N3b3JkOiIsImNvbG9yIjoiZ3JlZW4ifQA=",
            "RAACQHsidGV4dCI6IsKnNyhZb3VyIHBhc3N3b3JkIHdpbGwgbm90IGJlIHZpc2libGUpIiwiY29sb3IiOiJncmF5In0A",
        ];
        for (packet, frozen) in invalid.into_iter().chain(valid).zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }

        assert_eq!(awaiting_email_responses("\t \r\n").unwrap().0, None);
        assert_eq!(
            awaiting_email_responses("\u{00a0}qa@example.test\u{00a0}")
                .unwrap()
                .0
                .as_deref(),
            Some("\u{00a0}qa@example.test\u{00a0}")
        );

        let mut overlong = Vec::new();
        write_varint(&mut overlong, 101);
        overlong.extend_from_slice(&[b'x'; 101]);
        assert!(PacketReader::new(&overlong).read_string(100).is_err());

        let supplementary = "\u{1f600}".repeat(51);
        let mut supplementary_packet = Vec::new();
        write_string(&mut supplementary_packet, &supplementary).unwrap();
        assert!(
            PacketReader::new(&supplementary_packet)
                .read_string(100)
                .is_err()
        );
    }

    #[test]
    fn static_play_uuid_and_json_inputs_are_strict_and_escaped() {
        assert_eq!(
            parse_uuid_bytes("01234567-89AB-cdef-0123-456789abcdef"),
            Some([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])
        );
        assert!(parse_uuid_bytes("01234567-89ab-cdef-0123-456789abcdeg").is_none());
        assert!(parse_uuid_bytes("0123456789abcdef0123456789abcde").is_none());
        assert_eq!(
            chat_json("quote=\" slash=\\", Some("gray")),
            r#"{"text":"quote=\" slash=\\","color":"gray"}"#
        );
        assert!(static_play_packets("not-a-uuid", "Player").is_err());
    }

    #[test]
    fn hologram_entity_ids_are_reserved_per_process() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        assert_eq!(service.reserve_hologram_entity_ids(7), 900_000);
        assert_eq!(service.reserve_hologram_entity_ids(7), 900_007);
    }

    #[tokio::test]
    async fn compression_envelope_is_exact_and_bounded() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let packet = vec![0x5a; 256];
        let compressed = compress_packet(packet.clone(), &cancellation, deadline).unwrap();
        let mut envelope = Vec::new();
        write_varint(&mut envelope, packet.len() as u32);
        envelope.extend_from_slice(&compressed);
        assert_eq!(
            decode_compression_envelope(&service, envelope.clone(), 256, deadline, &cancellation,)
                .await
                .unwrap(),
            packet
        );

        envelope.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, envelope, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut uncompressed_at_threshold = vec![0];
        uncompressed_at_threshold.extend_from_slice(&vec![0x5a; 256]);
        assert!(matches!(
            decode_compression_envelope(
                &service,
                uncompressed_at_threshold,
                256,
                deadline,
                &cancellation,
            )
            .await,
            Err(ProtocolError::Malformed)
        ));

        let mut oversized = Vec::new();
        write_varint(&mut oversized, MAX_FRAME_LENGTH as u32 + 1);
        oversized.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, oversized, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut negative = Vec::new();
        write_varint(&mut negative, u32::MAX);
        negative.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, negative, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let short_packet = vec![0x5a; 128];
        let short_compressed = compress_packet(short_packet, &cancellation, deadline).unwrap();
        let mut below_threshold = Vec::new();
        write_varint(&mut below_threshold, 128);
        below_threshold.extend_from_slice(&short_compressed);
        assert!(matches!(
            decode_compression_envelope(&service, below_threshold, 256, deadline, &cancellation,)
                .await,
            Err(ProtocolError::Malformed)
        ));

        let mut truncated = Vec::new();
        write_varint(&mut truncated, 256);
        truncated.extend_from_slice(&compressed[..compressed.len() - 1]);
        assert!(matches!(
            decode_compression_envelope(&service, truncated, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut mismatched = Vec::new();
        write_varint(&mut mismatched, 257);
        mismatched.extend_from_slice(&compressed);
        assert!(matches!(
            decode_compression_envelope(&service, mismatched, 1, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));
    }

    #[test]
    fn compression_workers_observe_cancellation_and_deadline() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            compress_packet(
                vec![0; COMPRESSION_CHUNK_BYTES * 2],
                &cancellation,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ProtocolError::Cancelled)
        ));
        let active = CancellationToken::new();
        assert!(matches!(
            compress_packet(vec![0; 1], &active, Instant::now()),
            Err(ProtocolError::TimedOut)
        ));
    }

    #[test]
    fn configured_spawn_position_uses_java_integer_cast_and_wire_packing() {
        let mut configured = config(Duration::from_secs(3));
        configured.spawn.x = -12.75;
        configured.spawn.y = 70.9;
        configured.spawn.z = 34.5;
        let packets = initial_play_packets(1, &configured).unwrap();
        let expected_packed = ((i64::from(-12_i32) & 0x3ff_ffff) << 38)
            | ((i64::from(70_i32) & 0xfff) << 26)
            | (i64::from(34_i32) & 0x3ff_ffff);
        let mut expected = vec![0x05];
        expected.extend_from_slice(&expected_packed.to_be_bytes());
        assert_eq!(packets[2], expected);
    }

    #[test]
    fn map_video_parser_clamps_the_frozen_command_and_rejects_unknown_options() {
        let configured = config(Duration::from_secs(3));
        let ParsedVideoCommand::StartMap(params) = parse_video_command(
            "/video play map width=1 fps=0 dither=99 contrast=9",
            &configured,
        ) else {
            panic!("expected map video parameters");
        };
        assert_eq!(params.maps_x, 2);
        assert_eq!(params.fps, 1);
        assert_eq!(params.dither, 1);
        assert_eq!(params.contrast, 3.0);

        assert!(matches!(
            parse_video_command("/video play map nope=1", &configured),
            ParsedVideoCommand::Error(error) if error == "Unknown option: nope"
        ));
    }

    #[test]
    fn block_video_parser_preserves_auto_height_and_frozen_clamps() {
        let configured = config(Duration::from_secs(3));
        let ParsedVideoCommand::StartBlock(params) =
            parse_video_command("/video play width=1 fps=0 contrast=9", &configured)
        else {
            panic!("expected block video parameters");
        };
        assert_eq!(params.width, 4);
        assert_eq!(params.height, 2);
        assert_eq!(params.fps, 1);
        assert_eq!(params.contrast, 3.0);

        assert!(matches!(
            parse_video_command("/video play nope=1", &configured),
            ParsedVideoCommand::Error(error) if error == "Unknown option: nope"
        ));
    }

    #[test]
    fn block_video_wall_resends_dirty_sections_and_restores_touched_chunks() {
        let mut configured = config(Duration::from_secs(3));
        configured.spawn.x = 0.5;
        configured.spawn.y = 160.0;
        configured.spawn.z = 0.5;
        configured.video.center_x = 0;
        configured.video.center_y = 161;
        configured.video.wall_z = -3;
        configured.video.clear_margin = 2;
        configured.video.spawn_protect_radius = 1;
        let service = StatusService::new(&configured).unwrap();
        let wall = BlockVideoWall::new(
            &service,
            BlockVideoParams {
                width: 4,
                height: 2,
                fps: 1,
                contrast: 1.2,
            },
        )
        .unwrap();
        let setup = wall.setup_packets().unwrap();
        assert!(!setup.is_empty());
        assert!(setup.iter().all(|packet| packet[0] == 0x21));

        let mut previous = None;
        let mut frame = vec![16_u16; 8];
        let first = wall.frame_packets(&frame, &mut previous).unwrap();
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|packet| packet[0] == 0x21));
        assert!(
            wall.frame_packets(&frame, &mut previous)
                .unwrap()
                .is_empty()
        );
        frame[0] = 2768;
        assert_eq!(wall.frame_packets(&frame, &mut previous).unwrap().len(), 1);

        let restored = wall.teardown_packets().unwrap();
        assert!(restored.iter().any(|packet| packet[0] == 0x21));
        assert_eq!(restored.last().unwrap()[0], 0x02);
    }

    #[test]
    fn video_menu_back_preserves_current_render_settings() {
        let configured = config(Duration::from_secs(3));
        let settings = RenderSettings {
            maps_x: 17,
            maps_y: 9,
            font_size: 31,
        };
        let (packets, effect) = video_menu_click_packets(
            WindowClick {
                window_id: 7,
                slot: 22,
                action_number: 3,
                mode: 0,
            },
            Some(8),
            settings,
            &configured,
        )
        .unwrap();
        assert_eq!(effect, VideoMenuEffect::Back(8));
        assert_eq!(packets[3], vec![0x2e, 7]);
        assert_eq!(packets[4..], main_menu_packets(8, settings).unwrap());
    }

    #[test]
    fn map_video_delta_packets_skip_identical_tiles_and_bound_the_rectangle() {
        let wall = MapWall {
            maps_x: 1,
            maps_y: 1,
            facing: MapWallFacing::South,
            center_x: 0,
            center_y: 0,
            center_z: 0,
            map_ids: vec![10].into_boxed_slice(),
            entity_ids: vec![20].into_boxed_slice(),
            saved_blocks: Vec::new(),
        };
        let mut previous = None;
        let mut frame = vec![34_u8; MAP_TILE_PIXELS];
        let first = video_frame_packets(&wall, &frame, &mut previous).unwrap();
        assert_eq!(first.len(), 1);
        assert!(
            video_frame_packets(&wall, &frame, &mut previous)
                .unwrap()
                .is_empty()
        );

        frame[65 * 128 + 17] = 42;
        let changed = video_frame_packets(&wall, &frame, &mut previous).unwrap();
        assert_eq!(changed, vec![vec![0x34, 10, 0, 0, 1, 1, 17, 65, 1, 42]]);
    }

    #[test]
    fn outbound_addresses_match_java_comma_semicolon_trim_and_empty_filtering() {
        assert_eq!(
            parse_outbound_addresses(" a@example.test, ; b@example.test;; c@example.test "),
            vec![
                "a@example.test".to_owned(),
                "b@example.test".to_owned(),
                "c@example.test".to_owned(),
            ]
        );
        assert!(parse_outbound_addresses(" , ; \t").is_empty());
    }

    #[test]
    fn outbound_body_joins_pages_and_appends_the_frozen_footer_once() {
        let draft = MinecraftDraft {
            body_pages: vec!["first".to_owned(), "second".to_owned()],
            ..MinecraftDraft::default()
        };
        assert_eq!(
            minecraft_outbound_body(&draft),
            "first\nsecond\n\n\n\n\n\n\n\n--- Sent with lmyzmail from Minecraft 1.8.9 ---"
        );
    }

    proptest! {
        #[test]
        fn packet_reader_never_panics_on_arbitrary_frames(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut packet = PacketReader::new(&bytes);
            let _ = packet.read_varint();
            let _ = packet.read_string(255);
            let _ = packet.read_u16();
            let _ = packet.read_i64();
            prop_assert!(packet.cursor <= bytes.len());

            let mut click = PacketReader::new(&bytes);
            let _ = read_window_click(&mut click);
            prop_assert!(click.cursor <= bytes.len());

            let mut sign = PacketReader::new(&bytes);
            let _ = read_update_sign(&mut sign);
            prop_assert!(sign.cursor <= bytes.len());
        }
    }
}
