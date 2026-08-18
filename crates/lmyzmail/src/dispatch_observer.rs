use std::{
    env,
    fmt::Write as _,
    os::raw::{c_int, c_void},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::mail_render::{RenderBackend, host_simd_capabilities};

const SCHEMA: &str = "lmyzmail.renderer-dispatch-observation.v1";
const FD_ENV: &str = "LMYZMAIL_RENDER_OBSERVER_FD";
const BINARY_FD_ENV: &str = "LMYZMAIL_RENDER_OBSERVER_BINARY_FD";
const SESSION_ENV: &str = "LMYZMAIL_RENDER_OBSERVER_SESSION";
const SOURCE_ENV: &str = "LMYZMAIL_RENDER_OBSERVER_SOURCE_SHA256";
const BUILD_ENV: &str = "LMYZMAIL_RENDER_OBSERVER_BUILD_SHA256";
const MAX_EVENT_BYTES: usize = 1024;

#[cfg(target_os = "linux")]
const F_GETFD: c_int = 1;
#[cfg(target_os = "linux")]
const F_SETFD: c_int = 2;
#[cfg(target_os = "linux")]
const F_GETFL: c_int = 3;
#[cfg(target_os = "linux")]
const F_SETFL: c_int = 4;
#[cfg(target_os = "linux")]
const FD_CLOEXEC: c_int = 1;
#[cfg(target_os = "linux")]
const O_NONBLOCK: c_int = 0o4000;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn fcntl(fd: c_int, operation: c_int, ...) -> c_int;
    fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchComponent {
    MailRenderResize,
    MailRenderContrast,
    MailRenderMapPalette,
    MinecraftMapPalette,
    MinecraftBlockPaletteRgb,
    MinecraftBlockPaletteStates,
}

impl DispatchComponent {
    const fn bit(self) -> u64 {
        match self {
            Self::MailRenderResize => 1 << 0,
            Self::MailRenderContrast => 1 << 1,
            Self::MailRenderMapPalette => 1 << 2,
            Self::MinecraftMapPalette => 1 << 3,
            Self::MinecraftBlockPaletteRgb => 1 << 4,
            Self::MinecraftBlockPaletteStates => 1 << 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::MailRenderResize => "mail_render.resize_rgb24_box",
            Self::MailRenderContrast => "mail_render.apply_rgb24_contrast",
            Self::MailRenderMapPalette => "mail_render.map_palette",
            Self::MinecraftMapPalette => "minecraft.map_palette",
            Self::MinecraftBlockPaletteRgb => "minecraft.block_palette_rgb",
            Self::MinecraftBlockPaletteStates => "minecraft.block_palette_states",
        }
    }
}

struct Observer {
    descriptor: c_int,
    session: Box<str>,
    source_sha256: Box<str>,
    build_sha256: Box<str>,
    seen: AtomicU64,
    sequence: AtomicU64,
}

static OBSERVER: OnceLock<Option<Observer>> = OnceLock::new();

/// Initializes the dormant-by-default benchmark observer before any service or
/// helper process can be started. The only accepted sink is an inherited file
/// descriptor capability; paths are deliberately unsupported.
#[doc(hidden)]
pub fn initialize() {
    let _ = observer();
}

pub(crate) fn observe(
    component: DispatchComponent,
    requested: RenderBackend,
    resolved: RenderBackend,
) {
    let Some(observer) = observer() else {
        return;
    };
    if observer.seen.fetch_or(component.bit(), Ordering::AcqRel) & component.bit() != 0 {
        return;
    }
    let sequence = observer.sequence.fetch_add(1, Ordering::AcqRel) + 1;
    let capabilities = host_simd_capabilities();
    let requested_mode = match requested {
        RenderBackend::Scalar => "SCALAR",
        RenderBackend::Avx2Fma => "AVX2",
        RenderBackend::Avx512 => "AVX512",
    };
    let mut event = String::with_capacity(512);
    write!(
        event,
        concat!(
            "{{\"schema\":\"{}\",\"sequence\":{},\"component\":\"{}\",",
            "\"requested_mode\":\"{}\",\"requested_backend\":\"{}\",",
            "\"resolved_backend\":\"{}\",",
            "\"host_capabilities\":{{\"avx2\":{},\"fma\":{},\"avx512f\":{}}},",
            "\"source_sha256\":\"{}\",\"build_sha256\":\"{}\",\"session\":\"{}\"}}\n"
        ),
        SCHEMA,
        sequence,
        component.name(),
        requested_mode,
        requested.name(),
        resolved.name(),
        capabilities.avx2,
        capabilities.fma,
        capabilities.avx512f,
        observer.source_sha256,
        observer.build_sha256,
        observer.session,
    )
    .expect("writing a bounded dispatch event to String cannot fail");
    if event.len() > MAX_EVENT_BYTES {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let _write_completed = write_event(observer.descriptor, event.as_bytes());
        // The formal harness requires the exact component set and sequence, so
        // a dropped or partial event fails closed without blocking production.
    }
}

#[cfg(target_os = "linux")]
fn write_event(descriptor: c_int, event: &[u8]) -> bool {
    // SAFETY: initialization validated that this inherited descriptor was open
    // and made it nonblocking. `event` stays alive for the syscall.
    (unsafe { write(descriptor, event.as_ptr().cast(), event.len()) }) == event.len() as isize
}

fn observer() -> Option<&'static Observer> {
    OBSERVER.get_or_init(Observer::from_environment).as_ref()
}

impl Observer {
    #[cfg(target_os = "linux")]
    fn from_environment() -> Option<Self> {
        let descriptor = parse_descriptor(FD_ENV)?;
        let binary_descriptor = parse_descriptor(BINARY_FD_ENV)?;
        let session = parse_hex_identity(SESSION_ENV)?;
        let source_sha256 = parse_hex_identity(SOURCE_ENV)?;
        let build_sha256 = parse_hex_identity(BUILD_ENV)?;
        set_close_on_exec(descriptor)?;
        set_close_on_exec(binary_descriptor)?;
        set_nonblocking(descriptor)?;
        Some(Self {
            descriptor,
            session,
            source_sha256,
            build_sha256,
            seen: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn from_environment() -> Option<Self> {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_descriptor(name: &str) -> Option<c_int> {
    let value = env::var(name).ok()?.parse::<c_int>().ok()?;
    (value >= 3).then_some(value)
}

#[cfg(target_os = "linux")]
fn parse_hex_identity(name: &str) -> Option<Box<str>> {
    let value = env::var(name).ok()?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase().into_boxed_str())
}

#[cfg(target_os = "linux")]
fn set_close_on_exec(descriptor: c_int) -> Option<()> {
    // SAFETY: `fcntl` receives no pointer arguments. A negative return is
    // handled as observer initialization failure.
    let flags = unsafe { fcntl(descriptor, F_GETFD) };
    if flags < 0 {
        return None;
    }
    // SAFETY: same descriptor validity and integer-only ABI as above.
    (unsafe { fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) } >= 0).then_some(())
}

#[cfg(target_os = "linux")]
fn set_nonblocking(descriptor: c_int) -> Option<()> {
    // SAFETY: `fcntl` receives no pointer arguments and errors fail closed.
    let flags = unsafe { fcntl(descriptor, F_GETFL) };
    if flags < 0 {
        return None;
    }
    // SAFETY: same descriptor validity and integer-only ABI as above.
    (unsafe { fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) } >= 0).then_some(())
}

#[cfg(test)]
mod tests {
    use std::os::raw::c_int;

    use super::{DispatchComponent, O_NONBLOCK, write, write_event};

    const O_CLOEXEC: c_int = 0o2000000;

    unsafe extern "C" {
        fn pipe2(descriptors: *mut c_int, flags: c_int) -> c_int;
        fn close(descriptor: c_int) -> c_int;
    }

    #[test]
    fn component_names_and_bits_are_unique() {
        let components = [
            DispatchComponent::MailRenderResize,
            DispatchComponent::MailRenderContrast,
            DispatchComponent::MailRenderMapPalette,
            DispatchComponent::MinecraftMapPalette,
            DispatchComponent::MinecraftBlockPaletteRgb,
            DispatchComponent::MinecraftBlockPaletteStates,
        ];
        let mut bits = 0_u64;
        let mut names = std::collections::HashSet::new();
        for component in components {
            assert_eq!(bits & component.bit(), 0);
            bits |= component.bit();
            assert!(names.insert(component.name()));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observer_is_dormant_without_inherited_capability() {
        for name in [
            super::FD_ENV,
            super::BINARY_FD_ENV,
            super::SESSION_ENV,
            super::SOURCE_ENV,
            super::BUILD_ENV,
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "test environment unexpectedly set {name}"
            );
        }
        assert!(super::observer().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_nonblocking_pipe_fails_without_waiting() {
        let mut descriptors = [-1; 2];
        // SAFETY: `descriptors` contains space for both returned integers.
        assert_eq!(
            unsafe { pipe2(descriptors.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC) },
            0
        );
        let block = [0_u8; 4096];
        loop {
            // SAFETY: the write descriptor is live and `block` is readable.
            let written = unsafe { write(descriptors[1], block.as_ptr().cast(), block.len()) };
            if written < 0 {
                break;
            }
            assert_eq!(written, block.len() as isize);
        }
        assert!(!write_event(descriptors[1], b"bounded\n"));
        // SAFETY: both descriptors are still live and owned by this test.
        unsafe {
            close(descriptors[0]);
            close(descriptors[1]);
        }
    }
}
