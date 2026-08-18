use std::{
    ffi::{CStr, c_char, c_int, c_void},
    fmt,
    ptr::NonNull,
    sync::{Mutex, MutexGuard, OnceLock},
};

use getrandom::fill as fill_random;

const EXPRESSION_CAPACITY: usize = 64;
const MIN_EXPRESSION_LENGTH: usize = 18;
const MAX_EXPRESSION_LENGTH: usize = 43;
const BATCH_RECORD_CAPACITY: usize = 44;
const MAX_BATCH_EXPRESSIONS: usize = 4096;
const EXPECTED_VERSION: &str = "1.8.0-skibidi-ultra";
const EXPECTED_RNG_STATE_SIZE: usize = 128;
const EXPECTED_CONTEXT_SIZE: usize = 192;
const EXPECTED_CONTEXT_ALIGNMENT: usize = 64;

const SKIBIDI_OK: c_int = 0;
const SKIBIDI_ERR_NULL_PTR: c_int = -1;
const SKIBIDI_ERR_BUFFER_TOO_SMALL: c_int = -2;
const SKIBIDI_ERR_INVALID_CONFIG: c_int = -3;

type NativeContext = c_void;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeConfig {
    enable_avx512: c_int,
    enable_simd_rng: c_int,
    reserved: [c_int; 6],
}

const _: () = {
    assert!(std::mem::size_of::<NativeConfig>() == 32);
    assert!(std::mem::align_of::<NativeConfig>() == std::mem::align_of::<c_int>());
};

macro_rules! native_variant {
    ($module:ident, $library:literal, $prefix:literal) => {
        #[allow(dead_code)]
        mod $module {
            use super::{NativeConfig, NativeContext, c_char, c_int};

            #[link(name = $library, kind = "static")]
            // SAFETY: declarations exactly mirror the frozen 1.8.0 header.
            // Callers must first pass this object's ISA gate and then uphold
            // every pointer, size, and allocation-ownership contract.
            unsafe extern "C" {
                #[link_name = concat!($prefix, "_init")]
                pub(super) fn init(context: *mut NativeContext, seed: u64) -> c_int;
                #[link_name = concat!($prefix, "_configure")]
                pub(super) fn configure(config: *const NativeConfig) -> c_int;
                #[link_name = concat!($prefix, "_get_config")]
                pub(super) fn get_config(config: *mut NativeConfig) -> c_int;
                #[link_name = concat!($prefix, "_generate")]
                pub(super) fn generate(
                    context: *mut NativeContext,
                    buffer: *mut c_char,
                    buffer_size: usize,
                ) -> c_int;
                #[link_name = concat!($prefix, "_generate_variant")]
                pub(super) fn generate_variant(
                    context: *mut NativeContext,
                    buffer: *mut c_char,
                    buffer_size: usize,
                ) -> c_int;
                #[link_name = concat!($prefix, "_generate_batch")]
                pub(super) fn generate_batch(
                    context: *mut NativeContext,
                    buffer: *mut c_char,
                    buffer_size: usize,
                    count: c_int,
                    lengths: *mut c_int,
                ) -> c_int;
                #[link_name = concat!($prefix, "_destroy")]
                pub(super) fn destroy(context: *mut NativeContext);
                #[link_name = concat!($prefix, "_alloc_context")]
                pub(super) fn alloc_context() -> *mut NativeContext;
                #[link_name = concat!($prefix, "_alloc_context_array")]
                pub(super) fn alloc_context_array(count: usize) -> *mut NativeContext;
                #[link_name = concat!($prefix, "_free_context")]
                pub(super) fn free_context(context: *mut NativeContext);
                #[link_name = concat!($prefix, "_version")]
                pub(super) fn version() -> *const c_char;
                #[link_name = concat!($prefix, "_has_avx2")]
                pub(super) fn has_avx2() -> c_int;
                #[link_name = concat!($prefix, "_has_avx512")]
                pub(super) fn has_avx512() -> c_int;
                #[link_name = concat!($prefix, "_get_capabilities")]
                pub(super) fn get_capabilities() -> u32;
                #[link_name = concat!($prefix, "_get_active_simd")]
                pub(super) fn get_active_simd() -> *const c_char;
                #[link_name = concat!($prefix, "_is_avx512_enabled")]
                pub(super) fn is_avx512_enabled() -> c_int;
                #[link_name = concat!($prefix, "_get_rng_state_size")]
                pub(super) fn get_rng_state_size() -> usize;
                #[link_name = concat!($prefix, "_get_context_size")]
                pub(super) fn get_context_size() -> usize;
                #[link_name = concat!($prefix, "_get_context_alignment")]
                pub(super) fn get_context_alignment() -> usize;
            }
        }
    };
}

native_variant!(
    scalar_native,
    "lmyzmail_skibidi_scalar",
    "lmyzmail_skibidi_scalar"
);
native_variant!(
    avx2_native,
    "lmyzmail_skibidi_avx2",
    "lmyzmail_skibidi_avx2"
);
native_variant!(
    avx512_native,
    "lmyzmail_skibidi_avx512",
    "lmyzmail_skibidi_avx512"
);

// SAFETY invariant for every function pointer: selection keeps it paired with
// one object, calls happen only behind that object's ISA/configuration guard,
// and memory allocated by one variant is never passed to another.
#[cfg_attr(not(test), allow(dead_code))]
struct NativeApi {
    init: unsafe extern "C" fn(*mut NativeContext, u64) -> c_int,
    configure: unsafe extern "C" fn(*const NativeConfig) -> c_int,
    get_config: unsafe extern "C" fn(*mut NativeConfig) -> c_int,
    generate: unsafe extern "C" fn(*mut NativeContext, *mut c_char, usize) -> c_int,
    generate_variant: unsafe extern "C" fn(*mut NativeContext, *mut c_char, usize) -> c_int,
    generate_batch:
        unsafe extern "C" fn(*mut NativeContext, *mut c_char, usize, c_int, *mut c_int) -> c_int,
    destroy: unsafe extern "C" fn(*mut NativeContext),
    alloc_context: unsafe extern "C" fn() -> *mut NativeContext,
    alloc_context_array: unsafe extern "C" fn(usize) -> *mut NativeContext,
    free_context: unsafe extern "C" fn(*mut NativeContext),
    version: unsafe extern "C" fn() -> *const c_char,
    has_avx2: unsafe extern "C" fn() -> c_int,
    has_avx512: unsafe extern "C" fn() -> c_int,
    get_capabilities: unsafe extern "C" fn() -> u32,
    get_active_simd: unsafe extern "C" fn() -> *const c_char,
    is_avx512_enabled: unsafe extern "C" fn() -> c_int,
    get_rng_state_size: unsafe extern "C" fn() -> usize,
    get_context_size: unsafe extern "C" fn() -> usize,
    get_context_alignment: unsafe extern "C" fn() -> usize,
}

macro_rules! native_api {
    ($module:ident) => {
        NativeApi {
            init: $module::init,
            configure: $module::configure,
            get_config: $module::get_config,
            generate: $module::generate,
            generate_variant: $module::generate_variant,
            generate_batch: $module::generate_batch,
            destroy: $module::destroy,
            alloc_context: $module::alloc_context,
            alloc_context_array: $module::alloc_context_array,
            free_context: $module::free_context,
            version: $module::version,
            has_avx2: $module::has_avx2,
            has_avx512: $module::has_avx512,
            get_capabilities: $module::get_capabilities,
            get_active_simd: $module::get_active_simd,
            is_avx512_enabled: $module::is_avx512_enabled,
            get_rng_state_size: $module::get_rng_state_size,
            get_context_size: $module::get_context_size,
            get_context_alignment: $module::get_context_alignment,
        }
    };
}

static SCALAR_API: NativeApi = native_api!(scalar_native);
static AVX2_API: NativeApi = native_api!(avx2_native);
static AVX512_API: NativeApi = native_api!(avx512_native);

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
            Self::Avx2 => avx2_supported(),
            Self::Avx512 => avx512_supported(),
        }
    }

    fn api(self) -> &'static NativeApi {
        match self {
            Self::Scalar => &SCALAR_API,
            Self::Avx2 => &AVX2_API,
            Self::Avx512 => &AVX512_API,
        }
    }

    fn lock(self) -> MutexGuard<'static, ()> {
        static SCALAR_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        static AVX2_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        static AVX512_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = match self {
            Self::Scalar => SCALAR_LOCK.get_or_init(|| Mutex::new(())),
            Self::Avx2 => AVX2_LOCK.get_or_init(|| Mutex::new(())),
            Self::Avx512 => AVX512_LOCK.get_or_init(|| Mutex::new(())),
        };
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            // JAVA is a legacy configuration alias for the frozen C scalar object.
            "JAVA" | "SCALAR" => SkibidiBackend::Scalar,
            "AVX2" => require_backend(SkibidiBackend::Avx2)?,
            "AVX512" | "AVX-512" => {
                if !enable_avx512 {
                    return Err(SkibidiError::InvalidMode(
                        "AVX-512 mode requires skibidi-generator-enable-avx512=true".into(),
                    ));
                }
                require_backend(SkibidiBackend::Avx512)?
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
        generator.runtime_info()?;
        generator.validate_batch_smoke()?;
        Ok(generator)
    }

    fn with_native<T>(
        self,
        operation: impl FnOnce(&'static NativeApi) -> Result<T, SkibidiError>,
    ) -> Result<T, SkibidiError> {
        if !self.backend.is_supported() {
            return Err(SkibidiError::UnsupportedBackend(self.backend.name()));
        }

        // The frozen C configuration is global per compiled object. Holding this
        // backend-specific lock across configuration and the complete context
        // lifetime makes conflicting service configurations deterministic.
        let _guard = self.backend.lock();
        let api = self.backend.api();
        let expected = NativeConfig {
            enable_avx512: if self.backend == SkibidiBackend::Avx512 && self.enable_avx512 {
                1
            } else {
                0
            },
            enable_simd_rng: if self.enable_simd_rng { 1 } else { 0 },
            reserved: [0; 6],
        };
        // SAFETY: the CPU/OS gate above runs before every entry into an AVX
        // object, and both pointers refer to initialized repr(C) values.
        unsafe {
            expect_ok("skibidi_configure", (api.configure)(&expected))?;
            let mut observed = NativeConfig::default();
            expect_ok("skibidi_get_config", (api.get_config)(&mut observed))?;
            if observed.enable_avx512 != expected.enable_avx512
                || observed.enable_simd_rng != expected.enable_simd_rng
            {
                return Err(SkibidiError::InvalidOutput(format!(
                    "native configuration mismatch: expected avx512={} simd_rng={}, got avx512={} simd_rng={}",
                    expected.enable_avx512,
                    expected.enable_simd_rng,
                    observed.enable_avx512,
                    observed.enable_simd_rng
                )));
            }
        }
        operation(api)
    }

    fn validate_batch_smoke(self) -> Result<(), SkibidiError> {
        let output = self.generate_batch_seeded(1, 1)?;
        if output.lengths.len() != 1 || output.bytes.is_empty() {
            return Err(SkibidiError::InvalidOutput(
                "native Skibidi batch startup probe returned no expression".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn runtime_info(self) -> Result<SkibidiRuntimeInfo, SkibidiError> {
        self.with_native(|api| {
            validate_native_abi(api)?;
            // SAFETY: with_native gated the selected object and still holds its
            // configuration lock. String calls return process-lifetime static
            // C strings; capability and state calls take no pointers.
            let (version, active_simd, native_capabilities, native_has_avx2, native_has_avx512, avx512_enabled) =
                unsafe {
                    (
                        native_string("skibidi_version", (api.version)())?,
                        native_string("skibidi_get_active_simd", (api.get_active_simd)())?,
                        (api.get_capabilities)(),
                        (api.has_avx2)() != 0,
                        (api.has_avx512)() != 0,
                        (api.is_avx512_enabled)() != 0,
                    )
                };
            if version != EXPECTED_VERSION {
                return Err(SkibidiError::InvalidOutput(format!(
                    "native Skibidi version mismatch: expected {EXPECTED_VERSION:?}, got {version:?}"
                )));
            }
            if active_simd != self.backend.name() {
                return Err(SkibidiError::InvalidOutput(format!(
                    "native Skibidi backend mismatch: selected {}, native reported {active_simd:?}",
                    self.backend.name()
                )));
            }
            let capabilities = native_capabilities & cpu_os_capabilities();
            Ok(SkibidiRuntimeInfo {
                backend: self.backend,
                version,
                capabilities,
                has_avx2: native_has_avx2 && capabilities & (1 << 2) != 0,
                has_avx512: native_has_avx512 && capabilities & (1 << 3) != 0,
                avx512_enabled,
                simd_rng_enabled: self.enable_simd_rng,
            })
        })
    }

    pub(crate) fn generate(self) -> Result<Expression, SkibidiError> {
        let mut seed = [0_u8; 8];
        fill_random(&mut seed).map_err(|error| SkibidiError::Random(error.to_string()))?;
        self.generate_seeded(u64::from_le_bytes(seed), false)
    }

    fn generate_seeded(self, seed: u64, variant: bool) -> Result<Expression, SkibidiError> {
        self.with_native(|api| {
            let mut context = OwnedContext::new(api, seed)?;
            context.generate(variant)
        })
    }

    fn generate_batch_seeded(self, seed: u64, count: usize) -> Result<BatchOutput, SkibidiError> {
        self.with_native(|api| {
            let mut context = OwnedContext::new(api, seed)?;
            context.generate_batch(count)
        })
    }

    #[cfg(test)]
    fn generate_sequence_seeded(
        self,
        seed: u64,
        variant: bool,
        count: usize,
    ) -> Result<Vec<Expression>, SkibidiError> {
        self.with_native(|api| {
            let mut context = OwnedContext::new(api, seed)?;
            (0..count).map(|_| context.generate(variant)).collect()
        })
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

struct OwnedContext {
    pointer: NonNull<NativeContext>,
    api: &'static NativeApi,
}

impl OwnedContext {
    fn new(api: &'static NativeApi, seed: u64) -> Result<Self, SkibidiError> {
        // SAFETY: allocation is invoked only after the selected backend gate.
        let pointer =
            NonNull::new(unsafe { (api.alloc_context)() }).ok_or(SkibidiError::Allocation)?;
        let context = Self { pointer, api };
        // SAFETY: the pointer came from this exact API variant's allocator and
        // remains owned by context until the matching free_context in Drop.
        unsafe {
            expect_ok("skibidi_init", (api.init)(context.pointer.as_ptr(), seed))?;
        }
        Ok(context)
    }

    fn generate(&mut self, variant: bool) -> Result<Expression, SkibidiError> {
        let mut bytes = [0_u8; EXPRESSION_CAPACITY];
        // SAFETY: context is initialized, the writable buffer is 64 bytes, and
        // the API pointer is the same backend variant that allocated context.
        let status = unsafe {
            if variant {
                (self.api.generate_variant)(
                    self.pointer.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            } else {
                (self.api.generate)(
                    self.pointer.as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            }
        };
        if status < 0 {
            return Err(native_status("Skibidi single generation", status));
        }
        let length = usize::try_from(status).map_err(|_| {
            SkibidiError::InvalidOutput(format!(
                "native Skibidi returned an invalid length {status}"
            ))
        })?;
        validate_expression(&bytes, length)?;
        Ok(Expression { bytes, length })
    }

    fn generate_batch(&mut self, count: usize) -> Result<BatchOutput, SkibidiError> {
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
        let native_count = c_int::try_from(count).map_err(|_| {
            SkibidiError::InvalidOutput(format!("batch count {count} exceeds the C ABI"))
        })?;
        let capacity = count
            .checked_mul(BATCH_RECORD_CAPACITY)
            .ok_or_else(|| SkibidiError::InvalidOutput("batch output capacity overflow".into()))?
            .max(EXPRESSION_CAPACITY);
        let mut bytes = vec![0_u8; capacity];
        let mut native_lengths = vec![c_int::default(); count];
        // SAFETY: all buffer arithmetic was checked, both slices are writable
        // for the requested count, and context belongs to this API variant.
        let produced = unsafe {
            (self.api.generate_batch)(
                self.pointer.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                native_count,
                native_lengths.as_mut_ptr(),
            )
        };
        if produced != native_count {
            return Err(SkibidiError::InvalidOutput(format!(
                "native Skibidi batch produced {produced} of {native_count} requested expressions"
            )));
        }

        let mut lengths = Vec::with_capacity(count);
        let mut offset = 0_usize;
        for native_length in native_lengths {
            let length = usize::try_from(native_length).map_err(|_| {
                SkibidiError::InvalidOutput(format!(
                    "native Skibidi batch returned invalid length {native_length}"
                ))
            })?;
            let end = offset.checked_add(length).ok_or_else(|| {
                SkibidiError::InvalidOutput("batch expression offset overflow".into())
            })?;
            let record_end = end.checked_add(1).ok_or_else(|| {
                SkibidiError::InvalidOutput("batch record offset overflow".into())
            })?;
            if record_end > bytes.len() {
                return Err(SkibidiError::InvalidOutput(
                    "native Skibidi batch length exceeds its output buffer".into(),
                ));
            }
            validate_expression(&bytes[offset..end], length)?;
            if bytes[end] != b'\n' {
                return Err(SkibidiError::InvalidOutput(
                    "native Skibidi batch record is missing its newline".into(),
                ));
            }
            lengths.push(length);
            offset = record_end;
        }
        bytes.truncate(offset);
        Ok(BatchOutput { bytes, lengths })
    }
}

impl Drop for OwnedContext {
    fn drop(&mut self) {
        // SAFETY: pointer was allocated by this same NativeApi and has not been
        // freed. The C function securely destroys the context before freeing.
        unsafe { (self.api.free_context)(self.pointer.as_ptr()) };
    }
}

fn validate_expression(bytes: &[u8], length: usize) -> Result<(), SkibidiError> {
    if !(MIN_EXPRESSION_LENGTH..=MAX_EXPRESSION_LENGTH).contains(&length) || bytes.len() < length {
        return Err(SkibidiError::InvalidOutput(format!(
            "native Skibidi expression length {length} is outside the frozen contract"
        )));
    }
    let expression = &bytes[..length];
    if !expression
        .iter()
        .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b' ' | b'!'))
        || !expression.ends_with(b"!")
        || !(expression.starts_with(b"Skibidi ") || expression.starts_with(b"Brrrrr Skibidi "))
    {
        return Err(SkibidiError::InvalidOutput(
            "native Skibidi expression violated the ASCII grammar".into(),
        ));
    }
    Ok(())
}

fn validate_native_abi(api: &NativeApi) -> Result<(), SkibidiError> {
    // SAFETY: with_native has already gated the selected object. These calls
    // return compile-time sizeof/_Alignof constants and touch no caller memory.
    let (rng_size, context_size, context_alignment) = unsafe {
        (
            (api.get_rng_state_size)(),
            (api.get_context_size)(),
            (api.get_context_alignment)(),
        )
    };
    if rng_size != EXPECTED_RNG_STATE_SIZE
        || context_size != EXPECTED_CONTEXT_SIZE
        || context_alignment != EXPECTED_CONTEXT_ALIGNMENT
    {
        return Err(SkibidiError::InvalidOutput(format!(
            "native Skibidi ABI mismatch: rng={rng_size}, context={context_size}, alignment={context_alignment}"
        )));
    }
    Ok(())
}

// SAFETY: pointer must be a non-null process-lifetime C string returned by the
// frozen version or active-SIMD API while its selected object is gated.
unsafe fn native_string(
    operation: &'static str,
    pointer: *const c_char,
) -> Result<String, SkibidiError> {
    if pointer.is_null() {
        return Err(SkibidiError::InvalidOutput(format!(
            "{operation} returned NULL"
        )));
    }
    // SAFETY: the frozen C ABI promises a process-lifetime NUL-terminated
    // string for version and active-SIMD queries.
    let value = unsafe { CStr::from_ptr(pointer) };
    value.to_str().map(str::to_owned).map_err(|error| {
        SkibidiError::InvalidOutput(format!("{operation} returned invalid UTF-8: {error}"))
    })
}

fn expect_ok(operation: &'static str, status: c_int) -> Result<(), SkibidiError> {
    if status == SKIBIDI_OK {
        Ok(())
    } else {
        Err(native_status(operation, status))
    }
}

fn native_status(operation: &'static str, status: c_int) -> SkibidiError {
    let meaning = match status {
        SKIBIDI_ERR_NULL_PTR => "null pointer",
        SKIBIDI_ERR_BUFFER_TOO_SMALL => "buffer too small",
        SKIBIDI_ERR_INVALID_CONFIG => "invalid configuration",
        _ => "unknown status",
    };
    SkibidiError::Native {
        operation,
        status,
        meaning,
    }
}

fn require_backend(backend: SkibidiBackend) -> Result<SkibidiBackend, SkibidiError> {
    if backend.is_supported() {
        Ok(backend)
    } else {
        Err(SkibidiError::UnsupportedBackend(backend.name()))
    }
}

fn avx2_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn avx512_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        avx2_supported()
            && std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512vl")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512dq")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn cpu_os_capabilities() -> u32 {
    static CAPABILITIES: OnceLock<u32> = OnceLock::new();
    *CAPABILITIES.get_or_init(|| {
        let mut capabilities = 0;
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sse2") {
                capabilities |= 1 << 0;
            }
            if std::is_x86_feature_detected!("avx") {
                capabilities |= 1 << 1;
            }
            if avx2_supported() {
                capabilities |= 1 << 2;
            }
            if std::is_x86_feature_detected!("avx512f") {
                capabilities |= 1 << 3;
            }
            if std::is_x86_feature_detected!("avx512vl") {
                capabilities |= 1 << 4;
            }
            if std::is_x86_feature_detected!("avx512bw") {
                capabilities |= 1 << 5;
            }
            if std::is_x86_feature_detected!("avx512dq") {
                capabilities |= 1 << 6;
            }
        }
        capabilities
    })
}

#[derive(Debug)]
pub(crate) enum SkibidiError {
    InvalidMode(String),
    UnsupportedBackend(&'static str),
    InvalidOutput(String),
    Native {
        operation: &'static str,
        status: c_int,
        meaning: &'static str,
    },
    Allocation,
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
            Self::Native {
                operation,
                status,
                meaning,
            } => write!(
                formatter,
                "{operation} failed with native status {status} ({meaning})"
            ),
            Self::Allocation => formatter.write_str("native Skibidi context allocation failed"),
            Self::Random(error) => write!(formatter, "Skibidi seed generation failed: {error}"),
        }
    }
}

impl std::error::Error for SkibidiError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{ptr, sync::Arc, thread};

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

    fn sequence_strings(output: Vec<Expression>) -> Vec<String> {
        output
            .into_iter()
            .map(|expression| String::from_utf8(expression.as_bytes().to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn scalar_seed_variant_and_batch_match_frozen_c_probe() {
        let expected = golden();
        let scalar = SkibidiGenerator::new("SCALAR", false, false).unwrap();
        let singles = scalar.generate_sequence_seeded(0, false, 8).unwrap();
        assert_eq!(
            serde_json::to_value(sequence_strings(singles)).unwrap(),
            expected["single_seed_0"]
        );
        let variants = scalar
            .generate_sequence_seeded(0xfedc_ba98_7654_3210, true, 8)
            .unwrap();
        assert_eq!(
            serde_json::to_value(sequence_strings(variants)).unwrap(),
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
    fn vector_batch_matches_frozen_c_probe_when_available() {
        let expected = golden();
        for backend in [SkibidiBackend::Avx2, SkibidiBackend::Avx512] {
            if !backend.is_supported() {
                continue;
            }
            let generator = SkibidiGenerator {
                backend,
                enable_avx512: true,
                enable_simd_rng: true,
            };
            let batch = generator.generate_batch_seeded(42, 8).unwrap();
            assert_eq!(
                serde_json::to_value(expressions(&batch)).unwrap(),
                expected["batch_vector_seed_42"]["expressions"]
            );
        }
    }

    #[test]
    fn java_mode_is_only_a_native_scalar_compatibility_alias() {
        let java = SkibidiGenerator::new("JAVA", true, true).unwrap();
        let scalar = SkibidiGenerator::new("SCALAR", false, true).unwrap();
        assert_eq!(java.backend, SkibidiBackend::Scalar);
        assert_eq!(
            java.generate_seeded(0x1234, false).unwrap().as_bytes(),
            scalar.generate_seeded(0x1234, false).unwrap().as_bytes()
        );
        assert_eq!(java.runtime_info().unwrap().version, EXPECTED_VERSION);
    }

    #[test]
    fn native_abi_allocation_and_error_contract_match_header() {
        let generator = SkibidiGenerator::new("SCALAR", false, false).unwrap();
        generator
            .with_native(|api| {
                validate_native_abi(api)?;
                let mut output = [0_u8; EXPRESSION_CAPACITY];
                // SAFETY: scalar is baseline-safe; these calls intentionally
                // exercise documented NULL and short-buffer error contracts.
                unsafe {
                    assert_eq!((api.init)(ptr::null_mut(), 1), SKIBIDI_ERR_NULL_PTR);
                    assert_eq!(
                        (api.generate)(ptr::null_mut(), output.as_mut_ptr().cast(), output.len()),
                        SKIBIDI_ERR_NULL_PTR
                    );
                    let pointer =
                        NonNull::new((api.alloc_context)()).ok_or(SkibidiError::Allocation)?;
                    expect_ok("skibidi_init", (api.init)(pointer.as_ptr(), 7))?;
                    assert_eq!(
                        (api.generate)(pointer.as_ptr(), output.as_mut_ptr().cast(), 63),
                        SKIBIDI_ERR_BUFFER_TOO_SMALL
                    );
                    (api.destroy)(pointer.as_ptr());
                    (api.free_context)(pointer.as_ptr());

                    let array = NonNull::new((api.alloc_context_array)(3))
                        .ok_or(SkibidiError::Allocation)?;
                    assert_eq!(array.as_ptr() as usize % EXPECTED_CONTEXT_ALIGNMENT, 0);
                    (api.free_context)(array.as_ptr());
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn batch_bounds_are_checked_and_output_is_ascii() {
        let generator = SkibidiGenerator::new("SCALAR", false, false).unwrap();
        let empty = generator.generate_batch_seeded(1, 0).unwrap();
        assert!(empty.bytes.is_empty());
        assert!(empty.lengths.is_empty());
        assert!(
            generator
                .generate_batch_seeded(1, MAX_BATCH_EXPRESSIONS + 1)
                .is_err()
        );
        let batch = generator
            .generate_batch_seeded(1, MAX_BATCH_EXPRESSIONS)
            .unwrap();
        assert_eq!(batch.lengths.len(), MAX_BATCH_EXPRESSIONS);
        assert!(batch.bytes.is_ascii());
    }

    #[test]
    fn conflicting_batch_configurations_are_serialized() {
        if !SkibidiBackend::Avx2.is_supported() {
            return;
        }
        let expected = Arc::new(golden());
        let handles = (0..8)
            .map(|index| {
                let expected = Arc::clone(&expected);
                thread::spawn(move || {
                    let vector = index % 2 == 0;
                    let generator = SkibidiGenerator {
                        backend: SkibidiBackend::Avx2,
                        enable_avx512: false,
                        enable_simd_rng: vector,
                    };
                    let key = if vector {
                        "batch_vector_seed_42"
                    } else {
                        "batch_scalar_seed_42"
                    };
                    for _ in 0..32 {
                        let batch = generator.generate_batch_seeded(42, 8).unwrap();
                        assert_eq!(
                            serde_json::to_value(expressions(&batch)).unwrap(),
                            expected[key]["expressions"]
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
