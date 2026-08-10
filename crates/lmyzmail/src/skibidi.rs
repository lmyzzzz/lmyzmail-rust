use std::{
    ffi::{CStr, c_char, c_int, c_void},
    fmt,
    ptr::NonNull,
};

use getrandom::fill as fill_random;

const SKIBIDI_OK: c_int = 0;
const EXPRESSION_CAPACITY: usize = 64;
const MIN_EXPRESSION_LENGTH: usize = 18;
const MAX_EXPRESSION_LENGTH: usize = 43;
const BATCH_RECORD_CAPACITY: usize = 44;
const MAX_BATCH_EXPRESSIONS: usize = 4096;
const EXPECTED_VERSION: &str = "1.8.0-skibidi-ultra";
const EXPECTED_RNG_SIZE: usize = 128;
const EXPECTED_CONTEXT_SIZE: usize = 192;
const EXPECTED_CONTEXT_ALIGNMENT: usize = 64;

#[repr(C)]
struct RawConfig {
    enable_avx512: c_int,
    enable_simd_rng: c_int,
    reserved: [c_int; 6],
}

const _: () = assert!(std::mem::size_of::<RawConfig>() == 32);
const _: () = assert!(std::mem::align_of::<RawConfig>() == std::mem::align_of::<c_int>());

type InitFn = unsafe extern "C" fn(*mut c_void, u64) -> c_int;
type ConfigureFn = unsafe extern "C" fn(*const RawConfig) -> c_int;
type GetConfigFn = unsafe extern "C" fn(*mut RawConfig) -> c_int;
type GenerateFn = unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> c_int;
type GenerateBatchFn =
    unsafe extern "C" fn(*mut c_void, *mut c_char, usize, c_int, *mut c_int) -> c_int;
type DestroyFn = unsafe extern "C" fn(*mut c_void);
type AllocFn = unsafe extern "C" fn() -> *mut c_void;
type AllocArrayFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type StringFn = unsafe extern "C" fn() -> *const c_char;
type IntFn = unsafe extern "C" fn() -> c_int;
type U32Fn = unsafe extern "C" fn() -> u32;
type SizeFn = unsafe extern "C" fn() -> usize;

struct RawApi {
    init: InitFn,
    configure: ConfigureFn,
    get_config: GetConfigFn,
    generate: GenerateFn,
    generate_variant: GenerateFn,
    generate_batch: GenerateBatchFn,
    destroy: DestroyFn,
    alloc: AllocFn,
    alloc_array: AllocArrayFn,
    free: FreeFn,
    version: StringFn,
    has_avx2: IntFn,
    has_avx512: IntFn,
    capabilities: U32Fn,
    active_simd: StringFn,
    avx512_enabled: IntFn,
    rng_size: SizeFn,
    context_size: SizeFn,
    context_alignment: SizeFn,
}

unsafe extern "C" {
    fn skibidi_init(context: *mut c_void, seed: u64) -> c_int;
    fn skibidi_configure(config: *const RawConfig) -> c_int;
    fn skibidi_get_config(config: *mut RawConfig) -> c_int;
    fn skibidi_generate(context: *mut c_void, output: *mut c_char, size: usize) -> c_int;
    fn skibidi_generate_variant(context: *mut c_void, output: *mut c_char, size: usize) -> c_int;
    fn skibidi_generate_batch(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
        count: c_int,
        lengths: *mut c_int,
    ) -> c_int;
    fn skibidi_destroy(context: *mut c_void);
    fn skibidi_alloc_context() -> *mut c_void;
    fn skibidi_alloc_context_array(count: usize) -> *mut c_void;
    fn skibidi_free_context(context: *mut c_void);
    fn skibidi_version() -> *const c_char;
    fn skibidi_has_avx2() -> c_int;
    fn skibidi_has_avx512() -> c_int;
    fn skibidi_get_capabilities() -> u32;
    fn skibidi_get_active_simd() -> *const c_char;
    fn skibidi_is_avx512_enabled() -> c_int;
    fn skibidi_get_rng_state_size() -> usize;
    fn skibidi_get_context_size() -> usize;
    fn skibidi_get_context_alignment() -> usize;

    fn lmyzmail_skibidi_avx2_skibidi_init(context: *mut c_void, seed: u64) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_configure(config: *const RawConfig) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_get_config(config: *mut RawConfig) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_generate(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
    ) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_generate_variant(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
    ) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_generate_batch(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
        count: c_int,
        lengths: *mut c_int,
    ) -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_destroy(context: *mut c_void);
    fn lmyzmail_skibidi_avx2_skibidi_alloc_context() -> *mut c_void;
    fn lmyzmail_skibidi_avx2_skibidi_alloc_context_array(count: usize) -> *mut c_void;
    fn lmyzmail_skibidi_avx2_skibidi_free_context(context: *mut c_void);
    fn lmyzmail_skibidi_avx2_skibidi_version() -> *const c_char;
    fn lmyzmail_skibidi_avx2_skibidi_has_avx2() -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_has_avx512() -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_get_capabilities() -> u32;
    fn lmyzmail_skibidi_avx2_skibidi_get_active_simd() -> *const c_char;
    fn lmyzmail_skibidi_avx2_skibidi_is_avx512_enabled() -> c_int;
    fn lmyzmail_skibidi_avx2_skibidi_get_rng_state_size() -> usize;
    fn lmyzmail_skibidi_avx2_skibidi_get_context_size() -> usize;
    fn lmyzmail_skibidi_avx2_skibidi_get_context_alignment() -> usize;

    fn lmyzmail_skibidi_avx512_skibidi_init(context: *mut c_void, seed: u64) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_configure(config: *const RawConfig) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_get_config(config: *mut RawConfig) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_generate(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
    ) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_generate_variant(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
    ) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_generate_batch(
        context: *mut c_void,
        output: *mut c_char,
        size: usize,
        count: c_int,
        lengths: *mut c_int,
    ) -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_destroy(context: *mut c_void);
    fn lmyzmail_skibidi_avx512_skibidi_alloc_context() -> *mut c_void;
    fn lmyzmail_skibidi_avx512_skibidi_alloc_context_array(count: usize) -> *mut c_void;
    fn lmyzmail_skibidi_avx512_skibidi_free_context(context: *mut c_void);
    fn lmyzmail_skibidi_avx512_skibidi_version() -> *const c_char;
    fn lmyzmail_skibidi_avx512_skibidi_has_avx2() -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_has_avx512() -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_get_capabilities() -> u32;
    fn lmyzmail_skibidi_avx512_skibidi_get_active_simd() -> *const c_char;
    fn lmyzmail_skibidi_avx512_skibidi_is_avx512_enabled() -> c_int;
    fn lmyzmail_skibidi_avx512_skibidi_get_rng_state_size() -> usize;
    fn lmyzmail_skibidi_avx512_skibidi_get_context_size() -> usize;
    fn lmyzmail_skibidi_avx512_skibidi_get_context_alignment() -> usize;
}

static SCALAR_API: RawApi = RawApi {
    init: skibidi_init,
    configure: skibidi_configure,
    get_config: skibidi_get_config,
    generate: skibidi_generate,
    generate_variant: skibidi_generate_variant,
    generate_batch: skibidi_generate_batch,
    destroy: skibidi_destroy,
    alloc: skibidi_alloc_context,
    alloc_array: skibidi_alloc_context_array,
    free: skibidi_free_context,
    version: skibidi_version,
    has_avx2: skibidi_has_avx2,
    has_avx512: skibidi_has_avx512,
    capabilities: skibidi_get_capabilities,
    active_simd: skibidi_get_active_simd,
    avx512_enabled: skibidi_is_avx512_enabled,
    rng_size: skibidi_get_rng_state_size,
    context_size: skibidi_get_context_size,
    context_alignment: skibidi_get_context_alignment,
};

static AVX2_API: RawApi = RawApi {
    init: lmyzmail_skibidi_avx2_skibidi_init,
    configure: lmyzmail_skibidi_avx2_skibidi_configure,
    get_config: lmyzmail_skibidi_avx2_skibidi_get_config,
    generate: lmyzmail_skibidi_avx2_skibidi_generate,
    generate_variant: lmyzmail_skibidi_avx2_skibidi_generate_variant,
    generate_batch: lmyzmail_skibidi_avx2_skibidi_generate_batch,
    destroy: lmyzmail_skibidi_avx2_skibidi_destroy,
    alloc: lmyzmail_skibidi_avx2_skibidi_alloc_context,
    alloc_array: lmyzmail_skibidi_avx2_skibidi_alloc_context_array,
    free: lmyzmail_skibidi_avx2_skibidi_free_context,
    version: lmyzmail_skibidi_avx2_skibidi_version,
    has_avx2: lmyzmail_skibidi_avx2_skibidi_has_avx2,
    has_avx512: lmyzmail_skibidi_avx2_skibidi_has_avx512,
    capabilities: lmyzmail_skibidi_avx2_skibidi_get_capabilities,
    active_simd: lmyzmail_skibidi_avx2_skibidi_get_active_simd,
    avx512_enabled: lmyzmail_skibidi_avx2_skibidi_is_avx512_enabled,
    rng_size: lmyzmail_skibidi_avx2_skibidi_get_rng_state_size,
    context_size: lmyzmail_skibidi_avx2_skibidi_get_context_size,
    context_alignment: lmyzmail_skibidi_avx2_skibidi_get_context_alignment,
};

static AVX512_API: RawApi = RawApi {
    init: lmyzmail_skibidi_avx512_skibidi_init,
    configure: lmyzmail_skibidi_avx512_skibidi_configure,
    get_config: lmyzmail_skibidi_avx512_skibidi_get_config,
    generate: lmyzmail_skibidi_avx512_skibidi_generate,
    generate_variant: lmyzmail_skibidi_avx512_skibidi_generate_variant,
    generate_batch: lmyzmail_skibidi_avx512_skibidi_generate_batch,
    destroy: lmyzmail_skibidi_avx512_skibidi_destroy,
    alloc: lmyzmail_skibidi_avx512_skibidi_alloc_context,
    alloc_array: lmyzmail_skibidi_avx512_skibidi_alloc_context_array,
    free: lmyzmail_skibidi_avx512_skibidi_free_context,
    version: lmyzmail_skibidi_avx512_skibidi_version,
    has_avx2: lmyzmail_skibidi_avx512_skibidi_has_avx2,
    has_avx512: lmyzmail_skibidi_avx512_skibidi_has_avx512,
    capabilities: lmyzmail_skibidi_avx512_skibidi_get_capabilities,
    active_simd: lmyzmail_skibidi_avx512_skibidi_get_active_simd,
    avx512_enabled: lmyzmail_skibidi_avx512_skibidi_is_avx512_enabled,
    rng_size: lmyzmail_skibidi_avx512_skibidi_get_rng_state_size,
    context_size: lmyzmail_skibidi_avx512_skibidi_get_context_size,
    context_alignment: lmyzmail_skibidi_avx512_skibidi_get_context_alignment,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SkibidiBackend {
    Scalar,
    Avx2,
    Avx512,
}

impl SkibidiBackend {
    fn api(self) -> &'static RawApi {
        match self {
            Self::Scalar => &SCALAR_API,
            Self::Avx2 => &AVX2_API,
            Self::Avx512 => &AVX512_API,
        }
    }

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
            Self::Avx2 => std::is_x86_feature_detected!("avx2"),
            // This object is compiled with both -mavx2 and -mavx512f. The
            // standard library checks CPU and OS extended-state support.
            Self::Avx512 => {
                std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("avx512f")
            }
        }
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
}

impl SkibidiGenerator {
    pub(crate) fn new(
        mode: &str,
        enable_avx512: bool,
        enable_simd_rng: bool,
    ) -> Result<Self, SkibidiError> {
        let normalized = mode.trim().to_ascii_uppercase();
        let backend = match normalized.as_str() {
            "JAVA" | "SCALAR" => SkibidiBackend::Scalar,
            "AVX2" => {
                if !SkibidiBackend::Avx2.is_supported() {
                    return Err(SkibidiError::UnsupportedBackend("AVX2"));
                }
                SkibidiBackend::Avx2
            }
            "AVX512" | "AVX-512" => {
                if !enable_avx512 {
                    return Err(SkibidiError::InvalidMode(
                        "AVX-512 mode requires skibidi-generator-enable-avx512=true".into(),
                    ));
                }
                if !SkibidiBackend::Avx512.is_supported() {
                    return Err(SkibidiError::UnsupportedBackend("AVX-512"));
                }
                SkibidiBackend::Avx512
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
        Self::for_backend(backend, enable_avx512, enable_simd_rng)
    }

    fn for_backend(
        backend: SkibidiBackend,
        enable_avx512: bool,
        enable_simd_rng: bool,
    ) -> Result<Self, SkibidiError> {
        let api = backend.api();
        let config = RawConfig {
            enable_avx512: i32::from(enable_avx512),
            enable_simd_rng: i32::from(enable_simd_rng),
            reserved: [0; 6],
        };
        // SAFETY: `config` has the frozen 32-byte C layout and remains valid for
        // the complete call. Each compiled backend owns an independent atomic
        // global configuration.
        check_api("configure", unsafe { (api.configure)(&raw const config) })?;
        let generator = Self { backend };
        generator.runtime_info()?;
        generator.validate_batch_smoke()?;
        Ok(generator)
    }

    fn validate_batch_smoke(self) -> Result<(), SkibidiError> {
        let mut context = OwnedContext::new(self.backend, 0)?;
        let output = context.generate_batch(1)?;
        if output.lengths.len() != 1 || output.bytes.is_empty() {
            return Err(SkibidiError::InvalidOutput(
                "Skibidi batch startup probe returned no expression".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn runtime_info(self) -> Result<SkibidiRuntimeInfo, SkibidiError> {
        let api = self.backend.api();
        // SAFETY: these functions take no pointers and return immutable static
        // metadata or atomic scalar values from the selected backend.
        let (version, active, rng_size, context_size, context_alignment) = unsafe {
            (
                c_string((api.version)(), "version")?,
                c_string((api.active_simd)(), "active SIMD")?,
                (api.rng_size)(),
                (api.context_size)(),
                (api.context_alignment)(),
            )
        };
        if version != EXPECTED_VERSION
            || active != self.backend.name()
            || rng_size != EXPECTED_RNG_SIZE
            || context_size != EXPECTED_CONTEXT_SIZE
            || context_alignment != EXPECTED_CONTEXT_ALIGNMENT
        {
            return Err(SkibidiError::Abi(format!(
                "metadata mismatch: version={version:?}, active={active:?}, rng={rng_size}, context={context_size}, alignment={context_alignment}"
            )));
        }
        let mut config = RawConfig {
            enable_avx512: 0,
            enable_simd_rng: 0,
            reserved: [0; 6],
        };
        // SAFETY: `config` is writable and has the exact frozen C layout.
        check_api("get_config", unsafe { (api.get_config)(&raw mut config) })?;
        // SAFETY: the remaining metadata functions return atomic scalar values.
        let (capabilities, has_avx2, has_avx512, avx512_enabled) = unsafe {
            (
                (api.capabilities)(),
                (api.has_avx2)() != 0,
                (api.has_avx512)() != 0,
                (api.avx512_enabled)() != 0,
            )
        };
        Ok(SkibidiRuntimeInfo {
            backend: self.backend,
            version,
            capabilities,
            has_avx2,
            has_avx512,
            avx512_enabled,
            simd_rng_enabled: config.enable_simd_rng != 0,
        })
    }

    pub(crate) fn generate(self) -> Result<Expression, SkibidiError> {
        let mut seed = [0_u8; 8];
        fill_random(&mut seed).map_err(|error| SkibidiError::Random(error.to_string()))?;
        self.generate_seeded(u64::from_le_bytes(seed), false)
    }

    fn generate_seeded(self, seed: u64, variant: bool) -> Result<Expression, SkibidiError> {
        let mut context = OwnedContext::new(self.backend, seed)?;
        context.generate(variant)
    }

    #[cfg(test)]
    fn generate_batch_seeded(self, seed: u64, count: usize) -> Result<BatchOutput, SkibidiError> {
        let mut context = OwnedContext::new(self.backend, seed)?;
        context.generate_batch(count)
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
    backend: SkibidiBackend,
    pointer: NonNull<c_void>,
}

impl OwnedContext {
    fn new(backend: SkibidiBackend, seed: u64) -> Result<Self, SkibidiError> {
        let api = backend.api();
        // SAFETY: the frozen allocator returns either null or a 64-byte-aligned
        // allocation large enough for one 192-byte context.
        let pointer = NonNull::new(unsafe { (api.alloc)() }).ok_or(SkibidiError::Allocation)?;
        // SAFETY: `pointer` is owned, correctly aligned, and live for this call.
        if let Err(error) = check_api("init", unsafe { (api.init)(pointer.as_ptr(), seed) }) {
            // SAFETY: the pointer came from this backend's allocator and has not
            // been freed. The C free function accepts initialized or zeroed state.
            unsafe { (api.free)(pointer.as_ptr()) };
            return Err(error);
        }
        Ok(Self { backend, pointer })
    }

    fn generate(&mut self, variant: bool) -> Result<Expression, SkibidiError> {
        let api = self.backend.api();
        let mut bytes = [0_u8; EXPRESSION_CAPACITY];
        let generate = if variant {
            api.generate_variant
        } else {
            api.generate
        };
        // SAFETY: the context is exclusively borrowed and live; `bytes` is a
        // writable 64-byte buffer as required by the frozen ABI.
        let length = unsafe {
            generate(
                self.pointer.as_ptr(),
                bytes.as_mut_ptr().cast::<c_char>(),
                bytes.len(),
            )
        };
        let length = checked_expression_length(length, bytes.len())?;
        validate_expression(&bytes[..length])?;
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
        let capacity = count
            .checked_mul(BATCH_RECORD_CAPACITY)
            .ok_or_else(|| SkibidiError::InvalidOutput("batch capacity overflow".into()))?
            .max(EXPRESSION_CAPACITY);
        let count = c_int::try_from(count)
            .map_err(|_| SkibidiError::InvalidOutput("batch count exceeds C int".into()))?;
        let mut bytes = vec![0_u8; capacity];
        let mut raw_lengths = vec![0_i32; count as usize];
        let api = self.backend.api();
        // SAFETY: all pointers refer to writable allocations of the declared
        // sizes, the context is exclusively borrowed, and count fits C `int`.
        let generated = unsafe {
            (api.generate_batch)(
                self.pointer.as_ptr(),
                bytes.as_mut_ptr().cast::<c_char>(),
                bytes.len(),
                count,
                raw_lengths.as_mut_ptr(),
            )
        };
        if generated < 0 || generated > count {
            return Err(SkibidiError::InvalidOutput(format!(
                "batch returned invalid count {generated} for request {count}"
            )));
        }
        let generated = generated as usize;

        // Exercise the frozen ownership ABI once before accepting this batch.
        // The selected object file has its own allocator and must preserve
        // 64-byte alignment for both single and array allocations.
        // SAFETY: allocations are checked for null before use and are released
        // through the same backend that created them.
        unsafe {
            let single = NonNull::new((api.alloc)()).ok_or(SkibidiError::Allocation)?;
            if !(single.as_ptr() as usize).is_multiple_of(EXPECTED_CONTEXT_ALIGNMENT) {
                (api.free)(single.as_ptr());
                return Err(SkibidiError::Abi(
                    "single context allocation is not 64-byte aligned".into(),
                ));
            }
            (api.destroy)(single.as_ptr());
            (api.free)(single.as_ptr());

            let array = NonNull::new((api.alloc_array)(2)).ok_or(SkibidiError::Allocation)?;
            if !(array.as_ptr() as usize).is_multiple_of(EXPECTED_CONTEXT_ALIGNMENT) {
                (api.free)(array.as_ptr());
                return Err(SkibidiError::Abi(
                    "context array allocation is not 64-byte aligned".into(),
                ));
            }
            (api.free)(array.as_ptr());
        }

        let mut lengths = Vec::with_capacity(generated);
        let mut used = 0_usize;
        for raw_length in raw_lengths.into_iter().take(generated) {
            let length = checked_expression_length(raw_length, bytes.len())?;
            let end = used
                .checked_add(length)
                .ok_or_else(|| SkibidiError::InvalidOutput("batch offset overflow".into()))?;
            if end >= bytes.len() || bytes[end] != b'\n' {
                return Err(SkibidiError::InvalidOutput(
                    "batch record is not newline terminated".into(),
                ));
            }
            validate_expression(&bytes[used..end])?;
            lengths.push(length);
            used = end + 1;
        }
        bytes.truncate(used);
        Ok(BatchOutput { bytes, lengths })
    }
}

impl Drop for OwnedContext {
    fn drop(&mut self) {
        let api = self.backend.api();
        // SAFETY: this pointer is uniquely owned and came from the matching
        // backend allocator. C performs the required secure destroy before free.
        unsafe { (api.free)(self.pointer.as_ptr()) };
    }
}

fn checked_expression_length(value: c_int, capacity: usize) -> Result<usize, SkibidiError> {
    if value < 0 {
        return Err(SkibidiError::Api {
            operation: "generate",
            code: value,
        });
    }
    let length = value as usize;
    if !(MIN_EXPRESSION_LENGTH..=MAX_EXPRESSION_LENGTH).contains(&length) || length > capacity {
        return Err(SkibidiError::InvalidOutput(format!(
            "expression length {length} is outside the frozen contract"
        )));
    }
    Ok(length)
}

fn validate_expression(bytes: &[u8]) -> Result<(), SkibidiError> {
    if !bytes.is_ascii()
        || !bytes.starts_with(b"Skibidi ") && !bytes.starts_with(b"Brrrrr Skibidi ")
        || !bytes.ends_with(b"!")
        || bytes.contains(&b'\r')
        || bytes.contains(&b'\n')
    {
        return Err(SkibidiError::InvalidOutput(
            "expression bytes violate the frozen grammar".into(),
        ));
    }
    Ok(())
}

unsafe fn c_string(pointer: *const c_char, field: &'static str) -> Result<String, SkibidiError> {
    if pointer.is_null() {
        return Err(SkibidiError::Abi(format!("{field} pointer is null")));
    }
    // SAFETY: the frozen ABI promises a process-lifetime NUL-terminated static
    // string. Null was rejected above.
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map_err(|_| SkibidiError::Abi(format!("{field} is not UTF-8")))?;
    Ok(value.to_owned())
}

fn check_api(operation: &'static str, code: c_int) -> Result<(), SkibidiError> {
    if code == SKIBIDI_OK {
        Ok(())
    } else {
        Err(SkibidiError::Api { operation, code })
    }
}

#[derive(Debug)]
pub(crate) enum SkibidiError {
    InvalidMode(String),
    UnsupportedBackend(&'static str),
    Abi(String),
    Api {
        operation: &'static str,
        code: c_int,
    },
    Allocation,
    InvalidOutput(String),
    Random(String),
}

impl fmt::Display for SkibidiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMode(error) | Self::Abi(error) | Self::InvalidOutput(error) => {
                formatter.write_str(error)
            }
            Self::UnsupportedBackend(backend) => {
                write!(
                    formatter,
                    "Skibidi {backend} backend is not supported by this CPU/OS"
                )
            }
            Self::Api { operation, code } => {
                write!(formatter, "Skibidi {operation} failed with code {code}")
            }
            Self::Allocation => formatter.write_str("Skibidi context allocation failed"),
            Self::Random(error) => write!(formatter, "Skibidi seed generation failed: {error}"),
        }
    }
}

impl std::error::Error for SkibidiError {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::Value;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn scalar_seed_variant_and_batch_match_frozen_c_probe() {
        let _guard = TEST_LOCK.lock().unwrap();
        let expected = golden();
        let scalar = SkibidiGenerator::for_backend(SkibidiBackend::Scalar, false, false).unwrap();
        let info = scalar.runtime_info().unwrap();
        assert_eq!(info.backend, SkibidiBackend::Scalar);
        assert_eq!(info.version, EXPECTED_VERSION);
        assert!(!info.simd_rng_enabled);

        let mut context = OwnedContext::new(SkibidiBackend::Scalar, 0).unwrap();
        let singles = (0..8)
            .map(|_| {
                String::from_utf8(context.generate(false).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(&singles).unwrap(),
            expected["single_seed_0"]
        );

        let mut context =
            OwnedContext::new(SkibidiBackend::Scalar, UINT64_C_FEDCBA9876543210).unwrap();
        let variants = (0..8)
            .map(|_| {
                String::from_utf8(context.generate(true).unwrap().as_bytes().to_vec()).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            serde_json::to_value(&variants).unwrap(),
            expected["variant_seed_fedcba9876543210"]
        );

        let batch = scalar.generate_batch_seeded(42, 8).unwrap();
        assert_eq!(batch.lengths, vec![32, 32, 28, 24, 22, 24, 26, 24]);
        assert_eq!(
            serde_json::to_value(expressions(&batch)).unwrap(),
            expected["batch_scalar_seed_42"]["expressions"]
        );
    }

    const UINT64_C_FEDCBA9876543210: u64 = 0xfedc_ba98_7654_3210;

    #[test]
    fn runtime_dispatch_never_calls_an_unsupported_backend() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generator = SkibidiGenerator::new("AUTO_SAFE", true, true).unwrap();
        let expected = if SkibidiBackend::Avx512.is_supported() {
            SkibidiBackend::Avx512
        } else if SkibidiBackend::Avx2.is_supported() {
            SkibidiBackend::Avx2
        } else {
            SkibidiBackend::Scalar
        };
        assert_eq!(generator.backend, expected);
        assert_eq!(generator.runtime_info().unwrap().backend, expected);
        assert!(generator.generate().unwrap().as_bytes().is_ascii());
    }

    #[test]
    fn vector_batch_matches_frozen_c_probe_when_available() {
        let _guard = TEST_LOCK.lock().unwrap();
        let expected = golden();
        for backend in [SkibidiBackend::Avx2, SkibidiBackend::Avx512] {
            if !backend.is_supported() {
                continue;
            }
            let generator = SkibidiGenerator::for_backend(backend, true, true).unwrap();
            let batch = generator.generate_batch_seeded(42, 8).unwrap();
            assert_eq!(
                serde_json::to_value(expressions(&batch)).unwrap(),
                expected["batch_vector_seed_42"]["expressions"]
            );
        }
    }

    #[test]
    fn legacy_java_mode_uses_scalar_c_without_a_jvm() {
        let _guard = TEST_LOCK.lock().unwrap();
        let generator = SkibidiGenerator::new("JAVA", true, true).unwrap();
        assert_eq!(generator.backend, SkibidiBackend::Scalar);
        assert_eq!(
            generator.runtime_info().unwrap().backend,
            SkibidiBackend::Scalar
        );
        let expression = generator.generate_seeded(0, false).unwrap();
        assert_eq!(expression.as_bytes(), b"Skibidi dop dop yeS yes!");
    }
}
