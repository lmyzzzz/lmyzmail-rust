# Skibidi banner contract

The SMTP greeting banner is exposed through the Rust module
crates/lmyzmail/src/skibidi.rs, which is a narrow, checked FFI wrapper around
the frozen 1.8.0 C library under native/lmyzmail-skibidi/upstream. Cargo
builds three ISA-capped objects (Scalar, AVX2, and AVX-512) and links only the
selected backend through the wrapper.

The C source is the sole probability and byte-level authority:

- SplitMix64 seed expansion and xoroshiro128++ 64-bit generation.
- The 32-bit prophecy threshold 1680443541, vibration threshold 38, and
  rejection threshold 38.
- Dop population boundaries 12/204/230/243, DOM infiltration bits, zodiac
  capitalization tables, and the exact ASCII grammar and length limits.
- JAVA is retained as a configuration alias for existing deployments. It
  selects the Scalar C backend; it never starts a JVM or a separate Java
  fast path.
- AUTO, AUTO_SAFE, NATIVE, AVX2, and AVX-512 retain their validation and
  hardware capability reporting. Unsupported explicitly requested CPU modes
  are rejected before serving.

Generation writes into a fixed 64-byte Rust buffer supplied to C. Batch output
has a hard limit of 4096 expressions and a 44-byte record budget. The wrapper
checks every C return code, length, newline delimiter, ASCII grammar, metadata
size, alignment, and matching allocator ownership. Its unsafe code is
confined to these ABI calls and documented by the safety invariants in the
module. There is no JVM dependency.
