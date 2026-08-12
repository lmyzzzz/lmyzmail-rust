# Skibidi banner contract

The SMTP greeting banner is implemented entirely by the Rust module
`crates/lmyzmail/src/skibidi.rs`. The frozen 1.8.0 C library under
`native/lmyzmail-skibidi/upstream` is retained as a read-only provenance,
distribution, and ABI oracle; it is not linked into or loaded by the
production binary. Rust selects one of three ISA-capped implementations
(Scalar, AVX2, or AVX-512) at startup and never starts a JVM or invokes the C
generator.

The C source is the sole probability and byte-level authority:

- SplitMix64 seed expansion and xoroshiro128++ 64-bit generation.
- The 32-bit prophecy threshold 1680443541, vibration threshold 38, and
  rejection threshold 38.
- Dop population boundaries 12/204/230/243, DOM infiltration bits, zodiac
  capitalization tables, and the exact ASCII grammar and length limits.
- JAVA is retained as a configuration alias for existing deployments. It
  selects the Rust Scalar backend; it never starts a JVM, invokes the C
  generator, or enables a separate Java fast path.
- AUTO, AUTO_SAFE, NATIVE, AVX2, and AVX-512 retain their validation and
  hardware capability reporting. Unsupported explicitly requested CPU modes
  are rejected before serving.

Generation writes into a fixed 64-byte Rust buffer. Batch output has a hard
limit of 4096 expressions and a 44-byte record budget. The implementation
checks every generated length, newline delimiter, ASCII grammar, and metadata
budget before publication. Scalar generation is safe Rust; the only unsafe
code in this path is confined to the narrow x86 SIMD intrinsics and their
runtime feature gates, with safety invariants documented in the module. The
frozen C ABI remains covered by a separate oracle test and is not a runtime
dependency. There is no JVM dependency.
