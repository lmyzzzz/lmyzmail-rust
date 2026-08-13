# Skibidi banner contract

The SMTP greeting banner always uses the frozen Skibidi 1.8.0 C library under
`native/lmyzmail-skibidi/upstream`. Rust owns only the narrow FFI wrapper,
OS-aware ISA dispatch, seeding, resource lifetime, and output validation. The
production binary statically links ISA-capped Scalar, AVX2, and AVX-512 C
objects and never starts a JVM.

The frozen C source is the sole probability and byte-level authority:

- SplitMix64 seed expansion and xoroshiro128++ generation.
- All prophecy, vibration, rejection, population, capitalization, and variant
  thresholds and tables.
- The exact ASCII grammar, seed sequence, batch layout, context ABI, and
  allocation ownership rules.
- `JAVA` is retained as a configuration alias for existing deployments. It
  selects the Scalar C object and does not enable the historical Java outer
  fast path.
- `AUTO`, `AUTO_SAFE`, `NATIVE`, `AVX2`, and `AVX-512` retain their validation
  and hardware capability reporting. Unsupported explicit modes are rejected
  before serving.

Rust never duplicates the C probability implementation. It uses
`is_x86_feature_detected!` before selecting a vector object, so both CPU support
and OS extended-state support are required before AVX2 or AVX-512 instructions
can execute. External compiler ISA overrides are rejected, and each object is
built with a fixed instruction ceiling.

Single generation writes into a fixed 64-byte Rust-owned buffer. Batch output
has a hard limit of 4096 expressions and a 44-byte record budget. The wrapper
checks C version and layout metadata, allocator alignment, every returned
length, newline delimiter, ASCII grammar, and output budget before publication.
All unsafe code is confined to the documented FFI boundary, and matching C
allocators release every context. There is no JVM dependency.
