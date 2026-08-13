# Skibidi banner contract

The SMTP greeting banner is implemented entirely in Rust. The frozen Skibidi
1.8.0 C source under `native/lmyzmail-skibidi/upstream` remains a read-only
probability, table, and behavior oracle only; it is not compiled, linked, or
loaded by the production binary, and no JVM is started.

The frozen C source is the sole probability and byte-level authority:

- SplitMix64 seed expansion and xoroshiro128++ generation.
- All prophecy, vibration, rejection, population, capitalization, and variant
  thresholds and tables.
- The exact ASCII grammar, seed sequence, batch layout, context ABI, and
  allocation ownership rules.
- `JAVA` is retained as a configuration alias for existing deployments. It
  selects the pure-Rust Scalar backend and does not enable a Java outer fast
  path.
- `AUTO`, `AUTO_SAFE`, `NATIVE`, `AVX2`, and `AVX-512` retain their validation
  and hardware capability reporting. Unsupported explicit modes are rejected
  before serving.

Rust mirrors the frozen C thresholds, tables, RNG transitions, and packed batch
ending semantics. It uses `is_x86_feature_detected!` for safe runtime backend
selection; AVX-labelled modes retain their capability reporting while sharing
the same checked Rust behavior.

Single generation writes into a fixed 64-byte Rust-owned buffer. Batch output
has a hard limit of 4096 expressions and a 44-byte record budget. Every output
length, newline delimiter, ASCII grammar, and output budget is checked before
publication. The generator contains no unsafe code, C ABI, native Skibidi
allocator, or JVM dependency.
