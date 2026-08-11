# SkibidiInferX runtime contract

SkibidiInferX is implemented entirely in Rust under
`crates/lmyzmail/src/skibidi_inferx`. It does not load the frozen Java
inference classes, their native kernel, JNI, or a JVM. The frozen Java sources,
probe, model, tokenizer, and generated text in
`blackbox/golden/native/skibidi-inferx-java-v1/contract.json` remain the
behavior oracle.

## Model and memory

- The SafeTensors file is opened read-only and memory-mapped. Its file size is
  limited to 512 MiB, the tensor count to 4096, and every tensor must be F32,
  naturally aligned, in range, named exactly, and have the expected shape.
- The tokenizer JSON is limited to 8 MiB, 1,048,576 vocabulary entries, and
  1,048,576 merges. IDs must be unique, in range, and preserve the four
  special-token IDs.
- Scratch allocation is checked for integer overflow and capped at 16,777,216
  floats (64 MiB). It includes both complete KV caches, logits, attention
  scores, and all transformer intermediates. Allocation failure disables the
  engine and leaves deterministic fallback messages available.
- Configured model and tokenizer files are trusted, immutable deployment
  assets for the process lifetime. Replace them atomically and restart the
  process; in-place truncation of a live mapped file is outside the supported
  administration contract.

## Admission, deadlines, and shutdown

One dedicated blocking worker owns one `InferenceEngine`. One request may be
running at a time and the pool queue has capacity one, while an atomic busy
gate makes later requests fall back immediately instead of occupying that
queue. This preserves the frozen Java engine lock's externally observable
single-generation behavior even when the legacy concurrency property is
greater than one.

Seed input is limited to 4096 bytes. Generation is limited to the frozen
engine's effective 120 new tokens and the model's sequence length. Cancellation
and monotonic deadlines are checked before inference, before every token,
before every transformer layer, and before logits. A timed-out caller cancels
the worker operation; the busy gate remains set until the worker observes that
cancellation and exits. Shutdown waits at most two seconds for the bounded
worker.

The legacy `max-tokens` property is parsed, validated, and reported, but the
frozen Java `InferenceEngine` does not consume it and always uses 120. The Rust
engine therefore also uses 120. The legacy `fallback-on-error=false` value is
reported, but the frozen Java service's outer completion handler still returns
a fallback for every generation error or timeout, which is the behavior kept
here.

## SIMD and unsafe boundaries

Scalar kernels use safe Rust. AVX2 requires both AVX2 and FMA; AVX-512 requires
AVX-512F, AVX2, and FMA. Runtime feature detection occurs before a backend enum
can be constructed, and every intrinsic function has a matching
`target_feature` declaration. Explicit unsupported preferences are clamped in
the same order as the frozen Java dispatcher, preventing illegal instruction
execution.

Unsafe Rust is limited to the read-only mmap creation and private x86_64
intrinsic functions. The safe engine establishes every slice length and model
shape before dispatch; SIMD loads are unaligned, loop tails are scalar, and no
intrinsic function escapes the module. Scalar and AVX2 complete-output goldens
exercise the same three seeds. AVX-512 compiles on stable Rust but still
requires execution evidence on an AVX-512 host before the overall migration
can complete.

## Configuration and integration status

Every `lmyzmail.skibidi-inferx.*` key has a legacy
`botmail.skibidi-inferx.*` alias, with the new key taking precedence per field.
Legacy `classpath:skibidi-inferx-model/...` values resolve to the repository
model during development or `/usr/share/lmyzmail/models/skibidi-inferx` after
installation, without starting Java.

The service is initialized and shut down by the Rust monolith and exposes
bounded runtime status. It is intentionally not connected to the SMTP
self-spoofing reply path in this milestone. That connection must follow a raw
socket Java oracle golden for the exact reply, tag, timing, and fallback
semantics; internal Java classes are not a substitute for the wire oracle.
