# Privileged XDP acceptance gate

`tools/lmyzmail-xdp-check` is intentionally excluded from the default Cargo
workspace. It is a Linux x86_64 acceptance tool, not part of the lmyzmail
runtime or release binary.

The runner refuses to operate unless it is root and has entered private mount
and network namespaces. It mounts fresh bpffs instances at the final test pin
paths, creates a veth pair
with the peer in a nested network namespace backed by a private `/run/netns`
tmpfs, and uses only the reserved
`lmyz-xdp0`, `lmyz-xdp1`, and `lmyz-xdp-peer` names. This prevents the gate from
attaching XDP to a host interface or reading and replacing host pins.

Build as the normal development user, then run only the already-built checker
as root:

```sh
cargo build --locked --manifest-path tools/lmyzmail-xdp-check/Cargo.toml
sudo tools/lmyzmail-xdp-check/run-isolated.sh \
  "$PWD/tools/lmyzmail-xdp-check/target/x86_64-unknown-linux-gnu/debug/lmyzmail-xdp-check"
```

The gate checks:

- failed initialization releases the Rust/native singleton and leaves no pin;
- a pre-existing XDP program is rejected without replacement;
- an incompatible pinned map ABI is rejected before attach;
- a concurrent lmyzmail process cannot acquire the netns/interface lock;
- a validated crash-recovery program is adopted without replacing it, and its
  two non-persistent per-IP maps remain readable by the recovered userspace;
- the final binary invokes the link-time attach and detach guards and the
  guard-owned program ID matches the kernel attachment;
- an injected detach failure retains the owner token, live program, and flock,
  while a second shutdown retries successfully and releases all three;
- generic XDP attach and detach on shutdown;
- real IPv4 and IPv6 traffic across the veth boundary;
- pass, ban, kernel drop, unban, and pass behavior;
- global, per-IP, ban-count, and PPS kernel statistics;
- exact type, key size, value size, and capacity for all eight runtime maps;
- the five persistent pinned maps and their live ABI;
- persistent IPv4 and IPv6 bans across detach and a fresh service instance.

The checker exits nonzero on every mismatch. It does not skip unsupported
privileged behavior and does not fall back to a userspace simulation.
Live map and pin metadata is queried through a narrow system-libbpf C boundary,
so the gate does not depend on a kernel-version-specific `bpftool` package.

## Attach/detach safety invariants

The frozen XDP userspace source is linked beside a narrow C guard. The final
link must wrap both `bpf_xdp_attach` and `bpf_xdp_detach`; downstream binaries
must repeat the two linker wrap arguments because Cargo does not propagate
`rustc-link-arg` from a library crate. A successful wrapped attach always uses
`XDP_FLAGS_UPDATE_IF_NOEXIST` and records the program ID from the attached
program fd before returning success. Rust treats that ID as the ownership
token for every post-attach rollback and normal shutdown. Wrapped detach
requires the same token, checks the currently attached ID, and supplies
`old_prog_fd`, so it cannot detach a replacement program.

Crash recovery validates the attached program tag, name, complete seven-map
ABI, and the identity of all five persistent pins. The two unpinned per-IP
maps are staged under fixed temporary bpffs names only long enough for the
frozen userspace library to open their FDs. Each temporary pin is matched back
to the recovery program's map ID before unlink, and the checker rejects any
residual pin. This keeps the frozen C/eBPF source and normal five-pin ABI
unchanged while ensuring traffic and userspace statistics refer to the same
maps after a process crash.
