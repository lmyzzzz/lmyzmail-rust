# Privileged XDP acceptance gate

`tools/lmyzmail-xdp-check` is intentionally excluded from the default Cargo
workspace. It is a Linux x86_64 acceptance tool, not part of the lmyzmail
runtime or release binary.

The runner refuses to operate unless it is root and has entered private mount
and network namespaces. It mounts fresh bpffs instances at the production
`/sys/fs/bpf/lmyzmail` path, the legacy `/sys/fs/bpf/botmail` path, and the
rollback fixture path, then creates a veth pair
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
- incompatible and partial legacy pin sets are rejected before attach;
- a crash-owned program, persistent ban, and all five maps under the legacy
  path are adopted through same-map-ID aliases under the new default path;
- legacy aliases remain present for rollback, while any existing new-path pin
  prevents fallback to legacy state;
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
- an enabled PPS monitor with `record-to-cringe=false` makes no PostgreSQL
  connection and creates no automatic ban even when threshold events fire;
  the checker waits for a completed baseline poll and a real event rather than
  relying on elapsed wall time, and reports positive `recordDisabledCompletedPolls`
  and `recordDisabledObservedEvents` counters;
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

## Legacy pin takeover

Legacy takeover is attempted only when the configured pin path is exactly the
new default `/sys/fs/bpf/lmyzmail`. Custom paths and an explicitly configured
legacy path do not trigger it. If any persistent new-path pin exists, that
state has priority and no legacy alias is created.

When the new path has no persistent pins, the native guard requires the legacy
directory to be a real root-owned directory with no group or world write bit.
All five legacy maps must exist and match the complete frozen ABI. For crash
recovery, Rust additionally proves that those exact map IDs belong to the
already attached program before adoption. The guard then pins the same kernel
map file descriptors under the new names, validates the new directory with the
same ownership and mode rules, and Rust repeats full program/map identity
validation through the new aliases.

Adoption never unlinks `/sys/fs/bpf/botmail`, so a rollback can continue to use
the old pins. A failed partial adoption removes only new aliases whose kernel
map IDs match the current attempt; it never removes a pre-existing or replaced
object.
