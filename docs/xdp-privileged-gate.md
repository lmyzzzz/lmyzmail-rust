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
