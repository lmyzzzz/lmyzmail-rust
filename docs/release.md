# Linux x86_64 release

The runtime archive contains the lmyzmail ELF, default configuration, systemd
unit, installer/uninstaller, compact InferX model, tokenizer and video asset.
It needs no Java, JNI, Python or Rust runtime. PostgreSQL and Redis remain
external data services. The installer validates the ELF and packaged asset
hashes before changing managed files. The exact shared libraries required by
this build are recorded in `RELEASE.json`; install their x86_64 distributions
before installation. Ubuntu 24.04/WSL2 is the validated build environment.

Verify and unpack the archive on Linux, preserving Unix file permissions:

```bash
sha256sum -c SHA256SUMS
tar -xzf lmyzmail-0.1.0-rc.<commit>-linux-x86_64.tar.gz
cd lmyzmail-0.1.0-rc.<commit>
./bin/lmyzmail --version
sudo tools/install-lmyzmail.sh
```

The unit remains stopped. Edit `/etc/lmyzmail/application.properties` with the
real database/Redis endpoints, domain, Maildir and credentials; configure TLS
and listen addresses for the deployment. The example binds to loopback and
disables public registration, XDP and Minecraft until explicitly configured.
Filesystem fsync is enabled by default. Disable `lmyzmail.storage.fsync-enabled`
only if the deployment accepts the documented loss of filesystem durability.

```bash
sudo -u lmyzmail /usr/bin/lmyzmail --config /etc/lmyzmail/application.properties --check-config
sudo systemctl enable --now lmyzmail
```

For existing data, stop the old service before starting lmyzmail. The installer
never overwrites existing configuration. Legacy `botmail.*` keys remain valid;
the corresponding `lmyzmail.*` key wins when both occur. See the main README
for exact-path legacy directory grants and rollback. Do not run old and new
outbound workers concurrently against the same queue. Packaged model upgrades
replace weights atomically; restart a running process to load new weights.

The source archive contains every tracked source, frozen native source,
vendor source, model, fixture, golden and evidence file at `source_commit`.
The separate Git bundle contains all local branches and complete history:

```bash
git clone lmyzmail-0.1.0-rc.<commit>-history.bundle lmyzmail-source
cd lmyzmail-source
rustup show
cargo build --release --locked --target x86_64-unknown-linux-gnu -p lmyzmail
```

Build dependencies include the pinned Rust 1.94.0 toolchain, C/C++ toolchain,
Clang 18.1.3, pkg-config, Cairo/FreeType and the native dependencies selected
by `crates/lmyzmail/build.rs`. Cargo dependencies are pinned by Cargo.lock and
may need an initial download. Two independent frozen builds are required by
`tools/verify-release-reproducibility.sh`; this is stronger than rebuilding
from an existing target cache. The source archive intentionally excludes
temporary databases, credentials, Cargo caches and raw profiler recordings.
Those recordings remain in the development workspace.

Release-candidate packaging is not a claim that every production acceptance
gate has passed. `docs/acceptance-status.md` tracks remaining formal stability,
complete differential and SIMD execution evidence. Do not interpret a package
checksum or a successful short smoke as proof of those long-running gates.
