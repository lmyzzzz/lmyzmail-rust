# Playwright browser fixture

The black-box harness is pinned to Playwright `1.54.0` (`chromium-1181`,
`chromium_headless_shell-1181`, and `ffmpeg-1011`). The browser bytes are kept
outside Git. `bin/provision-playwright.sh` restores them only from the local
`.blackbox/playwright-cache` directory (or `LMYZMAIL_PLAYWRIGHT_CACHE`) and
never downloads packages.

The three lock files are generated from a pristine installation on a normal
Linux filesystem by the explicit `bin/record-playwright-manifests.sh` command.
`LMYZMAIL_PLAYWRIGHT_SOURCE` may select that read-only source tree.

* `playwright-files.sha256` contains every regular-file digest.
* `playwright-links.lock` contains every symlink and its exact target.
* `playwright-modes.lock` contains every node type, mode, and relative path.

Both cache and target paths are canonicalized and must remain under the
repository `.blackbox` directory. Provisioning is serialized with `flock`,
copies into a staging directory, verifies the staged tree, and swaps it into
place atomically. A target that already matches all three manifests is reused.

On filesystems that preserve Unix mode changes, every mode is compared exactly.
DrvFS without metadata reports every node as `0777`; the provisioner detects
that limitation with a chmod probe and then still compares every node type and
path, symlink target, and file hash. Production Linux filesystems must pass the
full mode comparison.

To seed the offline cache from an already accepted WSL installation, copy the
tree with metadata preserved, then provision into a separate target:

```sh
mkdir -p -- .blackbox/playwright-cache
cp -a -- .blackbox/ms-playwright/. .blackbox/playwright-cache/
LMYZMAIL_PLAYWRIGHT_CACHE=.blackbox/playwright-cache \
LMYZMAIL_PLAYWRIGHT_ROOT=.blackbox/ms-playwright \
    blackbox/bin/provision-playwright.sh
```
