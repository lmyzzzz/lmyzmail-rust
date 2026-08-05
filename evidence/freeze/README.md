# Frozen baseline evidence

This directory records source commits, patches, sanitized configuration keys,
resource inventories, artifact hashes, and the exact verification commands.
Generated manifests are derived from committed Git objects, never from a
drifting worktree.

The Java patch intentionally preserves documented honeypot scanner bait that
looks like cloud, database, Redis, and JWT credentials. Those example values
are fake protocol content, not secrets or production credentials; they remain
in the immutable oracle evidence because clients can observe them.
