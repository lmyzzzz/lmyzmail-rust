# Frozen baseline evidence

This directory records source commits, patches, sanitized configuration keys,
resource inventories, artifact hashes, and the exact verification commands.
Generated manifests are derived from committed Git objects, never from a
drifting worktree.

The Java baseline records two byte identities from the same source state. The
user-provided `040bfa...` identity was an incremental `bootJar` that existed and
ran before the mandatory clean rebuild. The selected `fe2d8f...` identity is the
artifact produced by the required `clean test bootJar --rerun-tasks` run. Their
equal sizes but different hashes are caused by preserved ZIP entry timestamps;
the complete timeline and selection rule are in
`java-oracle/artifact-provenance.json`.

The Java patch intentionally preserves documented honeypot scanner bait that
looks like cloud, database, Redis, and JWT credentials. Those example values
are fake protocol content, not secrets or production credentials; they remain
in the immutable oracle evidence because clients can observe them.
