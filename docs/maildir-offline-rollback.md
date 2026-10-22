# Offline rollback of encoded mailbox directories

`tools/export_java_maildir.py` creates a separate Maildir that the frozen Java
reader can open. It is an offline deployment tool, not a runtime dependency.
It needs Python 3.12 and psycopg (the pinned blackbox environment supplies both).
The lmyzmail service itself still needs no Python or JVM.

The tool copies the complete source tree with bounded one-MiB reads and adds
ownership-checked Java reader aliases for indexed v2/v1 mail. It preserves the
original bytes, PostgreSQL rows, Redis state, original directories and spool.
One repeatable-read, read-only PostgreSQL transaction provides the owner/index
snapshot; every source file is checked again before publication. Files and
directories are fsynced. Publication creates a new private wrapper and atomically
renames the completed Maildir into its `maildir/` child. Existing output paths
are never overwritten. A failure leaves an unpublished `.lmyzmail-java-export-*`
directory for diagnosis and never produces an accepted output Maildir.

1. Stop both Java and lmyzmail. Prevent supervisors from restarting either
   process. Retain backups of PostgreSQL, Redis, the entire Maildir/spool,
   configuration, certificates and models. Do not run both outbound workers
   against one queue. PostgreSQL remains running for the read-only export.
2. Choose a new output directory on a trusted local filesystem. Budget for the
   complete source tree plus the extra Java aliases; the original stays intact.
   Supply the normal libpq `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE` and secure
   password mechanism, then run, for example:

   ```bash
   .blackbox/venv/bin/python tools/export_java_maildir.py \
     --offline --source /srv/lmyzmail/mail --output /srv/lmyzmail/rollback-20261023 \
     --max-bytes 107374182400 --timeout 3600
   ```

3. Require `status=passed`. Keep the JSON result and the exported
   `.lmyzmail-java-rollback.jsonl` manifest. Point the stopped Java service's
   `botmail.maildir.base` at the reported `.../maildir` path and grant the
   service access to it. Retain the same PostgreSQL/Redis endpoints and the
   **original Maildir and temporary spool at their original absolute paths**:
   queued file-mode tasks can still refer to those paths. The exporter does
   not rewrite or reset tasks, TTLs, retries or indexes. Start only Java.
4. To return to Rust, stop Java first and point lmyzmail at the exported
   Maildir, which includes the original encoded tree and Java publications.
   Reverting to the old source tree after accepting new Java mail would omit
   those publications. Keep the original for recovery; do not merge directories
   or copy database indexes separately.

The exporter fails closed on owner collisions, differing source/destination
bytes, absent indexed messages, symlinks, invalid path components, source
mutation and disk/file/directory/mailbox/row/deadline budgets. Two registered
addresses that share a lossy Java alias cannot safely roll back into frozen
Java. This refusal preserves the evidenced security exception; it is not a
claim that the vulnerable Java runtime can isolate those owners. Resolve such
ownership conflicts under a separately reviewed migration before rolling back.

`handoff-port-diagnostic-20261023/result-1.json` through `result-5.json` record
five consecutive passes with actual SMTP-created new Rust mail
for underscore, consecutive dots, literal `v1-` and Unicode addresses, followed
by this export, byte-exact frozen Java reads and a Rust reopen. It also proves
unchanged source/index rows and failed budget, offline-mode, owner-collision
and symlink publication. `pending-takeover-20261023-v6.json` independently
proves real HTTP-created PENDING memory/file-mode tasks survive both runtime
directions with exact SMTP DATA bytes, no retries/duplicates and SENT archives.
The latter also restarts Rust and observes a complete scheduling cycle to
reject resurrection of already completed tasks.
The final source-verification hardening additionally passed four focused
regular-file/FIFO/symlink/deadline checks and a fresh complete rollback cycle
in `v2-export-takeover-20261023-v5.json`. Hash verification checks its deadline
between one-MiB reads; a replaced FIFO is opened nonblocking and rejected.
These do not cover every possible in-flight delivery/crash boundary; existing
fault and recovery tests remain separate acceptance requirements.
