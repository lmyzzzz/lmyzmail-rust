# lmyzmail Fail2Ban contract

The `lmyzmail` Fail2Ban service incrementally tails the first readable path in
`lmyzmail.fail2ban.ssh-log-paths`. It starts at EOF, accepts both traditional
syslog and RFC 5424 style lines, detects Linux device/inode rotation and
truncation, and falls back to the next configured path after an I/O failure.
The legacy `botmail.fail2ban.*` keys remain readable; a matching
`lmyzmail.fail2ban.*` key wins independently for each field.

Eight frozen SSH failure patterns produce `SSH_BRUTEFORCE` activity with score
10 after `max-retries` matches in `find-time`, subject to `report-cooldown`.
The activity and aggregate row are written in one PostgreSQL transaction using
the existing `skibidi_cringe_ip_activity` and `skibidi_cringe_ip` schema. File
reading uses one bounded blocking worker and a one-job queue; persistence admits
at most eight reports concurrently.

Input and state budgets are hard limits: 1 MiB and 8192 complete events per
scan, 64 KiB per line, 4096 timestamps per IP, and the configured 200000-IP
maximum. Complete lines beyond a scan budget are deferred by the file offset;
an oversized line is discarded only after its terminating newline. Hourly and
shutdown summaries retain at most 4096 IP details, 10 usernames, and 3 bounded
sample lines.

The candidate deliberately preserves the report cooldown when cleanup runs on
an empty post-report queue. The frozen Java cleanup removes that queue and its
cooldown marker early, which can cause a second report before the configured
cooldown; this is an approved security difference. The bounded summary and
streaming input budgets are likewise security differences outside the in-budget
protocol and PostgreSQL contract. See
`evidence/compatibility/fail2ban-v1.json` for hashes, golden observations, and
the exact verification commands.
