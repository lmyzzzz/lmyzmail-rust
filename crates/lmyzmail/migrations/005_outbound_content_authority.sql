CREATE TABLE IF NOT EXISTS lmyzmail_outbound_content (
    task_id BIGINT PRIMARY KEY
        REFERENCES outbound_mail_queue(id) ON DELETE CASCADE,
    source_root VARCHAR(16) NOT NULL
        CHECK (source_root IN ('SPOOL', 'MAILDIR')),
    relative_path TEXT NOT NULL
        CHECK (
            octet_length(relative_path) BETWEEN 1 AND 4096
            AND relative_path !~ '(^|/)\.\.?(/|$)'
            AND left(relative_path, 1) <> '/'
        ),
    content_size BIGINT NOT NULL
        CHECK (content_size >= 0),
    content_sha256 BYTEA NOT NULL
        CHECK (octet_length(content_sha256) = 32),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS lmyzmail_outbound_content_root_idx
    ON lmyzmail_outbound_content(source_root, task_id);
