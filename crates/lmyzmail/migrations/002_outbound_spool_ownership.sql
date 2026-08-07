CREATE TABLE IF NOT EXISTS lmyzmail_outbound_spool (
    task_id BIGINT PRIMARY KEY,
    spool_path TEXT NOT NULL
        CHECK (octet_length(spool_path) BETWEEN 1 AND 4096),
    spool_kind VARCHAR(16) NOT NULL
        CHECK (spool_kind IN ('RUST', 'LEGACY_JAVA')),
    cleanup_state VARCHAR(16) NOT NULL
        CHECK (cleanup_state IN ('OWNED', 'REMOVED')),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    UNIQUE (spool_path)
);

DO $lmyzmail$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'lmyzmail_outbound_spool'::regclass
          AND conname = 'lmyzmail_outbound_spool_task_id_fkey'
          AND confdeltype <> 'r'
    ) THEN
        ALTER TABLE lmyzmail_outbound_spool
            DROP CONSTRAINT lmyzmail_outbound_spool_task_id_fkey;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'lmyzmail_outbound_spool'::regclass
          AND conname = 'lmyzmail_outbound_spool_task_id_fkey'
    ) THEN
        ALTER TABLE lmyzmail_outbound_spool
            ADD CONSTRAINT lmyzmail_outbound_spool_task_id_fkey
            FOREIGN KEY (task_id) REFERENCES outbound_mail_queue(id) ON DELETE RESTRICT;
    END IF;
END
$lmyzmail$;

CREATE INDEX IF NOT EXISTS lmyzmail_outbound_spool_cleanup_idx
    ON lmyzmail_outbound_spool(cleanup_state, task_id);
