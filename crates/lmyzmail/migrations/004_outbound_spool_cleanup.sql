ALTER TABLE lmyzmail_outbound_spool
    ADD COLUMN IF NOT EXISTS cleanup_after_publish BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS lmyzmail_outbound_spool_recovery_idx
    ON lmyzmail_outbound_spool(cleanup_state, cleanup_after_publish, task_id);
