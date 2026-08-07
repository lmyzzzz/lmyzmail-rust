-- Durable DSN eligibility and admission marker.  The source row is never
-- re-evaluated from Redis: payload_json is the terminal PostgreSQL snapshot.
CREATE TABLE IF NOT EXISTS lmyzmail_outbound_dsn (
    original_task_id BIGINT PRIMARY KEY
        REFERENCES outbound_mail_queue(id) ON DELETE RESTRICT,
    dsn_task_id BIGINT UNIQUE
        CHECK (dsn_task_id IS NULL OR dsn_task_id > 0),
    state VARCHAR(16) NOT NULL
        CHECK (state IN ('PENDING', 'LEASED', 'ADMITTING', 'ADMITTED', 'SUPPRESSED')),
    payload_json TEXT NOT NULL
        CHECK (octet_length(payload_json) BETWEEN 1 AND 4194304),
    expected_sha256 BYTEA
        CHECK (expected_sha256 IS NULL OR octet_length(expected_sha256) = 32),
    prepared_bytes BYTEA,
    suppress_reason TEXT
        CHECK (suppress_reason IS NULL OR octet_length(suppress_reason) <= 512),
    lease_token VARCHAR(100),
    lease_until TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CHECK (
        (state = 'PENDING'
            AND dsn_task_id IS NULL
            AND expected_sha256 IS NULL
            AND prepared_bytes IS NULL
            AND suppress_reason IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL)
        OR (state = 'ADMITTING'
            AND dsn_task_id IS NOT NULL
            AND ((expected_sha256 IS NULL AND prepared_bytes IS NULL)
                 OR (expected_sha256 IS NOT NULL AND prepared_bytes IS NOT NULL))
            AND suppress_reason IS NULL
            AND lease_token IS NOT NULL
            AND lease_until IS NOT NULL)
        OR (state = 'LEASED'
            AND dsn_task_id IS NULL
            AND expected_sha256 IS NULL
            AND prepared_bytes IS NULL
            AND suppress_reason IS NULL
            AND lease_token IS NOT NULL
            AND lease_until IS NOT NULL)
        OR (state = 'ADMITTED'
            AND dsn_task_id IS NOT NULL
            AND expected_sha256 IS NOT NULL
            AND prepared_bytes IS NULL
            AND suppress_reason IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL)
        OR (state = 'SUPPRESSED'
            AND expected_sha256 IS NULL
            AND prepared_bytes IS NULL
            AND suppress_reason IS NOT NULL
            AND lease_token IS NULL
            AND lease_until IS NULL)
    )
);

-- The ADD COLUMN path keeps development databases created by an earlier
-- draft of this migration usable. The named constraint supplies the same
-- recovery-image invariant to both old and newly created tables.
ALTER TABLE lmyzmail_outbound_dsn
    ADD COLUMN IF NOT EXISTS prepared_bytes BYTEA;

-- An early development build checkpointed only the digest. Those rows are
-- deliberately reopened for a fresh checkpoint; without the signed bytes a
-- digest alone cannot survive a DKIM key rotation safely.
UPDATE lmyzmail_outbound_dsn
SET expected_sha256 = NULL
WHERE state = 'ADMITTING'
  AND expected_sha256 IS NOT NULL
  AND prepared_bytes IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'lmyzmail_outbound_dsn'::regclass
          AND conname = 'lmyzmail_outbound_dsn_prepared_bytes_check'
    ) THEN
        ALTER TABLE lmyzmail_outbound_dsn
            ADD CONSTRAINT lmyzmail_outbound_dsn_prepared_bytes_check CHECK (
                (state = 'ADMITTING'
                    AND ((expected_sha256 IS NULL AND prepared_bytes IS NULL)
                         OR (expected_sha256 IS NOT NULL
                             AND prepared_bytes IS NOT NULL
                             AND octet_length(prepared_bytes) BETWEEN 1 AND 4194304)))
                OR (state <> 'ADMITTING' AND prepared_bytes IS NULL)
            );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS lmyzmail_outbound_dsn_state_idx
    ON lmyzmail_outbound_dsn(state, original_task_id);
