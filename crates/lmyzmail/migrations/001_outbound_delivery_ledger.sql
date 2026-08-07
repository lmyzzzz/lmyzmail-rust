CREATE TABLE IF NOT EXISTS lmyzmail_outbound_delivery_attempt (
    task_id BIGINT PRIMARY KEY
        REFERENCES outbound_mail_queue(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL CHECK (generation > 0),
    owner_token VARCHAR(100),
    recipient_count INTEGER NOT NULL
        CHECK (recipient_count > 0 AND recipient_count <= 1000),
    roster_sha256 BYTEA NOT NULL CHECK (octet_length(roster_sha256) = 32),
    phase VARCHAR(20) NOT NULL
        CHECK (phase IN ('PREPARING', 'COMMIT_ARMED', 'PROJECTED')),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CHECK (
        (phase = 'PROJECTED' AND owner_token IS NULL)
        OR (phase <> 'PROJECTED' AND owner_token IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS lmyzmail_outbound_delivery_recipient (
    task_id BIGINT NOT NULL
        REFERENCES lmyzmail_outbound_delivery_attempt(task_id) ON DELETE CASCADE,
    recipient_ordinal INTEGER NOT NULL
        CHECK (recipient_ordinal >= 0 AND recipient_ordinal < 1000),
    recipient_address VARCHAR(320) NOT NULL
        CHECK (octet_length(recipient_address) BETWEEN 1 AND 320),
    state VARCHAR(20) NOT NULL
        CHECK (state IN (
            'PENDING', 'RETRYABLE', 'PERMANENT', 'COMMIT_ARMED',
            'DELIVERED', 'AMBIGUOUS'
        )),
    attempt_generation BIGINT NOT NULL CHECK (attempt_generation >= 0),
    smtp_code INTEGER CHECK (smtp_code BETWEEN 100 AND 599),
    detail TEXT CHECK (detail IS NULL OR octet_length(detail) <= 2000),
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    PRIMARY KEY (task_id, recipient_ordinal)
);

CREATE INDEX IF NOT EXISTS lmyzmail_delivery_recipient_state_idx
    ON lmyzmail_outbound_delivery_recipient(task_id, state, recipient_ordinal);

CREATE OR REPLACE FUNCTION lmyzmail_guard_delivery_recipient_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.task_id <> OLD.task_id
       OR NEW.recipient_ordinal <> OLD.recipient_ordinal
       OR NEW.recipient_address <> OLD.recipient_address THEN
        RAISE EXCEPTION 'delivery recipient identity is immutable';
    END IF;

    IF OLD.state IN ('DELIVERED', 'PERMANENT', 'AMBIGUOUS')
       AND NEW.state <> OLD.state THEN
        RAISE EXCEPTION 'terminal delivery recipient state is immutable';
    END IF;

    IF OLD.state = 'COMMIT_ARMED'
       AND NEW.state NOT IN (
           'COMMIT_ARMED', 'DELIVERED', 'RETRYABLE', 'PERMANENT', 'AMBIGUOUS'
       ) THEN
        RAISE EXCEPTION 'invalid armed delivery recipient transition';
    END IF;

    IF OLD.state = 'RETRYABLE'
       AND NEW.state NOT IN ('RETRYABLE', 'PERMANENT', 'COMMIT_ARMED') THEN
        RAISE EXCEPTION 'invalid retryable delivery recipient transition';
    END IF;

    IF OLD.state = 'PENDING'
       AND NEW.state NOT IN ('PENDING', 'RETRYABLE', 'PERMANENT', 'COMMIT_ARMED') THEN
        RAISE EXCEPTION 'invalid pending delivery recipient transition';
    END IF;

    RETURN NEW;
END;
$$;

DO $$
BEGIN
    CREATE TRIGGER lmyzmail_delivery_recipient_transition_guard
        BEFORE UPDATE ON lmyzmail_outbound_delivery_recipient
        FOR EACH ROW
        EXECUTE FUNCTION lmyzmail_guard_delivery_recipient_transition();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;
