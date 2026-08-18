CREATE TABLE IF NOT EXISTS lmyzmail_inbound_delivery_intent (
    intent_id varchar(32) PRIMARY KEY,
    mailbox_address varchar(255) NOT NULL,
    folder varchar(50) NOT NULL,
    subdirectory integer,
    temporary_file_name varchar(255) NOT NULL,
    file_name varchar(255) NOT NULL,
    device bytea NOT NULL CHECK (octet_length(device) = 8),
    inode bytea NOT NULL CHECK (octet_length(inode) = 8),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    has_attachments boolean NOT NULL,
    received_at timestamp(6) with time zone NOT NULL,
    from_address varchar(500),
    message_id varchar(500) NOT NULL,
    subject varchar(1000),
    to_addresses varchar(2000) NOT NULL,
    state varchar(16) NOT NULL DEFAULT 'PREPARED'
        CHECK (state IN ('PREPARED', 'INDEXED')),
    created_at timestamp(6) with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp(6) with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lmyzmail_inbound_intent_recovery
    ON lmyzmail_inbound_delivery_intent (state, created_at, intent_id);

CREATE TABLE IF NOT EXISTS lmyzmail_inbound_mail_count_projection (
    mailbox_address varchar(255) NOT NULL,
    folder varchar(50) NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    desired_count bigint NOT NULL CHECK (desired_count >= 0),
    updated_at timestamp(6) with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mailbox_address, folder)
);

CREATE TABLE IF NOT EXISTS lmyzmail_inbound_mail_count_state (
    mailbox_address varchar(255) NOT NULL,
    folder varchar(50) NOT NULL,
    exact_count bigint NOT NULL CHECK (exact_count >= 0),
    updated_at timestamp(6) with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mailbox_address, folder)
);

INSERT INTO lmyzmail_inbound_mail_count_state
    (mailbox_address,folder,exact_count,updated_at)
SELECT mailbox_address,folder,COUNT(*),CURRENT_TIMESTAMP
FROM email_index
GROUP BY mailbox_address,folder
ON CONFLICT (mailbox_address,folder) DO NOTHING;
