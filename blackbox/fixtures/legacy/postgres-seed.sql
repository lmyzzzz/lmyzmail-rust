INSERT INTO "public"."mailbox" (
    "id", "address", "password_hash", "created_at"
) VALUES (
    1001,
    'qa@example.test',
    '$2a$10$KMejGNeOXWSJBM831XMwmeVrw.16AhD65yYCs7vxZIM0osXpoyPsm',
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."user_preference" (
    "id", "mailbox_address", "preferences_json", "created_at", "updated_at"
) VALUES (
    1101,
    'qa@example.test',
    '{"itemsPerPage":25,"legacyFixture":true,"theme":"dark"}',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."contact" (
    "id", "mailbox_address", "email", "name", "notes", "created_at", "updated_at"
) VALUES (
    1201,
    'qa@example.test',
    'legacy-contact@example.test',
    'Legacy Contact',
    'Imported contact fixture',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."email_index" (
    "id", "mailbox_address", "folder", "subdirectory", "file_name", "message_id",
    "from_address", "to_addresses", "subject", "received_at", "indexed_at",
    "size_bytes", "has_attachments"
) VALUES
    (
        1301, 'qa@example.test', 'inbox', 0, 'legacy-root.eml',
        '<legacy-root@sender.example>', 'sender@sender.example', 'qa@example.test',
        'Legacy root mail', TIMESTAMPTZ '2024-01-01 00:00:00+00',
        TIMESTAMPTZ '2024-01-01 00:00:01+00', 561, FALSE
    ),
    (
        1302, 'qa@example.test', 'inbox', 1, 'legacy-shard-1.eml',
        '<legacy-shard-1@sender.example>', 'sender@sender.example', 'qa@example.test',
        'Legacy shard one', TIMESTAMPTZ '2024-01-02 00:00:00+00',
        TIMESTAMPTZ '2024-01-02 00:00:01+00', 567, FALSE
    ),
    (
        1303, 'qa@example.test', 'inbox', 2, 'legacy-shard-2.eml',
        '<legacy-shard-2@sender.example>', 'sender@sender.example', 'qa@example.test',
        'Legacy shard attachment', TIMESTAMPTZ '2024-01-03 00:00:00+00',
        TIMESTAMPTZ '2024-01-03 00:00:01+00', 869, TRUE
    );

INSERT INTO "public"."email_label" (
    "id", "mailbox_address", "label_name", "color", "created_at"
) VALUES (
    1401, 'qa@example.test', 'Legacy', '#336699', TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."email_label_assignment" (
    "id", "mailbox_address", "folder", "email_file_name", "label_id", "assigned_at"
) VALUES (
    1501, 'qa@example.test', 'inbox', 'legacy-root.eml', 1401,
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."starred_email" (
    "id", "mailbox_address", "folder", "email_file_name", "starred_at"
) VALUES (
    1601, 'qa@example.test', 'inbox', 'legacy-root.eml',
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."user_session" (
    "id", "mailbox_address", "token_hash", "token_prefix", "created_at", "expires_at",
    "last_used_at", "created_ip", "user_agent"
) VALUES (
    1701,
    'qa@example.test',
    '2643f7be36cdfb283688b1a18c0b923661046fee4f997c75b8003ddec10d8c97',
    'legacy-s',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    TIMESTAMPTZ '2099-01-01 00:00:00+00',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    '192.0.2.20',
    'lmyzmail-legacy-fixture/1'
);

INSERT INTO "public"."inbound_dmarc_log" (
    "id", "source_ip", "header_from_domain", "envelope_from_domain", "spf_domain",
    "spf_result", "spf_alignment", "dkim_domain", "dkim_selector", "dkim_result",
    "dkim_alignment", "dmarc_policy", "dmarc_result", "disposition", "message_count",
    "report_date", "received_at"
) VALUES (
    1801, '192.0.2.10', 'sender.example', 'sender.example', 'sender.example',
    'pass', 'aligned', 'sender.example', 'legacy', 'none', 'unaligned', 'reject', 'pass',
    'none', 1, DATE '2024-01-01', TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."outbound_tls_log" (
    "id", "recipient_domain", "mx_host", "target_ip", "target_port", "tls_success",
    "tls_protocol", "cipher_suite", "failure_type", "failure_reason", "mta_sts_enforced",
    "mta_sts_mode", "sts_policy_version", "sts_policy_mode", "sts_mx_patterns",
    "sts_max_age", "connection_count", "report_date", "logged_at"
) VALUES (
    1901, 'recipient.example', 'mx.recipient.example', '192.0.2.30', 25, TRUE,
    'TLSv1.3', 'TLS_AES_256_GCM_SHA384', NULL, NULL, TRUE, 'enforce', 'STSv1', 'enforce',
    'mx.recipient.example', 604800, 1, DATE '2024-01-01',
    TIMESTAMPTZ '2024-01-01 00:00:00+00'
);

INSERT INTO "public"."skibidi_cringe_ip" (
    "ip_address", "current_score", "total_score", "activity_count", "first_seen_at",
    "last_seen_at", "last_decay_at", "honeypot_hit_count", "http_port_scanning_count",
    "ssh_bruteforce_count", "open_relay_count", "illegal_domain_count",
    "self_spoofing_count", "http_on_smtp_count", "ssh_on_smtp_count", "auth_probe_count",
    "spamhaus_count", "other_count"
) VALUES (
    '203.0.113.77', 7, 7, 1, TIMESTAMPTZ '2024-01-01 00:00:00+00',
    TIMESTAMPTZ '2024-01-01 00:00:00+00', TIMESTAMPTZ '2024-01-01 00:00:00+00',
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
);

INSERT INTO "public"."skibidi_cringe_ip_activity" (
    "id", "ip_address", "activity_type", "score", "timestamp", "session_id",
    "response_message", "metadata", "helo_name", "mail_from", "rcpt_to"
) VALUES (
    2001, '203.0.113.77', 'HONEYPOT_HIT', 7, TIMESTAMPTZ '2024-01-01 00:00:00+00',
    'legacy-session', 'fixture response', '{"fixture":true}', 'legacy-client.example',
    'sender@sender.example', 'qa@example.test'
);

INSERT INTO "public"."outbound_mail_queue" (
    "id", "sender_address", "recipients_json", "subject", "body_text", "body_html",
    "attachments_json", "message_id", "sent_file_name", "sent_subdirectory", "status",
    "retry_count", "max_retries", "next_retry_at", "last_error", "sent_domains_json",
    "failed_domains_json", "created_at", "updated_at", "sent_at",
    "processing_started_at", "processor_id"
) VALUES (
    2101,
    'qa@example.test',
    '["recipient@example.invalid"]',
    'Legacy cancelled outbound task',
    'Legacy outbound body.',
    '<p>Legacy outbound body.</p>',
    '[]',
    '<legacy-outbound@example.test>',
    NULL,
    NULL,
    'CANCELLED',
    0,
    5,
    TIMESTAMPTZ '2100-01-01 00:00:00+00',
    'Cancelled before migration fixture',
    '[]',
    '{}',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    TIMESTAMPTZ '2024-01-01 00:00:00+00',
    NULL,
    NULL,
    NULL
);

SELECT pg_catalog.setval('public.contact_id_seq', 1201, TRUE);
SELECT pg_catalog.setval('public.email_index_id_seq', 1303, TRUE);
SELECT pg_catalog.setval('public.email_label_assignment_id_seq', 1501, TRUE);
SELECT pg_catalog.setval('public.email_label_id_seq', 1401, TRUE);
SELECT pg_catalog.setval('public.inbound_dmarc_log_id_seq', 1801, TRUE);
SELECT pg_catalog.setval('public.mailbox_id_seq', 1001, TRUE);
SELECT pg_catalog.setval('public.outbound_mail_queue_id_seq', 2101, TRUE);
SELECT pg_catalog.setval('public.outbound_tls_log_id_seq', 1901, TRUE);
SELECT pg_catalog.setval('public.skibidi_cringe_ip_activity_id_seq', 2001, TRUE);
SELECT pg_catalog.setval('public.starred_email_id_seq', 1601, TRUE);
SELECT pg_catalog.setval('public.user_preference_id_seq', 1101, TRUE);
SELECT pg_catalog.setval('public.user_session_id_seq', 1701, TRUE);
