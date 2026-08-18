#![cfg(target_os = "linux")]

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use lmyzmail::config::{Properties, RuntimeConfig};
use lmyzmail::outbound_smtp::{
    DataStatus, DeliveryErrorKind, DeliveryPreparation, DeliveryRequest, DeliveryStage,
    MessageContentProof, MessageSource, OutboundSmtpClient, RecipientStatus, SmtpEndpoint, TlsMode,
};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Vec<u8> {
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).await.unwrap();
    assert!(line.ends_with(b"\r\n"));
    line
}

fn message_content_proof(bytes: &[u8]) -> MessageContentProof {
    MessageContentProof::new(bytes.len() as u64, Sha256::digest(bytes).into())
}

async fn read_data<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Vec<u8> {
    let mut wire = Vec::new();
    loop {
        let line = read_line(reader).await;
        wire.extend_from_slice(&line);
        if line == b".\r\n" {
            return wire;
        }
    }
}

fn tls_material() -> (Arc<ClientConfig>, TlsAcceptor) {
    let key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "smtp.example.test")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.set_pubkey(&key).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    certificate
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    certificate
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    certificate
        .append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
    certificate
        .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("smtp.example.test")
        .build(&certificate.x509v3_context(None, None))
        .unwrap();
    certificate.append_extension(san).unwrap();
    certificate.sign(&key, MessageDigest::sha256()).unwrap();
    let certificate = CertificateDer::from(certificate.build().to_der().unwrap());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        key.private_key_to_pkcs8().unwrap(),
    ));

    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    (Arc::new(client), TlsAcceptor::from(Arc::new(server)))
}

fn request(port: u16, message: MessageSource, recipients: Vec<&str>) -> DeliveryRequest {
    DeliveryRequest {
        endpoint: SmtpEndpoint::trusted_relay(([127, 0, 0, 1], port).into(), "smtp.example.test")
            .unwrap(),
        hello_name: "mail.example.test".into(),
        envelope_from: "sender@example.test".into(),
        recipients: recipients.into_iter().map(str::to_owned).collect(),
        message,
        tls_mode: TlsMode::Disabled,
        max_message_bytes: 1024 * 1024,
    }
}

fn temporary_message_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "lmyzmail-outbound-smtp-{}-{nonce}.eml",
        std::process::id()
    ))
}

#[tokio::test]
async fn configured_pool_reuses_rset_session_and_honors_message_limit() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();

        for ordinal in 0..2 {
            assert_eq!(
                read_line(&mut reader).await,
                b"MAIL FROM:<sender@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.0 sender accepted\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"RCPT TO:<accepted@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.5 recipient accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
            reader
                .get_mut()
                .write_all(b"354 send message\r\n")
                .await
                .unwrap();
            let data = read_data(&mut reader).await;
            assert!(data.starts_with(format!("Subject: pooled-{ordinal}\r\n").as_bytes()));
            reader
                .get_mut()
                .write_all(b"250 2.0.0 accepted\r\n")
                .await
                .unwrap();
            if ordinal == 0 {
                assert_eq!(read_line(&mut reader).await, b"RSET\r\n");
                reader
                    .get_mut()
                    .write_all(b"250 2.0.0 reset\r\n")
                    .await
                    .unwrap();
            }
        }

        let mut trailing = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), reader.read(&mut trailing))
                .await
                .unwrap()
                .unwrap(),
            0,
            "connection remained open after reaching its message limit"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "client opened a second connection instead of reusing the first"
        );
    });

    let config = RuntimeConfig::from_properties(
        Properties::parse(
            b"lmyzmail.outbound.pool-enabled=true\n\
              lmyzmail.outbound.max-connections-per-host=1\n\
              lmyzmail.outbound.max-messages-per-connection=2\n\
              lmyzmail.outbound.max-idle-time-ms=60000\n\
              lmyzmail.outbound.connection-life-time-ms=60000\n",
        )
        .unwrap(),
    )
    .unwrap();
    let client = OutboundSmtpClient::from_config(&config).unwrap();
    for ordinal in 0..2 {
        let message = MessageSource::Bytes(Arc::from(
            format!("Subject: pooled-{ordinal}\r\n\r\nbody\r\n").into_bytes(),
        ));
        let result = client
            .deliver(
                &request(port, message, vec!["accepted@example.test"]),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.data_status, DataStatus::Accepted);
    }
    server.await.unwrap();
}

#[tokio::test]
async fn configured_pool_lifetime_includes_connect_and_handshake_time() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for ordinal in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            tokio::time::sleep(Duration::from_millis(200)).await;
            reader
                .get_mut()
                .write_all(b"220 fixture.example ESMTP\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
            reader
                .get_mut()
                .write_all(b"250 fixture.example\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"MAIL FROM:<sender@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.0 sender accepted\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"RCPT TO:<accepted@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.5 recipient accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
            reader
                .get_mut()
                .write_all(b"354 send message\r\n")
                .await
                .unwrap();
            let data = read_data(&mut reader).await;
            assert!(data.starts_with(format!("Subject: lifetime-{ordinal}\r\n").as_bytes()));
            reader
                .get_mut()
                .write_all(b"250 2.0.0 accepted\r\n")
                .await
                .unwrap();

            let mut trailing = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), reader.read(&mut trailing))
                    .await
                    .unwrap()
                    .unwrap(),
                0,
                "connection outlived its configured lifetime or received RSET"
            );
        }
    });

    let config = RuntimeConfig::from_properties(
        Properties::parse(
            b"lmyzmail.outbound.pool-enabled=true\n\
              lmyzmail.outbound.max-connections-per-host=1\n\
              lmyzmail.outbound.max-messages-per-connection=100\n\
              lmyzmail.outbound.connection-life-time-ms=100\n",
        )
        .unwrap(),
    )
    .unwrap();
    let client = OutboundSmtpClient::from_config(&config).unwrap();
    for ordinal in 0..2 {
        let message = MessageSource::Bytes(Arc::from(
            format!("Subject: lifetime-{ordinal}\r\n\r\nbody\r\n").into_bytes(),
        ));
        let result = client
            .deliver(
                &request(port, message, vec!["accepted@example.test"]),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.data_status, DataStatus::Accepted);
    }
    server.await.unwrap();
}

#[tokio::test]
async fn failed_rset_preserves_delivery_success_and_forces_a_new_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for connection_ordinal in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            reader
                .get_mut()
                .write_all(b"220 fixture.example ESMTP\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
            reader
                .get_mut()
                .write_all(b"250 fixture.example\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"MAIL FROM:<sender@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.0 sender accepted\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"RCPT TO:<accepted@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.5 recipient accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
            reader
                .get_mut()
                .write_all(b"354 send message\r\n")
                .await
                .unwrap();
            let _ = read_data(&mut reader).await;
            reader
                .get_mut()
                .write_all(b"250 2.0.0 accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"RSET\r\n");
            if connection_ordinal == 0 {
                continue;
            }
            reader
                .get_mut()
                .write_all(b"250 2.0.0 reset\r\n")
                .await
                .unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(reader.read(&mut trailing).await.unwrap(), 0);
        }
    });

    let config = RuntimeConfig::from_properties(
        Properties::parse(
            b"lmyzmail.outbound.pool-enabled=true\n\
              lmyzmail.outbound.max-connections-per-host=1\n\
              lmyzmail.outbound.max-messages-per-connection=100\n",
        )
        .unwrap(),
    )
    .unwrap();
    let client = OutboundSmtpClient::from_config(&config).unwrap();
    for ordinal in 0..2 {
        let message = MessageSource::Bytes(Arc::from(
            format!("Subject: reset-failure-{ordinal}\r\n\r\nbody\r\n").into_bytes(),
        ));
        let result = client
            .deliver(
                &request(port, message, vec!["accepted@example.test"]),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.data_status, DataStatus::Accepted);
    }
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn remotely_closed_idle_session_is_not_reused() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for ordinal in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            reader
                .get_mut()
                .write_all(b"220 fixture.example ESMTP\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
            reader
                .get_mut()
                .write_all(b"250 fixture.example\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"MAIL FROM:<sender@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.0 sender accepted\r\n")
                .await
                .unwrap();
            assert_eq!(
                read_line(&mut reader).await,
                b"RCPT TO:<accepted@example.test>\r\n"
            );
            reader
                .get_mut()
                .write_all(b"250 2.1.5 recipient accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
            reader
                .get_mut()
                .write_all(b"354 send message\r\n")
                .await
                .unwrap();
            let data = read_data(&mut reader).await;
            assert!(data.starts_with(format!("Subject: remote-close-{ordinal}\r\n").as_bytes()));
            reader
                .get_mut()
                .write_all(b"250 2.0.0 accepted\r\n")
                .await
                .unwrap();
            assert_eq!(read_line(&mut reader).await, b"RSET\r\n");
            reader
                .get_mut()
                .write_all(b"250 2.0.0 reset\r\n")
                .await
                .unwrap();
            if ordinal == 0 {
                continue;
            }
            let mut trailing = [0_u8; 1];
            assert_eq!(reader.read(&mut trailing).await.unwrap(), 0);
        }
    });

    let config = RuntimeConfig::from_properties(
        Properties::parse(
            b"lmyzmail.outbound.pool-enabled=true\n\
              lmyzmail.outbound.max-connections-per-host=1\n\
              lmyzmail.outbound.max-messages-per-connection=100\n",
        )
        .unwrap(),
    )
    .unwrap();
    let client = OutboundSmtpClient::from_config(&config).unwrap();
    for ordinal in 0..2 {
        let message = MessageSource::Bytes(Arc::from(
            format!("Subject: remote-close-{ordinal}\r\n\r\nbody\r\n").into_bytes(),
        ));
        let result = client
            .deliver(
                &request(port, message, vec!["accepted@example.test"]),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.data_status, DataStatus::Accepted);
        if ordinal == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn prepare_stops_before_data_terminator_until_commit() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (body_ready, wait_for_body) = oneshot::channel();
    let (barrier_checked, wait_for_barrier) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();

        let expected = b"Subject: barrier\r\n\r\nbody\r\n";
        let mut body = vec![0_u8; expected.len()];
        reader.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
        body_ready.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), read_line(&mut reader))
                .await
                .is_err(),
            "DATA terminator crossed the durable commit barrier"
        );
        barrier_checked.send(()).unwrap();
        assert_eq!(read_line(&mut reader).await, b".\r\n");
        reader
            .get_mut()
            .write_all(b"250 2.0.0 accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"QUIT\r\n");
        reader
            .get_mut()
            .write_all(b"221 2.0.0 bye\r\n")
            .await
            .unwrap();
    });

    let message = MessageSource::Bytes(Arc::from(&b"Subject: barrier\r\n\r\nbody\r\n"[..]));
    let cancellation = CancellationToken::new();
    let preparation = OutboundSmtpClient::default()
        .prepare(
            &request(port, message, vec!["accepted@example.test"]),
            &cancellation,
        )
        .await
        .unwrap();
    wait_for_body.await.unwrap();
    let DeliveryPreparation::CommitReady(prepared) = preparation else {
        panic!("accepted recipient did not produce a commit-ready transaction");
    };
    wait_for_barrier.await.unwrap();
    let result = prepared.commit().await.unwrap();
    server.await.unwrap();
    assert_eq!(result.data_status, DataStatus::Accepted);
}

#[tokio::test]
async fn cancellation_after_commit_barrier_is_ambiguous() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (body_ready, wait_for_body) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let expected = b"Subject: barrier\r\n\r\nbody\r\n";
        let mut body = vec![0_u8; expected.len()];
        reader.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
        body_ready.send(()).unwrap();
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut trailing))
            .await
            .unwrap()
            .unwrap();
        assert!(trailing.is_empty() || trailing == b".\r\n");
    });

    let cancellation = CancellationToken::new();
    let preparation = OutboundSmtpClient::default()
        .prepare(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: barrier\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &cancellation,
        )
        .await
        .unwrap();
    wait_for_body.await.unwrap();
    let DeliveryPreparation::CommitReady(prepared) = preparation else {
        panic!("accepted recipient did not produce a commit-ready transaction");
    };
    cancellation.cancel();
    let failure = prepared.commit().await.unwrap_err();
    assert_eq!(failure.kind, DeliveryErrorKind::Ambiguous);
    assert_eq!(failure.stage, DeliveryStage::DataFinal);
    server.await.unwrap();
}

#[tokio::test]
async fn pipelines_recipients_and_streams_dot_stuffed_file_after_354() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250-PIPE")
            .await
            .unwrap();
        tokio::task::yield_now().await;
        reader
            .get_mut()
            .write_all(b"LINING\r\n250 SIZE 1048576\r\n")
            .await
            .unwrap();

        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<temporary@example.test>\r\n"
        );
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<permanent@example.test>\r\n"
        );
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(
                b"250 2.1.0 sender accepted\r\n\
                  451 4.2.0 mailbox busy\r\n\
                  550 5.1.1 mailbox missing\r\n\
                  250 2.1.5 recipient accepted\r\n",
            )
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let wire = read_data(&mut reader).await;
        assert!(
            wire.windows(b"\r\n..cross-boundary\r\n".len())
                .any(|window| { window == b"\r\n..cross-boundary\r\n" })
        );
        assert!(wire.ends_with(b".\r\n"));
        reader
            .get_mut()
            .write_all(b"250 2.0.0 accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"QUIT\r\n");
        reader
            .get_mut()
            .write_all(b"221 2.0.0 bye\r\n")
            .await
            .unwrap();
    });

    let path = temporary_message_path();
    let mut message = b"Subject: boundary\r\n\r\n".to_vec();
    message.resize(16_382, b'a');
    message.extend_from_slice(b"\r\n.cross-boundary\r\n");
    fs::write(&path, &message).await.unwrap();
    let result = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::file_under_root(
                    path.parent().unwrap(),
                    path.file_name().unwrap(),
                    message_content_proof(&message),
                )
                .unwrap(),
                vec![
                    "temporary@example.test",
                    "permanent@example.test",
                    "accepted@example.test",
                ],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    fs::remove_file(path).await.unwrap();
    server.await.unwrap();

    assert!(result.pipelining);
    assert!(!result.tls);
    assert_eq!(result.data_status, DataStatus::Accepted);
    assert_eq!(
        result
            .recipients
            .iter()
            .map(|value| value.status)
            .collect::<Vec<_>>(),
        [
            RecipientStatus::TemporaryFailure,
            RecipientStatus::PermanentFailure,
            RecipientStatus::Accepted,
        ]
    );
}

#[tokio::test]
async fn disconnect_after_complete_data_is_ambiguous() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let wire = read_data(&mut reader).await;
        assert_eq!(wire, b"Subject: ambiguous\r\n\r\nbody\r\n.\r\n");
    });

    let failure = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: ambiguous\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Ambiguous);
    assert_eq!(failure.stage, DeliveryStage::DataFinal);
    assert_eq!(failure.recipients.len(), 1);
    assert_eq!(failure.recipients[0].status, RecipientStatus::Accepted);
}

#[tokio::test]
async fn required_starttls_repeats_ehlo_and_enables_smtp_utf8() {
    let (client_tls, acceptor) = tls_material();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250-STARTTLS\r\n250 SMTPUTF8\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"STARTTLS\r\n");
        reader
            .get_mut()
            .write_all(b"220 2.0.0 ready\r\n")
            .await
            .unwrap();
        let stream = reader.into_inner();
        let tls = acceptor.accept(stream).await.unwrap();
        let mut reader = BufReader::new(tls);
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250-PIPELINING\r\n250 SMTPUTF8\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            "MAIL FROM:<送信@example.test> SMTPUTF8\r\n".as_bytes()
        );
        assert_eq!(
            read_line(&mut reader).await,
            "RCPT TO:<受信@example.test>\r\n".as_bytes()
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let wire = read_data(&mut reader).await;
        assert_eq!(wire, b"Subject: utf8\r\n\r\nbody\r\n.\r\n");
        reader
            .get_mut()
            .write_all(b"250 2.0.0 accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"QUIT\r\n");
        reader
            .get_mut()
            .write_all(b"221 2.0.0 bye\r\n")
            .await
            .unwrap();
    });

    let client = OutboundSmtpClient::new(
        client_tls,
        std::time::Duration::from_secs(3),
        std::time::Duration::from_secs(3),
        std::time::Duration::from_secs(10),
    )
    .unwrap();
    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"Subject: utf8\r\n\r\nbody\r\n"[..])),
        vec!["受信@example.test"],
    );
    delivery.envelope_from = "送信@example.test".into();
    delivery.tls_mode = TlsMode::Required;
    let result = client
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap();
    server.await.unwrap();
    assert!(result.tls);
    assert!(result.smtp_utf8);
    assert!(result.pipelining);
    assert_eq!(result.data_status, DataStatus::Accepted);
}

#[tokio::test]
async fn buffered_plaintext_after_starttls_is_not_downgraded() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"STARTTLS\r\n");
        reader
            .get_mut()
            .write_all(b"220 2.0.0 ready\r\n250 2.0.0 injected plaintext\r\n")
            .await
            .unwrap();
    });

    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"Subject: blocked\r\n\r\nbody\r\n"[..])),
        vec!["accepted@example.test"],
    );
    delivery.tls_mode = TlsMode::Opportunistic;
    let failure = OutboundSmtpClient::default()
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Protocol);
    assert!(failure.message.contains("plaintext bytes"));
}

#[tokio::test]
async fn total_deadline_after_complete_data_is_ambiguous() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        tokio::time::sleep(Duration::from_millis(600)).await;
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let _ = read_data(&mut reader).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
    });

    let client = OutboundSmtpClient::new(
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        ),
        Duration::from_millis(250),
        Duration::from_secs(1),
        Duration::from_millis(1_200),
    )
    .unwrap();
    let failure = client
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: deadline\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Ambiguous);
    assert_eq!(failure.stage, DeliveryStage::DataFinal);
    assert_eq!(failure.recipients.len(), 1);
    assert!(failure.message.contains("deadline exceeded"));
}

#[tokio::test]
async fn cancellation_after_complete_data_is_ambiguous() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (data_complete_tx, data_complete_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let _ = read_data(&mut reader).await;
        data_complete_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    let canceller = tokio::spawn(async move {
        data_complete_rx.await.unwrap();
        cancel.cancel();
    });
    let failure = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: cancel\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &cancellation,
        )
        .await
        .unwrap_err();
    canceller.await.unwrap();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Ambiguous);
    assert_eq!(failure.stage, DeliveryStage::DataFinal);
    assert_eq!(failure.recipients.len(), 1);
    assert!(failure.message.contains("cancelled"));
}

#[tokio::test]
async fn helo_fallback_preserves_rejections_and_never_starts_data() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example SMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"500 5.5.1 EHLO unsupported\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"HELO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<missing@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"550 5.1.1 recipient missing\r\n")
            .await
            .unwrap();
        let mut trailing = Vec::new();
        reader.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
    });

    let result = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: rejected\n\nbody\n"[..])),
                vec!["missing@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    server.await.unwrap();
    assert!(!result.pipelining);
    assert_eq!(result.data_status, DataStatus::NotAttempted);
    assert_eq!(
        result.recipients[0].status,
        RecipientStatus::PermanentFailure
    );
}

#[tokio::test]
async fn normalizes_mixed_line_endings_and_supports_null_reverse_path() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"MAIL FROM:<>\r\n");
        reader
            .get_mut()
            .write_all(b"250 2.1.0 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.1.5 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_data(&mut reader).await,
            b"a\r\n..b\r\nc\r\n..d\r\n.\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 2.0.0 accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"QUIT\r\n");
        reader
            .get_mut()
            .write_all(b"221 2.0.0 bye\r\n")
            .await
            .unwrap();
    });

    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"a\n.b\rc\r\n.d"[..])),
        vec!["accepted@example.test"],
    );
    delivery.envelope_from.clear();
    let result = OutboundSmtpClient::default()
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(result.data_status, DataStatus::Accepted);
}

#[tokio::test]
async fn unavailable_file_is_rejected_before_data() {
    let missing = temporary_message_path();
    let failure = MessageSource::file_under_root(
        missing.parent().unwrap(),
        missing.file_name().unwrap(),
        MessageContentProof::new(0, [0; 32]),
    )
    .unwrap_err();
    assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
}

#[tokio::test]
async fn unexpected_success_code_after_data_is_ambiguous() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let _ = read_data(&mut reader).await;
        reader
            .get_mut()
            .write_all(b"220 invalid success code\r\n")
            .await
            .unwrap();
    });
    let failure = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: invalid\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Ambiguous);
    assert_eq!(failure.stage, DeliveryStage::DataFinal);
    assert_eq!(failure.recipients.len(), 1);
}

#[tokio::test]
async fn required_tls_rejects_server_without_starttls() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250 fixture.example\r\n")
            .await
            .unwrap();
        let mut trailing = Vec::new();
        reader.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
    });
    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"Subject: tls\r\n\r\nbody\r\n"[..])),
        vec!["accepted@example.test"],
    );
    delivery.tls_mode = TlsMode::Required;
    let failure = OutboundSmtpClient::default()
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
    assert_eq!(
        failure.message,
        "MTA-STS policy requires TLS, but server does not support STARTTLS"
    );
}

#[tokio::test]
async fn required_tls_validates_server_name() {
    let (client_tls, acceptor) = tls_material();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"STARTTLS\r\n");
        reader
            .get_mut()
            .write_all(b"220 2.0.0 ready\r\n")
            .await
            .unwrap();
        assert!(acceptor.accept(reader.into_inner()).await.is_err());
    });
    let client = OutboundSmtpClient::new(
        client_tls,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(10),
    )
    .unwrap();
    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"Subject: tls\r\n\r\nbody\r\n"[..])),
        vec!["accepted@example.test"],
    );
    delivery.endpoint =
        SmtpEndpoint::trusted_relay(([127, 0, 0, 1], port).into(), "wrong.example.test").unwrap();
    delivery.tls_mode = TlsMode::Required;
    let failure = client
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
    assert_eq!(
        failure.message,
        "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
         MTA-STS enforced TLS handshake failed: TLS handshake failed: \
         General OpenSslEngine problem"
    );
}

#[tokio::test]
async fn overlong_reply_line_is_rejected_with_bounded_protocol_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reply = b"220 ".to_vec();
        reply.resize(2_049, b'a');
        reply.extend_from_slice(b"\r\n");
        stream.write_all(&reply).await.unwrap();
    });
    let failure = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: bound\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Protocol);
    assert!(failure.message.contains("byte budget"));
}

#[tokio::test]
async fn greeting_554_is_a_structured_endpoint_failure() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"554 5.3.0 service unavailable\r\n")
            .await
            .unwrap();
    });
    let failure = OutboundSmtpClient::default()
        .deliver(
            &request(
                port,
                MessageSource::Bytes(Arc::from(&b"Subject: endpoint\r\n\r\nbody\r\n"[..])),
                vec!["accepted@example.test"],
            ),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert_eq!(failure.kind, DeliveryErrorKind::Temporary);
    assert_eq!(failure.stage, DeliveryStage::Greeting);
    assert_eq!(failure.smtp_code, Some(554));
}

#[tokio::test]
async fn opportunistic_tls_name_failure_retries_on_a_fresh_plaintext_connection() {
    let (client_tls, acceptor) = tls_material();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"STARTTLS\r\n");
        reader
            .get_mut()
            .write_all(b"220 2.0.0 ready\r\n")
            .await
            .unwrap();
        assert!(acceptor.accept(reader.into_inner()).await.is_err());

        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(b"220 fixture.example ESMTP\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"EHLO mail.example.test\r\n");
        reader
            .get_mut()
            .write_all(b"250-fixture.example\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"MAIL FROM:<sender@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 sender accepted\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_line(&mut reader).await,
            b"RCPT TO:<accepted@example.test>\r\n"
        );
        reader
            .get_mut()
            .write_all(b"250 recipient accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"DATA\r\n");
        reader
            .get_mut()
            .write_all(b"354 send message\r\n")
            .await
            .unwrap();
        let _ = read_data(&mut reader).await;
        reader
            .get_mut()
            .write_all(b"250 accepted\r\n")
            .await
            .unwrap();
        assert_eq!(read_line(&mut reader).await, b"QUIT\r\n");
        reader.get_mut().write_all(b"221 bye\r\n").await.unwrap();
    });
    let client = OutboundSmtpClient::new(
        client_tls,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(10),
    )
    .unwrap();
    let mut delivery = request(
        port,
        MessageSource::Bytes(Arc::from(&b"Subject: fallback\r\n\r\nbody\r\n"[..])),
        vec!["accepted@example.test"],
    );
    delivery.endpoint =
        SmtpEndpoint::trusted_relay(([127, 0, 0, 1], port).into(), "wrong.example.test").unwrap();
    delivery.tls_mode = TlsMode::Opportunistic;
    let result = client
        .deliver(&delivery, &CancellationToken::new())
        .await
        .unwrap();
    server.await.unwrap();
    assert!(!result.tls);
    assert_eq!(result.data_status, DataStatus::Accepted);
}
