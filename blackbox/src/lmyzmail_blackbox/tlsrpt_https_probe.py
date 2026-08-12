from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from typing import Any, cast

import psycopg

from .persistent_runtime import PersistentJavaOracleRuntime
from .protocols import http_exchange
from .runtime import API_KEY, CandidateRuntime, JavaOracleRuntime
from .scripted_dns import AAnswer, DnsAnswer, DnsQuery, ScriptedDnsServer, TxtAnswer
from .scripted_https import HttpsRequest, HttpsScenario, ScriptedHttpsServer
from .tls_fixture import (
    EphemeralOutboundTlsMaterial,
    create_server_ssl_context,
    provision_ephemeral_outbound_tls_material,
)

_TARGET_ENV = "LMYZMAIL_TLSRPT_TARGET"
_PUBLIC_IP = "93.184.216.34"
_REPORT_DATE = "2024-01-01"
_DATABASE = "lmyzmail"
_DATABASE_USER = "lmyzmail_test"
_MAX_REPORT_BYTES = 4 * 1024 * 1024
_UUID_V4 = re.compile(
    rb"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_CASES = ("success", "redirect", "certificate_failure", "private_address", "timeout")
_DOMAINS = {label: f"{label.replace('_', '-')}.delivery.tlsrpt.fixture.test" for label in _CASES}
_COLLECTORS = {
    label: f"collector-{label.replace('_', '-')}.tlsrpt.fixture.test" for label in _CASES
}
_ENDPOINTS = {
    label: f"https://{_COLLECTORS[label]}/v1/reports/tls?case={label.replace('_', '-')}"
    for label in _CASES
}
_PUBLIC_COLLECTORS = tuple(
    host for label, host in _COLLECTORS.items() if label != "private_address"
)


class TlsRptJavaRuntime(PersistentJavaOracleRuntime):
    def __init__(
        self,
        workspace_path: Path,
        *,
        dns: ScriptedDnsServer,
        tls_material: EphemeralOutboundTlsMaterial,
    ) -> None:
        super().__init__(workspace_path, index_migration_enabled=False)
        self.report_dns = dns
        self.tls_material = tls_material

    def _application_arguments(self) -> list[str]:
        workspace, _ = self._require_state()
        hosts_file = workspace / "tlsrpt-hosts"
        hosts_file.write_text(
            f"{_PUBLIC_IP} {' '.join(_PUBLIC_COLLECTORS)}\n"
            f"127.0.0.1 {_COLLECTORS['private_address']}\n",
            encoding="ascii",
        )
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments[jar_index:jar_index] = (
            f"-Djdk.net.hosts.file={hosts_file}",
            f"-Ddns.server={self.report_dns.host}:{self.report_dns.port}",
            f"-Djavax.net.ssl.trustStore={self.tls_material.java_truststore_path}",
            "-Djavax.net.ssl.trustStoreType=PKCS12",
            "-Djavax.net.ssl.trustStorePassword="
            f"{self.tls_material.java_truststore_password}",
        )
        disabled = "--botmail.reporting.http-delivery-enabled=false"
        arguments[arguments.index(disabled)] = "--botmail.reporting.http-delivery-enabled=true"
        arguments.extend(
            (
                "--botmail.reporting.dmarc-report-sender-address=qa@example.test",
                "--botmail.reporting.tls-report-sender-address=qa@example.test",
                "--botmail.reporting.organization-name=Blackbox Reports",
                "--botmail.reporting.organization-email=reports@example.test",
                "--botmail.reporting.http-delivery-timeout-seconds=2",
                "--botmail.queue.poll-interval-ms=60000",
            )
        )
        return arguments


class TlsRptCandidateRuntime(CandidateRuntime):
    def __init__(
        self,
        *,
        command_template: tuple[str, ...],
        dns: ScriptedDnsServer,
        tls_material: EphemeralOutboundTlsMaterial,
    ) -> None:
        super().__init__(command_template=command_template)
        self.report_dns = dns
        self.tls_material = tls_material

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["features"]["report_delivery"] = True
        value["reporting"] = {
            "enabled": True,
            "auto_send_enabled": False,
            "dns_server": f"{self.report_dns.host}:{self.report_dns.port}",
            "dmarc_report_sender_address": "qa@example.test",
            "tls_report_sender_address": "qa@example.test",
            "organization_name": "Blackbox Reports",
            "organization_email": "reports@example.test",
            "http_delivery_enabled": True,
            "http_delivery_timeout_seconds": 2,
        }
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _application_environment(self) -> dict[str, str]:
        environment = super()._application_environment()
        environment["SSL_CERT_FILE"] = str(self.tls_material.ca_certificate_path)
        return environment

    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        arguments.extend(
            (
                "--lmyzmail.reporting.enabled=true",
                "--lmyzmail.reporting.http-delivery-enabled=true",
                "--lmyzmail.reporting.http-delivery-timeout-seconds=2",
                "--lmyzmail.queue.poll-interval-ms=60000",
                "--lmyzmail.maildir.max-files-per-directory=1",
            )
        )
        return arguments

    def _start_postgres(self) -> None:
        super()._start_postgres()
        workspace, ports = self._require_state()
        psql = self.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        seed = self.paths.repository / "blackbox/fixtures/legacy/postgres-seed.sql"
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                f"--file={seed}",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-seed.log",
        )


def _target() -> str:
    value = os.environ.get(_TARGET_ENV, "java").casefold()
    if value not in {"java", "candidate"}:
        raise AssertionError(f"unsupported TLSRPT target: {value}")
    return value


def _dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    answers: dict[tuple[str, int], DnsAnswer] = {}
    for label in _CASES:
        domain = _DOMAINS[label]
        collector = _COLLECTORS[label]
        answers[(f"_smtp._tls.{domain}", 16)] = DnsAnswer(
            txt=(TxtAnswer((f"v=TLSRPTv1; rua={_ENDPOINTS[label]}",), ttl=0),)
        )
        address = "127.0.0.1" if label == "private_address" else _PUBLIC_IP
        answers[(collector, 1)] = DnsAnswer(a=(AAnswer(address, ttl=0),))
        answers[(collector, 28)] = DnsAnswer()
    return answers


def _candidate_runtime(
    repository: Path,
    dns: ScriptedDnsServer,
    material: EphemeralOutboundTlsMaterial,
) -> TlsRptCandidateRuntime:
    configured = os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON")
    if configured is not None:
        command = CandidateRuntime.from_environment().command_template
    else:
        command = (
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    return TlsRptCandidateRuntime(
        command_template=command,
        dns=dns,
        tls_material=material,
    )


def _connect_postgres(
    runtime: JavaOracleRuntime,
) -> psycopg.Connection[tuple[Any, ...]]:
    if runtime.ports is None:
        raise AssertionError("TLSRPT runtime ports are unavailable")
    connection = psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        user=_DATABASE_USER,
        dbname=_DATABASE,
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '5s'")
    connection.execute("SET lock_timeout = '5s'")
    return connection


def _seed_tls_rows(runtime: JavaOracleRuntime) -> None:
    with _connect_postgres(runtime) as connection:
        for index, label in enumerate(_CASES, start=1):
            domain = _DOMAINS[label]
            connection.execute(
                """
                INSERT INTO outbound_tls_log (
                    id, recipient_domain, mx_host, target_ip, target_port,
                    tls_success, tls_protocol, cipher_suite, failure_type,
                    failure_reason, mta_sts_enforced, mta_sts_mode,
                    sts_policy_version, sts_policy_mode, sts_mx_patterns,
                    sts_max_age, connection_count, report_date, logged_at
                ) VALUES (
                    %s, %s, %s, '192.0.2.30', 25,
                    TRUE, 'TLSv1.3', 'TLS_AES_256_GCM_SHA384', NULL,
                    NULL, TRUE, 'enforce',
                    'STSv1', 'enforce', %s,
                    604800, %s, DATE '2024-01-01', TIMESTAMPTZ '2024-01-01 00:00:00+00'
                )
                """,
                (3100 + index, domain, f"mx.{domain}", f"mx.{domain}", index),
            )


def _row_snapshot(runtime: JavaOracleRuntime, domain: str) -> dict[str, Any]:
    with _connect_postgres(runtime) as connection:
        row = connection.execute(
            """
            SELECT id, recipient_domain, mx_host, target_ip, target_port,
                   tls_success, tls_protocol, cipher_suite, failure_type,
                   failure_reason, mta_sts_enforced, mta_sts_mode,
                   sts_policy_version, sts_policy_mode, sts_mx_patterns,
                   sts_max_age, connection_count, report_date::text, logged_at::text
            FROM outbound_tls_log
            WHERE recipient_domain = %s
            """,
            (domain,),
        ).fetchone()
    if row is None:
        raise AssertionError(f"TLSRPT seed row is missing for {domain}")
    return {
        "id": row[0],
        "recipient_domain": row[1],
        "mx_host": row[2],
        "target_ip": row[3],
        "target_port": row[4],
        "tls_success": row[5],
        "tls_protocol": row[6],
        "cipher_suite": row[7],
        "failure_type": row[8],
        "failure_reason": row[9],
        "mta_sts_enforced": row[10],
        "mta_sts_mode": row[11],
        "sts_policy_version": row[12],
        "sts_policy_mode": row[13],
        "sts_mx_patterns": row[14],
        "sts_max_age": row[15],
        "connection_count": row[16],
        "report_date": row[17],
        "logged_at": row[18],
    }


def _strict_json_object(value: bytes) -> tuple[dict[str, Any], bytes]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise AssertionError(f"duplicate TLSRPT JSON key: {key}")
            result[key] = item
        return result

    parsed = json.loads(value, object_pairs_hook=no_duplicates)
    if not isinstance(parsed, dict):
        raise AssertionError("TLSRPT body is not a JSON object")
    result = cast(dict[str, Any], parsed)
    report_id = result.get("report-id")
    if not isinstance(report_id, str) or not report_id:
        raise AssertionError("TLSRPT report-id is missing")
    report_id_bytes = report_id.encode("ascii", errors="strict")
    if not _UUID_V4.fullmatch(report_id_bytes) or value.count(report_id_bytes) != 1:
        raise AssertionError("TLSRPT report-id is not one unique UUIDv4 occurrence")
    result["report-id"] = "<report-id>"
    return result, value.replace(report_id_bytes, b"<report-id>")


def _decompress_gzip_bounded(value: bytes, *, max_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(value)) as stream:
            decompressed = stream.read(max_bytes + 1)
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        raise AssertionError("TLSRPT request body is not a complete gzip stream") from error
    if len(decompressed) > max_bytes:
        raise AssertionError("TLSRPT decompressed body exceeded its byte budget")
    return decompressed


def _request_snapshot(request: HttpsRequest) -> dict[str, Any]:
    headers: dict[str, str] = {}
    for name, value in request.headers:
        normalized = name.casefold()
        if normalized in headers:
            raise AssertionError(f"duplicate TLSRPT request header: {name}")
        headers[normalized] = value
    expected_headers = {
        "host",
        "connection",
        "content-length",
        "content-type",
        "user-agent",
    }
    if set(headers) != expected_headers:
        raise AssertionError(f"TLSRPT request headers changed: {headers!r}")
    decompressed = _decompress_gzip_bounded(request.body, max_bytes=_MAX_REPORT_BYTES)
    if headers.get("content-length") != str(len(request.body)):
        raise AssertionError("TLSRPT Content-Length does not match the captured body")
    headers["content-length"] = "<uuid-derived-content-length>"
    report, normalized_text = _strict_json_object(decompressed)
    return {
        "connection": request.connection_id,
        "method": request.method,
        "target": request.target,
        "version": request.version,
        "headers": [[name, value] for name, value in sorted(headers.items())],
        "host": headers.get("host"),
        "connection_header": headers.get("connection"),
        "content_type": headers.get("content-type"),
        "content_length_matches": True,
        "user_agent": headers.get("user-agent"),
        "sni": request.sni,
        "tls_protocol": request.tls_protocol,
        "tls_cipher": request.tls_cipher,
        "tls_secret_bits": request.tls_secret_bits,
        "gzip_header_hex": request.body[:10].hex(),
        "compressed_bytes_bounded": 0 < len(request.body) <= _MAX_REPORT_BYTES,
        "decompressed_bytes": len(decompressed),
        "normalized_decompressed_sha256": hashlib.sha256(normalized_text).hexdigest(),
        "normalized_decompressed_text": normalized_text.decode("utf-8", errors="strict"),
        "report": report,
    }


def _response_snapshot(runtime: JavaOracleRuntime, label: str) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("TLSRPT runtime ports are unavailable")
    domain = _DOMAINS[label]
    response = http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        f"/api/reports/domain/{domain}?date={_REPORT_DATE}",
        headers=(("X-API-Key", API_KEY),),
        timeout=10.0,
        max_response=1024 * 1024,
    )
    if response.status_code != 200:
        raise AssertionError(
            f"TLSRPT report endpoint returned {response.status_line!r}: {response.body!r}"
        )

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise AssertionError(f"duplicate TLSRPT API JSON key: {key}")
            result[key] = item
        return result

    body = json.loads(response.body, object_pairs_hook=no_duplicates)
    if not isinstance(body, dict):
        raise AssertionError("TLSRPT report response is not a JSON object")
    normalized_body = _canonicalize_json(cast(dict[str, Any], body))
    normalized_wire = json.dumps(
        normalized_body,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = [
        [name.decode("ascii", errors="strict"), value.decode("latin-1")]
        for name, value in response.headers
    ]
    for header in headers:
        if header[0].casefold() == "content-length":
            header[1] = str(len(normalized_wire))
    return {
        "status_code": response.status_code,
        "headers": headers,
        "body_wire": normalized_wire.decode("utf-8", errors="strict"),
        "body": normalized_body,
    }


def _canonicalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonicalize_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize_json(item) for item in value]
    return value


def _dns_snapshot(queries: tuple[DnsQuery, ...]) -> list[dict[str, Any]]:
    return [
        {"name": query.qname, "type": query.qtype, "class": query.qclass}
        for query in queries
    ]


def _server(
    label: str,
    material: EphemeralOutboundTlsMaterial,
) -> ScriptedHttpsServer | None:
    if label == "private_address":
        return None
    identity = (
        material.untrusted_policy_server
        if label == "certificate_failure"
        else material.policy_server
    )
    if identity is None:
        raise AssertionError("TLSRPT fixture TLS identity is missing")
    scenario = (
        HttpsScenario(status=204, reason="No Content")
        if label == "success"
        else HttpsScenario(
            status=302,
            reason="Found",
            headers=(("Location", "https://redirect.invalid/tls"),),
        )
        if label == "redirect"
        else HttpsScenario(response_delay_seconds=5.0)
        if label == "timeout"
        else HttpsScenario()
    )
    return ScriptedHttpsServer(
        scenario,
        tls_context=create_server_ssl_context(identity),
        bind_host=_PUBLIC_IP,
        bind_port=443,
        max_request_body_bytes=_MAX_REPORT_BYTES,
    )


def _run_case(
    runtime: JavaOracleRuntime,
    dns: ScriptedDnsServer,
    material: EphemeralOutboundTlsMaterial,
    label: str,
) -> dict[str, Any]:
    if dns.drain_queries():
        raise AssertionError("TLSRPT DNS trace was not empty before a case")
    before = _row_snapshot(runtime, _DOMAINS[label])
    server = _server(label, material)
    context: AbstractContextManager[ScriptedHttpsServer | None] = (
        server if server is not None else nullcontext(None)
    )
    with context:
        response = _response_snapshot(runtime, label)
    requests = (
        [] if server is None else [_request_snapshot(item) for item in server.requests()]
    )
    handshake_failures = 0 if server is None else server.handshake_failures()
    after = _row_snapshot(runtime, _DOMAINS[label])
    if after != before:
        raise AssertionError(f"TLSRPT report delivery mutated its source row for {label}")
    return {
        "response": response,
        "dns": _dns_snapshot(dns.drain_queries()),
        "https": {
            "requests": requests,
            "handshake_failures": handshake_failures,
        },
        "source_row_unchanged": True,
    }


def run_probe() -> dict[str, Any]:
    target = _target()
    repository = Path(__file__).resolve().parents[3]
    dns = ScriptedDnsServer(_dns_answers())
    with tempfile.TemporaryDirectory(prefix="lmyzmail-tlsrpt-https-") as workspace:
        workspace_path = Path(workspace)
        material_root = workspace_path / "material"
        material_root.mkdir(mode=0o700)
        material = provision_ephemeral_outbound_tls_material(
            material_root,
            mx_hostname="unused.tlsrpt.fixture.test",
            policy_hostnames=_PUBLIC_COLLECTORS,
        )
        runtime: TlsRptJavaRuntime | TlsRptCandidateRuntime
        if target == "java":
            runtime = TlsRptJavaRuntime(
                workspace_path / "runtime",
                dns=dns,
                tls_material=material,
            )
        else:
            runtime = _candidate_runtime(repository, dns, material)
        with dns, runtime:
            _seed_tls_rows(runtime)
            cases = {
                label: _run_case(runtime, dns, material, label)
                for label in _CASES
            }
    return {"target": target, "cases": cases}


def main() -> int:
    if sys.argv[1:] != ["--child"]:
        raise AssertionError("TLSRPT HTTPS probe must run through its network namespace launcher")
    observed = run_probe()
    sys.stdout.write(json.dumps(observed, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
