from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_delivery
from .smtp_dkim_contract import _DOMAIN, DNS_TXT_TYPE


class AuthenticationDnsTarget(Protocol):
    def drain_authentication_dns_queries(self) -> tuple[DnsQuery, ...]: ...


@dataclass(frozen=True, slots=True)
class SpfVariant:
    name: str
    source: str
    base_domain: str
    record: str | None


@dataclass(frozen=True, slots=True)
class DkimVariant:
    name: str
    result: str


@dataclass(frozen=True, slots=True)
class CombinedCase:
    spf: SpfVariant
    dkim: DkimVariant

    @property
    def name(self) -> str:
        return f"spf-{self.spf.name}-dkim-{self.dkim.name}"

    @property
    def spf_domain(self) -> str:
        return f"{self.dkim.name}.{self.spf.base_domain}"

    @property
    def sender(self) -> str:
        return f"sender@{self.spf_domain}"

    @property
    def message_id(self) -> str:
        return f"<bb-spf-dkim-{self.spf.name}-{self.dkim.name}@example.test>"

    @property
    def expected_folder(self) -> str:
        if self.spf.name == "pass" or self.dkim.result == "pass":
            return "inbox"
        return "spam"

    @property
    def expected_spam_status(self) -> str:
        if self.spf.name == "fail" or self.dkim.result == "fail":
            return "Yes"
        return "No"

    @property
    def expected_protocol_score(self) -> float:
        spf_score = {"fail": 3.0, "softfail": 1.0}.get(self.spf.name, 0.0)
        dkim_score = 3.0 if self.dkim.result == "fail" else 0.0
        return spf_score + dkim_score


_SPF_VARIANTS = (
    SpfVariant(
        "pass",
        "127.0.0.81",
        "spf-pass.combined-blackbox-example.com",
        "v=spf1 ip4:127.0.0.81 -all",
    ),
    SpfVariant(
        "fail",
        "127.0.0.82",
        "spf-fail.combined-blackbox-example.net",
        "v=spf1 -all",
    ),
    SpfVariant(
        "softfail",
        "127.0.0.83",
        "spf-softfail.combined-blackbox-example.org",
        "v=spf1 ~all",
    ),
    SpfVariant(
        "neutral",
        "127.0.0.84",
        "spf-neutral.combined-blackbox-example.info",
        "v=spf1 ?all",
    ),
    SpfVariant(
        "none",
        "127.0.0.85",
        "spf-none.combined-blackbox-example.co",
        None,
    ),
)

_DKIM_VARIANTS = (
    DkimVariant("pass", "pass"),
    DkimVariant("fail", "fail"),
    DkimVariant("permerror", "permerror"),
    DkimVariant("none", "none"),
)

_CASES = tuple(
    CombinedCase(spf=spf, dkim=dkim)
    for spf in _SPF_VARIANTS
    for dkim in _DKIM_VARIANTS
)

_COMBINED_SELECTOR = "combined"
_SIGNED_HEADERS = "from:to:subject:date:message-id:mime-version:content-type"
_SIGNATURE_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures/smtp-spf-dkim-signatures.json"
)


def _load_signature_fixture() -> tuple[str, dict[str, tuple[str, str]]]:
    value = json.loads(_SIGNATURE_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("public_key"), str):
        raise AssertionError("invalid combined SPF/DKIM public-key fixture")
    raw_signatures = value.get("signatures")
    if not isinstance(raw_signatures, dict):
        raise AssertionError("invalid combined SPF/DKIM signature fixture")
    signatures: dict[str, tuple[str, str]] = {}
    for name, entry in raw_signatures.items():
        if (
            not isinstance(name, str)
            or not isinstance(entry, dict)
            or not isinstance(entry.get("bh"), str)
            or not isinstance(entry.get("b"), str)
        ):
            raise AssertionError("invalid combined SPF/DKIM signature entry")
        signatures[name] = (entry["bh"], entry["b"])
    expected = {
        case.name for case in _CASES if case.dkim.result in {"pass", "fail"}
    }
    if set(signatures) != expected:
        raise AssertionError("combined SPF/DKIM signature fixture keys do not match cases")
    return value["public_key"], signatures


_COMBINED_PUBLIC_KEY, _SIGNATURES = _load_signature_fixture()


def authentication_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    answers = {
        (f"{_COMBINED_SELECTOR}._domainkey.{_DOMAIN}", DNS_TXT_TYPE): DnsAnswer(
            txt=(
                TxtAnswer(
                    tuple(
                        _COMBINED_PUBLIC_KEY[offset : offset + 200]
                        for offset in range(0, len(_COMBINED_PUBLIC_KEY), 200)
                    ),
                    ttl=0,
                ),
            )
        )
    }
    for case in _CASES:
        if case.spf.record is not None:
            answers[(case.spf_domain, DNS_TXT_TYPE)] = DnsAnswer(
                txt=(TxtAnswer((case.spf.record,), ttl=0),)
            )
    return answers


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP SPF/DKIM contract violation: {details!r}")


def _drain_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    return cast(AuthenticationDnsTarget, target).drain_authentication_dns_queries()


def _unsigned_message(case: CombinedCase) -> bytes:
    return (
        f"From: Fixture Sender <sender@{_DOMAIN}>\r\n"
        "To: qa@example.test\r\n"
        f"Subject: bb-spf-dkim-{case.spf.name}-none\r\n"
        "Date: Wed, 12 Aug 2026 02:00:00 +0000\r\n"
        f"Message-ID: {case.message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"Combined SPF {case.spf.name} and unsigned DKIM fixture.\r\n"
    ).encode("ascii")


def combined_message(case: CombinedCase) -> tuple[bytes, str, str | None]:
    subject = f"bb-spf-dkim-{case.spf.name}-{case.dkim.name}"
    if case.dkim.result == "none":
        return _unsigned_message(case), subject, None

    signed_body = (
        f"Combined SPF {case.spf.name} and DKIM {case.dkim.name} signed fixture."
    )
    if case.dkim.result == "permerror":
        selector = f"missing-{case.spf.name}"
        body_hash = base64.b64encode(
            hashlib.sha256(f"{signed_body}\r\n".encode("ascii")).digest()
        ).decode("ascii")
        signature = "AA=="
    else:
        selector = _COMBINED_SELECTOR
        body_hash, signature = _SIGNATURES[case.name]
    body = (
        f"Combined SPF {case.spf.name} and DKIM fail tampered fixture."
        if case.dkim.result == "fail"
        else signed_body
    )
    message = (
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
        f"d={_DOMAIN}; s={selector}; h={_SIGNED_HEADERS}; "
        f"bh={body_hash}; b={signature}\r\n"
        f"From: Fixture Sender <sender@{_DOMAIN}>\r\n"
        "To: qa@example.test\r\n"
        f"Subject: {subject}\r\n"
        "Date: Wed, 12 Aug 2026 02:00:00 +0000\r\n"
        f"Message-ID: {case.message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"{body}\r\n"
    ).encode("ascii")
    return message, subject, selector


def _query_count(
    queries: tuple[DnsQuery, ...],
    qname: str,
    *,
    positive: bool,
) -> int | str:
    matching = tuple(
        query
        for query in queries
        if query.qname == qname and query.qtype == DNS_TXT_TYPE
    )
    if positive:
        _check(len(matching) == 1, {qname: matching})
        return 1
    _check(1 <= len(matching) <= 4, {qname: matching})
    return "at-least-one"


def _assert_authentication_headers(case: CombinedCase, delivery: dict[str, Any]) -> None:
    encoded = delivery["storage"]["maildir"]["raw"]["base64"]
    raw = base64.b64decode(encoded, validate=True)
    expected = (
        f"\r\n\tspf={case.spf.name} (".encode("ascii"),
        f";\r\n\tdkim={case.dkim.result} (".encode("ascii"),
        b";\r\n\tdmarc=none No DMARC record found\r\n",
        f"X-Spam-Status: {case.expected_spam_status}\r\n".encode("ascii"),
        f"X-Spam-Score: {case.expected_protocol_score:.1f}\r\n".encode("ascii"),
    )
    for fragment in expected:
        _check(fragment in raw, {case.name: fragment})


def _capture_case(target: RuntimeTarget, case: CombinedCase) -> dict[str, Any]:
    _drain_queries(target)
    message, subject, selector = combined_message(case)
    try:
        delivery = capture_delivery(
            target,
            mode="data",
            subject=subject,
            message_id=case.message_id,
            message=message,
            expected_folder=case.expected_folder,
            expected_from_address=f"Fixture Sender <sender@{_DOMAIN}>",
            expected_to_addresses='["qa@example.test"]',
            envelope_sender=case.sender,
            source=case.spf.source,
        )
    except AssertionError as error:
        raise AssertionError(
            f"SMTP SPF/DKIM case {case.name!r} failed: {error}"
        ) from error
    queries = _drain_queries(target)
    spf_query_count = _query_count(
        queries,
        case.spf_domain,
        positive=case.spf.record is not None,
    )
    if selector is None:
        dkim_query_count: int | str = 0
        dkim_queries = tuple(
            query
            for query in queries
            if query.qtype == DNS_TXT_TYPE and "._domainkey." in query.qname
        )
        _check(not dkim_queries, {case.name: dkim_queries})
    else:
        dkim_query_count = _query_count(
            queries,
            f"{selector}._domainkey.{_DOMAIN}",
            positive=case.dkim.result != "permerror",
        )
    _assert_authentication_headers(case, delivery)
    return {
        "name": case.name,
        "source": case.spf.source,
        "sender": case.sender,
        "spf_record": case.spf.record,
        "expected_spf_result": case.spf.name,
        "expected_dkim_result": case.dkim.result,
        "expected_folder": case.expected_folder,
        "expected_spam_status": case.expected_spam_status,
        "expected_protocol_score": case.expected_protocol_score,
        "spf_txt_query_count": spf_query_count,
        "dkim_txt_query_count": dkim_query_count,
        "delivery": delivery,
    }


def capture_combined_spf_dkim_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_capture_case(target, case) for case in _CASES]}


SMTP_SPF_DKIM_SCENARIOS = (
    Scenario(
        "smtp/authentication/combined-spf-dkim",
        capture_combined_spf_dkim_matrix,
        normalizers=(
            "smtp:greeting-skibidi-grammar",
            "smtp:server-hostname",
            "smtp:session-id",
            "maildir:generated-filename",
            "maildir:server-hostname",
            "maildir:received-id",
            "maildir:received-at",
            "postgres:identity-timestamps-and-hostname-derived-size",
            "dns:nxdomain-retry-count",
        ),
        contract={
            "protocol": "SMTP DATA combined SPF and DKIM verdicts and storage",
            "case_count": len(_CASES),
            "spf_verdicts": "pass, fail, softfail, neutral, and none",
            "dkim_verdicts": "pass, fail, permerror, and none",
            "folder_routing": "inbox when either mechanism passes; spam otherwise",
            "spam_status": "Yes for explicit SPF or DKIM fail; No otherwise",
            "score": "additive SPF fail 3, softfail 1, and DKIM fail 3",
            "dns": "unique zero-TTL SPF domains and bounded missing-record retries",
            "persistence": "Maildir, email_index, and legacy Redis count key",
        },
    ),
)
