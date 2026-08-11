from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_accepted_without_delivery, capture_delivery
from .smtp_dkim_contract import _BODY_HASH_FAIL, _DOMAIN, _PASS, _PUBLIC_KEY

DNS_TXT_TYPE = 16
_DKIM_SELECTOR = "blackbox"


class DmarcDnsTarget(Protocol):
    def drain_dmarc_dns_queries(self) -> tuple[DnsQuery, ...]: ...


@dataclass(frozen=True, slots=True)
class UnsignedCase:
    name: str
    source: str
    envelope_domain: str | None
    header_from_domain: str
    spf_record: str | None
    dmarc_record: str
    expected_folder: str | None

    @property
    def sender(self) -> str:
        if self.envelope_domain is None:
            return ""
        return f"sender@{self.envelope_domain}"

    @property
    def subject(self) -> str:
        return f"bb-dmarc-{self.name}"

    @property
    def message_id(self) -> str:
        return f"<bb-dmarc-{self.name}@example.test>"

    @property
    def dmarc_qname(self) -> str:
        return f"_dmarc.{self.header_from_domain}"


_SPF_ALIGNED = UnsignedCase(
    name="spf-aligned",
    source="127.0.0.71",
    envelope_domain="spf-aligned.dmarc-blackbox-example.com",
    header_from_domain="spf-aligned.dmarc-blackbox-example.com",
    spf_record="v=spf1 ip4:127.0.0.71 -all",
    dmarc_record="v=DMARC1; p=reject; aspf=s; adkim=s; pct=100",
    expected_folder="inbox",
)
_SPF_UNALIGNED = UnsignedCase(
    name="spf-unaligned-quarantine",
    source="127.0.0.72",
    envelope_domain="spf-auth.dmarc-blackbox-example.net",
    header_from_domain="from-unaligned.dmarc-blackbox-example.org",
    spf_record="v=spf1 ip4:127.0.0.72 -all",
    dmarc_record="v=DMARC1; p=quarantine; aspf=r; adkim=r; pct=100",
    expected_folder="spam",
)
_REJECT = UnsignedCase(
    name="reject-no-auth",
    source="127.0.0.73",
    envelope_domain=None,
    header_from_domain="reject.dmarc-blackbox-example.info",
    spf_record=None,
    dmarc_record="v=DMARC1; p=reject; aspf=r; adkim=r; pct=100",
    expected_folder=None,
)
_UNSIGNED_CASES = (_SPF_ALIGNED, _SPF_UNALIGNED, _REJECT)


def dmarc_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    answers: dict[tuple[str, int], DnsAnswer] = {
        (
            f"{_DKIM_SELECTOR}._domainkey.{_DOMAIN}",
            DNS_TXT_TYPE,
        ): DnsAnswer(
            txt=(
                TxtAnswer(
                    tuple(
                        _PUBLIC_KEY[offset : offset + 200]
                        for offset in range(0, len(_PUBLIC_KEY), 200)
                    ),
                    ttl=0,
                ),
            )
        ),
        (f"_dmarc.{_DOMAIN}", DNS_TXT_TYPE): DnsAnswer(
            txt=(
                TxtAnswer(
                    ("v=DMARC1; p=quarantine; aspf=s; adkim=s; pct=100",),
                    ttl=0,
                ),
            )
        ),
    }
    for case in _UNSIGNED_CASES:
        answers[(case.dmarc_qname, DNS_TXT_TYPE)] = DnsAnswer(
            txt=(TxtAnswer((case.dmarc_record,), ttl=0),)
        )
        if case.envelope_domain is not None and case.spf_record is not None:
            answers[(case.envelope_domain, DNS_TXT_TYPE)] = DnsAnswer(
                txt=(TxtAnswer((case.spf_record,), ttl=0),)
            )
    return answers


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP DMARC contract violation: {details!r}")


def _drain_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    return cast(DmarcDnsTarget, target).drain_dmarc_dns_queries()


def _positive_query_count(queries: tuple[DnsQuery, ...], qname: str) -> int:
    count = sum(
        query.qname == qname and query.qtype == DNS_TXT_TYPE for query in queries
    )
    _check(count == 1, {qname: queries})
    return count


def _unsigned_message(case: UnsignedCase) -> bytes:
    return (
        f"From: Fixture Sender <sender@{case.header_from_domain}>\r\n"
        "To: qa@example.test\r\n"
        f"Subject: {case.subject}\r\n"
        "Date: Tue, 11 Aug 2026 00:00:00 +0000\r\n"
        f"Message-ID: {case.message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"DMARC {case.name} fixture.\r\n"
    ).encode("ascii")


def _capture_dkim_case(
    target: RuntimeTarget,
    *,
    name: str,
    message: bytes,
    subject: str,
    message_id: str,
    expected_folder: str,
) -> dict[str, Any]:
    _drain_queries(target)
    delivery = capture_delivery(
        target,
        mode="data",
        subject=subject,
        message_id=message_id,
        message=message,
        expected_from_address=f"Fixture Sender <sender@{_DOMAIN}>",
        expected_to_addresses='["qa@example.test"]',
        expected_folder=expected_folder,
        source="127.0.0.70",
    )
    queries = _drain_queries(target)
    return {
        "name": name,
        "authenticated_mechanism": "dkim",
        "dkim_txt_query_count": _positive_query_count(
            queries, f"{_DKIM_SELECTOR}._domainkey.{_DOMAIN}"
        ),
        "dmarc_txt_query_count": _positive_query_count(
            queries, f"_dmarc.{_DOMAIN}"
        ),
        "delivery": delivery,
    }


def _capture_unsigned_case(target: RuntimeTarget, case: UnsignedCase) -> dict[str, Any]:
    _drain_queries(target)
    message = _unsigned_message(case)
    expected_from = f"Fixture Sender <sender@{case.header_from_domain}>"
    if case.expected_folder is None:
        delivery = capture_accepted_without_delivery(
            target,
            subject=case.subject,
            message_id=case.message_id,
            message=message,
            envelope_sender=case.sender,
            source=case.source,
        )
    else:
        delivery = capture_delivery(
            target,
            mode="data",
            subject=case.subject,
            message_id=case.message_id,
            message=message,
            expected_from_address=expected_from,
            expected_to_addresses='["qa@example.test"]',
            expected_folder=case.expected_folder,
            envelope_sender=case.sender,
            source=case.source,
        )
    queries = _drain_queries(target)
    result: dict[str, Any] = {
        "name": case.name,
        "authenticated_mechanism": "spf" if case.spf_record is not None else "none",
        "dmarc_txt_query_count": _positive_query_count(queries, case.dmarc_qname),
        "delivery": delivery,
    }
    if case.envelope_domain is not None and case.spf_record is not None:
        result["spf_txt_query_count"] = _positive_query_count(
            queries, case.envelope_domain
        )
    if case is _SPF_UNALIGNED:
        early_qname = f"_dmarc.{case.envelope_domain}"
        early_count = sum(
            query.qname == early_qname and query.qtype == DNS_TXT_TYPE
            for query in queries
        )
        _check(1 <= early_count <= 4, {early_qname: queries})
        result["early_envelope_dmarc_query_count"] = "at-least-one"
    return result


def capture_external_dmarc_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "cases": [
            _capture_dkim_case(
                target,
                name="dkim-aligned",
                message=_PASS,
                subject="bb-dkim-pass",
                message_id="<bb-dkim-pass@example.test>",
                expected_folder="inbox",
            ),
            _capture_dkim_case(
                target,
                name="dkim-fail-quarantine",
                message=_BODY_HASH_FAIL,
                subject="bb-dkim-body-hash-fail",
                message_id="<bb-dkim-body-hash-fail@example.test>",
                expected_folder="spam",
            ),
            _capture_unsigned_case(target, _SPF_ALIGNED),
            _capture_unsigned_case(target, _SPF_UNALIGNED),
            _capture_unsigned_case(target, _REJECT),
        ]
    }


SMTP_DMARC_SCENARIOS = (
    Scenario(
        "smtp/authentication/external-dmarc",
        capture_external_dmarc_matrix,
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
            "protocol": "SMTP DATA DMARC alignment, disposition, and storage",
            "case_count": 5,
            "alignment": "strict DKIM and SPF plus relaxed SPF cross-org failure",
            "verdicts": "pass, quarantine failure, and reject failure",
            "dns": "zero-TTL DKIM, SPF, and DMARC TXT fixtures",
            "persistence": "Maildir/PostgreSQL/Redis delivery or five-second absence",
        },
    ),
)
