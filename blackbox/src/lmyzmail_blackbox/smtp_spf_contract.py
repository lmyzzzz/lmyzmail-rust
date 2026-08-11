from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_delivery

DNS_TXT_TYPE = 16


class SpfDnsTarget(Protocol):
    def drain_spf_dns_queries(self) -> tuple[DnsQuery, ...]: ...


@dataclass(frozen=True, slots=True)
class SpfCase:
    name: str
    source: str
    domain: str
    record: str | None
    expected_folder: str

    @property
    def sender(self) -> str:
        return f"sender@{self.domain}"

    @property
    def message_id(self) -> str:
        return f"<bb-spf-{self.name}@example.test>"

    @property
    def subject(self) -> str:
        return f"bb-spf-{self.name}"


_CASES = (
    SpfCase(
        "pass",
        "127.0.0.51",
        "spf-pass.blackbox-example.com",
        "v=spf1 ip4:127.0.0.51 -all",
        "inbox",
    ),
    SpfCase(
        "fail",
        "127.0.0.52",
        "spf-fail.blackbox-example.net",
        "v=spf1 -all",
        "spam",
    ),
    SpfCase(
        "softfail",
        "127.0.0.53",
        "spf-softfail.blackbox-example.org",
        "v=spf1 ~all",
        "spam",
    ),
    SpfCase(
        "neutral",
        "127.0.0.54",
        "spf-neutral.blackbox-example.info",
        "v=spf1 ?all",
        "spam",
    ),
    SpfCase(
        "none",
        "127.0.0.55",
        "spf-none.blackbox-example.co",
        None,
        "spam",
    ),
)


def spf_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    return {
        (case.domain, DNS_TXT_TYPE): DnsAnswer(txt=(TxtAnswer((case.record,)),))
        for case in _CASES
        if case.record is not None
    }


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP SPF contract violation: {details!r}")


def _message(case: SpfCase) -> bytes:
    return (
        f"Subject: {case.subject}\r\n"
        f"Message-ID: {case.message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"External SPF {case.name} fixture.\r\n"
    ).encode("ascii")


def _drain_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    return cast(SpfDnsTarget, target).drain_spf_dns_queries()


def _capture_case(target: RuntimeTarget, case: SpfCase) -> dict[str, Any]:
    _drain_queries(target)
    delivery = capture_delivery(
        target,
        mode="data",
        subject=case.subject,
        message_id=case.message_id,
        message=_message(case),
        expected_folder=case.expected_folder,
        envelope_sender=case.sender,
        source=case.source,
    )
    queries = tuple(
        query
        for query in _drain_queries(target)
        if query.qname == case.domain and query.qtype == DNS_TXT_TYPE
    )
    if case.record is None:
        _check(1 <= len(queries) <= 4, {case.name: queries})
        query_count: int | str = "at-least-one"
    else:
        _check(len(queries) == 1, {case.name: queries})
        query_count = len(queries)
    return {
        "name": case.name,
        "source": case.source,
        "sender": case.sender,
        "spf_record": case.record,
        "expected_folder": case.expected_folder,
        "spf_txt_query_count": query_count,
        "delivery": delivery,
    }


def capture_external_spf_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_capture_case(target, case) for case in _CASES]}


SMTP_SPF_SCENARIOS = (
    Scenario(
        "smtp/authentication/external-spf",
        capture_external_spf_matrix,
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
            "protocol": "SMTP external MAIL FROM SPF result carried through DATA storage",
            "case_count": len(_CASES),
            "dns": "one positive TXT lookup; bounded nonzero NXDOMAIN retries",
            "persistence": "Maildir, email_index, and legacy Redis count key",
            "verdicts": "pass, fail, softfail, neutral, and no record",
            "folder_routing": "SPF pass to inbox; all other unsigned messages to spam",
        },
    ),
)
