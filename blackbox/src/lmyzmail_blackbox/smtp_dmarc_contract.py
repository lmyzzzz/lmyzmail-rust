from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_accepted_without_delivery, capture_delivery
from .smtp_dkim_contract import (
    _BODY_HASH_FAIL,
    _DOMAIN,
    _MISSING_FIRST_VALID_SECOND,
    _MISSING_MULTI_SELECTOR,
    _MULTI_PUBLIC_KEY,
    _MULTI_SELECTOR,
    _PASS,
    _PUBLIC_KEY,
    _VALID_FIRST_MISSING_SECOND,
)

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


@dataclass(frozen=True, slots=True)
class DmarcEdgeCase:
    name: str
    source: str
    envelope_sender: str
    subject: str
    message_id: str
    message: bytes
    expected_from_address: str
    expected_folder: str
    mode: str = "data"
    positive_txt_qnames: tuple[str, ...] = ()
    missing_txt_qnames: tuple[str, ...] = ()
    forbidden_txt_qnames: tuple[str, ...] = ()


def _edge_message(name: str, *from_headers: str) -> bytes:
    return (
        "\r\n".join(
            (
                *from_headers,
                "To: qa@example.test",
                f"Subject: bb-dmarc-edge-{name}",
                "Date: Wed, 12 Aug 2026 00:00:00 +0000",
                f"Message-ID: <bb-dmarc-edge-{name}@example.test>",
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=us-ascii",
                "",
                f"DMARC edge {name} fixture.",
                "",
            )
        )
    ).encode("ascii")


_MULTIPLE_FROM_ENVELOPE = "auth-multiple-from.dmarc-edge-example.net"
_GROUP_FROM_ENVELOPE = "auth-group-from.dmarc-edge-example.net"
_SUBDOMAIN_POLICY_ENVELOPE = "auth.subpolicy-dmarc-example.net"
_SUBDOMAIN_POLICY_DOMAIN = "mail.subpolicy-dmarc-example.com"
_SUBDOMAIN_POLICY_ORG = "subpolicy-dmarc-example.com"
_MALFORMED_ENVELOPE = "auth.malformed-dmarc-example.net"
_MALFORMED_DOMAIN = "malformed-dmarc-example.com"
_MULTIPLE_RECORD_DOMAIN = "multiple-record-dmarc-example.com"
_BDAT_DOMAIN = "bdat-dmarc-example.com"

_DMARC_EDGE_CASES = (
    DmarcEdgeCase(
        name="multiple-from",
        source="127.0.0.74",
        envelope_sender=f"sender@{_MULTIPLE_FROM_ENVELOPE}",
        subject="bb-dmarc-edge-multiple-from",
        message_id="<bb-dmarc-edge-multiple-from@example.test>",
        message=_edge_message(
            "multiple-from",
            "From: First Sender <first@first-from.dmarc-edge-example.org>",
            "From: Second Sender <second@second-from.dmarc-edge-example.org>",
        ),
        expected_from_address=(
            "Second Sender <second@second-from.dmarc-edge-example.org>"
        ),
        expected_folder="inbox",
        positive_txt_qnames=(_MULTIPLE_FROM_ENVELOPE,),
        forbidden_txt_qnames=(
            "_dmarc.first-from.dmarc-edge-example.org",
            "_dmarc.second-from.dmarc-edge-example.org",
        ),
    ),
    DmarcEdgeCase(
        name="group-from",
        source="127.0.0.75",
        envelope_sender=f"sender@{_GROUP_FROM_ENVELOPE}",
        subject="bb-dmarc-edge-group-from",
        message_id="<bb-dmarc-edge-group-from@example.test>",
        message=_edge_message(
            "group-from",
            "From: Fixture Group: member@group-member.dmarc-edge-example.org;",
        ),
        expected_from_address=(
            "Fixture Group: member@group-member.dmarc-edge-example.org;"
        ),
        expected_folder="inbox",
        positive_txt_qnames=(_GROUP_FROM_ENVELOPE,),
        forbidden_txt_qnames=("_dmarc.group-member.dmarc-edge-example.org",),
    ),
    DmarcEdgeCase(
        name="organizational-fallback-subdomain-policy",
        source="127.0.0.76",
        envelope_sender=f"sender@{_SUBDOMAIN_POLICY_ENVELOPE}",
        subject="bb-dmarc-edge-organizational-fallback-subdomain-policy",
        message_id=(
            "<bb-dmarc-edge-organizational-fallback-subdomain-policy@example.test>"
        ),
        message=_edge_message(
            "organizational-fallback-subdomain-policy",
            f"From: Fixture Sender <sender@{_SUBDOMAIN_POLICY_DOMAIN}>",
        ),
        expected_from_address=f"Fixture Sender <sender@{_SUBDOMAIN_POLICY_DOMAIN}>",
        expected_folder="spam",
        positive_txt_qnames=(
            _SUBDOMAIN_POLICY_ENVELOPE,
            f"_dmarc.{_SUBDOMAIN_POLICY_ORG}",
        ),
        missing_txt_qnames=(
            f"_dmarc.{_SUBDOMAIN_POLICY_ENVELOPE}",
            "_dmarc.subpolicy-dmarc-example.net",
            f"_dmarc.{_SUBDOMAIN_POLICY_DOMAIN}",
        ),
    ),
    DmarcEdgeCase(
        name="malformed-then-valid",
        source="127.0.0.77",
        envelope_sender=f"sender@{_MALFORMED_ENVELOPE}",
        subject="bb-dmarc-edge-malformed-then-valid",
        message_id="<bb-dmarc-edge-malformed-then-valid@example.test>",
        message=_edge_message(
            "malformed-then-valid",
            f"From: Fixture Sender <sender@{_MALFORMED_DOMAIN}>",
        ),
        expected_from_address=f"Fixture Sender <sender@{_MALFORMED_DOMAIN}>",
        expected_folder="spam",
        positive_txt_qnames=(_MALFORMED_ENVELOPE, f"_dmarc.{_MALFORMED_DOMAIN}"),
        missing_txt_qnames=(
            f"_dmarc.{_MALFORMED_ENVELOPE}",
            "_dmarc.malformed-dmarc-example.net",
        ),
    ),
    DmarcEdgeCase(
        name="multiple-valid-records",
        source="127.0.0.78",
        envelope_sender=f"sender@{_MULTIPLE_RECORD_DOMAIN}",
        subject="bb-dmarc-edge-multiple-valid-records",
        message_id="<bb-dmarc-edge-multiple-valid-records@example.test>",
        message=_edge_message(
            "multiple-valid-records",
            f"From: Fixture Sender <sender@{_MULTIPLE_RECORD_DOMAIN}>",
        ),
        expected_from_address=f"Fixture Sender <sender@{_MULTIPLE_RECORD_DOMAIN}>",
        expected_folder="spam",
        positive_txt_qnames=(
            _MULTIPLE_RECORD_DOMAIN,
            f"_dmarc.{_MULTIPLE_RECORD_DOMAIN}",
        ),
    ),
    DmarcEdgeCase(
        name="dkim-valid-first-missing-second",
        source="127.0.0.79",
        envelope_sender="",
        subject="bb-dkim-valid-first-missing-second",
        message_id="<bb-dkim-valid-first-missing-second@example.test>",
        message=_VALID_FIRST_MISSING_SECOND,
        expected_from_address=f"Fixture Sender <sender@{_DOMAIN}>",
        expected_folder="inbox",
        positive_txt_qnames=(
            f"{_MULTI_SELECTOR}._domainkey.{_DOMAIN}",
            f"_dmarc.{_DOMAIN}",
        ),
        forbidden_txt_qnames=(f"{_MISSING_MULTI_SELECTOR}._domainkey.{_DOMAIN}",),
    ),
    DmarcEdgeCase(
        name="dkim-missing-first-valid-second",
        source="127.0.0.80",
        envelope_sender="",
        subject="bb-dkim-missing-first-valid-second",
        message_id="<bb-dkim-missing-first-valid-second@example.test>",
        message=_MISSING_FIRST_VALID_SECOND,
        expected_from_address=f"Fixture Sender <sender@{_DOMAIN}>",
        expected_folder="spam",
        positive_txt_qnames=(f"_dmarc.{_DOMAIN}",),
        missing_txt_qnames=(f"{_MISSING_MULTI_SELECTOR}._domainkey.{_DOMAIN}",),
        forbidden_txt_qnames=(f"{_MULTI_SELECTOR}._domainkey.{_DOMAIN}",),
    ),
    DmarcEdgeCase(
        name="bdat-last",
        source="127.0.0.81",
        envelope_sender=f"sender@{_BDAT_DOMAIN}",
        subject="bb-dmarc-edge-bdat-last",
        message_id="<bb-dmarc-edge-bdat-last@example.test>",
        message=_edge_message(
            "bdat-last",
            f"From: Fixture Sender <sender@{_BDAT_DOMAIN}>",
        ),
        expected_from_address=f"Fixture Sender <sender@{_BDAT_DOMAIN}>",
        expected_folder="inbox",
        mode="bdat",
        positive_txt_qnames=(_BDAT_DOMAIN, f"_dmarc.{_BDAT_DOMAIN}"),
    ),
)


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
        (f"{_MULTI_SELECTOR}._domainkey.{_DOMAIN}", DNS_TXT_TYPE): DnsAnswer(
            txt=(
                TxtAnswer(
                    tuple(
                        _MULTI_PUBLIC_KEY[offset : offset + 200]
                        for offset in range(0, len(_MULTI_PUBLIC_KEY), 200)
                    ),
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
    for domain, source in (
        (_MULTIPLE_FROM_ENVELOPE, "127.0.0.74"),
        (_GROUP_FROM_ENVELOPE, "127.0.0.75"),
        (_BDAT_DOMAIN, "127.0.0.81"),
    ):
        answers[(domain, DNS_TXT_TYPE)] = DnsAnswer(
            txt=(TxtAnswer((f"v=spf1 ip4:{source} -all",), ttl=0),)
        )
    answers[(_SUBDOMAIN_POLICY_ENVELOPE, DNS_TXT_TYPE)] = DnsAnswer(
        txt=(TxtAnswer(("v=spf1 ip4:127.0.0.76 -all",), ttl=0),)
    )
    answers[(_MALFORMED_ENVELOPE, DNS_TXT_TYPE)] = DnsAnswer(
        txt=(TxtAnswer(("v=spf1 ip4:127.0.0.77 -all",), ttl=0),)
    )
    for domain in (_MULTIPLE_RECORD_DOMAIN,):
        answers[(domain, DNS_TXT_TYPE)] = DnsAnswer(
            txt=(TxtAnswer(("v=spf1 -all",), ttl=0),)
        )
    answers[(f"_dmarc.{_SUBDOMAIN_POLICY_ORG}", DNS_TXT_TYPE)] = DnsAnswer(
        txt=(
            TxtAnswer(
                ("v=DMARC1; p=reject; sp=quarantine; aspf=s; adkim=s",), ttl=0
            ),
        )
    )
    answers[(f"_dmarc.{_MALFORMED_DOMAIN}", DNS_TXT_TYPE)] = DnsAnswer(
        txt=(
            TxtAnswer(("v=DMARC1evil; p=reject",), ttl=0),
            TxtAnswer(("v=DMARC1; p=quarantine; aspf=s; adkim=s",), ttl=0),
        )
    )
    answers[(f"_dmarc.{_MULTIPLE_RECORD_DOMAIN}", DNS_TXT_TYPE)] = DnsAnswer(
        txt=(
            TxtAnswer(("v=DMARC1; p=none; aspf=s; adkim=s",), ttl=0),
            TxtAnswer(("v=DMARC1; p=reject; aspf=s; adkim=s",), ttl=0),
        )
    )
    answers[(f"_dmarc.{_BDAT_DOMAIN}", DNS_TXT_TYPE)] = DnsAnswer(
        txt=(
            TxtAnswer(("v=DMARC1; p=reject; aspf=s; adkim=s",), ttl=0),
        )
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


def _query_count(queries: tuple[DnsQuery, ...], qname: str) -> int:
    return sum(
        query.qname == qname and query.qtype == DNS_TXT_TYPE for query in queries
    )


def _capture_edge_case(target: RuntimeTarget, case: DmarcEdgeCase) -> dict[str, Any]:
    _drain_queries(target)
    delivery = capture_delivery(
        target,
        mode=case.mode,
        subject=case.subject,
        message_id=case.message_id,
        message=case.message,
        expected_from_address=case.expected_from_address,
        expected_to_addresses='["qa@example.test"]',
        expected_folder=case.expected_folder,
        envelope_sender=case.envelope_sender,
        source=case.source,
    )
    queries = _drain_queries(target)
    positive: dict[str, int] = {}
    for qname in case.positive_txt_qnames:
        count = _query_count(queries, qname)
        _check(count == 1, {case.name: {qname: queries}})
        positive[qname] = count
    missing: dict[str, str] = {}
    for qname in case.missing_txt_qnames:
        count = _query_count(queries, qname)
        _check(1 <= count <= 4, {case.name: {qname: queries}})
        missing[qname] = "at-least-one"
    forbidden: dict[str, int] = {}
    for qname in case.forbidden_txt_qnames:
        count = _query_count(queries, qname)
        _check(count == 0, {case.name: {qname: queries}})
        forbidden[qname] = count
    return {
        "name": case.name,
        "mode": case.mode,
        "positive_txt_query_counts": positive,
        "missing_txt_query_counts": missing,
        "forbidden_txt_query_counts": forbidden,
        "delivery": delivery,
    }


def capture_external_dmarc_edge_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_capture_edge_case(target, case) for case in _DMARC_EDGE_CASES]}


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
    Scenario(
        "smtp/authentication/external-dmarc-edge",
        capture_external_dmarc_edge_matrix,
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
            "protocol": "SMTP DATA and BDAT LAST DMARC edge behavior",
            "case_count": len(_DMARC_EDGE_CASES),
            "from_cardinality": "multiple From fields and group syntax yield dmarc=none",
            "policy_lookup": "organizational fallback uses sp for a subdomain",
            "records": "malformed records are skipped and the first valid record wins",
            "multiple_signatures": "only the first DKIM-Signature contributes to DMARC",
            "completion": "DATA and BDAT LAST share the same DMARC delivery path",
            "persistence": "Maildir, email_index, and legacy Redis count key",
        },
    ),
)
