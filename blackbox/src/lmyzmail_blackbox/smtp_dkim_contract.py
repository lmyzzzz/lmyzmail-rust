from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_delivery

DNS_TXT_TYPE = 16
_DOMAIN = "dkim.blackbox-example.com"
_SELECTOR = "blackbox"
_MULTI_SELECTOR = "multi"
_MISSING_MULTI_SELECTOR = "missing-multi"
_PUBLIC_KEY = (
    "v=DKIM1; k=rsa; p="
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzAu/Fv067zysN0vELgeM0JIM"
    "ya3Vz1pBlsAK6kaNDeBwROJ+CcOORvGZs214xbMfYyzKF9iutZsXXEacwMIy/CmED6xi"
    "JpBH3AoqIKTz/fIZrh59TQtj99KGFhQQUBO6E2PrhVTiy01ObYan1nUU0+apjinTbVwK"
    "dnWgW/igAVurHiX4GxMjrqQ9dFKugXShyWnFUgJj1RP+6rQVoH1pTzco+AicJJloeRsc"
    "n3KpBdmB4iLxAT1fP8uN5URipSO+MjqPD/OqEpeI5lJepo+erB/FOzoxEk8YZVGoSRZo"
    "QqVTLIM97XTnkf+LZ+d8EEJChKuy9I69b3vPpzwkzZ3t/wIDAQAB"
)
_MULTI_PUBLIC_KEY = (
    "v=DKIM1; k=rsa; p="
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxAKPGKGU1c9sNq0CbtNUuspP"
    "evI/fCKy6wzQPwU5cV8IY3kMuQrVS4Qwqz7EMhN4n7IFDGg+NQihCF/5diITA/hVwv9"
    "SiDHXpfUed+elMhFi/bHq/ONpuMR268Z2Bs0/FnUBxQ+1j4ais7trQBLyUF5cc4Nqx4q"
    "f9qykpOJ9xdUvQ86GkEl6E/ayAKp2+u2lxRvJfPaxQQtSrBmGB1kpiTED8V1pHs3DG6d"
    "yfJmcbKNRrg9lBREDREfoahToyeUReJDNdatPmm94NXeXnmDibWbJPJ7gh5tpH/mYk9T"
    "NINMLDoum8/n2cqXnywx9kk3blWaQkomO2RFzYr9BKgLg1wIDAQAB"
)


class DkimDnsTarget(Protocol):
    def drain_dkim_dns_queries(self) -> tuple[DnsQuery, ...]: ...


@dataclass(frozen=True, slots=True)
class DkimCase:
    name: str
    message: bytes
    selector: str
    expected_result: str
    expected_folder: str
    expected_query_count: int | str
    ignored_selectors: tuple[str, ...] = ()

    @property
    def subject(self) -> str:
        return f"bb-dkim-{self.name}"

    @property
    def message_id(self) -> str:
        return f"<bb-dkim-{self.name}@example.test>"

    @property
    def qname(self) -> str:
        return f"{self.selector}._domainkey.{_DOMAIN}"


_PASS = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=blackbox; "
    "h=from:to:subject:date:message-id:mime-version:content-type; "
    "bh=xVQvYEbYLjrB4llh6ojCrkbrAq2GPXISeOT2/zg6xzA=; "
    "b=xDG3+dC7i3wskyjN0G32T2p2cF3h5Rv3RvT/NXKDzc0VevEvXUxBfMkwAr7r+PA32AzBE4HDNfnjRnO/VLhsq1rHc6XqNtbUgf85juI2XuR9HwRu2iTKq94/qIKMgW4g5YVvQxrBVmLoQigjAhpMCGX7VsUDVM+ZiZSGDxxMcwlFXCMkDYqjb0oBsR6jZUH6UUHgoJXZ7jVMg1r0o4rnKaMTyuZPZWGOUVoZKSeEepqbowbKIkwEZLBSAZCbVznknPQQ0yMg65DBLrEJ9HoqJYdJMXbtDCtsdbE1wEqCpCaLaWjEeoko4uwHps2lOGZ6gN9XAgo8jlhNBs0sHLQwrA==\r\n"
    "From: Fixture Sender <sender@dkim.blackbox-example.com>\r\n"
    "To: qa@example.test\r\n"
    "Subject: bb-dkim-pass\r\n"
    "Date: Tue, 11 Aug 2026 00:00:00 +0000\r\n"
    "Message-ID: <bb-dkim-pass@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=us-ascii\r\n"
    "\r\n"
    "DKIM pass fixture.\r\n"
).encode("ascii")

_BODY_HASH_FAIL = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=blackbox; "
    "h=from:to:subject:date:message-id:mime-version:content-type; "
    "bh=L/GsWHLjzcq18soZrc8EAK9tM2oB0pb8NduwR0tMldo=; "
    "b=tiQGYHSum1wdjSFigGQqkql2yDdKHcnlsPotyvlU0BogyCB0vBz7LnvnsaaB8fuBogIzGAYk4W/d+DY0PM96SERDh8EzuuoClX0erqmT02+py/DvOqSGGZpFc0zuW+rFuE41eCHxlssLtvivK9Bs3t6hHRHNUExBo/1JgmKbiQs+ZB4HCvWb2ikDxL91EHSp4a3HjCiJtpPQNSMKsI4hYdmpWYWkxtYkJR6pzs5PMblFnbNJa6RAo2lepqxyG93fdsNcy4fVVC6yeouOr7aeGxzJQPKWK76i1AKvJrQWx9dBU3NU9yT7xWEza3sOE2qwHKN+w1X6A/DSH6J28uv8Kw==\r\n"
    "From: Fixture Sender <sender@dkim.blackbox-example.com>\r\n"
    "To: qa@example.test\r\n"
    "Subject: bb-dkim-body-hash-fail\r\n"
    "Date: Tue, 11 Aug 2026 00:00:00 +0000\r\n"
    "Message-ID: <bb-dkim-body-hash-fail@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=us-ascii\r\n"
    "\r\n"
    "DKIM tampered body.\r\n"
).encode("ascii")

_SIGNATURE_FAIL = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=blackbox; "
    "h=from:to:subject:date:message-id:mime-version:content-type; "
    "bh=URNYIIWrK32tRIzZy52NywE8FO2MU1MjM4arPcWdIjQ=; "
    "b=AchjnYpteLfQr/bX2levAvJNOCnUnkbX+azctUMgzSldjbs/Iyozcrd0tRKbaC8JsFMhwWZYIHo3e7u0lfLocAR4FyX2z3Q7RP8t40lvXDN4xBCa8g1PU0OSku+Kv9/1AV/Bng55LfMSVrjxJ/P73umMYkCEVpFmscqLm/IY1ULuPvbjjlhuevs533UHmcuznePke8wLQkpCbot0hE4MwCIW147QlDjbKdehAyvYB16E6zpYXPAhIhAOTbLCRG2PH0NYUesZnlXtadBF9KsMeZW3B9ocF2bkqZJdhFgOmBfuEMcI9kUkKqaC6yjPKjHQVoA4FRfvCDYcDcZdR1ZqDQ==\r\n"
    "From: Fixture Sender <sender@dkim.blackbox-example.com>\r\n"
    "To: qa@example.test\r\n"
    "Subject: bb-dkim-signature-fail\r\n"
    "Date: Tue, 11 Aug 2026 00:00:00 +0000\r\n"
    "Message-ID: <bb-dkim-signature-fail@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=us-ascii\r\n"
    "\r\n"
    "DKIM signature fixture.\r\n"
).encode("ascii")

_MISSING_KEY = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=missing; "
    "h=from:to:subject:date:message-id:mime-version:content-type; "
    "bh=ZDVenUTR0CWho/aTg69qqIENKdYEGLjJGPcb7CfDOx4=; "
    "b=vZ1lFKU7D1I2HRtI73t4Gqj9r8Xa7Na9g+jbul6CAPQAZTf9O1cX8CEqzaOJvlvAnyBa3WVXCXtEf1mygLLUy3GPKDP6t+n4TmMrEpkXj9wSWWuD133g/6Gy0fSsXJUXERwunbaAmS5EMBwIzFKgfhYrtvyVZJX19Lco+EOVsxBU0rfnPR4mV8XBjFiAoRmXR0G8EmlChHzjAyzvTKZRjT+7pIF1pyyzwtyi0gJ84u+oC8az2LPzr2Gb1qPXU8oOFgvReNJqNuKW7cl0Wgox9bOSpOwWIo8ldVqHOym4ZCAoj47WLMRrMSWBXFL8JJ7o1waVw3kKQiWdm6+bPoBx7Q==\r\n"
    "From: Fixture Sender <sender@dkim.blackbox-example.com>\r\n"
    "To: qa@example.test\r\n"
    "Subject: bb-dkim-missing-key\r\n"
    "Date: Tue, 11 Aug 2026 00:00:00 +0000\r\n"
    "Message-ID: <bb-dkim-missing-key@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/plain; charset=us-ascii\r\n"
    "\r\n"
    "DKIM missing key fixture.\r\n"
).encode("ascii")

_SIGNED_HEADERS = "from:to:subject:date:message-id:mime-version:content-type"
_VALID_FIRST_HEADER = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=multi; "
    f"h={_SIGNED_HEADERS}; bh=mAkCyrxyVzaLotjDPlkIFn7fgIk9FLFoYKPM9IFeP9c=; "
    "b=YwkLWlSRDj8FIsvs2qC83ucYH4EHx0I/WJ1+E+6t1KyorNMy2Yji2X9v1BiQB1gou1KR"
    "IUKpZ6Bk8E7W1EEnekLnjAThFgqIaNuIXvQzP9Vi2xGP6IPKQVYokWA2LXzQ5NtjcUsV"
    "pvrf1kyqDB3tST+uKIuvGUAiu6RKi2HQcgobKslMe4wF5taUQiXVn8iNVqUjDT+GXSgY"
    "6qP8pUL/XP9us+3fJZpAPqs45jX7g9orm9o9MC+X9l0PgHIT9Wd74pafyyqZLD3zrkis"
    "cu7xaAy1URQ+xZR4zaUUFnwqoF75nyf1WSn9b/bMJjIuJCq+5vrSC8kA5JtlT5WajfQmYg=="
)
_VALID_SECOND_HEADER = (
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
    "d=dkim.blackbox-example.com; s=multi; "
    f"h={_SIGNED_HEADERS}; bh=y5/h3L3oVe0PSgH6ejcZEceqayFV/jEDSpS7L/B2OSA=; "
    "b=WSlGFM70bxRnuPDrwvVnDDquyORZtrZxqcRirZ4ZUevYo0s5a/qhWx3097NprXpMVLcx"
    "gMFbIllYiq+5DRqX2hX9DlZOVYkiFiy/LO7lgLqjw1zCar3EU9rFqFqw1JBaczuU6NV3"
    "UnyVsEQVr0zKgTzsaebJr0ua6BT+wg/lAa1bhzzfuSWkO9HZ1qTICBsleyTXy1lErXjh"
    "J2tCGl6S+tADFfj9fBhyam61cd5jZe0oGX4ts61Zk35NzsgX909M0j9FL0hDU77UmGeM"
    "PeEKdtsxnfXujOaGtYUeAilpFFaqH+JP2uLcNsif5NKagnyB+SKccjC7qIC/RkDDld5vlA=="
)


def _multiple_signature_message(
    label: str,
    body_hash: str,
    valid_header: str,
    *,
    valid_first: bool,
) -> bytes:
    missing_header = (
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
        f"d={_DOMAIN}; s={_MISSING_MULTI_SELECTOR}; h={_SIGNED_HEADERS}; "
        f"bh={body_hash}; b=AA=="
    )
    signatures = (valid_header, missing_header) if valid_first else (missing_header, valid_header)
    headers = (
        *signatures,
        f"From: Fixture Sender <sender@{_DOMAIN}>",
        "To: qa@example.test",
        f"Subject: bb-dkim-{label}",
        "Date: Wed, 12 Aug 2026 00:00:00 +0000",
        f"Message-ID: <bb-dkim-{label}@example.test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=us-ascii",
    )
    body = f"DKIM multiple signature {label} fixture."
    return ("\r\n".join((*headers, "", body, ""))).encode("ascii")


_VALID_FIRST_MISSING_SECOND = _multiple_signature_message(
    "valid-first-missing-second",
    "mAkCyrxyVzaLotjDPlkIFn7fgIk9FLFoYKPM9IFeP9c=",
    _VALID_FIRST_HEADER,
    valid_first=True,
)
_MISSING_FIRST_VALID_SECOND = _multiple_signature_message(
    "missing-first-valid-second",
    "y5/h3L3oVe0PSgH6ejcZEceqayFV/jEDSpS7L/B2OSA=",
    _VALID_SECOND_HEADER,
    valid_first=False,
)

_CASES = (
    DkimCase("pass", _PASS, _SELECTOR, "pass", "inbox", 1),
    DkimCase("body-hash-fail", _BODY_HASH_FAIL, _SELECTOR, "fail", "spam", 1),
    DkimCase("signature-fail", _SIGNATURE_FAIL, _SELECTOR, "fail", "spam", 1),
    DkimCase("missing-key", _MISSING_KEY, "missing", "permerror", "spam", "at-least-one"),
    DkimCase(
        "valid-first-missing-second",
        _VALID_FIRST_MISSING_SECOND,
        _MULTI_SELECTOR,
        "pass",
        "inbox",
        1,
        (_MISSING_MULTI_SELECTOR,),
    ),
    DkimCase(
        "missing-first-valid-second",
        _MISSING_FIRST_VALID_SECOND,
        _MISSING_MULTI_SELECTOR,
        "permerror",
        "spam",
        "at-least-one",
        (_MULTI_SELECTOR,),
    ),
)


def dkim_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    return {
        (f"{selector}._domainkey.{_DOMAIN}", DNS_TXT_TYPE): DnsAnswer(
            txt=(
                TxtAnswer(
                    tuple(key[offset : offset + 200] for offset in range(0, len(key), 200)),
                    ttl=0,
                ),
            )
        )
        for selector, key in ((_SELECTOR, _PUBLIC_KEY), (_MULTI_SELECTOR, _MULTI_PUBLIC_KEY))
    }


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP DKIM contract violation: {details!r}")


def _drain_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    return cast(DkimDnsTarget, target).drain_dkim_dns_queries()


def _capture_case(target: RuntimeTarget, case: DkimCase) -> dict[str, Any]:
    _drain_queries(target)
    try:
        delivery = capture_delivery(
            target,
            mode="data",
            subject=case.subject,
            message_id=case.message_id,
            message=case.message,
            expected_folder=case.expected_folder,
            expected_from_address=f"Fixture Sender <sender@{_DOMAIN}>",
            expected_to_addresses='["qa@example.test"]',
            source="127.0.0.61",
        )
    except AssertionError as error:
        raise AssertionError(f"SMTP DKIM case {case.name!r} failed: {error}") from error
    all_queries = _drain_queries(target)
    queries = tuple(
        query
        for query in all_queries
        if query.qname == case.qname and query.qtype == DNS_TXT_TYPE
    )
    if isinstance(case.expected_query_count, int):
        _check(len(queries) == case.expected_query_count, {case.name: queries})
        query_count: int | str = case.expected_query_count
    else:
        _check(1 <= len(queries) <= 4, {case.name: queries})
        query_count = "at-least-one"
    ignored_qnames = {
        f"{selector}._domainkey.{_DOMAIN}" for selector in case.ignored_selectors
    }
    ignored_queries = tuple(
        query
        for query in all_queries
        if query.qname in ignored_qnames and query.qtype == DNS_TXT_TYPE
    )
    _check(not ignored_queries, {case.name: ignored_queries})
    observation: dict[str, Any] = {
        "name": case.name,
        "selector": case.selector,
        "signing_domain": _DOMAIN,
        "expected_dkim_result": case.expected_result,
        "expected_folder": case.expected_folder,
        "dkim_txt_query_count": query_count,
        "delivery": delivery,
    }
    if case.ignored_selectors:
        observation["ignored_selectors"] = list(case.ignored_selectors)
        observation["ignored_selector_query_count"] = 0
    return observation


def capture_external_dkim_matrix(target: RuntimeTarget) -> dict[str, Any]:
    return {"cases": [_capture_case(target, case) for case in _CASES]}


SMTP_DKIM_SCENARIOS = (
    Scenario(
        "smtp/authentication/external-dkim",
        capture_external_dkim_matrix,
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
            "protocol": "SMTP DATA DKIM verification and storage",
            "case_count": len(_CASES),
            "fixtures": "fixed pre-signed RSA messages and public DNS key",
            "verdicts": "pass, body hash fail, signature fail, and missing key permerror",
            "multiple_signatures": "only the first DKIM-Signature header is evaluated",
            "dns": (
                "one positive zero-TTL TXT lookup per transaction; "
                "bounded nonzero NXDOMAIN retries"
            ),
            "persistence": "Maildir, email_index, and legacy Redis count key",
            "folder_routing": "DKIM pass to inbox; all other null-sender messages to spam",
        },
    ),
)
