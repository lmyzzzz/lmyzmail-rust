from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Protocol, cast

from .differential import RuntimeTarget, Scenario
from .scripted_dns import DnsAnswer, DnsQuery, TxtAnswer
from .smtp_contract import capture_delivery

DNS_TXT_TYPE = 16
_DOMAIN = "dkim.blackbox-example.com"
_SELECTOR = "blackbox"
_MULTI_SELECTOR = "multi"
_MISSING_MULTI_SELECTOR = "missing-multi"
_IDENTITY_SELECTOR = "identity"
_STRICT_IDENTITY_SELECTOR = "identity-strict"
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
_IDENTITY_PUBLIC_KEY = (
    "v=DKIM1; k=rsa; p="
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxc1dAcNG9C+rVhqK0ADNssPx"
    "giUyc2+j8UGotTEyneJNtP8gmVQJpRNJ7FJqobaI+cJ3EbLfp4HIN9gthZqMEeoP40xW"
    "oBeb/vW/Q1P8fKs+J6Wh3WOylCPRq+xCxcNQJ4XJl56ruS4oLOSsOjY3YMCrDXqEnvOW"
    "TJnR3O2E4R8w7eZ//r+eOJFNZsqhMBP061VlMI9yGSHGQlWhZPxzPiBAvv29JcmKg38h"
    "ShNBlrVoRAJZ3iQmmWltMxe/MTkkvmCZtx/WLGV3DYS4DskICeKgVWZRarqL2clTUnsh"
    "RgK56bwQZWMzwkuQXJ2gx98Cvnst/PCO6QRz1BNDi0HtAQIDAQAB"
)
_STRICT_IDENTITY_PUBLIC_KEY = _IDENTITY_PUBLIC_KEY.replace("p=", "t=s; p=", 1)


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


def _identity_case(
    label: str,
    selector: str,
    identity: str,
    body_hash: str,
    signature: str,
    *,
    expected_result: str = "pass",
    expected_folder: str = "inbox",
) -> DkimCase:
    header = (
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; "
        f"d={_DOMAIN}; s={selector}; i={identity}; "
        f"h={_SIGNED_HEADERS}; bh={body_hash}; b={signature}"
    )
    headers = (
        header,
        f"From: Fixture Sender <sender@{_DOMAIN}>",
        "To: qa@example.test",
        f"Subject: bb-dkim-{label}",
        "Date: Wed, 12 Aug 2026 01:00:00 +0000",
        f"Message-ID: <bb-dkim-{label}@example.test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=us-ascii",
    )
    body = f"DKIM identity {label} fixture."
    message = "\r\n".join((*headers, "", body, "")).encode("ascii")
    return DkimCase(label, message, selector, expected_result, expected_folder, 1)


_IDENTITY_COMPAT_CASES = (
    _identity_case(
        "identity-exact",
        _IDENTITY_SELECTOR,
        f"sender@{_DOMAIN}",
        "kJ4l2qKOOGCtPG2yEnpe31KVGslwEEuPoiwGx84SEkY=",
        "lxB4TPLiLZrUSjY+qscW6ka4hYqAKd3ShZAaPTZ56oky8pXS8TRpH74YA1Zd0gvN"
        "pFw1HlOrpkX80e5ajV3Svi3V+/szzwEUEOkoM7hNZvsFinWRrwKB8HTQ6e9ESKh3Q"
        "x2FzuH+Abq0ze88jYts8aGzt4+QjDv+v114lQeWa9T9IqHPNF20OWyGYZ02al+uwW"
        "1v/FFmXsf+6ymaUv3ai+wlRcrfviZSUMWIEMxDZR5eRPTiExGYipB29zJF9umIvIo"
        "fcyVjEZFjMZ/AS3srrIoHfV1w/TvqTnIplIEta7SBJFFptCOeeUg3jCgW8aNI30AU"
        "837QkCWoeOLq+Zhpng==",
    ),
    _identity_case(
        "identity-subdomain",
        _IDENTITY_SELECTOR,
        f"sender@sub.{_DOMAIN}",
        "f/InY0o+7uD0xbiuQoBaL5c9GN4W2G6xH/AzEUHD/Ug=",
        "o200fiZEogs2UVtVveACkt2CNS9RCbWh/wj1kn679AczA8tOXId8XtusT+gW48a6"
        "aC2Lc+rb0ZNC2oLH6ToV+Mp1ECaJQaOAqTJyptg6ruWaRvKbNYv3OyhiblSDhMVhk"
        "SE9liO8d3hJ+AT/9SpUmZByvHFnDnoPqrG6JX6Wf2n16P21jgEicbTSprkICJ5ddy"
        "zJxgkm+Lga4EJcsSL1EUu5Fgbx9ciO1I++l6HT34+VZnwpB0HcDuLAPSir1X9xoyf"
        "nBxoGjSVbQGTbw8egH5shLNsETypwiW341oeDY5BHSyQqKHwyHb83QfCrLdY9v857"
        "4I0kc5wEvZsaVLxXYA==",
    ),
    _identity_case(
        "identity-strict-exact",
        _STRICT_IDENTITY_SELECTOR,
        f"sender@{_DOMAIN}",
        "Fd7Y8YAlMHIRgLRVPMiu2WDhzQ2EyrxGKllBppJ6Z/Y=",
        "POEin/U4wG48RjYUIyEM8iWdmXjAUP1zyuKADJQUHAuHlLWkJYKrot99buPJzfBw"
        "ArdKh3WR7ow3N2QuYqWx729IEeo9ST/5CPfdFnOqzzIW+2eS6dpbgaCPiRg1ztZPS"
        "fCFbdncblJl5y3Hpa2M3AbS28HYmUaxEDAP82BSidpsr9NfituFcQJQd3LHG4oJPf"
        "BfS8pJ1FrXAiD+JtUJmsoI5nzDW3NGUqyC8X1yTx4bSL1HF3a1tb/ogNerV5K6Jm"
        "18GiN/LQkFs1BKKKhG2VZo0tni1DPajnFub3vHi8pZFUqq99kn/bTDUhsz2cDXk+1"
        "YZKkFCglgT8I+3W6nmg==",
    ),
)

_IDENTITY_ORACLE_EVIDENCE_CASES = (
    _identity_case(
        "identity-unrelated",
        _IDENTITY_SELECTOR,
        "sender@unrelated.example",
        "hjNdZX0sHItI9f2oZTNEb1DifnZ/1I99I7hzv8Gt9NQ=",
        "mpwIJra4ozjOLlCKcMZbVbVkumw0lLdxu7Nwdz+iuaObnncYrhkAZBjdWZn2rMsz"
        "ZH2MlwylHevntG9Fqr1JV/TOit4GewREFJpO/3Pr1rXQjK5ooCFPRQr3M+zQP/I7g"
        "oHzJAnp726YdNMXh8PJbXdo3BiiKW9gGuVSMgrz6BOXQrY7P8yfwQcqJfA4QlmNpv"
        "9yKar3Mh2kCqLn2XS8J3BJldvvCtNOC3QlDVlWF1l8aRwZiNTUX4v7GgucxrXxNC7"
        "fvppQqWf+IjOKFrnqyawA4kXABjU5HmbxV7YE2AjEqnP/7UtaHxbKwDxiX/9fMdcV"
        "a/wV11kR3gUjeb+6yA==",
    ),
    _identity_case(
        "identity-strict-subdomain",
        _STRICT_IDENTITY_SELECTOR,
        f"sender@sub.{_DOMAIN}",
        "Ff43eHP+6/fuJPlozSYwaVaXtgYMYXusUsDh4/EO/AQ=",
        "DjYigTFIPzUzZ+p6WfXXPM5NeIctxJACFjcqqlUXzuOmc1zuytcWu/Htwz8+8WQd"
        "h4cFv2JRirbkmEK3haFVJ9dNj7P1nvsSJGg5sWZTgjyuvvNbbl4cdmikNHkTBJzF"
        "PRbLISay1X5hQpxq+nWdpNWODGJtYsMElywjQyABSD7vJeE+Mb/5juhD8JVRcqmmR"
        "2PH7KNYDYSWlrUz7QapoCxHxagKJdV38Y+SDd0YnRSgfcgQLg8MIEKZpGPA0CXrQi"
        "Cps05YcQwoVVIAihbqAlbighQoOh2Ys5KcZ+NrMbXOHQPHqFuMoZU1/aJ7PWpg2/K"
        "KmlEnCB5pzSqlvVRj7Q==",
    ),
    _identity_case(
        "identity-strict-prefix-confusion",
        _STRICT_IDENTITY_SELECTOR,
        f"sender@{_DOMAIN}.attacker.example",
        "jKodcIA3ca4xDM5i2fXrD9cwn3TF5yhGgWjjREhIpuw=",
        "E5WqLTNlDDZ1755SJunRSElLWAzs0TsutSy7MLygyR+ivTHBcDhpVg/lEPD4inR8"
        "3vH9YARObKtbCMQsPty5Pitf6mKanKCj4AOCdrXrZ2rrsoGPz99BnQ6s5nOUIBZtj"
        "keGQeOwuwbojQ0JN+L60BEcp2IoT/yNHlWmcKlrxwe8TYlYfZ6XDcsF4p4YfWZaR"
        "fHFVPzw6JsVGght7mCwsH2cMxWNtZg5s/7PPSlYryhO9WpL25kjXDs6sY75XwRUXA"
        "efXoAQSnNfrzHQ/h2QJvx875wckWLKPXdus0yKBNTZB7tPmlSWkcYj5hqcTRsR1+s"
        "xBeCpw/VJo17rr4SbPA==",
    ),
    _identity_case(
        "identity-missing-at",
        _IDENTITY_SELECTOR,
        f"sender.{_DOMAIN}",
        "yfmGGoC5OGGFXwGeQOpbpAwI0BYkZMNHwnugmrgTbas=",
        "WZPrc962nZWbI5iUBnHLRUaE18PoV3NmEXynuwyEOQCIIHSRGDyP0b7MI2RZNIs0"
        "wOW8WCkW9jfIX4n3eLBJq8tzS7GbrS9khACsFl3mMagJwAWdtGwhoHfivwS5RQpUp"
        "3lVNE4UtJmsdHrYcpU4P/sVG5WKfcaeVRzHOZn3GZLuaNCSYYYo+eoLN90TkdTnpn"
        "CEIGO9pFHxCufQociDVS6fvZfwcjvIWq2Yjv+NhsFZQ6XZv4rgLQ392xFLAphFzhn"
        "addF455+pB0/EuqOY0eCyelx7R4Q5rQCfC08IZ174H7urD5nhXF/I+IzfYRmQ5Gs"
        "vUoOc63fqy7aManLTdw==",
    ),
)

_IDENTITY_CANDIDATE_SECURITY_CASES = tuple(
    replace(case, expected_result="fail", expected_folder="spam")
    for case in _IDENTITY_ORACLE_EVIDENCE_CASES
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
    *_IDENTITY_COMPAT_CASES,
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
        for selector, key in (
            (_SELECTOR, _PUBLIC_KEY),
            (_MULTI_SELECTOR, _MULTI_PUBLIC_KEY),
            (_IDENTITY_SELECTOR, _IDENTITY_PUBLIC_KEY),
            (_STRICT_IDENTITY_SELECTOR, _STRICT_IDENTITY_PUBLIC_KEY),
        )
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


def capture_external_dkim_identity_oracle_evidence(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "cases": [_capture_case(target, case) for case in _IDENTITY_ORACLE_EVIDENCE_CASES]
    }


def capture_external_dkim_identity_candidate_security(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "cases": [_capture_case(target, case) for case in _IDENTITY_CANDIDATE_SECURITY_CASES]
    }


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
            "identity": "absent, exact, subdomain, and strict exact AUID compatibility",
            "dns": (
                "one positive zero-TTL TXT lookup per transaction; "
                "bounded nonzero NXDOMAIN retries"
            ),
            "persistence": "Maildir, email_index, and legacy Redis count key",
            "folder_routing": "DKIM pass to inbox; all other null-sender messages to spam",
        },
    ),
)

SMTP_DKIM_IDENTITY_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "smtp/authentication/oracle-invalid-dkim-identity",
        capture_external_dkim_identity_oracle_evidence,
        normalizers=SMTP_DKIM_SCENARIOS[0].normalizers,
        contract={
            "protocol": "SMTP DATA DKIM AUID validation evidence",
            "case_count": len(_IDENTITY_ORACLE_EVIDENCE_CASES),
            "difference_id": "smtp-dkim-auid-domain-validation",
            "oracle_only": True,
            "candidate_expectation": (
                "reject malformed or out-of-domain AUID values and enforce t=s exact matching"
            ),
        },
    ),
)
