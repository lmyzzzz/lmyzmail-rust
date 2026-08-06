from __future__ import annotations

import pytest

from lmyzmail_blackbox.smtp_auth_contract import (
    SMTP_AUTH_SCENARIOS,
    SMTP_AUTH_TLS_SCENARIOS,
    _assert_auth_not_advertised,
)


def test_auth_capability_guard_rejects_any_advertised_mechanisms() -> None:
    _assert_auth_not_advertised(
        (
            b"250-example.test Hello client.example\r\n",
            b"250-PIPELINING\r\n",
            b"250 SIZE 1024\r\n",
        )
    )

    with pytest.raises(AssertionError, match="SMTP AUTH contract violation"):
        _assert_auth_not_advertised(
            (
                b"250-example.test Hello client.example\r\n",
                b"250 AUTH PLAIN LOGIN\r\n",
            )
        )


def test_auth_profiles_bind_plaintext_and_starttls_contracts() -> None:
    plaintext = SMTP_AUTH_SCENARIOS[0]
    starttls = SMTP_AUTH_TLS_SCENARIOS[0]

    assert plaintext.name == "smtp/auth/state-rate-limit-and-side-effects"
    assert plaintext.contract is not None
    assert plaintext.contract["auth_failure_limit"] == 20
    assert plaintext.contract["auth_advertised"] is False
    assert plaintext.contract["auth_probe_persistence_observed"] is False

    assert starttls.name == "smtp/auth/starttls-state"
    assert starttls.contract is not None
    assert starttls.contract["pre_tls_ehlo_required"] is True
    assert starttls.contract["post_tls_ehlo_required"] is True
    assert starttls.contract["auth_advertised_before_tls"] is False
    assert starttls.contract["auth_advertised_after_tls"] is False
