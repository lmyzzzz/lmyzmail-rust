from __future__ import annotations

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import JavaOracleRuntime, JavaOracleTlsRuntime
from lmyzmail_blackbox.smtp_auth_contract import (
    SMTP_AUTH_SCENARIOS,
    SMTP_AUTH_TLS_SCENARIOS,
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_auth_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-auth-v3",
        "managed-smtp-auth",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_AUTH_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_AUTH_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_auth_starttls_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-auth-starttls-v3",
        "managed-smtp-auth-starttls",
        record_java=record_java_golden,
    )

    with JavaOracleTlsRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_AUTH_TLS_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_AUTH_TLS_SCENARIOS, oracle)
