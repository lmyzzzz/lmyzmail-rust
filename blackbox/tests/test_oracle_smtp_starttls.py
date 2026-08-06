from __future__ import annotations

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import JavaOracleRuntime, JavaOracleTlsRuntime
from lmyzmail_blackbox.smtp_tls_contract import (
    STARTTLS_ORACLE_EVIDENCE_SCENARIOS,
    STARTTLS_SCENARIOS,
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_starttls_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-starttls-v7",
        "managed-starttls",
        record_java=record_java_golden,
    )
    oracle_evidence = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-starttls-oracle-evidence-v7",
        "managed-starttls-oracle-evidence",
        record_java=record_java_golden,
    )

    with JavaOracleTlsRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(STARTTLS_SCENARIOS, oracle)
            oracle_evidence.record_from_java(STARTTLS_ORACLE_EVIDENCE_SCENARIOS, oracle)
        else:
            differential.verify_java(STARTTLS_SCENARIOS, oracle)
            oracle_evidence.verify_java(STARTTLS_ORACLE_EVIDENCE_SCENARIOS, oracle)
