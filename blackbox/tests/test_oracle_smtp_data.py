from __future__ import annotations

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import JavaOracleRuntime
from lmyzmail_blackbox.smtp_data_contract import (
    SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_DATA_SCENARIOS,
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_smtp_data_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-data-v30",
        "managed-smtp-data",
        record_java=record_java_golden,
    )
    oracle_evidence = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-data-oracle-evidence-v30",
        "managed-smtp-data-oracle-evidence",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_DATA_SCENARIOS, oracle)
            oracle_evidence.record_from_java(
                SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )
        else:
            differential.verify_java(SMTP_DATA_SCENARIOS, oracle)
            oracle_evidence.verify_java(
                SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )
