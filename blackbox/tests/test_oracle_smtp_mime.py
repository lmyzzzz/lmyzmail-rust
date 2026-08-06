from __future__ import annotations

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import JavaOracleRuntime
from lmyzmail_blackbox.smtp_mime_contract import SMTP_MIME_SCENARIOS


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_mime_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-mime-v3",
        "managed-smtp-mime",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_MIME_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_MIME_SCENARIOS, oracle)
