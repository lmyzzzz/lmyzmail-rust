from __future__ import annotations

from lmyzmail_blackbox.smtp_data_contract import (
    SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_DATA_SCENARIOS,
)


def test_smtp_data_profile_binds_incremental_and_recovery_contracts() -> None:
    assert [scenario.name for scenario in SMTP_DATA_SCENARIOS] == [
        "smtp/data/fragmented-terminator-storage",
        "smtp/bdat/fragmented-binary-storage",
        "smtp/bdat/coalesced-multi-chunk-storage",
        "smtp/bdat/zero-and-oversize-state",
        "smtp/bdat/zero-last-transaction-state",
        "smtp/data/partial-disconnect-recovery",
        "smtp/bdat/partial-disconnect-recovery",
    ]
    first = SMTP_DATA_SCENARIOS[0].contract
    fourth = SMTP_DATA_SCENARIOS[3].contract
    assert first is not None
    assert fourth is not None
    assert first["requirements"] == [
        "incremental-framing",
        "bounded-buffering",
        "exact-bdat-octet-count",
        "partial-disconnect-cleans-state",
        "fresh-session-recovery",
    ]
    assert fourth["oversize_declared_bytes"] == 15_728_641


def test_smtp_data_evidence_keeps_oracle_only_behaviors_separate() -> None:
    assert [scenario.name for scenario in SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS] == [
        "smtp/data/oracle-terminator-tail-command-loss",
        "smtp/bdat/oracle-coalesced-prerequisite-state-stall",
    ]
    difference_ids: set[str] = set()
    for scenario in SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS:
        contract = scenario.contract
        assert contract is not None
        difference_ids.add(str(contract["difference_id"]))
    assert difference_ids == {
        "smtp-data-terminator-command-loss",
        "smtp-bdat-coalesced-prerequisite-state-stall",
    }
