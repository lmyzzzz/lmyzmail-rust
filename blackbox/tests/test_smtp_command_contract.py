from __future__ import annotations

from lmyzmail_blackbox.smtp_command_contract import (
    SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_COMMAND_SCENARIOS,
)


def test_smtp_command_profile_binds_parser_state_and_error_budget() -> None:
    assert [scenario.name for scenario in SMTP_COMMAND_SCENARIOS] == [
        "smtp/commands/utility-and-transaction-state",
        "smtp/commands/parser-and-line-limits",
        "smtp/commands/error-budget-and-recovery",
    ]

    utility, parser, errors = SMTP_COMMAND_SCENARIOS
    assert utility.contract is not None
    assert utility.contract["mail_size_limit_bytes"] == 15_728_640
    assert utility.contract["ehlo_resets_transaction"] is True

    assert parser.contract is not None
    assert parser.contract["maximum_command_bytes_excluding_crlf"] == 1000
    assert parser.contract["overlong_session_recovers"] is True

    assert errors.contract is not None
    assert errors.contract["maximum_dispatcher_or_decoder_errors"] == 10
    assert errors.contract["handler_syntax_errors_consume_budget"] is False
    assert errors.contract["threshold_closes_connection"] is True

    assert [scenario.name for scenario in SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS] == [
        "smtp/commands/oracle-control-byte-reflection",
        "smtp/commands/oracle-fragmented-overlong-line",
    ]
    for scenario in SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS:
        assert scenario.contract is not None
        assert scenario.contract["difference_id"].startswith("smtp-")
