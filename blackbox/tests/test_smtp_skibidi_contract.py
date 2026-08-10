from __future__ import annotations

from lmyzmail_blackbox.smtp_skibidi_contract import SMTP_SKIBIDI_SCENARIOS


def test_smtp_skibidi_profile_binds_quiz_video_and_admission() -> None:
    assert [scenario.name for scenario in SMTP_SKIBIDI_SCENARIOS] == [
        "smtp/skibidi/commands-and-session-state",
        "smtp/skibidi/complete-quizzes",
        "smtp/skibidi/video-parameter-boundaries",
        "smtp/skibidi/video-first-frame-and-admission",
    ]
    commands, quizzes, boundaries, video = SMTP_SKIBIDI_SCENARIOS
    assert commands.contract is not None
    assert commands.contract["question_bank_sha256"] == (
        "7bcbeacd0d36a58931efa49234143946cb981b4c978c74432313fcad843ba8d1"
    )
    assert quizzes.contract is not None
    assert quizzes.contract["question_count"] == 474
    assert quizzes.contract["selection_without_replacement"] is True
    assert boundaries.contract == {
        "default_width": 120,
        "maximum_width": 450,
        "default_fps": 10.0,
        "maximum_fps": 20.0,
    }
    assert video.contract is not None
    assert video.contract["global_viewer_limit"] == 1
    assert video.contract["disconnect_releases_admission"] is True
