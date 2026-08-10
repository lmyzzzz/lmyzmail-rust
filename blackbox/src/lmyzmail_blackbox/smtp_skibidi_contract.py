from __future__ import annotations

import hashlib
import json
import math
import time
from pathlib import Path
from typing import Any, cast

from .differential import RuntimeTarget, Scenario
from .protocols import RawSmtpClient, read_smtp_reply
from .smtp_contract import (
    open_smtp_client,
    smtp_ehlo,
    smtp_greeting_snapshot,
    smtp_reply_snapshot,
)
from .snapshots import bytes_snapshot

_QUESTION_BANK_SHA256 = "7bcbeacd0d36a58931efa49234143946cb981b4c978c74432313fcad843ba8d1"
_VIDEO_SHA256 = "0e76229bb77ebcf471aec692fa34709cfbbe3dc192127a852a518e34bdd0ecc7"
_RANDOM_SELECTION_NORMALIZER = "smtp:quiz-random-question-order-and-selection"

_LEVELS = {
    "BABYGRONK": ("BABY GRONK", 15, 60),
    "SKIBIDITOILET": ("SKIBIDI TOILET", 30, 150),
    "OHIOFINALBOSS": ("OHIO FINAL BOSS", 60, 400),
}

_CORRECT_FEEDBACK = (
    "CORRECT! You ate that no cap.",
    "CORRECT! Sheeeesh, you got that rizz fr fr.",
    "CORRECT! That is bussin. Certified sigma moment.",
    "CORRECT! Built different energy detected.",
    "CORRECT! No cap, you are not an NPC after all.",
    "CORRECT! The aura readings are off the charts.",
    "CORRECT! Goated with the sauce.",
    "CORRECT! Unspoken rizz confirmed.",
    "CORRECT! That answer just hit different.",
    "CORRECT! Ohio could never.",
)

_WRONG_FEEDBACK = (
    "WRONG! L + ratio + no rizz.",
    "WRONG! You are cooking with zero aura.",
    "WRONG! Absolute NPC behavior detected.",
    "WRONG! The Ohio final boss is disappointed.",
    "WRONG! Bro fell off harder than a failed looksmaxx attempt.",
    "WRONG! That answer is mid at best.",
    "WRONG! You need to grind your Brainrot knowledge stat.",
    "WRONG! Genuinely the least sigma answer possible.",
    "WRONG! Skibidi dop dop no no.",
    "WRONG! Even Grimace Shake could not save you.",
)

_HELP_LINES = (
    "SKIBIDITOILET - Brainrot Quiz & Video SMTP Extension",
    "Tests your Gen Alpha / internet slang knowledge. Are you built different?",
    "",
    "Subcommands:",
    "  SKIBIDITOILET HELP",
    "    Prints this help message. You clearly needed it.",
    "",
    "  SKIBIDITOILET START <LEVEL>",
    "    Starts a quiz. Available levels:",
    "      BABYGRONK      - 15 questions, easy mode. For the NPC crowd.",
    "      SKIBIDITOILET  - 30 questions, balanced. Mid-tier rizz required.",
    "      OHIOFINALBOSS  - 60 questions, maximum aura drain. Only sigma males apply.",
    "",
    "  SKIBIDITOILET ANSWER <your answer>",
    "    For multiple choice: reply with A, B, C, or D.",
    "    For fill-in-the-blank: type your answer.",
    "",
    "  SKIBIDITOILET QUIT",
    "    Forfeits the current quiz. Your aura will not recover from this.",
    "",
    "  SKIBIDITOILET WATCHSKIBIDITOILET [params...]",
    "    Streams Skibidi Toilet Episode 1 as ASCII Art over SMTP.",
    "    Your terminal must support ANSI escape codes.",
    "",
    "    Parameters (space-separated, all optional):",
    "      WIDTH=<n>       Output width in characters    (default: 120, max: 450)",
    "      FPS=<n>         Playback frame rate           (default: 10.0, max: 20)",
    "      CONTRAST=<f>    Contrast multiplier           (default: 1.2)",
    "      BRIGHTNESS=<f>  Brightness offset             (default: 0.0)",
    "      GAMMA=<f>       Gamma correction              (default: 1.0)",
    "      ASPECT=<f>      Character height/width ratio  (default: 2.0)",
    "      INVERT          Invert brightness mapping",
    "",
    "    Example:",
    "      SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=160 FPS=12 CONTRAST=1.5",
    "",
    "    WARNING: Color mode is not supported (monochrome only).",
    "    WARNING: Once playback starts, it CANNOT be stopped except by",
    "             disconnecting. You have been warned. No cap.",
    "    WARNING: Maximum 1 concurrent viewer globally.",
    "    WARNING: Each line is prefixed with '250-' per SMTP multi-line",
    "             response format. This is normal. Embrace the jank.",
    "",
    "Notes:",
    "  - Quiz runs inline in the SMTP session. No MAIL transaction needed.",
    "  - Commands are case-insensitive. Your excuses are not.",
    "214 End of HELP. Skibidi dop dop yes yes.",
)


def _check(condition: bool, details: object) -> None:
    if not condition:
        raise AssertionError(f"SMTP SKIBIDITOILET contract violation: {details!r}")


def _load_question_bank() -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    path = Path(__file__).resolve().parents[3] / "crates/lmyzmail/assets/brainrot_quiz.json"
    raw = path.read_bytes()
    _check(hashlib.sha256(raw).hexdigest() == _QUESTION_BANK_SHA256, path)
    parsed = json.loads(raw)
    _check(isinstance(parsed, list) and len(parsed) == 474, len(parsed))
    questions = cast(list[dict[str, Any]], parsed)
    by_text: dict[str, list[dict[str, Any]]] = {}
    ids: set[int] = set()
    for question in questions:
        _check(
            set(question) == {"id", "question", "type", "options", "answer", "difficulty"},
            question,
        )
        question_id = question["id"]
        text = question["question"]
        options = question["options"]
        _check(isinstance(question_id, int) and question_id > 0, question)
        _check(isinstance(text, str) and bool(text) and text.isascii(), question)
        _check(question["type"] == "multiple_choice", question)
        _check(
            isinstance(options, dict) and tuple(sorted(options)) == ("A", "B", "C", "D"),
            question,
        )
        _check(question["answer"] in options, question)
        _check(
            isinstance(question["difficulty"], int) and 1 <= question["difficulty"] <= 10,
            question,
        )
        _check(question_id not in ids, question)
        ids.add(question_id)
        by_text.setdefault(text, []).append(question)
    return questions, by_text


def _wire(code: int, lines: tuple[str, ...]) -> tuple[bytes, ...]:
    return tuple(
        f"{code}{'-' if index + 1 < len(lines) else ' '}{line}\r\n".encode("ascii")
        for index, line in enumerate(lines)
    )


def _command(
    client: RawSmtpClient,
    hostname: bytes,
    command: bytes,
    expected: tuple[bytes, ...],
) -> list[str]:
    reply = client.command(command)
    _check(reply == expected, {"command": command, "reply": reply})
    return smtp_reply_snapshot(reply, hostname)


def _payload(reply: tuple[bytes, ...], code: int) -> list[str]:
    _check(bool(reply), reply)
    expected_code = str(code).encode("ascii")
    lines: list[str] = []
    for index, line in enumerate(reply):
        separator = b" " if index + 1 == len(reply) else b"-"
        _check(
            line.startswith(expected_code + separator) and line.endswith(b"\r\n"),
            reply,
        )
        lines.append(line[4:-2].decode("ascii"))
    return lines


def _question_lines(question: dict[str, Any], number: int, total: int) -> list[str]:
    options = cast(dict[str, str], question["options"])
    return [
        f"Q{number}/{total} [DIFFICULTY: {question['difficulty']}/10] {question['question']}",
        *(f"  {key}) {options[key]}" for key in ("A", "B", "C", "D")),
        "ANSWER with A, B, C, or D",
    ]


def _parse_question(
    lines: list[str],
    *,
    prefix: list[str],
    number: int,
    total: int,
    by_text: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    _check(lines[: len(prefix)] == prefix, {"lines": lines, "prefix": prefix})
    question_lines = lines[len(prefix) :]
    marker = f"Q{number}/{total} [DIFFICULTY: "
    _check(bool(question_lines) and question_lines[0].startswith(marker), question_lines)
    try:
        text = question_lines[0].split("] ", 1)[1]
    except (IndexError, ValueError) as error:
        raise AssertionError(f"invalid quiz question header: {question_lines[0]!r}") from error
    matches = [
        question
        for question in by_text.get(text, ())
        if question_lines == _question_lines(question, number, total)
    ]
    if len(matches) != 1:
        raise AssertionError(f"question is not in the frozen bank: {text!r}")
    return matches[0]


def _java_percent(correct: int, total: int) -> int:
    return math.floor(correct / total * 100.0 + 0.5)


def _rating(percent: int) -> str:
    if percent == 100:
        return "CERTIFIED OHIO FINAL BOSS. You are the rizz incarnate."
    if percent >= 90:
        return "GIGACHAD SIGMA. Unspoken rizz fully unlocked."
    if percent >= 75:
        return "BUILT DIFFERENT. High aura individual detected."
    if percent >= 60:
        return "MAIN CHARACTER ENERGY. Could use more looksmaxxing."
    if percent >= 45:
        return "SIDE CHARACTER. Exists but rarely relevant."
    if percent >= 30:
        return "NPC BEHAVIOR. Touch grass and try harder."
    if percent >= 15:
        return "CERTIFIED BRAINROT PATIENT. Seek help."
    return "ABSOLUTE SNORLAX. Did you even try? L + ratio + go back to the lobby."


def _final_comment(percent: int, level: str) -> str:
    if percent >= 80:
        return {
            "BABYGRONK": (
                "You demolished Baby Gronk mode. Now stop flexing on the NPCs and step it up."
            ),
            "SKIBIDITOILET": ("Skibidi Toilet mode cleared with max aura. The algorithm approves."),
            "OHIOFINALBOSS": (
                "Ohio Final Boss conquered. You are the only living sigma male. Respect."
            ),
        }[level]
    if percent >= 50:
        return {
            "BABYGRONK": (
                "Barely surviving Baby Gronk mode. The bottom of the sigma grindset awaits you."
            ),
            "SKIBIDITOILET": (
                "Mid run. Your rizz is mid. Your aura is mid. You are mid. Grind harder."
            ),
            "OHIOFINALBOSS": ("Ohio Final Boss humbled you. Expected. Very few survive this arc."),
        }[level]
    return {
        "BABYGRONK": ("You failed Baby Gronk mode. This is the most Ohio outcome possible."),
        "SKIBIDITOILET": (
            "Skibidi Toilet flushed you. No aura detected. RIP to your sigma journey."
        ),
        "OHIOFINALBOSS": ("Ohio Final Boss was simply too powerful. You were not built different."),
    }[level]


def _feedback(question: dict[str, Any], number: int, correct: bool) -> str:
    if correct:
        return _CORRECT_FEEDBACK[number % len(_CORRECT_FEEDBACK)]
    options = cast(dict[str, str], question["options"])
    answer = cast(str, question["answer"])
    return (
        f"{_WRONG_FEEDBACK[number % len(_WRONG_FEEDBACK)]} "
        f"Correct answer: {answer}) {options[answer]}"
    )


def _capture_commands_and_session_state(target: RuntimeTarget) -> dict[str, Any]:
    _, by_text = _load_question_bank()
    client, hostname = open_smtp_client(target)
    with client:
        help_reply = client.command(b"SKIBIDITOILET HELP")
        _check(help_reply == _wire(214, _HELP_LINES), help_reply)
        boundaries = {
            "help": smtp_reply_snapshot(help_reply, hostname),
            "lowercase_help": _command(
                client, hostname, b"skibiditoilet help", _wire(214, _HELP_LINES)
            ),
            "missing_subcommand": _command(
                client,
                hostname,
                b"SKIBIDITOILET",
                _wire(
                    501,
                    ("5.5.4 Unknown subcommand. Type SKIBIDITOILET HELP to git gud.",),
                ),
            ),
            "answer_without_quiz": _command(
                client,
                hostname,
                b"SKIBIDITOILET ANSWER nope",
                _wire(
                    503,
                    (
                        "5.5.1 No quiz in progress. Use SKIBIDITOILET START "
                        "<LEVEL> to begin. Stop yapping and do something.",
                    ),
                ),
            ),
            "quit_without_quiz": _command(
                client,
                hostname,
                b"SKIBIDITOILET QUIT",
                _wire(
                    503,
                    (
                        "5.5.1 No quiz in progress. There is nothing to quit "
                        "from. Classic NPC move.",
                    ),
                ),
            ),
            "missing_level": _command(
                client,
                hostname,
                b"SKIBIDITOILET START",
                _wire(
                    501,
                    (
                        "5.5.4 Syntax: SKIBIDITOILET START <LEVEL>. Levels: "
                        "BABYGRONK, SKIBIDITOILET, OHIOFINALBOSS",
                    ),
                ),
            ),
            "unknown_level": _command(
                client,
                hostname,
                b"SKIBIDITOILET START INVALID",
                _wire(
                    501,
                    (
                        "5.5.4 Unknown level 'INVALID'. Valid: BABYGRONK, "
                        "SKIBIDITOILET, OHIOFINALBOSS. Cope harder and try again.",
                    ),
                ),
            ),
        }

        start_reply = client.command(b"SKIBIDITOILET START BABYGRONK")
        first_question = _parse_question(
            _payload(start_reply, 250),
            prefix=[
                "QUIZ STARTED: BABY GRONK (15 questions | target difficulty: 60)",
                "Demonstrate your aura or be forever NPC. No skipping. No crying.",
                "",
            ],
            number=1,
            total=15,
            by_text=by_text,
        )
        active = {
            "first_question": "<random-valid-question>",
            "duplicate_start": _command(
                client,
                hostname,
                b"SKIBIDITOILET START BABYGRONK",
                _wire(
                    503,
                    (
                        "5.5.1 Quiz already in progress. SKIBIDITOILET QUIT "
                        "to forfeit, or SKIBIDITOILET ANSWER to keep coping.",
                    ),
                ),
            ),
            "empty_answer": _command(
                client,
                hostname,
                b"SKIBIDITOILET ANSWER",
                _wire(
                    501,
                    (
                        "5.5.4 Empty answer detected. Submitting nothing is peak "
                        "NPC behavior. Type SKIBIDITOILET ANSWER <your answer>.",
                    ),
                ),
            ),
        }
        _check(isinstance(first_question["id"], int), first_question)
        helo_reply = client.command(b"HELO state.example")
        _check(
            helo_reply == (b"250 " + hostname + b" Hello state.example\r\n",),
            helo_reply,
        )
        already_active = _wire(
            503,
            (
                "5.5.1 Quiz already in progress. SKIBIDITOILET QUIT to "
                "forfeit, or SKIBIDITOILET ANSWER to keep coping.",
            ),
        )
        active["helo_preserves_quiz"] = _command(
            client,
            hostname,
            b"SKIBIDITOILET START SKIBIDITOILET",
            already_active,
        )
        active["rset"] = _command(client, hostname, b"RSET", _wire(250, ("2.0.0 Reset OK",)))
        active["rset_preserves_quiz"] = _command(
            client,
            hostname,
            b"SKIBIDITOILET START OHIOFINALBOSS",
            already_active,
        )
        active["forfeit"] = _command(
            client,
            hostname,
            b"SKIBIDITOILET QUIT",
            _wire(
                250,
                (
                    "Quiz forfeited. That is the most L take in recorded Brainrot history.",
                    "Progress: 0/0 correct before you rage-quit.",
                    "The Ohio final boss remains undefeated. You were not built different.",
                    "Use SKIBIDITOILET START <LEVEL> to try again and redeem your aura.",
                ),
            ),
        )
        active["answer_after_forfeit"] = _command(
            client,
            hostname,
            b"SKIBIDITOILET ANSWER A",
            _wire(
                503,
                (
                    "5.5.1 No quiz in progress. Use SKIBIDITOILET START "
                    "<LEVEL> to begin. Stop yapping and do something.",
                ),
            ),
        )
        quit_reply = client.quit()

    return {
        "greeting": smtp_greeting_snapshot(),
        "boundaries": boundaries,
        "active_state": active,
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }


def _run_level(target: RuntimeTarget, level: str) -> dict[str, Any]:
    _, by_text = _load_question_bank()
    display_name, question_count, target_difficulty = _LEVELS[level]
    client, hostname = open_smtp_client(target)
    selected_ids: set[int] = set()
    total_difficulty = 0
    correct_count = 0
    previous_prefix: list[str] = []
    with client:
        smtp_ehlo(client, hostname)
        reply = client.command(f"SKIBIDITOILET START {level}".encode("ascii"))
        for number in range(1, question_count + 1):
            prefix = (
                [
                    f"QUIZ STARTED: {display_name} "
                    f"({question_count} questions | target difficulty: "
                    f"{target_difficulty})",
                    "Demonstrate your aura or be forever NPC. No skipping. No crying.",
                    "",
                ]
                if number == 1
                else previous_prefix
            )
            question = _parse_question(
                _payload(reply, 250),
                prefix=prefix,
                number=number,
                total=question_count,
                by_text=by_text,
            )
            question_id = cast(int, question["id"])
            _check(
                question_id not in selected_ids,
                {"level": level, "duplicate": question_id},
            )
            selected_ids.add(question_id)
            total_difficulty += cast(int, question["difficulty"])

            correct = number % 3 != 0
            if correct:
                correct_count += 1
                answer = cast(str, question["answer"])
            else:
                answer = "Z"
            reply = client.command(f"SKIBIDITOILET ANSWER {answer}".encode("ascii"))
            expected_feedback = _feedback(question, number, correct)
            score_line = (
                f"Score so far: {correct_count}/{number} ({_java_percent(correct_count, number)}%)"
            )
            if number < question_count:
                previous_prefix = [expected_feedback, score_line, ""]
                continue

            _check(_payload(reply, 250) == [expected_feedback, score_line], reply)
            final_reply = read_smtp_reply(client.stream)
            percent = _java_percent(correct_count, question_count)
            expected_final = _wire(
                220,
                (
                    f"=== BRAINROT QUIZ COMPLETE: {display_name} ===",
                    f"Final Score: {correct_count}/{question_count} ({percent}%)",
                    f"Rating: {_rating(percent)}",
                    _final_comment(percent, level),
                    "Use SKIBIDITOILET START <LEVEL> to play again or touch grass.",
                ),
            )
            _check(final_reply == expected_final, final_reply)

        restart = client.command(f"SKIBIDITOILET START {level}".encode("ascii"))
        _parse_question(
            _payload(restart, 250),
            prefix=[
                f"QUIZ STARTED: {display_name} "
                f"({question_count} questions | target difficulty: "
                f"{target_difficulty})",
                "Demonstrate your aura or be forever NPC. No skipping. No crying.",
                "",
            ],
            number=1,
            total=question_count,
            by_text=by_text,
        )
        forfeit = client.command(b"SKIBIDITOILET QUIT")
        _check(
            forfeit
            == _wire(
                250,
                (
                    "Quiz forfeited. That is the most L take in recorded Brainrot history.",
                    "Progress: 0/0 correct before you rage-quit.",
                    "The Ohio final boss remains undefeated. You were not built different.",
                    "Use SKIBIDITOILET START <LEVEL> to try again and redeem your aura.",
                ),
            ),
            forfeit,
        )
        client.quit()

    tolerance = math.ceil(target_difficulty * 0.12)
    _check(
        target_difficulty - tolerance <= total_difficulty <= target_difficulty + tolerance,
        {"level": level, "total_difficulty": total_difficulty},
    )
    return {
        "level": level,
        "display_name": display_name,
        "question_count": question_count,
        "target_difficulty": target_difficulty,
        "difficulty_tolerance_fraction": 0.12,
        "selection": "<random-valid-unique-selection>",
        "total_difficulty": "<random-in-tolerance>",
        "answer_pattern": "correct,correct,wrong",
        "correct_count": correct_count,
        "final_percent": _java_percent(correct_count, question_count),
        "completed_state_cleared": True,
        "restart_and_forfeit": True,
    }


def _capture_complete_quizzes(target: RuntimeTarget) -> dict[str, Any]:
    questions, _ = _load_question_bank()
    return {
        "question_bank": {
            "sha256": _QUESTION_BANK_SHA256,
            "questions": len(questions),
            "unique_ids": len({cast(int, question["id"]) for question in questions}),
            "types": ["multiple_choice"],
        },
        "levels": [_run_level(target, level) for level in _LEVELS],
    }


def _capture_video_boundaries(target: RuntimeTarget) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    cases = (
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=nope",
            _wire(501, ("5.5.4 Invalid WIDTH value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET FPS=nope",
            _wire(501, ("5.5.4 Invalid FPS value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET CONTRAST=nope",
            _wire(501, ("5.5.4 Invalid CONTRAST value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET BRIGHTNESS=nope",
            _wire(501, ("5.5.4 Invalid BRIGHTNESS value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET GAMMA=nope",
            _wire(501, ("5.5.4 Invalid GAMMA value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET ASPECT=nope",
            _wire(501, ("5.5.4 Invalid ASPECT value.",)),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=9",
            _wire(
                501,
                (
                    "5.5.4 WIDTH must be 10..450. Got 9. Your terminal is "
                    "either microscopic or you are trying to crash the server.",
                ),
            ),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=451",
            _wire(
                501,
                (
                    "5.5.4 WIDTH must be 10..450. Got 451. Your terminal is "
                    "either microscopic or you are trying to crash the server.",
                ),
            ),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET FPS=0.5",
            _wire(
                501,
                ("5.5.4 FPS must be 1..20. Got 0.5. This is not a gaming PC benchmark.",),
            ),
        ),
        (
            b"SKIBIDITOILET WATCHSKIBIDITOILET FPS=21",
            _wire(
                501,
                ("5.5.4 FPS must be 1..20. Got 21.0. This is not a gaming PC benchmark.",),
            ),
        ),
    )
    with client:
        snapshots = [
            {
                "command": command.decode("ascii"),
                "reply": _command(client, hostname, command, expected),
            }
            for command, expected in cases
        ]
        client.quit()
    return {"parameter_cases": snapshots}


def _start_video_prefix(client: RawSmtpClient) -> bytes:
    client.stream.sendall(
        RawSmtpClient._command_bytes(
            b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=10 FPS=20 CONTRAST=1.2"
        )
    )
    initial = client.stream.read_line(max_line=1024)
    _check(initial == b"250-\x1b[2J\x1b[H\r\n", initial)
    rows = [client.stream.read_line(max_line=1024) for _ in range(3)]
    _check(
        rows[0].startswith(b"250-\x1b[H    ") and len(rows[0]) == 23,
        rows[0],
    )
    _check(
        all(row.startswith(b"250-") and row.endswith(b"\r\n") for row in rows),
        rows,
    )
    _check(all(len(row) == 16 for row in rows[1:]), rows)
    return initial + b"".join(rows)


def _capture_video_first_frame_and_admission(
    target: RuntimeTarget,
) -> dict[str, Any]:
    first, _ = open_smtp_client(target)
    try:
        prefix = _start_video_prefix(first)
        competing, competing_hostname = open_smtp_client(target)
        with competing:
            busy = competing.command(
                b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=10 FPS=20 CONTRAST=1.2"
            )
            expected_busy = _wire(
                451,
                (
                    "4.3.0 Another session is already watching Skibidi Toilet. "
                    "Max 1 concurrent viewer. Cope and try later.",
                ),
            )
            _check(busy == expected_busy, busy)
            busy_snapshot = smtp_reply_snapshot(busy, competing_hostname)
    finally:
        first.close()

    released = False
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        probe, _ = open_smtp_client(target)
        try:
            probe.stream.sendall(
                RawSmtpClient._command_bytes(
                    b"SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=10 FPS=20 CONTRAST=1.2"
                )
            )
            line = probe.stream.read_line(max_line=1024)
            if line == b"250-\x1b[2J\x1b[H\r\n":
                released = True
                break
            _check(line.startswith(b"451 "), line)
        finally:
            probe.close()
        time.sleep(0.05)
    _check(released, "video admission was not released after disconnect")
    return {
        "video": {
            "sha256": _VIDEO_SHA256,
            "source_dimensions": [1920, 1080],
            "source_fps": 30,
            "requested_width": 10,
            "derived_height": 3,
            "requested_fps": 20,
        },
        "first_frame_prefix": bytes_snapshot(prefix),
        "competing_viewer": busy_snapshot,
        "disconnect_releases_admission_within_seconds": 5,
    }


SMTP_SKIBIDI_SCENARIOS = (
    Scenario(
        "smtp/skibidi/commands-and-session-state",
        _capture_commands_and_session_state,
        contract={
            "question_bank_sha256": _QUESTION_BANK_SHA256,
            "help_and_video_capability_advertised": True,
            "quiz_state_is_connection_local": True,
            "helo_and_rset_preserve_quiz": True,
        },
        normalizers=(_RANDOM_SELECTION_NORMALIZER,),
    ),
    Scenario(
        "smtp/skibidi/complete-quizzes",
        _capture_complete_quizzes,
        contract={
            "question_bank_sha256": _QUESTION_BANK_SHA256,
            "question_count": 474,
            "levels": {level: values[1:] for level, values in _LEVELS.items()},
            "selection_without_replacement": True,
            "difficulty_tolerance_fraction": 0.12,
        },
        normalizers=(_RANDOM_SELECTION_NORMALIZER,),
    ),
    Scenario(
        "smtp/skibidi/video-parameter-boundaries",
        _capture_video_boundaries,
        contract={
            "default_width": 120,
            "maximum_width": 450,
            "default_fps": 10.0,
            "maximum_fps": 20.0,
        },
    ),
    Scenario(
        "smtp/skibidi/video-first-frame-and-admission",
        _capture_video_first_frame_and_admission,
        contract={
            "video_sha256": _VIDEO_SHA256,
            "global_viewer_limit": 1,
            "disconnect_releases_admission": True,
            "frame_framing": "SMTP-250-continuation-lines",
        },
    ),
)
