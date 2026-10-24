#!/usr/bin/env python3
"""Bounded external URI mutation smoke, against an isolated real candidate.

PYTHONPATH=blackbox/src:blackbox/tests .blackbox/venv/bin/python \
    tools/fuzz-cringe-detail.py .blackbox/<pinned>.elf
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote_from_bytes

from test_candidate_cringe_api_golden import _LegacyCandidateRuntime
from test_candidate_cringe_detail_golden import _activities_state, _request, _seed
from test_candidate_cringe_list_golden import _state


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    with binary.open("rb") as source:
        before_hash = hashlib.file_digest(source, "sha256").hexdigest()
    seed = 0x19_20261024
    randomizer = random.Random(seed)
    counts: Counter[int] = Counter()
    started = time.monotonic()
    with _LegacyCandidateRuntime(command_template=(str(binary), "--config", "{config}")) as candidate:
        _seed(candidate)
        before = (_state(candidate), _activities_state(candidate))
        baseline = _request(candidate, "203.0.113.77")
        assert baseline.status_code == 200
        for index in range(4096):
            data = randomizer.randbytes(randomizer.randrange(1, 256))
            path = quote_from_bytes(data, safe="")
            if index % 3 == 0:
                path = "203.0.113.77" + path
            if index % 5 == 0:
                position = randomizer.randrange(len(path) + 1)
                path = path[:position] + randomizer.choice(("%", "%A", "%GG", "%0G")) + path[position:]
            response = _request(candidate, path)
            counts[response.status_code] += 1
            body = json.loads(response.body)
            if response.status_code == 200:
                assert set(body) == {"summary", "activities"}
                assert isinstance(body["summary"]["ipAddress"], str)
                assert len(body["activities"]) <= 10000
                assert all(activity["ipAddress"] == body["summary"]["ipAddress"] for activity in body["activities"])
            elif response.status_code == 404:
                assert body == {"error": "not_found"}
            else:
                assert response.status_code == 500
                assert body == {"error": "internal_error"}
            if index % 64 == 0:
                healthy = _request(candidate, "203.0.113.77")
                assert healthy.status_code == 200 and healthy.body == baseline.body
        assert (_state(candidate), _activities_state(candidate)) == before
        assert _request(candidate, "203.0.113.77").body == baseline.body
    with binary.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == before_hash
    print(json.dumps({
        "binary_sha256": before_hash, "seed": seed, "mutations": 4096,
        "statuses": dict(sorted(counts.items())), "seconds": time.monotonic() - started,
        "database_unchanged": True, "health_probes": 66, "result": "passed",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
