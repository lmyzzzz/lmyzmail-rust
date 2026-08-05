from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--record-java-golden",
        action="store_true",
        default=False,
        help="create missing attested goldens from the frozen Java oracle",
    )


@pytest.fixture(scope="session")
def record_java_golden(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--record-java-golden"))
