from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .errors import HarnessError
from .golden import GoldenAttestation, GoldenStore
from .ports import PortSet


class RuntimeTarget(Protocol):
    @property
    def target_kind(self) -> str: ...

    @property
    def workspace(self) -> Path | None: ...

    @property
    def ports(self) -> PortSet | None: ...


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    capture: Callable[[RuntimeTarget], Any]
    normalizers: tuple[str, ...] = ()
    contract: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        parts = self.name.split("/")
        if not parts or any(not part or part in {".", ".."} for part in parts):
            raise ValueError(f"invalid scenario name: {self.name!r}")
        if self.contract is None:
            derived = getattr(self.capture, "__lmyzmail_contract__", None)
            if not isinstance(derived, dict):
                raise ValueError(f"scenario contract is missing: {self.name!r}")
            object.__setattr__(self, "contract", derived)


@dataclass(frozen=True, slots=True)
class DifferentialRunner:
    repository: Path
    golden_root: Path
    profile: str
    record_java: bool = False

    def _attestation(self, normalizers: tuple[str, ...]) -> GoldenAttestation:
        return GoldenAttestation.from_repository(
            self.repository,
            profile=self.profile,
            normalizers=normalizers,
        )

    @staticmethod
    def _require_started(target: RuntimeTarget) -> None:
        if target.workspace is None or target.ports is None:
            raise HarnessError(f"{target.target_kind} runtime is not started")

    def _assert_suite_manifest(self, scenarios: Sequence[Scenario], *, record: bool) -> None:
        store = GoldenStore(
            self.golden_root,
            self._attestation(("suite-manifest-v1",)),
            record=record,
        )
        store.assert_observation(
            "suite.json",
            {
                "profile": self.profile,
                "scenarios": [
                    {
                        "name": scenario.name,
                        "normalizers": list(scenario.normalizers),
                        "contract": scenario.contract,
                    }
                    for scenario in scenarios
                ],
            },
        )

    def record_from_java(
        self,
        scenarios: Sequence[Scenario],
        target: RuntimeTarget,
    ) -> None:
        if target.target_kind != "java-oracle":
            raise HarnessError("goldens may only be recorded from the frozen Java oracle")
        if not self.record_java:
            raise HarnessError("explicit Java golden record mode is not enabled")
        self._require_started(target)
        self._assert_suite_manifest(scenarios, record=True)
        for scenario in scenarios:
            observation = scenario.capture(target)
            GoldenStore(
                self.golden_root,
                self._attestation(scenario.normalizers),
                record=True,
            ).assert_observation(f"observations/{scenario.name}.json", observation)

    def verify_candidate(
        self,
        scenarios: Sequence[Scenario],
        target: RuntimeTarget,
    ) -> None:
        if target.target_kind == "java-oracle":
            raise HarnessError("candidate verification requires a non-oracle target")
        self._require_started(target)
        self._assert_suite_manifest(scenarios, record=False)
        for scenario in scenarios:
            observation = scenario.capture(target)
            GoldenStore(
                self.golden_root,
                self._attestation(scenario.normalizers),
            ).assert_observation(f"observations/{scenario.name}.json", observation)

    def verify_java(
        self,
        scenarios: Sequence[Scenario],
        target: RuntimeTarget,
    ) -> None:
        if target.target_kind != "java-oracle":
            raise HarnessError("Java golden verification requires the frozen oracle")
        self._require_started(target)
        self._assert_suite_manifest(scenarios, record=False)
        for scenario in scenarios:
            observation = scenario.capture(target)
            GoldenStore(
                self.golden_root,
                self._attestation(scenario.normalizers),
            ).assert_observation(f"observations/{scenario.name}.json", observation)
