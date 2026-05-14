"""Detector authoring helpers for plugin-style development."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from threatlib.graph.account_graph import AccountGraph
from threatlib.signals.base import BaseDetector, DetectorResult


@dataclass(frozen=True)
class DetectorContext:
    policy: Any
    graph: AccountGraph
    detector_results: dict[str, DetectorResult] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectorSpec:
    name: str
    required_fields: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    attack_vectors: tuple[str, ...] = ()
    version: str = "1.0.0"


class DetectorHarness:
    """Small test harness used by detector plugins and examples."""

    def __init__(self, detector_cls: type[BaseDetector], context: DetectorContext) -> None:
        validate_detector_class(detector_cls)
        self.detector_cls = detector_cls
        self.context = context

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        detector = self.detector_cls(policy=self.context.policy, graph=self.context.graph)
        enriched = dict(account_data)
        enriched["_detector_results"] = self.context.detector_results
        return detector.safe_score(enriched)

    def canonical_cases(
        self,
        clear_bot: dict[str, Any],
        clear_human: dict[str, Any],
        absent_data: dict[str, Any] | None = None,
    ) -> dict[str, DetectorResult]:
        return {
            "clear_bot": self.score(clear_bot),
            "clear_human": self.score(clear_human),
            "absent_data": self.score(absent_data or {"account_id": "absent"}),
        }


def validate_detector_class(detector_cls: type[BaseDetector]) -> DetectorSpec:
    if not issubclass(detector_cls, BaseDetector):
        raise TypeError("detector class must inherit BaseDetector")
    name = getattr(detector_cls, "name", "")
    if not name or name == "base":
        raise ValueError("detector class must declare a stable name")
    required_fields = tuple(getattr(detector_cls, "required_fields", ()))
    depends_on = tuple(getattr(detector_cls, "depends_on", ()))
    if name in depends_on:
        raise ValueError("detector cannot depend on itself")
    return DetectorSpec(name=name, required_fields=required_fields, depends_on=depends_on)
