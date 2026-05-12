"""Detector DAG orchestration."""

from __future__ import annotations

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


class DetectorDAGError(ValueError):
    pass


def default_detector_classes() -> dict[str, type[BaseDetector]]:
    from threatlib.risk.synthesis import DETECTOR_CLASSES as V1_DETECTORS
    from threatlib.signals.account_age_velocity import AccountAgeVelocityDetector
    from threatlib.signals.community_detection import CommunityDetectionDetector
    from threatlib.signals.coordinated_behavior import CoordinatedBehaviorDetector
    from threatlib.signals.cross_entropy_coherence import CrossEntropyCoherenceDetector
    from threatlib.signals.cross_signal_coherence import CrossSignalCoherenceDetector
    from threatlib.signals.external_link_pattern import ExternalLinkPatternDetector
    from threatlib.signals.hawkes_burst_v2 import HawkesBurstDetectorV2
    from threatlib.signals.hmm_intent import HMMIntentDetector
    from threatlib.signals.payment_signal import PaymentSignalDetector
    from threatlib.signals.sir_contagion import SIRContagionDetector
    from threatlib.signals.survival_analysis import SurvivalAnalysisDetector

    classes = dict(V1_DETECTORS)
    classes.update(
        {
            "cross_entropy_coherence": CrossEntropyCoherenceDetector,
            "account_age_velocity": AccountAgeVelocityDetector,
            "external_link_pattern": ExternalLinkPatternDetector,
            "payment_signal": PaymentSignalDetector,
            "hawkes_burst_v2": HawkesBurstDetectorV2,
            "community_detection": CommunityDetectionDetector,
            "cross_signal_coherence_v2": CrossSignalCoherenceDetector,
            "survival_analysis": SurvivalAnalysisDetector,
            "hmm_intent": HMMIntentDetector,
            "sir_contagion": SIRContagionDetector,
            "coordinated_behavior": CoordinatedBehaviorDetector,
        }
    )
    return classes


class DetectorOrchestrator:
    def __init__(self, policy: Any, graph: Any, detector_classes: dict[str, type[BaseDetector]] | None = None) -> None:
        self.policy = policy
        self.graph = graph
        self.detector_classes = detector_classes or default_detector_classes()
        if detector_classes is None:
            self.enabled_classes = {
                name: cls for name, cls in self.detector_classes.items() if self.policy.is_signal_enabled(name)
            }
        else:
            self.enabled_classes = dict(self.detector_classes)
        self.levels = self._topological_levels(self.enabled_classes)

    def _topological_levels(self, classes: dict[str, type[BaseDetector]]) -> list[list[str]]:
        dependencies: dict[str, set[str]] = {}
        reverse: dict[str, set[str]] = defaultdict(set)
        for name, cls in classes.items():
            depends_on = set(getattr(cls, "depends_on", ()))
            if name in depends_on:
                raise DetectorDAGError(f"detector {name} depends on itself")
            missing = depends_on - set(classes)
            if missing:
                depends_on = depends_on - missing
            dependencies[name] = depends_on
            for dependency in depends_on:
                reverse[dependency].add(name)

        ready = deque(sorted(name for name, deps in dependencies.items() if not deps))
        levels: list[list[str]] = []
        processed: set[str] = set()
        while ready:
            current_level = list(ready)
            ready.clear()
            levels.append(current_level)
            for name in current_level:
                processed.add(name)
                for child in sorted(reverse[name]):
                    dependencies[child].discard(name)
                    if not dependencies[child]:
                        ready.append(child)
        if len(processed) != len(classes):
            cycle_nodes = sorted(set(classes) - processed)
            raise DetectorDAGError(f"detector dependency cycle detected: {cycle_nodes}")
        return levels

    def run(self, account_data: dict[str, Any]) -> dict[str, DetectorResult]:
        results: dict[str, DetectorResult] = {}
        for level in self.levels:
            if len(level) == 1:
                name = level[0]
                results[name] = self._run_one(name, account_data, results)
            else:
                with ThreadPoolExecutor(max_workers=min(8, len(level))) as pool:
                    futures = {
                        pool.submit(self._run_one, name, account_data, dict(results)): name
                        for name in level
                    }
                    for future, name in futures.items():
                        results[name] = future.result()
        return results

    def _run_one(
        self,
        name: str,
        account_data: dict[str, Any],
        detector_results: dict[str, DetectorResult],
    ) -> DetectorResult:
        detector = self.enabled_classes[name](policy=self.policy, graph=self.graph)
        enriched = dict(account_data)
        enriched["_detector_results"] = detector_results
        return detector.safe_score(enriched)
