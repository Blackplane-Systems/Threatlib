"""Coordinated behavior detector."""

from __future__ import annotations

from collections import Counter
import json
import math
import time
from typing import Any

from threatlib.action.feature_restrictor import compute_network_isolation
from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


def compute_mutual_information(timestamps: list[float], content_patterns: list[str]) -> float:
    if not timestamps or len(timestamps) != len(content_patterns):
        return 0.0
    span = max(timestamps) - min(timestamps)
    bucket_size = 3600.0 if span >= 3600.0 else 1.0
    buckets = [int(ts // bucket_size) for ts in timestamps]
    total = len(buckets)
    joint = Counter(zip(buckets, content_patterns))
    bucket_counts = Counter(buckets)
    pattern_counts = Counter(content_patterns)
    mi = 0.0
    for key, count in joint.items():
        t_bucket, pattern = key
        p_tc = count / total
        p_t = bucket_counts[t_bucket] / total
        p_c = pattern_counts[pattern] / total
        mi += p_tc * math.log(p_tc / max(p_t * p_c, 1e-12))
    return mi


def granger_test_pair(series_a: list[float], series_b: list[float], lag: int) -> float:
    if len(series_a) <= lag + 2 or len(series_b) <= lag + 2:
        return 1.0
    try:
        from statsmodels.tsa.stattools import grangercausalitytests
        import numpy as np

        data = np.column_stack([series_a, series_b])
        result = grangercausalitytests(data, maxlag=[lag], verbose=False)
        return float(result[lag][0]["ssr_ftest"][1])
    except Exception:
        paired = list(zip(series_a[lag:], series_b[:-lag]))
        if not paired:
            return 1.0
        mean_a = sum(item[0] for item in paired) / len(paired)
        mean_b = sum(item[1] for item in paired) / len(paired)
        numerator = sum((a - mean_a) * (b - mean_b) for a, b in paired)
        denom_a = math.sqrt(sum((a - mean_a) ** 2 for a, _ in paired))
        denom_b = math.sqrt(sum((b - mean_b) ** 2 for _, b in paired))
        corr = abs(numerator / max(denom_a * denom_b, 1e-12))
        return 0.01 if corr > 0.8 else 1.0


class CoordinatedBehaviorDetector(BaseDetector):
    name = "coordinated_behavior"
    depends_on = ("hawkes_burst_v2", "community_detection", "external_link_pattern")
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        community = account_data.get("_detector_results", {}).get("community_detection")
        if not community or community.is_uncertain():
            return DetectorResult.uncertain(self.name, "no candidate community")
        members = community.metadata.get("members", [])
        if len(members) < self.policy.community_detection.min_cluster_size:
            return DetectorResult.uncertain(self.name, "community below min size")
        events = [event for event in self.graph.all_recent_events(time.time() - ONE_DAY_SECONDS) if event["account_id"] in members]
        if len(events) < len(members):
            return DetectorResult.uncertain(self.name, "insufficient cluster events")
        timestamps = [float(event["timestamp"]) for event in events]
        patterns = [_content_pattern(event) for event in events]
        lrs: list[tuple[float, str]] = []
        mi = compute_mutual_information(timestamps, patterns)
        if mi > self.policy.community_detection.mutual_info_threshold:
            lrs.append((5.0, "high timestamp/content mutual information"))  # REF: v2 formula 24 - MI coordination LR.
        shared_domain = _shared_domain_count(events)
        if shared_domain >= 3:
            lrs.append((10.0, "shared external link domain in cluster"))  # REF: v2 C.3.3 - coordinated redirect LR.
        hawkes = account_data.get("_detector_results", {}).get("hawkes_burst_v2")
        if hawkes and hawkes.fraud_mass > 0.4:
            lrs.append((6.0, "Hawkes burst overlaps community"))  # REF: v2 C.3.3 - temporal/graph overlap LR.
        if not lrs:
            return DetectorResult.uncertain(self.name, "coordination signals neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        if result.fraud_mass > 0.7:
            isolation = compute_network_isolation(list(members), self.policy)
            for member in members:
                self.graph.record_isolation_action(member, f"cluster-{hash(tuple(sorted(members)))}", isolation)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "coordinated behavior analysis",
            {"community_size": len(members), "mutual_information": mi, "shared_domain_accounts": shared_domain},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _content_pattern(event: Any) -> str:
    data = _load(event)
    return str(data.get("link_domain") or data.get("domain") or event["event_type"])


def _shared_domain_count(events: list[Any]) -> int:
    by_domain: dict[str, set[str]] = {}
    for event in events:
        data = _load(event)
        domain = data.get("link_domain") or data.get("domain")
        if domain:
            by_domain.setdefault(str(domain).lower(), set()).add(event["account_id"])
    return max((len(accounts) for accounts in by_domain.values()), default=0)


def _load(event: Any) -> dict[str, Any]:
    try:
        return json.loads(event["event_data_json"])
    except Exception:
        return {}
