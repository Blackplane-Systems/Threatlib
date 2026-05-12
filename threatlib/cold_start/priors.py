"""Cold-start prior helpers."""

from __future__ import annotations

from typing import Any


def deployment_phase(account_count: int, policy: Any) -> str:
    threshold = policy.cold_start.min_accounts_for_platform_baseline
    if account_count < threshold:
        return "cold_start_p1"
    if account_count < threshold * 2:
        return "cold_start_p2"
    return "stable"


def blend_prior(published: float, platform: float, n_accounts: int, n_threshold: int) -> float:
    weight = min(1.0, n_accounts / max(n_threshold, 1))
    return (1.0 - weight) * published + weight * platform

