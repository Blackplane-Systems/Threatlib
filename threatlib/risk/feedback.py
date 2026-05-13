"""Feedback metrics and fast-deploy readiness helpers."""

from __future__ import annotations

import time
from typing import Any

from threatlib.graph.account_graph import AccountGraph, ONE_DAY_SECONDS


def model_metrics(graph: AccountGraph, since_hours: float | None = None) -> dict[str, Any]:
    since_ts = time.time() - since_hours * 3600.0 if since_hours is not None else None
    return graph.feedback_metrics(since_ts)


def fast_deploy_status(policy: Any, graph: AccountGraph, now: float | None = None) -> dict[str, Any]:
    ts = now if now is not None else time.time()
    first_score_at = graph.first_audit_timestamp()
    if first_score_at is None:
        hours_observed = 0.0
    else:
        hours_observed = max(0.0, (ts - first_score_at) / 3600.0)
    metrics = graph.feedback_metrics()
    score_count = graph.audit_count()
    metric_values = metrics["metrics"]
    checks = {
        "enabled": bool(policy.fast_deploy.enabled),
        "shadow_mode_disabled": not bool(policy.shadow_mode),
        "observation_hours": hours_observed >= policy.fast_deploy.observation_hours,
        "min_scores": score_count >= policy.fast_deploy.min_scores,
        "min_labels": metrics["label_count"] >= policy.fast_deploy.min_labels,
        "max_false_positive_rate": metric_values["false_positive_rate"] <= policy.fast_deploy.max_false_positive_rate,
        "max_false_negative_rate": metric_values["false_negative_rate"] <= policy.fast_deploy.max_false_negative_rate,
        "min_precision": metric_values["precision"] >= policy.fast_deploy.min_precision,
        "min_recall": metric_values["recall"] >= policy.fast_deploy.min_recall,
    }
    eligible = all(checks.values())
    return {
        "eligible": eligible,
        "checks": checks,
        "hours_observed": hours_observed,
        "required_observation_hours": policy.fast_deploy.observation_hours,
        "score_count": score_count,
        "label_count": metrics["label_count"],
        "metrics": metrics["metrics"],
        "confusion_matrix": metrics["confusion_matrix"],
        "action_cap": policy.fast_deploy.active_action_cap,
        "message": _status_message(policy, eligible),
    }


def apply_fast_deploy_action_policy(action: str, policy: Any, graph: AccountGraph) -> str:
    if not getattr(policy, "fast_deploy", None) or not policy.fast_deploy.enabled:
        return action
    status = fast_deploy_status(policy, graph)
    if not status["eligible"]:
        return "monitor"
    return cap_action(action, policy.fast_deploy.active_action_cap)


def cap_action(action: str, cap: str) -> str:
    levels = {
        "monitor": 0,
        "velocity_throttle": 1,
        "audience_narrow": 2,
        "review_queue": 3,
        "soft_restrict": 4,
        "hard_restrict": 5,
        "suspend": 6,
        "auto_ban": 7,
    }
    if action not in levels or cap not in levels:
        return action
    if levels[action] > levels[cap]:
        return cap
    return action


def observation_start_timestamp(days_ago: float = 1.0) -> float:
    return time.time() - days_ago * ONE_DAY_SECONDS


def _status_message(policy: Any, eligible: bool) -> str:
    if eligible:
        return "fast_deploy_ready"
    if policy.shadow_mode:
        return "shadow_mode_enabled"
    if not policy.fast_deploy.enabled:
        return "fast_deploy_disabled"
    return "fast_deploy_guardrails_not_met"
