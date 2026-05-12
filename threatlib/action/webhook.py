"""Webhook delivery helper."""

from __future__ import annotations

from typing import Any


def should_send_high_risk_alert(score: float, policy: Any) -> bool:
    return bool(policy.webhooks.high_risk_alert and score >= policy.webhooks.alert_threshold)

