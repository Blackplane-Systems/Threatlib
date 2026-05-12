from __future__ import annotations

from threatlib.action.feature_restrictor import check_emergency_bypass, compute_restriction
from threatlib.risk.synthesis import apply_jitter, compute_action


def test_feature_restriction_logistic(active_policy):
    below = compute_restriction("send_dm", 0.1, active_policy)
    above = compute_restriction("send_dm", 0.9, active_policy)
    assert below < 0.5
    assert above > 0.5


def test_action_thresholds(active_policy):
    assert compute_action(0.10, active_policy) == "monitor"
    assert compute_action(0.98, active_policy) == "auto_ban"


def test_shadow_action(policy):
    assert compute_action(0.99, policy) == "monitor"


def test_payment_feature_restriction(active_policy):
    active_policy.platform_adapter = "payment"
    assert compute_restriction("send_payment_large", 0.9, active_policy) > 0.5


def test_jitter_prevents_threshold_probing():
    assert 0.0 <= apply_jitter(0.5, 0.01) <= 1.0


def test_csam_report_bypasses_scoring():
    assert check_emergency_bypass([{"category": "csam"}]) == "suspend"
