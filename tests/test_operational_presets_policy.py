from __future__ import annotations

from fastapi.testclient import TestClient

from threatlib.policy.versioning import diff_policies, lint_policy, policy_hash, policy_summary
from threatlib.presets import apply_preset, list_presets, load_preset
from threatlib.server import create_app


def test_policy_hash_lint_and_summary(policy):
    digest = policy_hash(policy)
    assert len(digest) == 64
    lint = lint_policy(policy)
    assert lint["valid"] is True
    summary = policy_summary(policy)
    assert summary["policy_hash"] == digest
    assert summary["shadow_mode"] is True


def test_policy_diff_reports_changed_fields(policy):
    changed = policy.model_copy(deep=True)
    changed.shadow_mode = False
    diffs = diff_policies(policy, changed)
    assert any(item["path"] == "shadow_mode" for item in diffs)


def test_presets_are_composable(policy):
    names = list_presets()
    assert "fintech_risk" in names
    preset = load_preset("fintech_risk")
    assert preset["threatlib"]["platform_adapter"] == "payment"
    merged = apply_preset(policy, "fintech_risk")
    assert merged.platform_adapter == "payment"
    assert "send_payment_large" in merged.feature_restrictions


def test_policy_and_preset_endpoints(policy, graph):
    app = create_app(policy=policy, graph=graph)
    client = TestClient(app)
    assert client.get("/policy/active").json()["shadow_mode"] is True
    assert client.get("/policy/lint").json()["valid"] is True
    assert "social_spam" in client.get("/presets").json()["presets"]
    assert client.get("/presets/social_spam").status_code == 200
