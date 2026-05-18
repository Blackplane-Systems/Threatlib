from __future__ import annotations

from fastapi.testclient import TestClient

from threatlib.domains import apply_domain_mode, domain_calibration_plan, domain_policy_preview, get_domain_profile, list_domain_modes
from threatlib.server import create_app


def test_domain_modes_list_and_profiles_are_complete() -> None:
    assert list_domain_modes() == ["chat_app", "gaming", "social_media"]
    for mode in list_domain_modes():
        profile = get_domain_profile(mode)
        assert profile["mode"] == mode
        assert profile["attack_vectors"]
        assert profile["feature_restrictions"]
        assert profile["event_requirements"]
        assert profile["calibration"]["min_labels"] >= 50
        assert profile["calibration"]["min_positive_labels"] >= 10


def test_apply_social_domain_mode_changes_policy_without_breaking_invariants(policy) -> None:
    social = apply_domain_mode(policy, "social")

    assert social.domain_mode == "social_media"
    assert social.platform_adapter == "social_network"
    assert social.shadow_mode is True
    assert social.signal_weight("external_link_pattern") > policy.signal_weight("external_link_pattern")
    assert "post_comment" in social.feature_restrictions
    assert "send_dm" in social.high_impact_actions


def test_chat_and_gaming_modes_have_distinct_feature_surfaces(policy) -> None:
    chat = apply_domain_mode(policy, "chat_app")
    gaming = apply_domain_mode(policy, "gaming")

    assert chat.platform_adapter == "whatsapp"
    assert "forward_message" in chat.feature_restrictions
    assert "broadcast_message" in chat.high_impact_actions
    assert gaming.platform_adapter == "generic"
    assert "ranked_match" in gaming.feature_restrictions
    assert "trade_item" in gaming.high_impact_actions


def test_domain_policy_preview_and_calibration_are_actionable(policy) -> None:
    preview = domain_policy_preview(policy, "gaming")
    calibration = domain_calibration_plan("gaming")

    assert preview["mode"] == "gaming"
    assert preview["detector_weight_changes"]["account_age_velocity"]["domain_weight"] > preview["detector_weight_changes"]["account_age_velocity"]["base_weight"]
    assert calibration["calibration"]["shadow_hours"] >= 24
    assert "threshold_sweep_completed_with_replay" in calibration["readiness_checks"]


def test_domain_api_endpoints(policy, graph) -> None:
    client = TestClient(create_app(policy=policy, graph=graph))

    assert client.get("/domains").json()["domain_modes"] == ["chat_app", "gaming", "social_media"]
    assert client.get("/domains/social_media").json()["display_name"] == "Social Media"
    assert client.get("/domains/chat/policy-preview").json()["mode"] == "chat_app"
    assert client.get("/domains/gaming/calibration").json()["calibration"]["min_scores"] >= 500
    assert client.get("/domains/unknown").status_code == 404
