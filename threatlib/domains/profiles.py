"""Product-domain policy profiles for social, chat, and gaming deployments."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from typing import Any

import yaml

from threatlib.config.policy import Policy, PolicyLoader
from threatlib.presets.loader import deep_merge


MIN_SHADOW_HOURS = 24.0  # REF: Fast-deploy operating mode requires one day of observation before active use.
SOCIAL_MIN_SCORES = 1000  # REF: Public social rollout needs enough feed/DM/post diversity for score-distribution review.
CHAT_MIN_SCORES = 750  # REF: Messaging rollouts have fewer public surfaces but high private-message impact.
GAMING_MIN_SCORES = 500  # REF: Gaming abuse profiles are session-heavy and can calibrate with lower account counts plus event coverage.
MIN_LABELS = 50  # REF: Minimum manual outcomes for early precision/recall estimates without claiming statistical finality.
MIN_POSITIVE_LABELS = 10  # REF: Ensure calibration includes confirmed harmful cases, not only clean traffic.


DOMAIN_PROFILES: dict[str, dict[str, Any]] = {
    "social_media": {
        "mode": "social_media",
        "display_name": "Social Media",
        "platform_adapter": "social_network",
        "primary_surfaces": ["feed", "profile", "follow graph", "comments", "dm", "external links"],
        "attack_vectors": ["AV-01", "AV-03", "AV-04", "AV-05", "AV-06", "AV-08", "AV-09", "AV-11", "AV-12", "AV-15"],
        "detector_weight_overrides": {
            "content_signal": 1.35,
            "external_link_pattern": 1.65,
            "hmm_intent": 1.45,
            "community_detection": 1.40,
            "coordinated_behavior": 1.75,
            "report_history": 1.40,
            "graph_distance": 1.45,
            "ml_model": 1.00,
        },
        "feature_restrictions": {
            "read_content": {"threshold": 0.90, "steepness": 5.0},
            "search": {"threshold": 0.85, "steepness": 5.0},
            "react": {"threshold": 0.60, "steepness": 6.0},
            "follow_user": {"threshold": 0.45, "steepness": 9.0},
            "post_comment": {"threshold": 0.40, "steepness": 8.0},
            "post_content": {"threshold": 0.50, "steepness": 8.0},
            "send_dm": {"threshold": 0.35, "steepness": 10.0},
            "share_content": {"threshold": 0.40, "steepness": 9.0},
            "create_group": {"threshold": 0.25, "steepness": 12.0},
            "mass_invite": {"threshold": 0.15, "steepness": 15.0},
        },
        "high_impact_actions": ["send_dm", "post_content", "share_content", "create_group", "mass_invite"],
        "event_requirements": ["view_profile", "follow_user", "send_dm", "post_content", "share_external_link", "report_user"],
        "calibration": {
            "shadow_hours": 72.0,
            "min_scores": SOCIAL_MIN_SCORES,
            "min_labels": MIN_LABELS,
            "min_positive_labels": MIN_POSITIVE_LABELS,
            "target_false_positive_rate": 0.08,
            "target_recall": 0.70,
            "signal_coverage_targets": {
                "content_events": 0.50,
                "graph_edges": 0.35,
                "reports": 0.05,
                "timing": 0.20,
            },
        },
    },
    "chat_app": {
        "mode": "chat_app",
        "display_name": "Chat and Messaging",
        "platform_adapter": "whatsapp",
        "primary_surfaces": ["direct messages", "group messages", "forwards", "broadcasts", "calls", "external links"],
        "attack_vectors": ["AV-01", "AV-02", "AV-04", "AV-05", "AV-06", "AV-08", "AV-09", "AV-11", "AV-12", "AV-14", "AV-15"],
        "detector_weight_overrides": {
            "content_signal": 1.50,
            "external_link_pattern": 1.75,
            "hmm_intent": 1.85,
            "report_history": 1.55,
            "session_anomaly": 1.35,
            "graph_distance": 1.30,
            "coordinated_behavior": 1.55,
            "ml_model": 1.00,
        },
        "feature_restrictions": {
            "view_chat": {"threshold": 0.90, "steepness": 5.0},
            "send_message": {"threshold": 0.35, "steepness": 10.0},
            "forward_message": {"threshold": 0.25, "steepness": 12.0},
            "create_group": {"threshold": 0.20, "steepness": 15.0},
            "add_to_group": {"threshold": 0.30, "steepness": 12.0},
            "share_link": {"threshold": 0.35, "steepness": 10.0},
            "voice_call": {"threshold": 0.50, "steepness": 8.0},
            "video_call": {"threshold": 0.55, "steepness": 8.0},
            "broadcast_message": {"threshold": 0.15, "steepness": 15.0},
        },
        "high_impact_actions": ["send_message", "forward_message", "create_group", "add_to_group", "share_link", "broadcast_message"],
        "event_requirements": ["send_message", "forward_message", "join_group", "create_group", "share_external_link", "report_user"],
        "calibration": {
            "shadow_hours": 72.0,
            "min_scores": CHAT_MIN_SCORES,
            "min_labels": MIN_LABELS,
            "min_positive_labels": MIN_POSITIVE_LABELS,
            "target_false_positive_rate": 0.06,
            "target_recall": 0.72,
            "signal_coverage_targets": {
                "message_events": 0.55,
                "forward_events": 0.20,
                "link_domains": 0.20,
                "reports": 0.03,
            },
        },
    },
    "gaming": {
        "mode": "gaming",
        "display_name": "Gaming and Virtual Economy",
        "platform_adapter": "generic",
        "primary_surfaces": ["matchmaking", "party chat", "item trading", "guilds", "leaderboards", "reporting"],
        "attack_vectors": ["AV-01", "AV-02", "AV-06", "AV-09", "AV-11", "AV-12", "AV-15"],
        "detector_weight_overrides": {
            "behavioral_timing": 1.35,
            "ip_network": 1.25,
            "session_anomaly": 1.45,
            "account_age_velocity": 1.60,
            "graph_distance": 1.45,
            "community_detection": 1.35,
            "hmm_intent": 1.30,
            "report_history": 1.30,
            "ml_model": 1.00,
        },
        "feature_restrictions": {
            "play_match": {"threshold": 0.85, "steepness": 5.0},
            "ranked_match": {"threshold": 0.55, "steepness": 8.0},
            "use_chat": {"threshold": 0.40, "steepness": 10.0},
            "trade_item": {"threshold": 0.35, "steepness": 12.0},
            "gift_item": {"threshold": 0.30, "steepness": 12.0},
            "create_party": {"threshold": 0.45, "steepness": 8.0},
            "join_guild": {"threshold": 0.50, "steepness": 8.0},
            "post_lfg": {"threshold": 0.45, "steepness": 9.0},
            "report_player": {"threshold": 0.60, "steepness": 6.0},
        },
        "high_impact_actions": ["ranked_match", "use_chat", "trade_item", "gift_item", "create_party", "join_guild"],
        "event_requirements": ["start_match", "finish_match", "send_chat", "trade_item", "join_party", "report_player"],
        "calibration": {
            "shadow_hours": MIN_SHADOW_HOURS,
            "min_scores": GAMING_MIN_SCORES,
            "min_labels": MIN_LABELS,
            "min_positive_labels": MIN_POSITIVE_LABELS,
            "target_false_positive_rate": 0.10,
            "target_recall": 0.68,
            "signal_coverage_targets": {
                "session_events": 0.60,
                "trade_events": 0.10,
                "party_or_guild_edges": 0.20,
                "reports": 0.04,
            },
        },
    },
}


def list_domain_modes() -> list[str]:
    return sorted(DOMAIN_PROFILES)


def get_domain_profile(mode: str) -> dict[str, Any]:
    normalized = _normalize_mode(mode)
    if normalized not in DOMAIN_PROFILES:
        raise ValueError(f"unknown domain mode: {mode}")
    return deepcopy(DOMAIN_PROFILES[normalized])


def apply_domain_mode(base: Policy | dict[str, Any], mode: str) -> Policy:
    profile = get_domain_profile(mode)
    base_raw = {"threatlib": base.model_dump(mode="json")} if isinstance(base, Policy) else deepcopy(base)
    override = _profile_to_policy_overlay(profile, base_raw)
    return PolicyLoader.from_dict(deep_merge(base_raw, override))


def domain_calibration_plan(mode: str) -> dict[str, Any]:
    profile = get_domain_profile(mode)
    calibration = deepcopy(profile["calibration"])
    return {
        "mode": profile["mode"],
        "display_name": profile["display_name"],
        "calibration": calibration,
        "readiness_checks": [
            "shadow_mode_enabled_until_review_complete",
            "minimum_score_volume_met",
            "minimum_label_volume_met",
            "minimum_positive_label_volume_met",
            "signal_coverage_targets_reviewed",
            "false_positive_candidates_reviewed",
            "threshold_sweep_completed_with_replay",
        ],
    }


def domain_policy_preview(base: Policy, mode: str) -> dict[str, Any]:
    profile = get_domain_profile(mode)
    applied = apply_domain_mode(base, mode)
    changed_detectors = {
        name: {
            "base_weight": base.signal_weight(name),
            "domain_weight": applied.signal_weight(name),
        }
        for name in profile["detector_weight_overrides"]
    }
    return {
        "mode": profile["mode"],
        "platform_adapter": applied.platform_adapter,
        "attack_vectors": applied.attack_vectors.model_dump(mode="json"),
        "feature_restrictions": applied.model_dump(mode="json")["feature_restrictions"],
        "high_impact_actions": applied.high_impact_actions,
        "detector_weight_changes": changed_detectors,
        "calibration": profile["calibration"],
    }


def _profile_to_policy_overlay(profile: dict[str, Any], base_raw: dict[str, Any]) -> dict[str, Any]:
    base_policy = base_raw.get("threatlib", {})
    base_signals = set((base_policy.get("signals") or {}).keys())
    base_detectors = set((base_policy.get("detectors") or {}).keys())
    signal_overlay: dict[str, dict[str, float]] = {}
    detector_overlay: dict[str, dict[str, float]] = {}
    for name, weight in profile["detector_weight_overrides"].items():
        if name in base_signals and name not in base_detectors:
            signal_overlay[name] = {"weight": weight}
        else:
            detector_overlay[name] = {"weight": weight}
    return {
        "threatlib": {
            "platform": profile["mode"],
            "domain_mode": profile["mode"],
            "platform_adapter": profile["platform_adapter"],
            "environment": "shadow_mode",
            "shadow_mode": True,
            "attack_vectors": {"enabled": profile["attack_vectors"], "disabled": []},
            "signals": signal_overlay,
            "detectors": detector_overlay,
            "feature_restrictions": profile["feature_restrictions"],
            "high_impact_actions": profile["high_impact_actions"],
        }
    }


def _normalize_mode(mode: str) -> str:
    aliases = {
        "social": "social_media",
        "social_network": "social_media",
        "messaging": "chat_app",
        "chat": "chat_app",
        "game": "gaming",
        "gaming_abuse": "gaming",
    }
    normalized = mode.strip().lower().replace("-", "_")
    return aliases.get(normalized, normalized)


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatLib product-domain modes")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("mode")
    calibration = sub.add_parser("calibration")
    calibration.add_argument("mode")
    apply_cmd = sub.add_parser("apply")
    apply_cmd.add_argument("mode")
    apply_cmd.add_argument("--base", default="threatlib.yaml")
    apply_cmd.add_argument("--output")
    args = parser.parse_args()

    if args.command == "list":
        print(json.dumps(list_domain_modes(), indent=2))
    elif args.command == "show":
        print(yaml.safe_dump(get_domain_profile(args.mode), sort_keys=False))
    elif args.command == "calibration":
        print(yaml.safe_dump(domain_calibration_plan(args.mode), sort_keys=False))
    else:
        policy = apply_domain_mode(PolicyLoader.load(args.base), args.mode)
        payload = {"threatlib": policy.model_dump(mode="json")}
        text = yaml.safe_dump(payload, sort_keys=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            print(text)


if __name__ == "__main__":
    main()
