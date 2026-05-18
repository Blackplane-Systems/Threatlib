"""Scenario-level domain playbook detector."""

from __future__ import annotations

from collections import Counter
import json
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


NEW_ACCOUNT_SCENARIO_HOURS = 24.0  # REF: v2 attack taxonomy emphasizes first-day abuse for bot, phishing, mule, and gaming farm accounts.
SOCIAL_DM_LINK_MIN = 3  # REF: AV-04 DM phishing playbook requires repeated linked outreach, not one incidental link.
SOCIAL_COMMENT_LINK_MIN = 5  # REF: Comment-spam redirect campaigns need several public placements before restriction.
CHAT_FORWARD_CASCADE_MIN = 8  # REF: Messaging spam/misinformation forwarding becomes operationally meaningful after repeated forwards.
CHAT_GROUP_SEED_MIN = 3  # REF: AV-06 chat coordination often starts with several groups seeded by a new account.
GAMING_SHORT_LOOP_MIN = 8  # REF: Farming automation is identified from repeated short session loops, not one abandoned match.
GAMING_ECONOMY_MOVE_MIN = 3  # REF: Early mule behavior requires repeated item/currency movement.
SCENARIO_CONFIDENCE = 0.80  # REF: Scenario detector combines multiple lower-level observations, so confidence is slightly above single weak signals.


class DomainScenarioDetector(BaseDetector):
    """Recognizes end-to-end attack playbooks for social, chat, and gaming modes."""

    name = "domain_scenario"
    required_fields = ("account_id",)
    depends_on = (
        "social_behavior",
        "chat_abuse",
        "gaming_integrity",
        "external_link_pattern",
        "content_signal",
        "account_age_velocity",
        "hmm_intent",
        "report_history",
        "community_detection",
    )

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no event store")
        events = list(reversed(self.graph.recent_events(account_data["account_id"], time.time() - ONE_DAY_SECONDS)))
        metadata = account_data.get("metadata") if isinstance(account_data.get("metadata"), dict) else {}
        detector_results = account_data.get("_detector_results") if isinstance(account_data.get("_detector_results"), dict) else {}
        mode = _domain_mode(self.policy, metadata)
        age_hours = _account_age_hours(self.graph, account_data["account_id"])
        if not events and not metadata:
            return DetectorResult.uncertain(self.name, "no scenario event surface")

        lrs: list[tuple[float, str]] = []
        scenarios: list[str] = []
        if mode == "social_media":
            lrs.extend(_social_scenarios(events, metadata, detector_results, age_hours, scenarios))
        elif mode == "chat_app":
            lrs.extend(_chat_scenarios(events, metadata, detector_results, age_hours, scenarios))
        elif mode == "gaming":
            lrs.extend(_gaming_scenarios(events, metadata, detector_results, age_hours, scenarios))
        else:
            lrs.extend(_generic_scenarios(events, metadata, detector_results, scenarios))

        if _clean_exploration(events, detector_results):
            lrs.append((0.45, "clean exploratory scenario"))  # REF: Exploration without reports, links, or high-impact actions is weak legitimate evidence.

        if not lrs:
            return DetectorResult.uncertain(self.name, "no scenario matched")
        result = mini_ds_from_lrs(self.name, lrs, confidence=SCENARIO_CONFIDENCE)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "domain scenario playbook analysis",
            {
                "domain_mode": mode,
                "matched_scenarios": scenarios,
                "event_count_24h": len(events),
                "account_age_hours": age_hours,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _social_scenarios(
    events: list[Any],
    metadata: dict[str, Any],
    detector_results: dict[str, DetectorResult],
    age_hours: float | None,
    scenarios: list[str],
) -> list[tuple[float, str]]:
    counts = _counts(events)
    linked_dms = _count_link_events(events, {"send_dm"})
    comment_links = _count_link_events(events, {"post_comment", "post_content"})
    top_domain_fraction = _top_domain_fraction(events)
    lrs: list[tuple[float, str]] = []
    if _ordered(events, "view_profile", "follow_user", "send_dm") and linked_dms >= SOCIAL_DM_LINK_MIN:
        scenarios.append("social_dm_phishing_funnel")
        lrs.append((14.0, "social profile-to-DM link funnel"))  # REF: AV-04 path view_profile -> follow_user -> send_dm_with_link.
    if comment_links >= SOCIAL_COMMENT_LINK_MIN and top_domain_fraction > 0.75:
        scenarios.append("social_comment_redirect_campaign")
        lrs.append((11.0, "social comment/link redirect campaign"))  # REF: AV-05 concentrated redirect placements.
    if _is_new(age_hours) and counts["share_content"] + counts["post_content"] >= 8 and _fraud(detector_results, "community_detection") >= 0.35:
        scenarios.append("new_account_amplification_cluster")
        lrs.append((10.0, "new account amplification in suspicious community"))  # REF: AV-06 new-account coordinated amplification.
    if _fraud(detector_results, "social_behavior") >= 0.50 and _fraud(detector_results, "hmm_intent") >= 0.30:
        scenarios.append("social_behavior_intent_alignment")
        lrs.append((9.0, "social behavior aligns with intent model"))  # REF: Independent behavior and HMM agreement raises confidence.
    if metadata.get("creator_impersonation_report_count_24h", 0) and counts["send_dm"] >= 3:
        scenarios.append("creator_impersonation_outreach")
        lrs.append((8.0, "creator impersonation outreach pattern"))  # REF: AV-03/AV-04 impersonation plus outreach.
    return lrs


def _chat_scenarios(
    events: list[Any],
    metadata: dict[str, Any],
    detector_results: dict[str, DetectorResult],
    age_hours: float | None,
    scenarios: list[str],
) -> list[tuple[float, str]]:
    counts = _counts(events)
    link_messages = _count_link_events(events, {"send_message", "send_dm", "forward_message", "broadcast_message", "share_link"})
    recipients = _distinct_values(events, "recipient_id", "target_account_id", "group_id")
    lrs: list[tuple[float, str]] = []
    if counts["forward_message"] >= CHAT_FORWARD_CASCADE_MIN and recipients >= 6 and link_messages >= 3:
        scenarios.append("chat_forward_cascade")
        lrs.append((13.0, "chat forward cascade with links"))  # REF: AV-08/AV-05 forward cascade plus links.
    if _is_new(age_hours) and counts["create_group"] + counts["add_to_group"] >= CHAT_GROUP_SEED_MIN and link_messages >= 2:
        scenarios.append("new_account_group_seed")
        lrs.append((12.0, "new chat account seeds groups with links"))  # REF: AV-06 group creation for coordinated harm.
    if counts["broadcast_message"] >= 2 and recipients >= 10:
        scenarios.append("broadcast_fanout")
        lrs.append((10.0, "broadcast fan-out scenario"))  # REF: Messaging abuse uses broadcast channels to scale reach.
    if _fraud(detector_results, "chat_abuse") >= 0.50 and _fraud(detector_results, "external_link_pattern") >= 0.40:
        scenarios.append("chat_link_campaign_alignment")
        lrs.append((11.0, "chat behavior aligns with external-link campaign"))  # REF: Domain behavior plus link campaign agreement.
    if metadata.get("minor_safety_report_count_24h", 0) and counts["send_dm"] + counts["send_message"] >= 2:
        scenarios.append("minor_safety_outreach")
        lrs.append((15.0, "minor-safety outreach scenario"))  # REF: AV-14 safety reports with outreach require strong escalation evidence.
    return lrs


def _gaming_scenarios(
    events: list[Any],
    metadata: dict[str, Any],
    detector_results: dict[str, DetectorResult],
    age_hours: float | None,
    scenarios: list[str],
) -> list[tuple[float, str]]:
    counts = _counts(events)
    short_matches = sum(1 for value in _numbers(events, "duration_s", "match_duration_s") if value < 60.0)
    economy_moves = counts["trade_item"] + counts["gift_item"]
    lrs: list[tuple[float, str]] = []
    if short_matches >= GAMING_SHORT_LOOP_MIN and counts["ranked_match"] >= 3:
        scenarios.append("ranked_short_loop_farming")
        lrs.append((12.0, "ranked short-loop farming scenario"))  # REF: AV-15 automation plus ranked manipulation.
    if _is_new(age_hours) and economy_moves >= GAMING_ECONOMY_MOVE_MIN:
        scenarios.append("new_account_economy_mule")
        lrs.append((14.0, "new gaming account moves virtual goods"))  # REF: AV-11 mule/economy movement on new account.
    if counts["report_player"] >= 3 and counts["send_chat"] + counts["use_chat"] >= 8:
        scenarios.append("reported_chat_harassment")
        lrs.append((10.0, "reported game-chat harassment scenario"))  # REF: AV-09 harassment confirmed by report density.
    if counts["join_party"] + counts["create_party"] + counts["join_guild"] >= 5 and economy_moves >= 2:
        scenarios.append("coordinated_party_economy")
        lrs.append((9.0, "party or guild economy coordination"))  # REF: Farming rings use party/guild graph plus economy transfers.
    if _fraud(detector_results, "gaming_integrity") >= 0.50 and _fraud(detector_results, "account_age_velocity") >= 0.35:
        scenarios.append("gaming_integrity_velocity_alignment")
        lrs.append((11.0, "gaming integrity aligns with age velocity"))  # REF: Product-native and velocity evidence agree.
    return lrs


def _generic_scenarios(
    events: list[Any],
    metadata: dict[str, Any],
    detector_results: dict[str, DetectorResult],
    scenarios: list[str],
) -> list[tuple[float, str]]:
    lrs: list[tuple[float, str]] = []
    if _fraud(detector_results, "external_link_pattern") >= 0.50 and _fraud(detector_results, "content_signal") >= 0.40:
        scenarios.append("generic_link_campaign")
        lrs.append((8.0, "generic link campaign agreement"))  # REF: Link and content detectors agree without a domain mode.
    return lrs


def _domain_mode(policy: Any, metadata: dict[str, Any]) -> str:
    raw = metadata.get("domain_mode") or metadata.get("product_domain") or getattr(policy, "domain_mode", "generic")
    normalized = str(raw).strip().lower().replace("-", "_")
    aliases = {"social": "social_media", "social_network": "social_media", "chat": "chat_app", "messaging": "chat_app", "game": "gaming"}
    return aliases.get(normalized, normalized)


def _account_age_hours(graph: Any, account_id: str) -> float | None:
    account = graph.get_account(account_id)
    if not account:
        return None
    return (time.time() - float(account["created_at"])) / 3600.0


def _is_new(age_hours: float | None) -> bool:
    return age_hours is not None and age_hours < NEW_ACCOUNT_SCENARIO_HOURS


def _load(event: Any) -> dict[str, Any]:
    try:
        return json.loads(event["event_data_json"])
    except Exception:
        return {}


def _counts(events: list[Any]) -> Counter[str]:
    return Counter(str(event["event_type"]) for event in events)


def _count_link_events(events: list[Any], event_types: set[str]) -> int:
    count = 0
    for event in events:
        if str(event["event_type"]) not in event_types:
            continue
        data = _load(event)
        if data.get("has_link") or data.get("link_domain") or data.get("domain"):
            count += 1
    return count


def _distinct_values(events: list[Any], *keys: str) -> int:
    values: set[str] = set()
    for event in events:
        data = _load(event)
        for key in keys:
            if data.get(key):
                values.add(str(data[key]))
    return len(values)


def _top_domain_fraction(events: list[Any]) -> float:
    domains = []
    for event in events:
        data = _load(event)
        domain = data.get("link_domain") or data.get("domain")
        if domain:
            domains.append(str(domain).lower())
    if not domains:
        return 0.0
    counts = Counter(domains)
    return max(counts.values()) / len(domains)


def _numbers(events: list[Any], *keys: str) -> list[float]:
    values: list[float] = []
    for event in events:
        data = _load(event)
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)):
                values.append(float(value))
                break
    return values


def _ordered(events: list[Any], *event_types: str) -> bool:
    position = 0
    for event in events:
        if str(event["event_type"]) == event_types[position]:
            position += 1
            if position == len(event_types):
                return True
    return False


def _fraud(results: dict[str, DetectorResult], name: str) -> float:
    result = results.get(name)
    return float(result.fraud_mass) if result else 0.0


def _clean_exploration(events: list[Any], detector_results: dict[str, DetectorResult]) -> bool:
    counts = _counts(events)
    high_impact = sum(counts[event] for event in ("send_dm", "send_message", "forward_message", "broadcast_message", "trade_item", "gift_item"))
    reports = counts["report_player"] + counts["report_user"]
    links = _count_link_events(events, {"send_dm", "send_message", "forward_message", "broadcast_message", "post_content", "post_comment"})
    lower_fraud = max((float(result.fraud_mass) for result in detector_results.values()), default=0.0)
    return len(events) >= 5 and high_impact <= 1 and reports == 0 and links == 0 and lower_fraud < 0.25
