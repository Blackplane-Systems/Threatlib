"""Domain-native behavioral detectors for social, chat, and gaming products."""

from __future__ import annotations

from collections import Counter
import json
import statistics
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


SOCIAL_DM_LINK_DENSITY_HIGH = 0.60  # REF: Social phishing campaigns are link-led; v2 AV-04 uses >60% link density as high risk.
SOCIAL_TARGET_DIVERSITY_HIGH = 15  # REF: Social cold-outreach abuse usually needs many strangers in the first day.
SOCIAL_FOLLOW_BURST_HIGH = 30  # REF: Follow-farm and DM-funnel accounts commonly front-load tens of follows in 24h.
CHAT_FORWARD_RATIO_HIGH = 0.60  # REF: Messaging misinformation/spam is dominated by forwards rather than conversations.
CHAT_RECIPIENT_DIVERSITY_HIGH = 20  # REF: v1 D.12 target-diversity threshold for abusive message fan-out.
CHAT_GROUP_ADD_BURST_HIGH = 20  # REF: Chat group abuse requires rapid member addition or group seeding.
GAMING_SHORT_MATCH_SECONDS = 60.0  # REF: Ranked/economy farming often produces mechanically short match loops.
GAMING_NEW_ACCOUNT_HOURS = 24.0  # REF: Virtual-economy abuse is highest before day-one trust has accumulated.
GAMING_ECONOMY_VALUE_HIGH = 1000.0  # REF: Conservative normalized economy-value threshold for early trade review.


class SocialBehaviorDetector(BaseDetector):
    """Detects social-feed and DM-funnel abuse patterns."""

    name = "social_behavior"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        events = _recent_events(self.graph, account_data["account_id"])
        metadata = _metadata(account_data)
        if not events and not _has_any(metadata, "follow_count_24h", "dm_count_24h", "post_count_24h"):
            return DetectorResult.uncertain(self.name, "no social behavior signals")

        counts = _count_events(events)
        follow_count = _number(metadata, "follow_count_24h", counts["follow_user"])
        dm_count = _number(metadata, "dm_count_24h", counts["send_dm"])
        post_count = _number(metadata, "post_count_24h", counts["post_content"] + counts["post_comment"])
        share_count = _number(metadata, "share_count_24h", counts["share_content"] + counts["share_external_link"])
        view_count = _number(metadata, "view_count_24h", counts["view_profile"] + counts["read_content"])
        link_dm_count = _number(metadata, "link_dm_count_24h", _link_event_count(events, {"send_dm"}))
        distinct_targets = _number(metadata, "distinct_social_targets_24h", _distinct_event_values(events, "recipient_id", "target_account_id"))

        lrs: list[tuple[float, str]] = []
        dm_link_density = link_dm_count / max(dm_count, 1.0)
        follow_to_dm_ratio = dm_count / max(follow_count, 1.0)
        content_to_view_ratio = (post_count + share_count) / max(view_count, 1.0)

        if follow_count >= SOCIAL_FOLLOW_BURST_HIGH and follow_to_dm_ratio >= 0.5:
            lrs.append((10.0, "follow-to-DM funnel burst"))  # REF: AV-04 social phishing path follow_user -> send_dm.
        if dm_count >= 10 and dm_link_density > SOCIAL_DM_LINK_DENSITY_HIGH:
            lrs.append((12.0, "DM link density above social phishing threshold"))  # REF: v1 D.12 high link-density LR.
        if distinct_targets >= SOCIAL_TARGET_DIVERSITY_HIGH and dm_count >= 10:
            lrs.append((8.0, "many distinct social outreach targets"))  # REF: AV-04 target diversity signal.
        if post_count + share_count >= 10 and content_to_view_ratio > 5.0:
            lrs.append((7.0, "publishes far more than it consumes"))  # REF: v1 D.12 content-to-consume ratio.
        if share_count >= 8 and _top_domain_fraction(events) > 0.80:
            lrs.append((9.0, "social shares concentrate on one external domain"))  # REF: AV-05 redirect campaign path.

        if view_count >= 5 and dm_count <= 2 and link_dm_count == 0:
            lrs.append((0.6, "social behavior shows exploration before outreach"))  # REF: Human social onboarding usually observes before messaging.
        if post_count + share_count <= 2 and view_count >= 8:
            lrs.append((0.7, "social consumption-heavy behavior"))  # REF: Lurker-heavy social use is common and weakly legitimate.

        if not lrs:
            return DetectorResult.uncertain(self.name, "social behavior neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.78)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "social behavior analysis",
            {
                "follow_count_24h": follow_count,
                "dm_count_24h": dm_count,
                "dm_link_density": dm_link_density,
                "distinct_targets_24h": distinct_targets,
                "content_to_view_ratio": content_to_view_ratio,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


class ChatAbuseDetector(BaseDetector):
    """Detects messaging-forward, broadcast, group-seeding, and link fan-out abuse."""

    name = "chat_abuse"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        events = _recent_events(self.graph, account_data["account_id"])
        metadata = _metadata(account_data)
        if not events and not _has_any(metadata, "message_count_24h", "forward_count_24h", "broadcast_count_24h"):
            return DetectorResult.uncertain(self.name, "no chat behavior signals")

        counts = _count_events(events)
        message_count = _number(metadata, "message_count_24h", counts["send_message"] + counts["send_dm"])
        forward_count = _number(metadata, "forward_count_24h", counts["forward_message"])
        broadcast_count = _number(metadata, "broadcast_count_24h", counts["broadcast_message"])
        create_group_count = _number(metadata, "create_group_count_24h", counts["create_group"])
        group_add_count = _number(metadata, "group_add_count_24h", counts["add_to_group"])
        link_count = _number(metadata, "link_message_count_24h", _link_event_count(events, {"send_message", "send_dm", "forward_message", "broadcast_message", "share_link"}))
        distinct_recipients = _number(metadata, "distinct_chat_recipients_24h", _distinct_event_values(events, "recipient_id", "target_account_id", "group_id"))
        inbound_count = _number(metadata, "inbound_message_count_24h", _direction_count(events, "inbound"))
        outbound_count = _number(metadata, "outbound_message_count_24h", _direction_count(events, "outbound", default_to_message_events=True))
        call_count = _number(metadata, "call_count_24h", counts["voice_call"] + counts["video_call"])

        lrs: list[tuple[float, str]] = []
        total_message_surface = max(message_count + forward_count + broadcast_count, 1.0)
        forward_ratio = forward_count / total_message_surface
        link_density = link_count / total_message_surface
        outbound_inbound_ratio = outbound_count / max(inbound_count, 1.0)

        if forward_count >= 5 and forward_ratio > CHAT_FORWARD_RATIO_HIGH:
            lrs.append((8.0, "forward-dominated messaging pattern"))  # REF: AV-08 misinformation forwarding signal.
        if broadcast_count >= 2 and link_density > 0.50:
            lrs.append((10.0, "broadcast messages carry high link density"))  # REF: AV-05 broadcast redirect campaign.
        if group_add_count >= CHAT_GROUP_ADD_BURST_HIGH or create_group_count >= 3:
            lrs.append((12.0, "rapid chat group seeding"))  # REF: AV-06 group creation/addition coordination path.
        if distinct_recipients >= CHAT_RECIPIENT_DIVERSITY_HIGH and link_density > 0.40:
            lrs.append((12.0, "multi-recipient link fan-out"))  # REF: v1 D.12 >20 targets plus links.
        if outbound_inbound_ratio > 10.0 and total_message_surface >= 10:
            lrs.append((6.0, "one-way outbound messaging"))  # REF: Scam outreach produces little inbound conversation.
        if call_count >= 10 and distinct_recipients >= 5:
            lrs.append((5.0, "high-volume call fan-out"))  # REF: Voice/video impersonation outreach signal.

        if inbound_count >= 2 and outbound_inbound_ratio <= 3.0 and link_density < 0.20:
            lrs.append((0.6, "reciprocal low-link conversation"))  # REF: Normal chat has replies and low external-link density.
        if message_count >= 3 and forward_count == 0 and broadcast_count == 0 and link_density < 0.20:
            lrs.append((0.7, "non-forward conversational messaging"))  # REF: Legitimate chat is usually conversation-first.

        if not lrs:
            return DetectorResult.uncertain(self.name, "chat behavior neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.78)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "chat abuse behavior analysis",
            {
                "message_count_24h": message_count,
                "forward_ratio": forward_ratio,
                "link_density": link_density,
                "distinct_recipients_24h": distinct_recipients,
                "outbound_inbound_ratio": outbound_inbound_ratio,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


class GamingIntegrityDetector(BaseDetector):
    """Detects game-session, ranked-play, chat, and virtual-economy abuse."""

    name = "gaming_integrity"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        events = _recent_events(self.graph, account_data["account_id"])
        metadata = _metadata(account_data)
        if not events and not _has_any(metadata, "match_count_24h", "trade_count_24h", "ranked_match_count_24h"):
            return DetectorResult.uncertain(self.name, "no gaming behavior signals")

        counts = _count_events(events)
        match_count = _number(metadata, "match_count_24h", counts["start_match"] + counts["finish_match"] + counts["play_match"])
        ranked_count = _number(metadata, "ranked_match_count_24h", counts["ranked_match"])
        trade_count = _number(metadata, "trade_count_24h", counts["trade_item"])
        gift_count = _number(metadata, "gift_count_24h", counts["gift_item"])
        chat_count = _number(metadata, "game_chat_count_24h", counts["send_chat"] + counts["use_chat"])
        party_count = _number(metadata, "party_or_guild_count_24h", counts["create_party"] + counts["join_party"] + counts["join_guild"])
        report_count = _number(metadata, "player_report_count_24h", counts["report_player"])
        economy_value = _number(metadata, "economy_value_moved_24h", _sum_event_values(events, "item_value", "currency_amount"))
        age_hours = _account_age_hours(self.graph, account_data["account_id"])
        durations = _event_numbers(events, "duration_s", "match_duration_s")
        median_duration = statistics.median(durations) if durations else None
        result_concentration = _top_value_fraction(events, "match_result", "result")

        lrs: list[tuple[float, str]] = []
        if match_count >= 10 and median_duration is not None and median_duration < GAMING_SHORT_MATCH_SECONDS:
            lrs.append((8.0, "short repeated match loop"))  # REF: AV-15 automation signal for session loops.
        if age_hours is not None and age_hours < GAMING_NEW_ACCOUNT_HOURS and ranked_count >= 5:
            lrs.append((8.0, "new account enters ranked play at high velocity"))  # REF: Gaming smurf/boosting risk in first day.
        if age_hours is not None and age_hours < GAMING_NEW_ACCOUNT_HOURS and trade_count + gift_count >= 3:
            lrs.append((12.0, "new account moves virtual goods early"))  # REF: AV-11 mule/economy account behavior.
        if economy_value >= GAMING_ECONOMY_VALUE_HIGH and age_hours is not None and age_hours < GAMING_NEW_ACCOUNT_HOURS:
            lrs.append((10.0, "high economy value moved by new account"))  # REF: Virtual-economy abuse threshold for normalized values.
        if chat_count >= 10 and report_count >= 3:
            lrs.append((8.0, "high game chat with player reports"))  # REF: AV-09 harassment campaign signal.
        if party_count >= 5 and trade_count + gift_count >= 3:
            lrs.append((6.0, "party or guild graph used with trading"))  # REF: Coordinated farming uses party/guild edges.
        if match_count >= 10 and result_concentration > 0.90:
            lrs.append((5.0, "repeated match result pattern"))  # REF: Boosting/farming often repeats outcomes.

        if match_count >= 3 and trade_count == 0 and gift_count == 0 and report_count == 0:
            lrs.append((0.6, "normal play without economy movement or reports"))  # REF: Benign early gameplay usually has matches before trades.
        if durations and len(durations) >= 3 and statistics.pstdev(durations) > 30.0 and report_count == 0:
            lrs.append((0.6, "varied match durations without reports"))  # REF: Human gameplay has variable session length.

        if not lrs:
            return DetectorResult.uncertain(self.name, "gaming behavior neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.78)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "gaming integrity behavior analysis",
            {
                "match_count_24h": match_count,
                "ranked_match_count_24h": ranked_count,
                "trade_or_gift_count_24h": trade_count + gift_count,
                "economy_value_moved_24h": economy_value,
                "median_match_duration_s": median_duration,
                "player_report_count_24h": report_count,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _recent_events(graph: Any, account_id: str) -> list[Any]:
    if not graph:
        return []
    return graph.recent_events(account_id, time.time() - ONE_DAY_SECONDS)


def _metadata(account_data: dict[str, Any]) -> dict[str, Any]:
    return account_data.get("metadata") if isinstance(account_data.get("metadata"), dict) else {}


def _has_any(metadata: dict[str, Any], *keys: str) -> bool:
    return any(metadata.get(key) is not None for key in keys)


def _count_events(events: list[Any]) -> Counter[str]:
    return Counter(str(event["event_type"]) for event in events)


def _load_event_data(event: Any) -> dict[str, Any]:
    try:
        return json.loads(event["event_data_json"])
    except Exception:
        return {}


def _number(metadata: dict[str, Any], key: str, default: float) -> float:
    value = metadata.get(key)
    return float(value) if isinstance(value, (int, float)) else float(default)


def _link_event_count(events: list[Any], event_types: set[str]) -> int:
    count = 0
    for event in events:
        if event_types and str(event["event_type"]) not in event_types:
            continue
        data = _load_event_data(event)
        if data.get("has_link") or data.get("link_domain") or data.get("domain"):
            count += 1
    return count


def _distinct_event_values(events: list[Any], *keys: str) -> int:
    values: set[str] = set()
    for event in events:
        data = _load_event_data(event)
        for key in keys:
            if data.get(key):
                values.add(str(data[key]))
    return len(values)


def _direction_count(events: list[Any], direction: str, default_to_message_events: bool = False) -> int:
    count = 0
    for event in events:
        event_type = str(event["event_type"])
        data = _load_event_data(event)
        if data.get("direction") == direction:
            count += 1
        elif default_to_message_events and not data.get("direction") and event_type in {"send_message", "send_dm", "forward_message", "broadcast_message"}:
            count += 1
    return count


def _top_domain_fraction(events: list[Any]) -> float:
    domains: list[str] = []
    for event in events:
        data = _load_event_data(event)
        domain = data.get("link_domain") or data.get("domain")
        if domain:
            domains.append(str(domain).lower())
    if not domains:
        return 0.0
    counts = Counter(domains)
    return max(counts.values()) / len(domains)


def _account_age_hours(graph: Any, account_id: str) -> float | None:
    if not graph:
        return None
    account = graph.get_account(account_id)
    if not account:
        return None
    return (time.time() - float(account["created_at"])) / 3600.0


def _sum_event_values(events: list[Any], *keys: str) -> float:
    total = 0.0
    for event in events:
        data = _load_event_data(event)
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)):
                total += float(value)
    return total


def _event_numbers(events: list[Any], *keys: str) -> list[float]:
    values: list[float] = []
    for event in events:
        data = _load_event_data(event)
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)):
                values.append(float(value))
                break
    return values


def _top_value_fraction(events: list[Any], *keys: str) -> float:
    values: list[str] = []
    for event in events:
        data = _load_event_data(event)
        for key in keys:
            if data.get(key) is not None:
                values.append(str(data[key]))
                break
    if not values:
        return 0.0
    counts = Counter(values)
    return max(counts.values()) / len(values)
