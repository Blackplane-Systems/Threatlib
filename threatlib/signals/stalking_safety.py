"""User safety detector for repeated target fixation and stalking-like behavior."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


TARGET_VIEW_THRESHOLD = 25  # REF: Repeated profile/story viewing over a day becomes safety-relevant beyond ordinary curiosity.
VIEW_ESCALATION_THRESHOLD = 12  # REF: Lower fixation threshold when views escalate to contact or capture events.
SAFETY_HOLD_LEVEL = 0.85  # REF: Safety hold restricts target interaction while preserving account access.
TARGET_CONCENTRATION_HIGH = 0.70  # REF: Stalking-like behavior is concentrated on one target, unlike broad browsing.


class StalkingSafetyDetector(BaseDetector):
    """Detects target fixation that should trigger temporary user-safety restrictions."""

    name = "stalking_safety"
    required_fields = ("account_id",)
    depends_on = ("report_history", "session_anomaly")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if self.graph is None:
            return DetectorResult.uncertain(self.name, "no event store")
        rows = self.graph.recent_events(account_data["account_id"], time.time() - ONE_DAY_SECONDS)
        metadata = account_data.get("metadata") if isinstance(account_data.get("metadata"), dict) else {}
        if not rows and not metadata:
            return DetectorResult.uncertain(self.name, "no safety event surface")

        target_views = _target_event_counts(rows, {"view_profile", "view_story", "search_user", "view_content"})
        target_contacts = _target_event_counts(rows, {"send_dm", "send_message", "follow_user", "mention_user", "react"})
        captures = _target_event_counts(rows, {"screenshot_detected", "screen_record_detected"})
        report_count = int(metadata.get("target_safety_report_count_7d", 0) or 0)
        top_target, top_views = target_views.most_common(1)[0] if target_views else (None, 0)
        total_views = sum(target_views.values())
        concentration = top_views / max(total_views, 1)
        top_contacts = target_contacts[top_target] if top_target else 0
        top_captures = captures[top_target] if top_target else 0

        lrs: list[tuple[float, str]] = []
        if top_target and top_views >= TARGET_VIEW_THRESHOLD and concentration >= TARGET_CONCENTRATION_HIGH:
            lrs.append((8.0, "highly repeated views of one target"))  # REF: Concentrated repeated viewing is a safety signal even without fraud.
        if top_target and top_views >= VIEW_ESCALATION_THRESHOLD and (top_contacts >= 2 or top_captures >= 1):
            lrs.append((10.0, "target fixation escalates to contact or capture"))  # REF: Viewing plus contact/capture is stronger stalking-like behavior.
        if report_count >= 1 and top_views >= VIEW_ESCALATION_THRESHOLD:
            lrs.append((12.0, "target safety report aligns with repeated views"))  # REF: Reporter signal corroborates target-fixation pattern.
        if total_views >= 10 and concentration < 0.35 and report_count == 0:
            lrs.append((0.4, "broad browsing without target concentration"))  # REF: Broad profile browsing is common legitimate behavior.

        if not lrs:
            return DetectorResult.uncertain(self.name, "no stalking safety pattern matched")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.76)
        restrictions = []
        if top_target and result.fraud_mass > 0:
            restrictions = [
                {
                    "feature": "view_profile",
                    "level": SAFETY_HOLD_LEVEL,
                    "reason": "temporary target-safety hold for repeated target viewing",
                },
                {
                    "feature": "send_dm",
                    "level": SAFETY_HOLD_LEVEL,
                    "reason": "temporary target-safety hold for direct contact",
                },
            ]
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "stalking safety analysis",
            {
                "top_target_seen": top_target is not None,
                "top_target_view_count": top_views,
                "top_target_contact_count": top_contacts,
                "target_concentration": concentration,
                "target_safety_report_count_7d": report_count,
                "temporary_restrictions": restrictions,
                "analysis_without_suspension": True,
                "action_cap": "review_queue",
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _target_event_counts(rows: list[Any], event_types: set[str]) -> Counter[str]:
    counts: Counter[str] = Counter()
    anonymous_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        event_type = str(row["event_type"])
        if event_type not in event_types:
            continue
        data = _load(row)
        target = _target_key(data)
        if target:
            counts[target] += 1
        elif event_type in {"screenshot_detected", "screen_record_detected"}:
            anonymous_counts[event_type] += 1
    if anonymous_counts and counts:
        top_target = counts.most_common(1)[0][0]
        counts[top_target] += sum(anonymous_counts.values())
    return counts


def _target_key(data: dict[str, Any]) -> str | None:
    for key in ("target_account_id", "profile_account_id", "viewed_account_id", "recipient_id", "user_id"):
        if data.get(key):
            return str(data[key])
    return None


def _load(row: Any) -> dict[str, Any]:
    try:
        return json.loads(row["event_data_json"])
    except Exception:
        return {}
