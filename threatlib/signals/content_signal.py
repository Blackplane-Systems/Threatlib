"""Content and external-link detector."""

from __future__ import annotations

import json
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


class ContentSignalDetector(BaseDetector):
    name = "content_signal"
    required_fields = ()

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        return bool(
            account_data.get("first_action_type")
            or account_data.get("first_search_query")
            or (self.graph and account_data.get("account_id") and self.graph.recent_events(account_data["account_id"]))
        )

    def missing_fields(self, account_data: dict[str, Any]) -> list[str]:
        return [] if self.has_required_data(account_data) else ["first_action_type OR first_search_query OR content events"]

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        metadata = dict(account_data.get("metadata") or {})
        if self.graph and account_data.get("account_id"):
            metadata.update(_event_content_features(self.graph.recent_events(account_data["account_id"], time.time() - ONE_DAY_SECONDS)))

        lrs: list[tuple[float, str]] = []
        link_density = metadata.get("external_link_density")
        if isinstance(link_density, (int, float)):
            if link_density > 0.90:
                lrs.append((12.0, "external link density above 90 percent"))  # REF: Section D.12 - extreme link density LR.
            elif link_density > 0.60:
                lrs.append((5.0, "external link density above 60 percent"))  # REF: Section D.12 - high link density LR.
            elif link_density < 0.20:
                lrs.append((0.6, "external link density in human baseline"))  # REF: Section D.12 - human baseline <20%.

        domains = [str(item) for item in metadata.get("external_link_domains", []) if item]
        if domains:
            most_common = max(domains.count(domain) for domain in set(domains))
            concentration = most_common / len(domains)
            if concentration > 0.80:
                lrs.append((8.0, "external links concentrated on one domain"))  # REF: Section D.12 - redirect campaign LR.

        query = str(account_data.get("first_search_query") or "").lower()
        sensitive_terms = [str(item).lower() for item in getattr(self.policy, "topic_sensitivity_list", []) or []]
        if query and any(term in query for term in sensitive_terms):
            lrs.append((4.0, "first search matches sensitive pattern"))  # REF: Section D.12 - weak harmful-intent LR.
        elif query:
            lrs.append((0.9, "first search not sensitivity-listed"))  # REF: Section D.12 - weak normal-use evidence.

        posted = metadata.get("content_posted_count")
        consumed = metadata.get("content_consumed_count")
        if isinstance(posted, (int, float)) and isinstance(consumed, (int, float)):
            ratio = posted / max(consumed, 1.0)
            if ratio > 5.0 and (posted + consumed) >= 10:
                lrs.append((8.0, "content-to-consume ratio above 5"))  # REF: Section D.12 - bot posting ratio LR.
            elif ratio < 0.5 and consumed >= 5:
                lrs.append((0.6, "content-to-consume ratio in human range"))  # REF: Section D.12 - human baseline.

        recipients = metadata.get("distinct_dm_recipients_24h")
        if isinstance(recipients, (int, float)):
            if recipients > 20:
                lrs.append((10.0, "high DM target diversity"))  # REF: Section D.12 - >20 recipients LR.
            elif 1 <= recipients <= 5:
                lrs.append((0.6, "DM target diversity in human range"))  # REF: Section D.12 - human baseline.

        shorteners = set(str(item).lower() for item in metadata.get("url_shorteners_used", []) if item)
        configured_shorteners = set(str(item).lower() for item in getattr(self.policy, "url_shortener_list", []) or [])
        uses_shortener = bool(shorteners & configured_shorteners)
        if uses_shortener and isinstance(link_density, (int, float)) and link_density > 0.60:
            lrs.append((8.0, "shortener with high link density"))  # REF: Section D.12 - combined shortener/density LR.
        elif uses_shortener:
            lrs.append((3.0, "URL shortener used"))  # REF: Section D.12 - weak shortener LR.
        elif configured_shorteners:
            lrs.append((0.9, "no configured URL shortener seen"))  # REF: Section D.12 - weak normal-use evidence.

        if not lrs:
            return DetectorResult.uncertain(self.name, "content signals neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "content signal analysis",
            {"subsignal_count": len(lrs)},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _event_content_features(rows: list[Any]) -> dict[str, Any]:
    link_events = 0
    message_events = 0
    domains: list[str] = []
    dm_recipients: set[str] = set()
    posted = 0
    consumed = 0
    for row in rows:
        event_type = row["event_type"]
        try:
            data = json.loads(row["event_data_json"])
        except json.JSONDecodeError:
            data = {}
        if event_type in {"send_dm", "post_content", "post_comment"}:
            message_events += 1
            posted += 1
        if event_type in {"view_profile", "read_content", "search"}:
            consumed += 1
        if data.get("has_link") or data.get("link_domain") or data.get("domain"):
            link_events += 1
        domain = data.get("link_domain") or data.get("domain")
        if domain:
            domains.append(str(domain))
        recipient = data.get("recipient_id")
        if recipient:
            dm_recipients.add(str(recipient))
    features: dict[str, Any] = {}
    if message_events:
        features["external_link_density"] = link_events / message_events
    if domains:
        features["external_link_domains"] = domains
    features["content_posted_count"] = posted
    features["content_consumed_count"] = consumed
    if dm_recipients:
        features["distinct_dm_recipients_24h"] = len(dm_recipients)
    return features
