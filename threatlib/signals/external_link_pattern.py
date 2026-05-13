"""External link campaign detector."""

from __future__ import annotations

from collections import Counter
import json
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


class ExternalLinkPatternDetector(BaseDetector):
    name = "external_link_pattern"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no event store")
        events = self.graph.recent_events(account_data["account_id"])
        if not events:
            return DetectorResult.uncertain(self.name, "no event stream")
        link_events: list[dict[str, Any]] = []
        domains: list[str] = []
        giveaway_present = False
        for event in events:
            data = _load_event_data(event)
            domain = data.get("link_domain") or data.get("domain")
            has_link = bool(data.get("has_link") or domain)
            if has_link:
                link_events.append(data)
                if domain:
                    domains.append(str(domain).lower())
                context = " ".join(str(value).lower() for value in data.values() if isinstance(value, str))
                giveaway_present = giveaway_present or any(term in context for term in self.policy.giveaway_terms)
        if not link_events:
            return DetectorResult.uncertain(self.name, "no link events")
        lrs: list[tuple[float, str]] = []
        link_density = len(link_events) / max(len(events), 1)
        if link_density > 0.6:
            lrs.append((5.0, "high link density"))  # REF: v2 C.1.3 - link density above 0.6.
        if domains:
            top_fraction = max(Counter(domains).values()) / len(domains)
            if top_fraction > 0.8:
                lrs.append((10.0, "link domain concentration"))  # REF: v2 C.1.3 - one destination campaign.
            shorteners = set(str(item).lower() for item in self.policy.url_shortener_list)
            if any(domain in shorteners for domain in domains):
                lrs.append((3.0, "URL shortener use"))  # REF: v2 C.1.3 - shortener weak LR.
            if _domain_account_count(self.graph, domains[0]) > 10:
                lrs.append((8.0, "shared link domain campaign"))  # REF: v2 C.1.3 - >10 accounts per domain.
            if any(self.graph.threat_indicator_exists("urlhaus_host", domain) for domain in domains):
                lrs.append((12.0, "domain matched URLhaus threat-intel cache"))  # REF: URLhaus is curated malicious URL intelligence.
        if giveaway_present:
            lrs.append((4.0, "giveaway language present"))  # REF: v2 C.1.3 - giveaway language LR.
        if not lrs:
            return DetectorResult.uncertain(self.name, "link behavior neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(result.fraud_mass, result.legitimate_mass, result.uncertainty_mass, self.name, "external link analysis", {"link_density": link_density, "domains": domains}, combination_rule=result.combination_rule, conflict_k=result.conflict_k)


def _load_event_data(event: Any) -> dict[str, Any]:
    try:
        return json.loads(event["event_data_json"])
    except Exception:
        return {}


def _domain_account_count(graph: Any, domain: str) -> int:
    since = time.time() - ONE_DAY_SECONDS
    accounts = set()
    for event in graph.all_recent_events(since):
        data = _load_event_data(event)
        if str(data.get("link_domain") or data.get("domain") or "").lower() == domain:
            accounts.add(event["account_id"])
    return len(accounts)
