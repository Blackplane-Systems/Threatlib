"""Session anomaly detector for ATO patterns."""

from __future__ import annotations

import math
import time
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


COUNTRY_CENTROIDS = {
    "US": (39.8, -98.6),
    "IN": (20.6, 78.9),
    "CN": (35.9, 104.2),
    "RU": (61.5, 105.3),
    "GB": (55.3, -3.4),
    "DE": (51.2, 10.4),
    "FR": (46.2, 2.2),
}  # REF: Section D.11 - approximate country centroids for impossible-travel foundation.
AIR_TRAVEL_KMH = 900.0  # REF: Section D.11 - plausible travel speed denominator.


class SessionAnomalyDetector(BaseDetector):
    name = "session_anomaly"
    required_fields = ("account_id", "device_hash")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no session store")
        previous_sessions = self.graph.last_sessions(account_data["account_id"], limit=10)
        if not previous_sessions:
            return DetectorResult.uncertain(self.name, "first session has no baseline")

        lrs: list[tuple[float, str]] = []
        current_device = str(account_data["device_hash"])
        current_country = account_data.get("ip_geo_country")
        previous_devices = {row["device_hash"] for row in previous_sessions if row["device_hash"]}
        previous_countries = {row["ip_geo_country"] for row in previous_sessions if row["ip_geo_country"]}

        new_device = current_device not in previous_devices
        country_changed = bool(current_country and previous_countries and current_country not in previous_countries)
        if new_device and country_changed:
            lrs.append((8.0, "new device and new country"))  # REF: Section D.11 - ATO device+country LR.
        elif new_device:
            lrs.append((1.5, "new device"))  # REF: Section D.11 - first-time new device weak LR.

        last = previous_sessions[0]
        if current_country and last["ip_geo_country"] and current_country != last["ip_geo_country"]:
            distance_km = _country_distance_km(str(current_country), str(last["ip_geo_country"]))
            if distance_km is not None:
                elapsed_hours = max((time.time() - float(last["created_at"])) / 3600.0, 0.001)
                if elapsed_hours < (distance_km / AIR_TRAVEL_KMH):
                    lrs.append((12.0, "impossible travel between sessions"))  # REF: Section D.11 - impossible travel LR.

        metadata = account_data.get("metadata") or {}
        if metadata.get("dm_to_non_followers_1h", 0) > 20:
            lrs.append((6.0, "sudden DM pattern shift"))  # REF: Section D.11 - action pattern shift LR.
        if metadata.get("session_duration_s", 999) < 2 and metadata.get("dm_to_non_followers_1h", 0) > 0:
            lrs.append((8.0, "short session with action burst"))  # REF: Section D.11 - session duration anomaly LR.

        if not lrs:
            return DetectorResult.uncertain(self.name, "session consistent with baseline")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "session anomaly analysis",
            {"previous_session_count": len(previous_sessions)},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _country_distance_km(left: str, right: str) -> float | None:
    if left not in COUNTRY_CENTROIDS or right not in COUNTRY_CENTROIDS:
        return None
    lat1, lon1 = COUNTRY_CENTROIDS[left]
    lat2, lon2 = COUNTRY_CENTROIDS[right]
    radius_km = 6371.0  # REF: Mean Earth radius used by haversine distance.
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2.0) ** 2
    )
    return 2.0 * radius_km * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

