"""Device fingerprint and automation-surface detector."""

from __future__ import annotations

import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


COUNTRY_TIMEZONE_PREFIXES = {
    "US": ("America/", "Pacific/Honolulu"),
    "IN": ("Asia/Kolkata",),
    "CN": ("Asia/Shanghai",),
    "RU": ("Europe/Moscow", "Asia/"),
    "GB": ("Europe/London",),
    "DE": ("Europe/Berlin",),
    "FR": ("Europe/Paris",),
    "BR": ("America/Sao_Paulo", "America/Manaus"),
    "AU": ("Australia/",),
    "CA": ("America/",),
}  # REF: Section D.3 - compact country/timezone plausibility map for v1 foundation.


class DeviceFingerprintDetector(BaseDetector):
    name = "device_fingerprint"
    required_fields = ("device_hash", "device_platform")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        account_id = account_data.get("account_id")
        platform = str(account_data["device_platform"]).lower()
        lrs: list[tuple[float, str]] = []
        now = time.time()

        if self.graph:
            reuse = self.graph.count_by_device_hash(
                str(account_data["device_hash"]),
                now - 30.0 * ONE_DAY_SECONDS,
                exclude_account_id=account_id,
            )
            if reuse == 0:
                lrs.append((0.7, "device not reused recently"))  # REF: Section D.3 - new device weak legitimacy.
            elif reuse <= 3:
                lrs.append((1.0, "device reuse neutral"))  # REF: Section D.3 - 1-3 accounts neutral.
            elif reuse <= 10:
                lrs.append((5.0, "device reuse elevated"))  # REF: Section D.3 - 4-10 account reuse LR.
            else:
                lrs.append((20.0, "device farm reuse"))  # REF: Section D.3 - >10 account reuse LR.

        if account_data.get("device_screen_on") is False:
            lrs.append((50.0, "screen off during registration"))  # REF: Section D.3 - impossible human registration.
        elif account_data.get("device_screen_on") is True:
            lrs.append((0.8, "screen on during registration"))  # REF: Section D.3 - weak normal-use evidence.

        reboot_s = account_data.get("device_time_since_reboot_s")
        if isinstance(reboot_s, (int, float)) and reboot_s < 60:
            lrs.append((8.0, "registration immediately after reboot"))  # REF: Section D.3 - scripted cycle LR.

        if (
            account_data.get("device_battery_level") == 1.0
            and account_data.get("device_battery_charging") is True
            and isinstance(reboot_s, (int, float))
            and reboot_s < 30
        ):
            lrs.append((15.0, "battery and reboot farm pattern"))  # REF: Section D.3 - device farm LR.

        services = [str(item).lower() for item in account_data.get("device_accessibility_services") or []]
        if any(token in service for service in services for token in ("uiautomator", "appium", "accessibilitytestframework")):
            lrs.append((25.0, "automation accessibility service"))  # REF: Section D.3 - known automation frameworks.
        elif services == [] and platform in {"android", "ios"}:
            lrs.append((0.9, "no automation accessibility service"))  # REF: Section D.3 - weak normal-use evidence.

        install_source = account_data.get("device_install_source")
        if install_source in {"adb", "apk_direct"}:
            lrs.append((12.0, "sideloaded or adb install source"))  # REF: Section D.3 - non-store install LR.
        elif install_source in {"play_store", "app_store"}:
            lrs.append((0.7, "official app store install"))  # REF: Section D.3 - weak legitimacy evidence.

        sensor_count = account_data.get("device_sensor_count")
        if isinstance(sensor_count, int) and sensor_count >= 3:
            lrs.append((0.8, "normal mobile sensor count"))  # REF: Section D.3 - physical device sensor evidence.
        elif isinstance(sensor_count, int) and sensor_count == 0 and platform in {"android", "ios"}:
            lrs.append((5.0, "zero mobile sensors"))  # REF: Section D.3 - emulator/device anomaly evidence.

        if _timezone_mismatch(account_data.get("ip_geo_country"), account_data.get("device_timezone")):
            lrs.append((4.0, "device timezone mismatches IP country"))  # REF: Section D.3 - timezone mismatch LR.
        elif account_data.get("ip_geo_country") and account_data.get("device_timezone"):
            lrs.append((0.8, "timezone plausible for country"))  # REF: Section D.3 - weak consistency evidence.

        if platform == "web":
            user_agent = str(account_data.get("device_user_agent", "")).lower()
            width = account_data.get("device_screen_width")
            height = account_data.get("device_screen_height")
            if "python" in user_agent or "curl" in user_agent or "bot" in user_agent:
                lrs.append((8.0, "automation-like web user agent"))  # REF: Section D.3 - web automation anomaly.
            if isinstance(width, int) and isinstance(height, int) and (width <= 0 or height <= 0):
                lrs.append((6.0, "invalid browser screen size"))  # REF: Section D.3 - web fingerprint anomaly.

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "device fingerprint analysis",
            {"subsignal_count": len(lrs)},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _timezone_mismatch(country: str | None, timezone: str | None) -> bool:
    if not country or not timezone:
        return False
    prefixes = COUNTRY_TIMEZONE_PREFIXES.get(str(country).upper())
    if not prefixes:
        return False
    return not any(str(timezone).startswith(prefix) for prefix in prefixes)

