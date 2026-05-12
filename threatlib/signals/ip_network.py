"""IP prefix and network reputation detector."""

from __future__ import annotations

import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs
from threatlib.signals.device_fingerprint import _timezone_mismatch


class IPNetworkDetector(BaseDetector):
    name = "ip_network"
    required_fields = ("ip_prefix",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        account_id = account_data.get("account_id")
        lrs: list[tuple[float, str]] = []

        if account_data.get("ip_is_datacenter") is True:
            lrs.append((6.0, "datacenter IP registration"))  # REF: Section D.6 - hosting IP LR.
        elif account_data.get("ip_is_datacenter") is False:
            lrs.append((0.8, "consumer-like IP"))  # REF: Section D.6 - weak non-datacenter evidence.

        if account_data.get("ip_is_tor") is True:
            lrs.append((8.0, "Tor exit node"))  # REF: Section D.6 - Tor registration LR.
        elif account_data.get("ip_is_tor") is False:
            lrs.append((0.9, "not Tor"))  # REF: Section D.6 - weak normal-use evidence.

        if account_data.get("ip_is_vpn") is True and account_data.get("ip_is_datacenter") is True:
            lrs.append((10.0, "VPN through datacenter"))  # REF: Section D.6 - combined VPN/datacenter LR.
        elif account_data.get("ip_is_vpn") is True:
            lrs.append((2.0, "VPN registration"))  # REF: Section D.6 - weak VPN LR.
        elif account_data.get("ip_is_vpn") is False:
            lrs.append((0.9, "not VPN"))  # REF: Section D.6 - weak normal-use evidence.

        if self.graph:
            count = self.graph.count_by_ip_prefix(
                str(account_data["ip_prefix"]),
                time.time() - ONE_DAY_SECONDS,
                exclude_account_id=account_id,
            )
            if count <= 3:
                lrs.append((0.8, "low IP prefix reuse"))  # REF: Section D.6 - 0-3 accounts from /24 LR.
            elif count <= 10:
                lrs.append((3.0, "moderate IP prefix reuse"))  # REF: Section D.6 - 4-10 accounts from /24 LR.
            elif count <= 30:
                lrs.append((8.0, "high IP prefix reuse"))  # REF: Section D.6 - 11-30 accounts from /24 LR.
            else:
                lrs.append((20.0, "extreme IP prefix reuse"))  # REF: Section D.6 - >30 accounts from /24 LR.

        if _timezone_mismatch(account_data.get("ip_geo_country"), account_data.get("device_timezone")):
            lrs.append((4.0, "country/timezone mismatch"))  # REF: Section D.6 - timezone mismatch LR.
        elif account_data.get("ip_geo_country") and account_data.get("device_timezone"):
            lrs.append((0.8, "country/timezone plausible"))  # REF: Section D.6 - weak consistency evidence.

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "IP network analysis",
            {"ip_prefix": account_data["ip_prefix"]},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )

