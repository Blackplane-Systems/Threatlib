"""Registration burst detector."""

from __future__ import annotations

import math
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


WINDOWS_SECONDS = [600.0, 1800.0, 3600.0, 21600.0, 86400.0]  # REF: Section D.7 - 10m, 30m, 60m, 6h, 24h windows.
POISSON_PRIOR_PER_10M = 1.0  # REF: Section D.7 - cold start Poisson prior lambda.


class RegistrationVelocityDetector(BaseDetector):
    name = "registration_velocity"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no graph store for velocity context")
        now = time.time()
        lrs: list[tuple[float, str]] = []
        z_scores: dict[str, float] = {}

        for window in WINDOWS_SECONDS:
            observed = self.graph.count_accounts_since(now - window)
            expected = POISSON_PRIOR_PER_10M * (window / 600.0)
            std = math.sqrt(max(expected, 1.0))
            z = (observed - expected) / std
            z_scores[str(int(window))] = z
            if z > 5.0:
                lrs.append((12.0, f"registration burst z>{5.0}"))  # REF: Section D.7 - burst LR.
            elif z >= 3.0:
                lrs.append((5.0, "registration burst z 3-5"))  # REF: Section D.7 - elevated burst LR.
            elif z >= 1.5:
                lrs.append((2.0, "registration burst z 1.5-3"))  # REF: Section D.7 - weak burst LR.

        ip_prefix = account_data.get("ip_prefix")
        if ip_prefix:
            ip_count = self.graph.count_by_ip_prefix(str(ip_prefix), now - 600.0, exclude_account_id=account_data["account_id"])
            if ip_count >= 5:
                lrs.append((15.0, "five accounts from /24 in ten minutes"))  # REF: Section D.7 - per-IP burst LR.

        device_model = account_data.get("device_model")
        if device_model:
            model_count = self.graph.count_by_device_model(
                str(device_model),
                now - 1800.0,
                exclude_account_id=account_data["account_id"],
            )
            if model_count >= 10:
                lrs.append((10.0, "device-model burst"))  # REF: Section D.7 - per-device-model burst LR.

        if not lrs:
            return DetectorResult.uncertain(self.name, "registration rate neutral", {"z_scores": z_scores})
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "registration velocity analysis",
            {"z_scores": z_scores},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )

