"""Mobile IMU motion evidence detector."""

from __future__ import annotations

from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


class IMUMotionDetector(BaseDetector):
    name = "imu_motion"
    required_fields = ("device_imu_variance_x", "device_imu_variance_y", "device_imu_variance_z")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        platform = str(account_data.get("device_platform", "")).lower()
        if platform in {"web", "desktop"}:
            return DetectorResult.uncertain(self.name, "IMU not applicable to web/desktop")
        if platform and platform not in {"android", "ios"}:
            return DetectorResult.uncertain(self.name, "IMU platform unsupported")

        total_variance = (
            float(account_data["device_imu_variance_x"])
            + float(account_data["device_imu_variance_y"])
            + float(account_data["device_imu_variance_z"])
        )
        lrs: list[tuple[float, str]] = []
        available_subsignals = 1

        if total_variance < 0.0004:
            lrs.append((20.0, "near-zero IMU variance"))  # REF: Section D.4 - physiological tremor threshold.
        elif total_variance >= 0.005:
            lrs.append((0.6, "natural handheld IMU variance"))  # REF: Section D.4 - physical motion evidence.

        breathing = account_data.get("device_imu_breathing_power")
        if isinstance(breathing, (int, float)):
            available_subsignals += 1
            if breathing < 0.001:
                lrs.append((6.0, "no breathing-band motion"))  # REF: Section D.4 - engineering estimate threshold.
            else:
                lrs.append((0.8, "breathing-band motion present"))  # REF: Section D.4 - physiological component.

        tremor = account_data.get("device_imu_tremor_power")
        if isinstance(tremor, (int, float)):
            available_subsignals += 1
            if tremor < 0.0005:
                lrs.append((4.0, "no tremor-band motion"))  # REF: Section D.4 - physiological tremor band threshold.
            else:
                lrs.append((0.8, "tremor-band motion present"))  # REF: Section D.4 - physiological component.

        sample_cv = account_data.get("device_imu_sample_cv")
        if isinstance(sample_cv, (int, float)):
            available_subsignals += 1
            if sample_cv < 0.001:
                lrs.append((8.0, "perfectly regular IMU sampling"))  # REF: Section D.4 - emulator clock evidence.
            elif 0.01 <= sample_cv <= 0.05:
                lrs.append((0.6, "human device IMU sampling CV"))  # REF: Section D.4 - human CV range.

        if available_subsignals < 2:
            return DetectorResult.uncertain(self.name, "fewer than two IMU sub-signals")

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "IMU motion analysis",
            {"total_variance": total_variance, "subsignal_count": available_subsignals},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )

