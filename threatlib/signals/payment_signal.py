"""Payment-surface detector."""

from __future__ import annotations

import time
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


PAYMENT_FIELDS = {
    "transaction_velocity_24h",
    "transaction_amount_variance",
    "transaction_recipient_count_24h",
    "transaction_max_amount",
    "transaction_pattern",
    "upi_id_age_days",
}


class PaymentSignalDetector(BaseDetector):
    name = "payment_signal"
    required_fields = ()

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        metadata = account_data.get("metadata") or {}
        return bool(PAYMENT_FIELDS & set(metadata))

    def missing_fields(self, account_data: dict[str, Any]) -> list[str]:
        return [] if self.has_required_data(account_data) else ["payment metadata fields"]

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        metadata = account_data.get("metadata") or {}
        velocity = metadata.get("transaction_velocity_24h")
        variance = metadata.get("transaction_amount_variance")
        recipient_count = metadata.get("transaction_recipient_count_24h")
        max_amount = metadata.get("transaction_max_amount")
        upi_age = metadata.get("upi_id_age_days")
        high_velocity = isinstance(velocity, (int, float)) and velocity > self.policy.payment.velocity_threshold
        lrs: list[tuple[float, str]] = []
        if high_velocity:
            lrs.append((8.0, "high transaction velocity"))  # REF: v2 C.1.4 - velocity threshold LR.
        if isinstance(variance, (int, float)) and variance < self.policy.payment.variance_floor and high_velocity:
            lrs.append((10.0, "low amount variance with high velocity"))  # REF: v2 C.1.4 - scripted amount LR.
        if recipient_count == 1 and high_velocity:
            lrs.append((12.0, "single recipient high velocity"))  # REF: v2 C.1.4 - mule pattern LR.
        if isinstance(upi_age, (int, float)) and upi_age < 3 and (velocity or max_amount):
            lrs.append((6.0, "new UPI ID with transaction"))  # REF: v2 C.1.4 - new UPI LR.
        if self.graph and account_data.get("account_id") and isinstance(max_amount, (int, float)):
            account = self.graph.get_account(account_data["account_id"])
            if account:
                age_hours = (time.time() - float(account["created_at"])) / 3600.0
                if age_hours < 24 and max_amount > self.policy.payment.new_account_limit:
                    lrs.append((15.0, "new account high max amount"))  # REF: v2 C.1.4 - new account large amount LR.
        if not lrs:
            return DetectorResult.uncertain(self.name, "payment signals neutral")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(result.fraud_mass, result.legitimate_mass, result.uncertainty_mass, self.name, "payment signal analysis", {"subsignals": len(lrs)}, combination_rule=result.combination_rule, conflict_k=result.conflict_k)
