"""Cold-start new account prior detector."""

from __future__ import annotations

import time
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


class NewAccountPriorDetector(BaseDetector):
    name = "new_account_prior"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult(
                fraud_mass=0.15,  # REF: Section D.9 - cold-start fraud mass for unknown new account.
                legitimate_mass=0.0,
                uncertainty_mass=0.85,
                detector_name=self.name,
                reason="cold-start prior without store",
            )
        self.graph.upsert_account(account_data)
        account = self.graph.get_account(account_data["account_id"])
        created_at = float(account["created_at"]) if account else time.time()
        account_age_hours = (time.time() - created_at) / 3600.0
        events_seen = self.graph.count_events(account_data["account_id"])

        if events_seen < 5:
            fraud_mass = 0.15  # REF: Section D.9 - fewer than five events cold-start mass.
        elif account_age_hours < 24:
            fraud_mass = 0.10  # REF: Section D.9 - under 24 hours elevated prior.
        elif account_age_hours < 168:
            fraud_mass = 0.05  # REF: Section D.9 - under one week residual prior.
        else:
            return DetectorResult.uncertain(self.name, "new-account prior expired")

        return DetectorResult(
            fraud_mass=fraud_mass,
            legitimate_mass=0.0,
            uncertainty_mass=1.0 - fraud_mass,
            detector_name=self.name,
            reason="new account cold-start prior",
            metadata={"account_age_hours": account_age_hours, "events_seen": events_seen},
        )

