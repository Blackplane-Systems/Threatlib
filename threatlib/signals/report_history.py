"""Report-history detector."""

from __future__ import annotations

import math
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult


REPORT_HALFLIFE_DAYS = 90.0  # REF: Section D.10 - report temporal decay half-life.
CATEGORY_WEIGHTS = {
    "spam": 1.0,
    "harassment": 1.5,
    "scam": 2.0,
    "doxxing": 3.0,
    "credible_threat": 4.0,
    "csam": 10.0,
}  # REF: Section D.10 - default report category weights.


class ReportHistoryDetector(BaseDetector):
    name = "report_history"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no report store")
        since = time.time() - REPORT_HALFLIFE_DAYS * ONE_DAY_SECONDS
        reports = self.graph.reports_for_account(account_data["account_id"], since)
        if not reports:
            return DetectorResult.uncertain(self.name, "no reports")

        weighted_reports = 0.0
        high_trust = False
        severe = False
        for report in reports:
            age_days = (time.time() - float(report["created_at"])) / ONE_DAY_SECONDS
            decay = math.exp(-math.log(2.0) / REPORT_HALFLIFE_DAYS * age_days)
            category = str(report["category"])
            if category == "csam":
                severe = True
            trust = float(report["reporter_trust_score"])
            high_trust = high_trust or trust > 0.9
            weighted_reports += trust * CATEGORY_WEIGHTS.get(category, 1.0) * decay
        if high_trust:
            weighted_reports += 2.0  # REF: Section D.10 - high-trust reporter bonus.

        if weighted_reports < 1.0:
            lr = 1.0  # REF: Section D.10 - report evidence neutral below weighted total 1.
        elif weighted_reports <= 3.0:
            lr = 2.0  # REF: Section D.10 - weighted report LR band.
        elif weighted_reports <= 6.0:
            lr = 5.0  # REF: Section D.10 - weighted report LR band.
        elif weighted_reports <= 10.0:
            lr = 10.0  # REF: Section D.10 - weighted report LR band.
        else:
            lr = 25.0  # REF: Section D.10 - weighted report LR band.
        if severe:
            lr = max(lr, 50.0)  # REF: Section D.10 - severe category immediate escalation.

        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="report history analysis",
            metadata={"weighted_reports": weighted_reports, "report_count": len(reports), "immediate_escalation": severe},
        )

