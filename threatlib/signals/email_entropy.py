"""Email domain entropy and domain-age detector."""

from __future__ import annotations

import math
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs, shannon_entropy


NEW_DOMAIN_STRONG_DAYS = 7  # REF: Section D.1 - domains under 7 days have LR 15.
NEW_DOMAIN_WEAK_DAYS = 30  # REF: Section D.1 - domains 7-30 days have LR 3.
ESTABLISHED_DOMAIN_DAYS = 365  # REF: Section D.1 - domains older than 365 days provide legitimacy evidence.


class EmailEntropyDetector(BaseDetector):
    name = "email_entropy"
    required_fields = ("email_domain", "email_domain_age_days")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        domain = str(account_data["email_domain"]).lower().strip()
        age_days = float(account_data["email_domain_age_days"])
        entropy = shannon_entropy(domain)
        lrs: list[tuple[float, str]] = []

        if entropy < 1.5 or entropy > 4.5:
            lrs.append((5.0, "domain entropy outside human range"))  # REF: Section D.1 - unusual domain entropy.
        elif 2.8 <= entropy <= 4.2:
            lrs.append((0.8, "domain entropy in human range"))  # REF: Section D.1 - human domain entropy range.
        else:
            lrs.append((1.0, "domain entropy neutral"))

        if age_days < NEW_DOMAIN_STRONG_DAYS:
            lrs.append((15.0, "domain age under 7 days"))  # REF: Section D.1 - strong fraud LR for new domains.
        elif age_days <= NEW_DOMAIN_WEAK_DAYS:
            lrs.append((3.0, "domain age 7-30 days"))  # REF: Section D.1 - weak fraud LR for new domains.
        elif age_days > ESTABLISHED_DOMAIN_DAYS:
            lrs.append((0.3, "established email domain"))  # REF: Section D.1 - old domains are legitimacy evidence.
        else:
            progress = (age_days - NEW_DOMAIN_WEAK_DAYS) / (ESTABLISHED_DOMAIN_DAYS - NEW_DOMAIN_WEAK_DAYS)
            lr = math.exp(math.log(3.0) + progress * (math.log(0.3) - math.log(3.0)))
            lrs.append((lr, "domain age interpolated on log scale"))

        tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
        suspicious_tlds = set(getattr(self.policy, "suspicious_tlds", []) or [])
        if tld in suspicious_tlds:
            lrs.append((4.0, "suspicious email TLD"))  # REF: Section D.1 - configured suspicious TLD evidence.
        elif domain.endswith(".edu") or domain.endswith(".ac.in"):
            lrs.append((0.7, "educational email domain"))  # REF: Section D.1 - provider class legitimacy evidence.
        else:
            lrs.append((1.0, "provider class neutral"))

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "email domain analysis",
            {"email_domain_entropy": entropy, "email_domain_age_days": age_days, "email_tld": tld},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )

