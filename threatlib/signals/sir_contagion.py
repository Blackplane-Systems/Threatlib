"""SIR social-prior detector."""

from __future__ import annotations

from typing import Any

from threatlib.contagion.sir_model import compute_social_prior
from threatlib.signals.base import BaseDetector, DetectorResult


PRIOR_HARM_RATE = 0.05  # REF: v2 C.3.2 - cold-start platform harm prior.


class SIRContagionDetector(BaseDetector):
    name = "sir_contagion"
    depends_on = ("graph_distance", "hmm_intent")
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no graph store")
        neighbours = []
        for other, weight in self.graph.edge_weights_for_account(account_data["account_id"], self.policy.contagion.propagation_depth):
            risk = self.graph.latest_risk_score(other)
            if risk is not None:
                neighbours.append((risk, weight))
        if not neighbours:
            return DetectorResult.uncertain(self.name, "no scored neighbourhood")
        social_prior = compute_social_prior(neighbours, self.policy.contagion.sir_beta)
        lr = max(0.01, social_prior / PRIOR_HARM_RATE)
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.5,
            detector_name=self.name,
            reason="SIR social contagion prior",
            metadata={"social_prior": social_prior, "neighbour_count": len(neighbours)},
        )

