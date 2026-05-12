"""Graph distance detector anchored on confirmed harmful accounts."""

from __future__ import annotations

from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


class GraphDistanceDetector(BaseDetector):
    name = "graph_distance"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no graph store")
        self.graph.upsert_account(account_data)
        anchors = self.graph.harmful_anchors()
        if not anchors:
            return DetectorResult.uncertain(self.name, "no confirmed harmful anchors")
        max_depth = getattr(getattr(self.policy, "graph", None), "bfs_max_depth", 3)
        distance = self.graph.distance_to_harmful(account_data["account_id"], max_depth=max_depth)
        if distance is None:
            return DetectorResult.uncertain(self.name, "not connected to confirmed harmful anchors")
        if distance <= 1:
            lr = 20.0  # REF: Section D.8 - direct confirmed-harmful connection LR.
        elif distance == 2:
            lr = 8.0  # REF: Section D.8 - distance two LR.
        else:
            lr = 3.0  # REF: Section D.8 - distance three LR.
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="confirmed harmful graph proximity",
            metadata={"distance": distance, "anchor_count": len(anchors)},
        )

