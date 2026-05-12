"""Community detection detector."""

from __future__ import annotations

import math
import time
from typing import Any

import networkx as nx

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult


def run_community_detection(graph: nx.Graph) -> dict[str, int]:
    try:
        import community as community_louvain

        return community_louvain.best_partition(graph)
    except Exception:
        partition: dict[str, int] = {}
        for index, component in enumerate(nx.connected_components(graph)):
            for node in component:
                partition[str(node)] = index
        return partition


def compute_spectral_gap(community_subgraph: nx.Graph) -> float:
    if community_subgraph.number_of_nodes() < 2:
        return 0.0
    try:
        eigenvalues = sorted(nx.normalized_laplacian_spectrum(community_subgraph))
        return float(eigenvalues[1] - eigenvalues[0])
    except Exception:
        return 0.0


class CommunityDetectionDetector(BaseDetector):
    name = "community_detection"
    depends_on = ("graph_distance",)
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no graph store")
        nx_graph = _load_graph(self.graph)
        if account_data["account_id"] not in nx_graph:
            return DetectorResult.uncertain(self.name, "account absent from graph")
        if nx_graph.number_of_edges() < 4:
            return DetectorResult.uncertain(self.name, "insufficient graph edges")
        partition = run_community_detection(nx_graph)
        community_id = partition.get(account_data["account_id"])
        members = [node for node, cid in partition.items() if cid == community_id]
        min_size = self.policy.community_detection.min_cluster_size
        if len(members) < min_size:
            return DetectorResult.uncertain(self.name, "community below min size")
        accounts = {row["account_id"]: row for row in self.graph.all_accounts(time.time() - 30.0 * ONE_DAY_SECONDS)}
        current = accounts.get(account_data["account_id"])
        same_window = 0
        risk_high = 0
        if current:
            base = float(current["created_at"])
            window_s = self.policy.community_detection.cluster_creation_window_hours * 3600.0
            for member in members:
                row = accounts.get(member)
                if row and abs(float(row["created_at"]) - base) <= window_s:
                    same_window += 1
                score = self.graph.latest_risk_score(member)
                if score is not None and score > 0.5:
                    risk_high += 1
        age_concentration = same_window / len(members)
        risk_density = risk_high / len(members)
        lr = 1.0
        if len(members) >= min_size and age_concentration >= 0.8:
            lr = 12.0  # REF: v2 C.2.2 - tight new-account cluster LR.
        if len(members) >= min_size and risk_density >= 0.6:
            lr = max(lr, 8.0)  # REF: v2 C.2.2 - high-risk community density LR.
        spectral_gap = compute_spectral_gap(nx_graph.subgraph(members).copy())
        if spectral_gap < self.policy.community_detection.spectral_gap_threshold and lr > 1.0:
            lr *= 1.5  # REF: v2 C.2.2 - spectral gap multiplier.
        if lr == 1.0:
            return DetectorResult.uncertain(self.name, "community risk neutral")
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="community cluster analysis",
            metadata={"community_size": len(members), "cluster_age_concentration": age_concentration, "cluster_risk_density": risk_density, "spectral_gap": spectral_gap, "members": members},
        )


def _load_graph(store: Any) -> nx.Graph:
    graph = nx.Graph()
    for row in store.all_accounts():
        graph.add_node(row["account_id"])
    for row in store.all_edges():
        graph.add_edge(row["source_account_id"], row["target_account_id"], weight=float(row["weight"]))
    return graph

