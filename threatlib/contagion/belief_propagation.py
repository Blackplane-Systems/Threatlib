"""Ising belief propagation on account graph."""

from __future__ import annotations

import math
from typing import Any


STATES = ("fraud", "legitimate")


def edge_potential(J: float) -> dict[tuple[str, str], float]:
    return {
        ("fraud", "fraud"): math.exp(J),
        ("legitimate", "legitimate"): math.exp(J),
        ("fraud", "legitimate"): math.exp(-J),
        ("legitimate", "fraud"): math.exp(-J),
    }


def update_messages(graph: dict[str, list[str]], beliefs: dict[str, dict[str, float]], potentials: dict[tuple[str, str], float]) -> dict[tuple[str, str], dict[str, float]]:
    messages: dict[tuple[str, str], dict[str, float]] = {}
    for source, neighbours in graph.items():
        for target in neighbours:
            message = {}
            for target_state in STATES:
                total = 0.0
                for source_state in STATES:
                    total += beliefs[source].get(source_state, 0.5) * potentials[(source_state, target_state)]
                message[target_state] = total
            normalizer = sum(message.values()) or 1.0
            messages[(source, target)] = {state: value / normalizer for state, value in message.items()}
    return messages


def run_belief_propagation(graph: dict[str, list[str]], beliefs: dict[str, dict[str, float]], J: float, max_iter: int = 50, threshold: float = 0.001) -> dict[str, dict[str, float]]:
    potentials = edge_potential(J)
    current = {node: dict(value) for node, value in beliefs.items()}
    for _ in range(max_iter):
        messages = update_messages(graph, current, potentials)
        updated: dict[str, dict[str, float]] = {}
        max_delta = 0.0
        for node in current:
            fraud = current[node].get("fraud", 0.5)
            legitimate = current[node].get("legitimate", 0.5)
            for neighbour in graph.get(node, []):
                message = messages.get((neighbour, node), {"fraud": 0.5, "legitimate": 0.5})
                fraud *= message["fraud"]
                legitimate *= message["legitimate"]
            total = fraud + legitimate or 1.0
            updated[node] = {"fraud": fraud / total, "legitimate": legitimate / total}
            max_delta = max(max_delta, abs(updated[node]["fraud"] - current[node].get("fraud", 0.5)))
        current = updated
        if max_delta < threshold:
            break
    return current

