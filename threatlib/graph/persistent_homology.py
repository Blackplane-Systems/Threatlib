"""Persistent homology sketch helpers."""

from __future__ import annotations

import math
from typing import Iterable


def persistence_entropy(persistence_diagram: Iterable[tuple[float, float]]) -> float:
    lengths = [max(0.0, float(death) - float(birth)) for birth, death in persistence_diagram if math.isfinite(death)]
    total = sum(lengths)
    if total <= 0:
        return 0.0
    return -sum((length / total) * math.log(length / total) for length in lengths if length > 0)


def compute_persistence_diagram(distances: list[float]) -> list[tuple[float, float]]:
    try:
        import gudhi

        rips = gudhi.RipsComplex(points=[[value] for value in distances])
        simplex_tree = rips.create_simplex_tree(max_dimension=1)
        return [(float(birth), float(death)) for _, (birth, death) in simplex_tree.persistence()]
    except Exception:
        sorted_distances = sorted(distances)
        return [(0.0, value) for value in sorted_distances]

