from __future__ import annotations

from threatlib.graph.persistent_homology import compute_persistence_diagram, persistence_entropy


def test_ph_entropy_bot_vs_organic():
    low = persistence_entropy([(0.0, 0.1)])
    high = persistence_entropy([(0.0, 0.1), (0.0, 0.5), (0.0, 1.0)])
    assert high >= low
    assert compute_persistence_diagram([0.1, 0.2])
