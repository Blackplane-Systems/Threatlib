from __future__ import annotations

from threatlib.contagion.belief_propagation import edge_potential, run_belief_propagation, update_messages
from threatlib.contagion.sir_model import compute_social_prior, run_sir


def test_sir_subcritical_damping():
    _, infected, _ = run_sir(99, 1, 0, beta=0.08, gamma=0.10, t_max=10)
    assert infected[-1] < infected[0]


def test_social_prior_isolated_account():
    assert compute_social_prior([], beta=0.08) == 0.0
    assert compute_social_prior([(0.9, 1.0)], beta=0.08) > 0.0


def test_ising_coupling_aligned_vs_opposed():
    potential = edge_potential(0.05)
    assert potential[("fraud", "fraud")] > potential[("fraud", "legitimate")]


def test_bp_convergence():
    graph = {"a": ["b"], "b": ["a"]}
    beliefs = {"a": {"fraud": 0.9, "legitimate": 0.1}, "b": {"fraud": 0.5, "legitimate": 0.5}}
    messages = update_messages(graph, beliefs, edge_potential(0.05))
    assert ("a", "b") in messages
    marginals = run_belief_propagation(graph, beliefs, 0.05)
    assert 0.0 <= marginals["b"]["fraud"] <= 1.0

