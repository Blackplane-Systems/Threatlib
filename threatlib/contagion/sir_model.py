"""SIR contagion helpers."""

from __future__ import annotations

from typing import Iterable


def run_sir(S0: float, I0: float, R0: float, beta: float, gamma: float, t_max: int) -> tuple[list[float], list[float], list[float]]:
    S = [float(S0)]
    I = [float(I0)]
    R = [float(R0)]
    for _ in range(max(t_max, 0)):
        n = max(S[-1] + I[-1] + R[-1], 1e-9)
        d_s = -beta * S[-1] * I[-1] / n
        d_i = beta * S[-1] * I[-1] / n - gamma * I[-1]
        d_r = gamma * I[-1]
        S.append(max(0.0, S[-1] + d_s))
        I.append(max(0.0, I[-1] + d_i))
        R.append(max(0.0, R[-1] + d_r))
    return S, I, R


def compute_social_prior(neighbourhood: Iterable[tuple[float, float]], beta: float) -> float:
    weighted = list(neighbourhood)
    z = sum(abs(weight) for _, weight in weighted)
    if z <= 0:
        return 0.0
    return beta * sum(risk * weight for risk, weight in weighted) / z

