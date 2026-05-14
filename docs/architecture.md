# Architecture Guide

ThreatLib is organized around stable package boundaries. The project does not require a disruptive repository move to expose operational layers.

## Operational Layers

`threatlib/signals` contains detector contracts and detector implementations.

`threatlib/fusion` contains Dempster-Shafer evidence fusion.

`threatlib/signals/orchestrator.py` resolves the detector DAG and runs detectors in topological order.

`threatlib/config` loads and validates policy.

`threatlib/policy` provides operational policy hashing, linting, summaries, and diffs.

`threatlib/replay` provides deterministic replay and policy simulation.

`threatlib/audit` and `threatlib/graph` provide append-only scoring audit and privacy-safe persistence.

`threatlib/observability` provides JSON metrics and Prometheus text output.

`threatlib/adapters` normalizes platform-specific events and account fields.

`threatlib/action` maps scores to restrictions and actions.

`threatlib/sdk` provides detector authoring utilities.

`threatlib/server` exposes the FastAPI service.

`threatlib/dashboard` exposes the Streamlit operator dashboard.

`deployment` contains starter deployment artifacts.

## Invariants

Detectors with absent required input return uncertainty.

Scoring audit records are append-only.

Shadow mode always returns `monitor`.

Quorum gates active action decisions.

Plaintext PII is not persisted.

Replay is deterministic by default.

Platform adapters add context but do not restrict signals.
