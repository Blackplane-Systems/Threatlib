# ThreatLib: Universal Account Risk Scoring SDK

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**ThreatLib** is a platform-agnostic account risk scoring SDK and engine built for enterprise scale. It normalizes signals from any application and produces resilient, auditable risk decisions using **Dempster Shafer evidence fusion** and conformal confidence bands.

**Why use ThreatLib:** It lets teams ship a consistent, privacy-preserving risk layer across products without rebuilding detection logic per platform. The SDK absorbs heterogeneous signals, handles missing data safely, and produces calibrated, explainable outputs suitable for compliance and operations.

**How to use ThreatLib:** Integrate it as a backend library or run it as a service. Send normalized account data and events through your adapter, review scores in shadow mode, then enable enforcement via YAML policy once thresholds are validated for your audience.

## System Overview

ThreatLib separates signal evaluation from enforcement through a layered pipeline:
1. **Platform Adapters:** Declare available signals, map platform events to universal event types, and mark relevant attack vectors. Adapters are additive and never restrict signals.
2. **Signal Detectors:** Independent detectors run in parallel. Interdependent detectors form a DAG and run in topological order.
3. **Evidence Fusion:** Dempster Shafer combination with Murphy averaging for high conflict.
4. **Risk Synthesis:** Composite score with conformal prediction bands and adversarial robustness safeguards.
5. **Action Engine:** YAML-driven restriction tiers and feature-level controls.
6. **API, SDKs, and Dashboard:** FastAPI server, Android Kotlin SDK, browser timing collector, and Streamlit operator dashboard.

## Key Capabilities

- **Cross-Platform Coverage:** Works across social networks, fintech, health apps, marketplaces, and messaging platforms.
- **Zero PII Storage:** Only hashed identifiers and derived features are persisted.
- **Cold-Start Ready:** Produces scores from account #1 using calibrated priors and wide confidence bands.
- **Temporal and Graph Models:** Hawkes burst modeling, HMM intent inference, SIR/Ising contagion, community detection, and persistent homology.
- **Append-Only Auditing:** Immutable SQLite logs for verifiable forensic trails.

## Attack Vector Coverage (15)

- Automated bot account creation
- Credential stuffing and account takeover
- Fake identity or synthetic accounts
- DM phishing and romance scams
- Fake giveaway and external redirect attacks
- Coordinated inauthentic behavior and influence operations
- Payment and transaction fraud
- Misinformation seeding
- Harassment campaigns
- Marketplace fraud
- Sybil attacks
- Compromised legitimate accounts
- Fake professional or credential fraud
- Child safety and CSAM escalation
- API abuse and scraping bots

## Mathematical Models

- Dempster Shafer evidence fusion with Murphy averaging
- Conformal prediction bands for calibrated confidence
- Multivariate Hawkes process for burst dynamics
- Hidden Markov Model (HMM) for intent inference
- Cox proportional hazards survival analysis
- SIR contagion model on account graphs
- Ising model with loopy belief propagation
- Community detection (Louvain/Leiden)
- Persistent homology sketch for graph topology

## Detector Suite

**Independent detectors** run without cross-dependencies and return `uncertain()` on absent data:
- Behavioral timing
- Device fingerprinting
- IP/network analysis
- IMU motion
- Psycholinguistics
- Email entropy
- Registration velocity
- Graph distance
- New account prior
- Report history
- Session anomaly
- Content signals

**Interdependent detectors** run after Layer 2 outputs and use a DAG orchestrator in [threatlib/signals/orchestrator.py](threatlib/signals/orchestrator.py):
- Cross-entropy coherence
- Account-age velocity
- External link pattern
- Payment signal
- Hawkes burst v2
- Community detection
- Cross-signal coherence v2
- Survival analysis
- HMM intent
- SIR contagion
- Coordinated behavior

## Scoring and Actioning

- Evidence fusion and conflict handling in [threatlib/fusion/dempster_shafer.py](threatlib/fusion/dempster_shafer.py).
- Risk synthesis with conformal bands in [threatlib/risk/synthesis.py](threatlib/risk/synthesis.py) and [threatlib/risk/conformal.py](threatlib/risk/conformal.py).
- Feature restriction engine in [threatlib/action/feature_restrictor.py](threatlib/action/feature_restrictor.py).
- Shadow mode is the safe default and always returns `monitor` while still scoring.
- CSAM reports trigger immediate escalation and are not configurable.

## SDKs and Interfaces

- FastAPI server in [threatlib/server.py](threatlib/server.py).
- Android Kotlin SDK under [android-sdk/threatlib-android](android-sdk/threatlib-android).
- Browser timing collector in [js-sdk/threatlib-timing.js](js-sdk/threatlib-timing.js).
- Streamlit operator dashboard in [threatlib/dashboard/app.py](threatlib/dashboard/app.py).
- Federation schema skeleton in [threatlib/federation/schema.py](threatlib/federation/schema.py).

## Operational Safety

**Shadow mode is the default.** Do not engage active enforcement in production until you have reviewed at least 30 days of shadow scores against your target audience. Under shadow mode, actions are still computed and logged, but the returned action is always `monitor`.

**Child safety emergency bypass:** A report with category `csam` triggers immediate escalation and cannot be disabled by YAML. Shadow mode still returns `monitor` for dry-run deployments.

## Quick Start

### Standalone Server

Run ThreatLib as an autonomous microservice using the built-in FastAPI implementation:

```bash
pip install -e .
threatlib-server --config threatlib.yaml --host 0.0.0.0 --port 8000
threatlib-dashboard --config threatlib.yaml
```

### SDK Integration

Embed ThreatLib strictly as a library into your secure backend:

```python
import threatlib as sdk
from threatlib.config.policy import PolicyLoader

# Initialize risk policy configuration
policy = PolicyLoader.load("threatlib.yaml")

print(f"Engine instantiated. Shadow mode restrictions: {policy.shadow_mode}")
```

## Repository Map

- Detector contracts: [threatlib/signals/base.py](threatlib/signals/base.py)
- Orchestrator and DAG execution: [threatlib/signals/orchestrator.py](threatlib/signals/orchestrator.py)
- Evidence fusion: [threatlib/fusion/dempster_shafer.py](threatlib/fusion/dempster_shafer.py)
- Risk synthesis: [threatlib/risk/synthesis.py](threatlib/risk/synthesis.py)
- Conformal prediction: [threatlib/risk/conformal.py](threatlib/risk/conformal.py)
- Account graph: [threatlib/graph/account_graph.py](threatlib/graph/account_graph.py)
- Platform adapters: [threatlib/adapters](threatlib/adapters)
- Policy schema: [threatlib/config/policy.py](threatlib/config/policy.py)
- Default policy: [threatlib.yaml](threatlib.yaml)
- Tests: [tests](tests)

## Contribution Notes

Changes should preserve privacy invariants, keep absent data classified as uncertain, and maintain the shadow mode safety default until operational review is complete. All modifications should continue to pass `pytest tests/` before being submitted.

## License

Licensed under the Apache License 2.0. See `LICENSE` for more information.
