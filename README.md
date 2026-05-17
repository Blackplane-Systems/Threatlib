# ThreatLib

ThreatLib is a platform-agnostic account risk scoring engine for backend services that need consistent, auditable, and privacy-preserving abuse detection across products. It accepts heterogeneous account, device, network, behavior, graph, payment, and content metadata; normalizes events through platform adapters; runs detector evidence through a dependency-aware orchestration graph; and returns a risk score, confidence band, action recommendation, and feature-level restriction map.

ThreatLib is designed for environments where missing data is common. A detector that lacks required input returns `DetectorResult.uncertain()` and does not treat absence of evidence as evidence of legitimacy. This behavior is central to the engine’s safety model.

## Production Safety

ThreatLib defaults to `shadow_mode: true`.

In shadow mode, the engine computes scores, detector outputs, restrictions, and audit records, but the returned action is always `monitor`. Production teams should review shadow-mode output against real outcomes before enabling active enforcement.

CSAM reports are handled by a hardcoded child-safety emergency bypass. A report with category `csam` produces immediate `suspend` escalation in active mode. This behavior is intentionally not configurable through YAML. Shadow mode still returns `monitor` while logging the emergency escalation path.

## System Architecture

ThreatLib is organized into seven operational layers:

1. **Contracts:** `DetectorResult`, `BaseDetector`, Dempster-Shafer fusion, policy loading, and SQLite persistence.
2. **Platform Adapters:** Event and field normalization for social, messaging, payment, health, marketplace, video, and generic platforms.
3. **Independent Detectors:** Detectors that rely only on account data, event data, or persisted context.
4. **Interdependent Detectors:** DAG-scheduled detectors that use outputs from lower layers.
5. **Risk Synthesis:** Evidence fusion, quorum enforcement, temporal decay, signal weighting, ML model plugin evidence, jitter, and confidence bands.
6. **Action Engine:** Threshold-based actions, feature restrictions, emergency bypass handling, and network isolation metadata.
7. **Interfaces:** FastAPI service, Python SDK surface, JavaScript timing collector, Android Kotlin SDK sketch, Streamlit dashboard, and federation schema.

## Core Invariants

- Missing detector input returns uncertainty, never legitimacy.
- Every scoring event is written to an append-only audit log.
- Shadow mode always returns `monitor`.
- Quorum is required before active action decisions.
- Plaintext PII is not persisted.
- Cold start scoring works from the first account.
- Detector dependencies are resolved as an acyclic graph.
- Platform adapters declare available signals but do not restrict extra data.

## Supported Attack Vectors

ThreatLib includes detection paths for:

- Automated bot account creation
- Credential stuffing and account takeover
- Fake identity and synthetic account creation
- DM phishing and romance scams
- Fake giveaway and redirect attacks
- Coordinated inauthentic behavior
- Payment and transaction fraud
- Misinformation seeding
- Harassment campaigns
- Marketplace fraud
- Sybil attacks
- Compromised legitimate accounts
- Fake professional or credential fraud
- Child-safety escalation
- API abuse and scraping

## Detector Families

The detector library includes:

- Email entropy analysis
- Psycholinguistic feature extraction
- Device fingerprint analysis
- IMU motion analysis
- Behavioral timing analysis
- IP and network reputation analysis
- Registration velocity analysis
- Graph distance analysis
- New-account prior modeling
- Report history analysis
- Session anomaly detection
- Content signal detection
- Cross-entropy coherence
- Account-age velocity
- External link pattern detection
- Payment signal detection
- Hawkes burst modeling
- Community detection
- Cross-signal coherence
- Survival analysis
- HMM intent inference
- SIR contagion modeling
- Coordinated behavior detection
- Developer-supplied ML model plugins

## Mathematical Components

ThreatLib uses the following model families:

- Dempster-Shafer evidence theory
- Murphy averaging for high-conflict evidence
- Conformal prediction
- Weibull timing priors
- Hawkes-style burst dynamics
- Hidden Markov Models
- Cox proportional hazards
- SIR contagion models
- Ising-style belief propagation
- Louvain community detection
- Spectral graph analysis
- Persistent homology sketches
- Mutual information estimates
- Granger causality helpers

Formula references are maintained in the project formula index when present and validated by the test suite.

## Quick Start

Run the full local stack with Docker:

```bash
docker compose up --build
```

The API listens on `http://127.0.0.1:8000` and the dashboard listens on `http://127.0.0.1:8501`.

Install the package in editable mode:

```bash
pip install -e .
```

Run the API server:

```bash
threatlib-server --config threatlib.yaml --host 0.0.0.0 --port 8000
```

Run the dashboard:

```bash
threatlib-dashboard --config threatlib.yaml
```

Replay the bundled demo records:

```bash
threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl
```

Inspect and validate policy state:

```bash
threatlib-policy lint --config threatlib.yaml
threatlib-policy explain --config threatlib.yaml
threatlib-preset list
```

Validate a developer-supplied ML model plugin:

```bash
threatlib-ml catalog
threatlib-ml validate --model examples/ml/logistic_model.json --sample examples/ml/sample_account.json
```

Import public calibration and threat-intelligence datasets:

```bash
threatlib-import-intel --config threatlib.yaml --tranco "<path-to>/top-1m.csv" --facebook "<path-to>/facebook_combined.txt" --sms "<path-to>/sms+spam+collection"
```

Train the compact public baseline model artifact:

```bash
threatlib-train-base-model --tranco "<path-to>/top-1m.csv" --facebook "<path-to>/facebook_combined.txt" --sms "<path-to>/sms+spam+collection" --output threatlib/models/base_model.json
```

Submit confirmed outcomes during shadow review:

```bash
threatlib-feedback --api-url http://127.0.0.1:8000 --account-id acct_123 --outcome true_positive --source reviewer
threatlib-feedback --api-url http://127.0.0.1:8000 --account-id acct_456 --outcome false_positive --risk-score 0.82 --source appeal
```

Refresh live indicator feeds:

```bash
threatlib-import-intel --config threatlib.yaml --fetch tor_exit_nodes --fetch urlhaus_recent --prune-expired
```

Use ThreatLib as a Python SDK:

```python
import threatlib as sdk
from threatlib.config.policy import PolicyLoader

policy = PolicyLoader.load("threatlib.yaml")
print(policy.shadow_mode)
```

## API Surface

The FastAPI service provides:

- `POST /score` for account scoring
- `POST /event` for ongoing event ingestion
- `POST /report` for abuse reports
- `POST /appeal` for appeal submission
- `POST /feedback` for confirmed `true_positive`, `true_negative`, `false_positive`, and `false_negative` labels
- `POST /replay` for deterministic policy and event replay simulation
- `POST /ml/validate` for ML model plugin input/output validation
- `GET /account/{account_id}` for privacy-safe account state
- `GET /health` for service status
- `GET /metrics` for operational counters
- `GET /metrics/model` for confusion matrix, precision, recall, FPR, FNR, F1, and calibration error
- `GET /metrics/detectors` for detector activation and uncertainty health
- `GET /metrics/replay` for the latest replay summary
- `GET /metrics/prometheus` for Prometheus-compatible process and engine metrics
- `GET /ml/models` for configured ML model plugins and built-in architecture metadata
- `GET /policy/active` for active policy metadata and hash
- `GET /policy/lint` for deployment-safety warnings
- `GET /presets` and `GET /presets/{name}` for deployment preset discovery
- `GET /deployment/fast-status` for fast-deploy readiness checks
- `GET /graph` for graph and community visibility

## Replay and Policy Simulation

Replay is a first-class operational path. By default, `POST /replay` and `threatlib-replay` run against an isolated in-memory graph, disable score jitter, and return deterministic score timelines without mutating production state. Operators can compare action distributions, quorum behavior, detector activations, uncertainty progression, and detector disagreement before changing thresholds.

Supported replay inputs include JSON, JSONL, NDJSON, CSV, gzip-compressed files, and zip archives containing a supported replay file. Replay records can represent `score`, `event`, `report`, and `feedback` operations.

## Deployment Presets

ThreatLib includes composable presets for common rollout shapes:

- `social_spam`
- `marketplace_fraud`
- `gaming_abuse`
- `creator_platform`
- `fintech_risk`
- `messaging_safety`

Presets are partial policy overlays. They configure adapters, attack-vector focus, feature restrictions, and high-impact actions while preserving the base policy's invariants. Operators can inspect and apply them with `threatlib-preset`.

## Configuration

The default policy lives in `threatlib.yaml`. Important sections include:

- `shadow_mode`
- `minimum_detectors_required`
- `signals`
- `detectors`
- `action_thresholds`
- `feature_restrictions`
- `platform_adapter`
- `attack_vectors`
- `payment`
- `hmm`
- `contagion`
- `community_detection`
- `federation`
- `network_isolation`
- `persistent_homology`
- `canary`
- `fast_deploy`
- `ml_models`

## ML Model Plugins

ThreatLib can ingest evidence from developer-supplied ML models without changing the core scoring pipeline. A model plugin declares:

- which account or detector-output fields are selected for the model input JSON
- which architecture adapter runs the model
- where the model's score, label, confidence, and reason appear in the output JSON
- which selected features are required before the model may contribute evidence

The public engine includes two local adapters:

- `json_logistic_v1` for coefficient-based logistic models stored as JSON
- `threshold_rules_v1` for ordered threshold rules over selected JSON features

Model plugins are configured under `ml_models` in `threatlib.yaml`. They are executed by the `ml_model` detector after lower-level detectors have run. If required model fields are missing, the model contributes uncertainty. If a model path is invalid, the model contributes uncertainty. Model input payloads are not stored in detector metadata or the audit log.

Example model declaration:

```json
{
  "name": "demo-api-abuse-logistic",
  "architecture": "json_logistic_v1",
  "feature_map": {
    "request_rate_per_minute": "metadata.request_rate_per_minute",
    "failed_login_count": "metadata.failed_login_count",
    "datacenter_ip": "ip_is_datacenter"
  },
  "required_features": ["request_rate_per_minute", "failed_login_count"],
  "inline_model": {
    "intercept": -2.0,
    "coefficients": {
      "request_rate_per_minute": 0.05,
      "failed_login_count": 0.20,
      "datacenter_ip": 1.10
    }
  }
}
```

The model output score is converted into Dempster-Shafer evidence through probability odds, then combined with every other detector subject to quorum, weights, shadow mode, and audit logging.

## Repository Map

- `threatlib/signals/base.py`: detector contracts
- `threatlib/signals/orchestrator.py`: detector DAG orchestration
- `threatlib/fusion/dempster_shafer.py`: evidence fusion
- `threatlib/risk/synthesis.py`: risk pipeline
- `threatlib/risk/conformal.py`: confidence bands
- `threatlib/action/feature_restrictor.py`: action and restriction logic
- `threatlib/adapters/`: platform adapters
- `threatlib/replay/`: deterministic replay and policy simulation
- `threatlib/presets/`: composable deployment presets
- `threatlib/policy/`: policy hashing, linting, summaries, and diffs
- `threatlib/observability/`: metrics and Prometheus export helpers
- `threatlib/sdk/`: detector authoring harness
- `threatlib/graph/account_graph.py`: SQLite persistence and graph helpers
- `threatlib/intel/`: safe threat-intelligence importers and hashed retention
- `threatlib/pretrain/`: public-dataset baseline model training
- `threatlib/models/base_model.json`: compact pretrained baseline artifact
- `threatlib/ml/`: ML model plugin adapters and validation CLI
- `threatlib/contagion/`: SIR and Ising models
- `threatlib/dashboard/app.py`: Streamlit dashboard
- `js-sdk/threatlib-timing.js`: browser timing collector
- `android-sdk/threatlib-android/`: Android SDK sketch
- `deployment/`: Kubernetes, Helm, and Grafana starter artifacts
- `examples/`: scoring and replay examples
- `examples/ml/`: model plugin examples and sample validation input
- `schemas/`: versioned replay and policy overlay schemas
- `docs/`: progressive operating guides
- `tests/`: unit and integration tests

## Threat Intelligence Datasets

ThreatLib can ingest public calibration data and live abuse indicators without storing raw malicious URLs, full IP addresses, SMS text, or account-like identifiers. The import path is intentionally conservative:

- Remote downloads are restricted to exact allowlisted feed names: `tor_exit_nodes` and `urlhaus_recent`.
- Remote feeds must use HTTPS, must not redirect, must match expected text content types, and must stay under parser size limits.
- URLhaus rows are treated as inert indicators. ThreatLib hashes the URL and host values and never requests the URLs listed inside the CSV.
- Tor exit IPs are hashed, and only hashed exact IP indicators plus hashed network prefixes are retained.
- Tranco domains are stored as hashed training features with rank buckets.
- UCI SMS Spam messages are converted into derived text features such as length, URL count, digit fraction, uppercase fraction, and urgency-term count. Raw SMS text is not stored.
- SNAP Facebook graph data is reduced to aggregate graph calibration features. Raw edge endpoints are not persisted in the ThreatLib database.
- Hashed indicators and derived feature rows expire by default after `30` days and can be removed with `threatlib-import-intel --prune-expired`.

The repository includes `threatlib/models/base_model.json`, a compact baseline trained from the local Tranco, SNAP ego-Facebook, and UCI SMS Spam files. It stores source hashes, aggregate domain and graph statistics, numeric SMS classifier coefficients, scaler parameters, and validation metrics. It does not store raw dataset rows, raw SMS messages, raw URLs, raw graph edges, or full domain lists.

## Feedback and Fast Deployment

Developers can feed confirmed outcomes from day one using `POST /feedback` or the `threatlib-feedback` CLI. Accepted outcomes are `true_positive`, `true_negative`, `false_positive`, and `false_negative`, with shorthand aliases `tp`, `tn`, `fp`, and `fn`.

Feedback labels update the calibration label store when a risk score is available. Operator notes are hashed before storage. The `/metrics/model` endpoint exposes the current confusion matrix and performance metrics so teams can see whether the system is improving or drifting.

Fast deploy mode is configured under `fast_deploy` in `threatlib.yaml`. It is disabled by default and never overrides `shadow_mode`. Once an operator deliberately disables shadow mode, fast deploy can allow limited active enforcement after one day of observation if these guardrails pass:

- enough scored accounts
- enough confirmed labels
- acceptable false-positive and false-negative rates
- minimum precision and recall
- active action cap, defaulting to `soft_restrict`

If fast deploy is enabled but guardrails are not met, actions remain `monitor`. If guardrails pass, active actions are capped so early deployment does not jump directly to severe enforcement.

## Testing

Run the full test suite:

```bash
pytest tests/ -v --tb=short
```

The tests cover detector contracts, evidence fusion, privacy behavior, adapters, DAG execution, v2 detectors, contagion models, graph topology helpers, action handling, API integration, CSAM bypass behavior, and packaging entry points.
Threat-intelligence tests additionally verify allowlist enforcement, inert URLhaus parsing, hashed indicator storage, derived-only training features, and expiry pruning. ML plugin tests verify feature selection, model output mapping, missing-feature uncertainty, API validation, and audit-safe metadata.

## Operational Guidance

Start every deployment in shadow mode. Review score distributions, detector uncertainty rates, appeal outcomes, and false-positive candidates before enabling enforcement. Calibrate thresholds per platform because normal behavior differs significantly between social, payment, health, messaging, marketplace, and content products.

Do not add plaintext usernames, email local parts, full IP addresses, raw message content, or raw sensor streams to persistence. Store hashes, prefixes, aggregate features, and derived statistics only.

Do not import arbitrary malware feeds by URL. Add a named allowlisted feed and parser first, then test that the importer stores only hashes or derived features. Indicator retention is configured in `threatlib.yaml` under `threat_intel.retention_days`.

## License

Licensed under the Apache License 2.0. See `LICENSE` for details.
