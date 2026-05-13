# ThreatLib Technical Guide

## Preface

This guide explains ThreatLib as a complete software engineering and applied security system.
It assumes familiarity with programming, databases, APIs, probability, and data structures, and
shows how those ideas come together in a realistic backend security project.

ThreatLib is not only a collection of detectors. It is a full risk-scoring architecture. It has
contracts, configuration, detector orchestration, mathematical fusion, persistence, API endpoints,
SDK surfaces, auditability, and operator documentation. The project shows how
academic concepts such as entropy, graph traversal, hidden Markov models, survival analysis, and
belief propagation can be placed inside a working engineering system.

The central problem is account abuse. Modern applications must defend against fake accounts,
credential stuffing, payment fraud, link scams, spam campaigns, harassment, scraping, coordinated
inauthentic behavior, and account takeover. These attacks do not appear in only one product type.
A social network, payment app, health community, marketplace, messaging app, or video platform can
all face abuse, but each platform observes different signals.

ThreatLib solves this by treating account scoring as a platform-agnostic evidence problem. The
platform sends whatever signals it can safely provide. Each detector reads only the fields it needs.
When a detector lacks data, it returns uncertainty. The engine then combines available evidence
without pretending that missing data proves the account is safe.

Before you read further, open a terminal at the repository root and inspect the project layout.

```bash
cd "D:\Vibe code\threatlib"
dir
```

On Unix-like systems the equivalent command is:

```bash
ls -la
```

The important lesson is that a production-style risk engine is not a single machine learning file.
It is a package with separate modules for contracts, configuration, detectors, graph storage,
API exposure, tests, documentation, and operational tooling.

## Chapter 1: The Problem ThreatLib Solves

Account abuse detection is difficult because attackers intentionally behave near the boundary of
normal user behavior. A legitimate user may use a VPN. A legitimate user may paste an email address.
A legitimate user may create an account and send a message quickly. None of these signals is enough
to classify an account by itself.

The engineering challenge is to combine weak signals responsibly. A good risk system must avoid
overreacting to one noisy signal, but it must also recognize when several weak signals align in a
meaningful way. ThreatLib approaches this through independent detectors and evidence fusion.

Consider a new account with these observations:

The email domain is three days old. The username looks randomly generated. The device is reused by
many accounts. The IP is a datacenter address. The registration timing has almost zero variance.
Each observation alone may be imperfect. Together, they describe a much stronger pattern.

Now consider a different account:

The email domain is Gmail. The username is normal. The user uses a VPN. The device is new. Timing
data is missing. In this case, the VPN should not dominate the score. Missing timing data should
not become legitimacy evidence. The system should remain cautious and uncertain.

This is why ThreatLib is built around explicit uncertainty.

## Chapter 2: Installing and Running the Project

ThreatLib is a Python package. The package can be installed in editable mode during development.
Editable mode means Python imports the source files directly from your workspace, so changes are
visible without rebuilding a wheel.

```bash
pip install -e .
```

Run the test suite after installation:

```bash
pytest tests/ -v --tb=short
```

The `-v` flag shows individual test names. The `--tb=short` flag keeps failure traces readable.
Run tests frequently while changing the system. In a project like ThreatLib, tests are the safety
net that ensures mathematical assumptions and privacy invariants continue to hold.

Start the API server:

```bash
threatlib-server --config threatlib.yaml --host 127.0.0.1 --port 8000
```

In another terminal, call the health endpoint:

```bash
curl http://127.0.0.1:8000/health
```

If `curl` is not available on Windows, PowerShell can call the same endpoint:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Run the operator dashboard:

```bash
threatlib-dashboard --config threatlib.yaml
```

These commands demonstrate three common deployment modes: package import, HTTP service, and
operator interface.

## Chapter 3: Repository Structure

The repository is organized around responsibility boundaries. This is an important software design
principle. A module should have a clear reason to exist, and unrelated logic should not be mixed
inside it.

The detector contracts live in:

```text
threatlib/signals/base.py
```

Evidence fusion lives in:

```text
threatlib/fusion/dempster_shafer.py
```

The risk synthesis pipeline lives in:

```text
threatlib/risk/synthesis.py
```

The API server lives in:

```text
threatlib/server.py
```

The SQLite graph and persistence layer live in:

```text
threatlib/graph/account_graph.py
```

The platform adapters live in:

```text
threatlib/adapters/
```

The tests live in:

```text
tests/
```

When learning a new codebase, a useful command is:

```bash
rg --files
```

`rg` is ripgrep. It is fast and useful for code navigation. To find where a class is defined:

```bash
rg "class DetectorResult"
```

To find all references to shadow mode:

```bash
rg "shadow_mode"
```

These commands are simple, but they are part of professional engineering workflow.

## Chapter 4: The Detector Contract

Every detector in ThreatLib returns a `DetectorResult`. This object contains three masses:
fraud mass, legitimate mass, and uncertainty mass. The masses sum to one.

This design is more expressive than returning a single probability. A detector can say:

```text
fraud_mass = 0.60
legitimate_mass = 0.00
uncertainty_mass = 0.40
```

This means the detector has meaningful fraud evidence, but it is not fully certain.

Another detector may say:

```text
fraud_mass = 0.00
legitimate_mass = 0.30
uncertainty_mass = 0.70
```

This means the detector has weak legitimacy evidence and significant uncertainty.

Open the detector contract:

```bash
code threatlib/signals/base.py
```

If you do not use VS Code, print the file:

```bash
Get-Content threatlib\signals\base.py
```

The most important method is `DetectorResult.uncertain()`. It is used whenever a detector cannot
score safely. This is not an error state. It is a valid evidence state.

A detector also has `required_fields`. If those fields are absent, `safe_score()` returns
uncertainty. This prevents a detector from crashing the scoring pipeline and prevents absent data
from being treated as a clean signal.

## Chapter 5: Why Missing Data Must Mean Uncertainty

Suppose a web application has no mobile accelerometer data. An IMU detector should not say the user
is legitimate because there is no suspicious accelerometer pattern. The correct answer is that the
detector has no evidence.

This is a common mistake in risk systems. Engineers sometimes encode missing values as zeros. A zero
may then accidentally look like safe behavior. ThreatLib avoids this by making uncertainty explicit.

The invariant is:

```text
Absent data -> uncertain, never legitimate.
```

You can observe this behavior in the tests:

```bash
pytest tests/test_detectors.py::test_absent_data_returns_uncertain -v
```

This test is not just a unit test. It is a policy guarantee encoded as software.

## Chapter 6: Dempster-Shafer Evidence Fusion

ThreatLib uses Dempster-Shafer evidence theory to combine detector results. The frame of
discernment has two hypotheses: fraud and legitimate. The third mass, uncertainty, represents
uncommitted belief.

The conversion from likelihood ratio to mass is implemented in `DetectorResult.from_likelihood_ratio`.
If a likelihood ratio is greater than one, the detector contributes fraud evidence. If it is less
than one, it contributes legitimate evidence. If it is exactly one, the detector returns uncertainty.

Run the relevant tests:

```bash
pytest tests/test_contracts.py::test_from_likelihood_ratio_contract -v
pytest tests/test_dempster_shafer.py -v
```

Dempster’s rule combines evidence while accounting for conflict. Conflict occurs when one detector
supports fraud and another supports legitimacy. ThreatLib uses Murphy averaging when conflict is
too high. This keeps combined evidence from becoming unstable.

The engineering principle is that a risk system is not only about detection. It is also about
principled aggregation.

## Chapter 7: Quorum and Responsible Enforcement

ThreatLib requires quorum before active enforcement. Quorum means a minimum number of detectors must
provide non-trivial evidence. This prevents one detector from making a severe decision alone.

For example, a datacenter IP alone should not ban an account. Some legitimate users work behind
enterprise infrastructure. But datacenter IP plus device automation plus timing regularity plus
new-domain email is a much stronger pattern.

Run the quorum test:

```bash
pytest tests/test_risk_synthesis.py::test_quorum_function -v
```

This rule matters in real systems because false positives can harm users. Engineering judgment
requires designing for both attacker resistance and legitimate user protection.

## Chapter 8: Shadow Mode

Shadow mode is a deployment safety mechanism. In shadow mode, ThreatLib computes scores and writes
audit records, but the returned action is `monitor`.

This lets operators answer questions before enforcement:

How many accounts would have been restricted? Which detectors contributed most? Which user segments
are affected? What is the appeal rate? How many high-risk accounts were later confirmed harmful?

Verify shadow mode behavior:

```bash
pytest tests/test_risk_synthesis.py::test_shadow_mode_forces_monitor -v
```

A mature security system should support measurement before enforcement. Shadow mode is how ThreatLib
implements that principle.

## Chapter 9: The Policy File

The default policy is stored in:

```text
threatlib.yaml
```

Open it:

```bash
code threatlib.yaml
```

Important sections include `signals`, `detectors`, `action_thresholds`, `feature_restrictions`,
`platform_adapter`, `hmm`, `contagion`, `community_detection`, and `network_isolation`.

Policy files allow operators to change thresholds without editing code. This separation is
important. Code defines capabilities. Policy defines deployment behavior.

YAML configuration is validated by Pydantic models in:

```text
threatlib/config/policy.py
```

Run the policy tests:

```bash
pytest tests/test_contracts.py::test_policy_loads_and_rejects_extra -v
```

Validation prevents silent configuration mistakes.

## Chapter 10: Platform Adapters

Different platforms use different event names. Instagram may call an event `instagram_dm_send`.
A generic social app may call the same behavior `dm_send`. ThreatLib wants a universal event name:
`send_dm`.

This is the job of adapters.

Adapters live in:

```text
threatlib/adapters/
```

Run the adapter tests:

```bash
pytest tests/test_adapters_v2.py -v
```

Adapters must not drop unknown events. Unknown events become `platform_custom`. This is important
because new product features may appear before the risk engine knows how to interpret them.

Adapters are additive. They declare what a platform can provide, but they do not prevent extra
signals from being used.

## Chapter 11: Independent Detectors

Independent detectors read direct account data, event data, or persisted context. They do not
depend on other detector outputs.

Examples include email entropy, device fingerprinting, behavioral timing, IP network analysis,
registration velocity, graph distance, report history, and content signals.

Run the detector tests:

```bash
pytest tests/test_detectors.py -v
```

A good detector test has three cases:

Clear bot behavior should produce fraud evidence.
Clear human behavior should produce legitimacy evidence or uncertainty.
Absent data should produce exact uncertainty.

This pattern is useful beyond ThreatLib. It is a good testing pattern for any signal-processing
component.

## Chapter 12: Interdependent Detectors and the DAG

Some detectors need outputs from other detectors. For example, a cross-signal coherence detector
may compare whether email entropy, username entropy, timing, IP, and IMU signals all point in the
same direction.

These dependencies form a directed graph. ThreatLib requires this graph to be acyclic.

The orchestrator lives in:

```text
threatlib/signals/orchestrator.py
```

Run the DAG cycle test:

```bash
pytest tests/test_detectors_v2.py::test_detector_dag_cycle_detection -v
```

This is a software architecture lesson. When modules depend on each other, you should make the
dependency structure explicit and validate it early.

## Chapter 13: Behavioral Timing

Behavioral timing analyzes intervals between user interactions. Humans are irregular. Scripts are
often regular.

ThreatLib uses analytical timing mode during cold start. It compares intervals against a Weibull
prior. After enough real data is collected, an empirical baseline can replace the analytical prior.

Run the timing test:

```bash
pytest tests/test_detectors.py::test_timing_ks_rejects_uniform -v
```

The test checks that highly uniform intervals are rejected as inconsistent with the human timing
baseline.

This example shows how probability distributions become engineering tools.

## Chapter 14: Device and IMU Signals

Device fingerprinting looks for reuse, automation indicators, install source, sensor properties,
screen state, and timezone coherence. IMU motion detection looks for mobile movement features.

A real handheld phone usually has small motion variance. An emulator or automation rig may show
near-zero variance or perfectly regular sampling.

The important privacy point is that raw sensor streams are not stored. The system stores derived
features only.

Run device and IMU tests:

```bash
pytest tests/test_detectors.py::test_direct_bot_detectors_emit_fraud -v
```

Derived features reduce privacy risk while preserving useful security evidence.

## Chapter 15: Graph-Based Detection

Graph detection is essential for Sybil and coordinated behavior. A single account may look normal
in isolation. A cluster of accounts sharing devices, IP prefixes, referrals, link domains, or timing
patterns may reveal the attack.

ThreatLib stores account relationships as graph edges in SQLite. The graph layer supports BFS,
edge lookup, recent accounts, and community analysis.

Inspect the graph storage file:

```bash
code threatlib/graph/account_graph.py
```

Run graph-related tests:

```bash
pytest tests/test_graph.py -v
pytest tests/test_detectors_v2.py::test_community_detects_bot_cluster -v
```

The main lesson is that structure can be evidence. Abuse campaigns often create unnatural graph
patterns.

## Chapter 16: HMM Intent Inference

Hidden Markov Models are useful when intent is not directly observable. ThreatLib uses hidden states
such as benign, watching, escalating, and acting.

Observable events include profile views, searches, follows, DMs, link sharing, reports, and custom
platform events. The forward algorithm estimates the probability distribution over hidden states
after observing an event sequence.

Run the HMM test:

```bash
pytest tests/test_detectors_v2.py::test_hmm_forward_escalating_sequence -v
```

This is a practical use of a topic often taught in probability or machine learning courses. The
model is simple enough to understand, but powerful enough to describe behavior over time.

## Chapter 17: Hawkes Burst Modeling

Hawkes processes model self-exciting events. In account abuse, one registration burst may trigger
more registrations. Bot farms often show clustered arrivals.

ThreatLib includes Hawkes-style intensity and log-likelihood helpers. The production scoring path
uses a deterministic approximation suitable for the foundation build, while the formula helpers are
tested separately.

Run Hawkes tests:

```bash
pytest tests/test_detectors_v2.py::test_hawkes_bot_burst_vs_human -v
pytest tests/test_detectors_v2.py::test_hawkes_mle_convergence -v
```

The engineering lesson is that advanced mathematical models should be introduced with clear
fallbacks and tests.

## Chapter 18: Survival Analysis

Survival analysis estimates time-to-event risk. In ThreatLib, the event of interest is a future bad
action. A Cox proportional hazards model expresses hazard as a baseline hazard multiplied by a
feature-dependent exponential term.

During cold start, ThreatLib uses prior coefficients. After enough confirmed outcomes exist, these
coefficients should be fitted from platform data.

Run the survival test:

```bash
pytest tests/test_detectors_v2.py::test_survival_high_risk_shorter_eta -v
```

This chapter connects statistics with operations. A model is not complete until you know how it will
be calibrated.

## Chapter 19: Contagion and Belief Propagation

SIR models come from epidemiology, but the same equations can describe risk propagation through a
social graph. ThreatLib uses conservative defaults so social risk does not overwhelm direct evidence.

Ising-style belief propagation models pairwise influence between connected accounts. If two accounts
are strongly linked, their risk beliefs may influence each other.

Run the contagion tests:

```bash
pytest tests/test_contagion.py -v
```

This shows how graph algorithms, probability, and security engineering can meet in one system.

## Chapter 20: Action Decisions

ThreatLib separates scoring from action. A score is a measure of risk. An action is a policy
decision. This separation matters because different platforms have different tolerance for risk.

Feature restrictions use logistic functions. A feature with a low threshold and steep curve becomes
restricted quickly as risk increases. A feature with a high threshold remains available longer.

Run action tests:

```bash
pytest tests/test_action_engine.py -v
```

The action engine also includes the hardcoded CSAM emergency bypass. This bypass is intentionally
not configurable because child-safety escalation must not depend on operator threshold tuning.

## Chapter 21: API Integration

ThreatLib exposes a FastAPI surface. You can score accounts, ingest events, submit reports, create
appeals, inspect account state, check health, read metrics, and view graph clusters.

Run integration tests:

```bash
pytest tests/test_integration.py -v
pytest tests/test_integration_v2.py -v
```

These tests are especially valuable because they exercise multiple components together. Unit tests
prove pieces. Integration tests prove the pipeline.

## Chapter 22: Privacy Engineering

Privacy is not a paragraph in the README. It is implemented in storage design and tests.

ThreatLib avoids plaintext account identifiers, email local parts, full IP addresses, raw usernames,
raw message content, and raw sensor streams. It stores hashes, prefixes, derived features, and
aggregate statistics.

Run privacy tests:

```bash
pytest tests/test_privacy.py -v
```

Privacy-preserving engineering is not only about encryption. It is also about data minimization.

Threat intelligence feeds require the same discipline. A URLhaus row may contain a URL that points
to malware, but ThreatLib treats that URL as data, not as something to visit. The importer hashes
the URL and host, records non-sensitive labels such as threat type and status, and stops there.
The Tor feed is handled similarly: exact IP values are hashed, and only hashed prefix indicators are
used for local lookup. Public training datasets such as Tranco, SNAP Facebook, and UCI SMS Spam are
converted into domain-rank buckets, graph summary features, and text-derived counters. Raw SMS text,
raw malicious URLs, and full IP addresses are not stored.

The import command is explicit about source type:

```bash
threatlib-import-intel --config threatlib.yaml --tranco "<path-to>/top-1m.csv" --facebook "<path-to>/facebook_combined.txt" --sms "<path-to>/sms+spam+collection"
```

Live feeds are loaded only through named allowlisted feed identifiers:

```bash
threatlib-import-intel --config threatlib.yaml --fetch tor_exit_nodes --fetch urlhaus_recent --prune-expired
```

The important engineering decision is that ThreatLib stores indicators for a short operational
window, not forever. The default retention period is thirty days, which is long enough to catch
fast-moving abuse campaigns while keeping database growth bounded.

The same datasets can also produce a compact baseline model:

```bash
threatlib-train-base-model --tranco "<path-to>/top-1m.csv" --facebook "<path-to>/facebook_combined.txt" --sms "<path-to>/sms+spam+collection" --output threatlib/models/base_model.json
```

This model is not a raw data bundle. The Tranco file becomes aggregate domain statistics and TLD
counts. The SNAP graph becomes structural graph baselines such as density, clustering, and degree
distribution. The SMS corpus becomes a numeric logistic classifier trained on derived features:
message length, token count, URL count, digit fraction, uppercase fraction, urgency-term count, and
exclamation count. The artifact stores coefficients, scaler values, metrics, and source hashes.
That gives ThreatLib a public-data starting point without committing the original datasets.

## Chapter 23: Auditability

Every scoring event is logged immutably. SQLite triggers prevent update and delete operations on the
audit table.

This matters because risk systems must be explainable after the fact. If an account was restricted,
operators need to know which detectors fired, what masses they produced, what score was computed,
and which action was returned.

Auditability is a legal, operational, and engineering requirement.

## Chapter 24: Running a Manual Scoring Experiment

You can run a manual score request by starting the server and posting JSON. First start the server:

```bash
threatlib-server --config threatlib.yaml --host 127.0.0.1 --port 8000
```

Then submit a minimal account:

```bash
curl -X POST http://127.0.0.1:8000/score ^
  -H "Content-Type: application/json" ^
  -d "{\"account_id\":\"demo_account\"}"
```

This should produce a conservative result because little evidence exists.

Submit richer account data:

```bash
curl -X POST http://127.0.0.1:8000/score ^
  -H "Content-Type: application/json" ^
  -d "{\"account_id\":\"demo_bot\",\"email_domain\":\"new-domain.xyz\",\"email_domain_age_days\":2,\"ip_prefix\":\"198.51.100\",\"ip_is_datacenter\":true,\"device_hash\":\"device-1\",\"device_platform\":\"web\",\"device_user_agent\":\"python-requests\"}"
```

Observe how the response includes detector outputs, risk score, action, restrictions, quorum, and
audit identifier.

## Chapter 25: Reading the Tests as Documentation

Tests are executable documentation. If you want to understand how a module is expected to behave,
read its tests.

Examples:

```bash
code tests/test_contracts.py
code tests/test_dempster_shafer.py
code tests/test_detectors_v2.py
code tests/test_integration_v2.py
```

The test names are intentionally descriptive. They explain the system’s expectations better than
comments alone.

## Chapter 26: Recommended Reading Path

Begin with `DetectorResult` and the detector contract. Then study Dempster-Shafer fusion. After that,
read the risk synthesis pipeline. Once you understand scoring, move to adapters and the API server.
Finally, study advanced detectors such as HMM, Hawkes, SIR, survival analysis, and community
detection.

A practical sequence is:

```bash
rg "class DetectorResult"
rg "def combine"
rg "class RiskSynthesizer"
rg "class DetectorOrchestrator"
rg "class HMMIntentDetector"
rg "def run_sir"
```

Do not try to understand every detector first. Understand the contract first. Once the contract is
clear, every detector becomes easier to read.

## Chapter 27: Extension Exercises

One useful extension exercise is to add a new platform adapter. Choose a platform domain such as
education, ride-sharing, food delivery, or gaming. Define five platform events and map them to
universal events. Then add tests similar to `tests/test_adapters_v2.py`.

Another exercise is to add a new detector. Start with a simple metadata detector. Declare required
fields. Return uncertainty on absent data. Add clear bot, clear human, and absent data tests.

You can also extend the dashboard. Add a page that displays detector uncertainty rates. This is a
useful operational metric because high uncertainty indicates missing instrumentation.

## Chapter 28: Common Mistakes to Avoid

Do not treat missing fields as safe.
Do not store raw PII for convenience.
Do not let one detector make irreversible decisions.
Do not bypass shadow-mode review.
Do not calibrate thresholds from synthetic fixtures alone.
Do not use unconfirmed harmful accounts as graph anchors.
Do not mix platform-specific event names directly into HMM logic.
Do not add detector dependencies without checking DAG behavior.

These are not stylistic preferences. They are safety rules.

## Chapter 29: System Walkthrough

When explaining ThreatLib, start with the problem. Account abuse is cross-platform, multi-signal,
adversarial, and uncertain. Then explain the architecture. Show how detectors produce evidence, how
evidence is fused, how actions are decided, and how privacy is preserved.

Demonstrate commands:

```bash
pytest tests/ -v --tb=short
threatlib-server --config threatlib.yaml
threatlib-dashboard --config threatlib.yaml
```

Show a score response. Point to the detector masses. Explain why uncertainty is visible in the
output. Explain why shadow mode returns monitor. Explain why audit logs are append-only.

This walkthrough connects theory, code, and operational safety.

## Chapter 30: Conclusion

ThreatLib combines probability, graphs, API design, configuration validation, testing, privacy
engineering, database constraints, event processing, and security policy in one coherent system.

The most important lesson is not any single detector. The most important lesson is architecture.
ThreatLib shows how to build a system where evidence is explicit, uncertainty is preserved, decisions
are auditable, and enforcement is separated from scoring.

That is the difference between a demo model and an engineering system.
