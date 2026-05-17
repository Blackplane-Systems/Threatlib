# Detector Authoring Guide

Detectors are small plugins that inherit `BaseDetector` and return `DetectorResult`. They must preserve ThreatLib's uncertainty contract: absent required input returns `DetectorResult.uncertain()`.

## Minimal Detector

```python
from threatlib.signals.base import BaseDetector, DetectorResult

class ExampleDetector(BaseDetector):
    name = "example_detector"
    required_fields = ("account_id", "example_signal")

    def score(self, account_data):
        value = account_data["example_signal"]
        if value > 10:
            return DetectorResult.from_likelihood_ratio(5.0, detector_name=self.name)
        return DetectorResult.from_likelihood_ratio(0.8, detector_name=self.name)
```

## SDK Harness

```python
from threatlib.sdk import DetectorContext, DetectorHarness

harness = DetectorHarness(ExampleDetector, DetectorContext(policy=policy, graph=graph))
results = harness.canonical_cases(clear_bot, clear_human)
```

The canonical cases should cover:

- clear bot behavior
- clear human or uncertain behavior
- absent data

## Dependencies

Interdependent detectors declare `depends_on`:

```python
class ExampleCoherenceDetector(BaseDetector):
    name = "example_coherence"
    depends_on = ("email_entropy", "behavioral_timing")
```

The DAG orchestrator validates acyclicity at startup. A detector cannot depend on itself.

## Storage

Do not persist plaintext PII from detectors. Store hashes, prefixes, aggregates, or derived feature values only.

## ML Model Plugins

Use an ML model plugin when the detector behavior is already represented by a trained or rule-based model and the required integration work is input selection plus output normalization.

Model plugins are declared in policy under `ml_models`. The `ml_model` detector runs after lower-level detectors, so a model can use both request fields and detector outputs:

```yaml
ml_models:
  - name: "identity-risk-v1"
    architecture: "json_logistic_v1"
    feature_map:
      email_fraud_mass: "detectors.email_entropy.fraud_mass"
      username_fraud_mass: "detectors.psycholinguistic.fraud_mass"
      request_rate: "metadata.request_rate_per_minute"
    required_features:
      - email_fraud_mass
      - username_fraud_mass
    inline_model:
      intercept: -1.5
      coefficients:
        email_fraud_mass: 2.0
        username_fraud_mass: 1.5
        request_rate: 0.03
```

If the selected model inputs are absent, the model contributes uncertainty. This preserves the same missing-data contract expected from handwritten detectors.
