# ML Model Plugin Guide

ThreatLib supports developer-supplied ML models as evidence providers. The model is treated as one detector named `ml_model`; it does not replace detector contracts, Dempster-Shafer fusion, quorum, shadow mode, audit logging, or privacy rules.

## Operational Model

A model plugin is a policy declaration. It selects fields from the account record and from prior detector outputs, builds a JSON input object, runs a supported adapter, maps the model output JSON into a standard prediction shape, and converts that prediction into `DetectorResult` evidence.

The default policy declares no model plugins. This preserves baseline behavior until an operator explicitly adds a model.

## Built-In Adapters

`json_logistic_v1` runs a local logistic model from JSON:

```json
{
  "intercept": -2.0,
  "coefficients": {
    "request_rate_per_minute": 0.05,
    "failed_login_count": 0.20
  },
  "confidence": 0.70
}
```

`threshold_rules_v1` runs ordered rules over selected JSON features:

```json
{
  "default_score": 0.50,
  "rules": [
    {
      "feature": "transaction_velocity_24h",
      "op": ">=",
      "value": 30,
      "score": 0.88,
      "label": "fraud",
      "reason": "high_transaction_velocity"
    }
  ]
}
```

## Policy Declaration

Model plugins are declared under `ml_models`:

```yaml
ml_models:
  - name: "api-abuse-v1"
    enabled: true
    architecture: "json_logistic_v1"
    feature_map:
      request_rate_per_minute: "metadata.request_rate_per_minute"
      failed_login_count: "metadata.failed_login_count"
      datacenter_ip: "ip_is_datacenter"
    required_features:
      - request_rate_per_minute
      - failed_login_count
    output_mapping:
      score: "score"
      label: "label"
      confidence: "confidence"
      reason: "reason"
    inline_model:
      intercept: -2.0
      coefficients:
        request_rate_per_minute: 0.05
        failed_login_count: 0.20
        datacenter_ip: 1.10
      confidence: 0.70
```

`feature_map` controls the model input JSON. The left side is the model input key. The right side is a dotted path into the score request, such as `metadata.request_rate_per_minute`, or into detector outputs, such as `detectors.email_entropy.fraud_mass`.

`required_features` defines the minimum selected model inputs. If any required feature is unavailable, the model contributes uncertainty.

`output_mapping` adapts the model response. At minimum, the mapped output must expose `score`. Optional mapped fields are `label`, `confidence`, and `reason`.

## Validation

List supported adapters:

```bash
threatlib-ml catalog
```

Validate a standalone model declaration:

```bash
threatlib-ml validate \
  --model examples/ml/logistic_model.json \
  --sample examples/ml/sample_account.json
```

Validate through the API:

```bash
curl -X POST http://127.0.0.1:8000/ml/validate \
  -H "Content-Type: application/json" \
  --data @examples/ml/validate_request.json
```

The validation response includes the selected model input, missing features, raw model output, mapped model output, and the equivalent detector result.

## Scoring Semantics

The model score is interpreted as a binary fraud probability. ThreatLib converts it to likelihood-ratio odds:

```text
LR = score / (1 - score)
```

The likelihood ratio is then converted to Dempster-Shafer mass using the same `DetectorResult.from_likelihood_ratio` method as other detectors.

Neutral scores near `0.5` contribute uncertainty. Invalid outputs, unsupported architectures, missing files, and missing required features also contribute uncertainty.

## Privacy Rules

Model input JSON is not written to the audit log or detector metadata. The `ml_model` detector records only model name, architecture, score, label, missing feature names, and error strings. Developers should not select plaintext PII fields for model input unless the model runs inside their own controlled process and the selected fields are never persisted by ThreatLib.

## Recommended Rollout

Start with `enabled: false` model declarations and validate them through `threatlib-ml validate`.

Enable one model at a time in shadow mode.

Watch `/ml/models`, `/metrics/detectors`, `/metrics/model`, score distributions, and false-positive labels before allowing active enforcement.

Keep `ml_model` weight low during the first deployment cycle. Raise the weight only after the model demonstrates stable precision and recall against confirmed outcomes.
