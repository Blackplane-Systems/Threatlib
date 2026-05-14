# Operational Migration Plan

This plan upgrades an existing ThreatLib installation without changing core scoring semantics.

## Step 1: Deploy Additive Interfaces

Deploy the API with the new replay, policy, metrics, and preset endpoints. Keep `shadow_mode: true`.

Validate:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/policy/lint
curl http://127.0.0.1:8000/metrics/prometheus
```

## Step 2: Run Replay Against Historical Samples

Convert a representative event slice to JSONL or CSV and run:

```bash
threatlib-replay --config threatlib.yaml --input historical-sample.jsonl --output replay-output.json
```

Review action distribution, quorum rate, uncertainty, and detector disagreement before changing thresholds.

## Step 3: Label Outcomes

Submit confirmed outcomes:

```bash
threatlib-feedback --api-url http://127.0.0.1:8000 --account-id acct --outcome false_positive
```

Use `/metrics/model` to check false-positive and false-negative behavior.

## Step 4: Select a Preset

Apply a preset to a staging copy of the base policy:

```bash
threatlib-preset apply fintech_risk --base threatlib.yaml --output staging.fintech.yaml
threatlib-policy lint --config staging.fintech.yaml
```

Run replay against the staging policy before replacing the active policy.

## Step 5: Enable Limited Enforcement

Disable shadow mode only after review. For fast rollout, enable `fast_deploy` with an action cap. The fast-deploy guardrails prevent severe action escalation until enough scores and labels exist.

## Rollback

Keep the previous policy file and policy hash. Revert by restarting the API with the previous policy. Replay can verify action distribution before and after rollback.
