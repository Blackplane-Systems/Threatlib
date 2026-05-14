# Mathematical Internals

This document is an index for engineers who need to audit or extend the scoring internals after they understand the operational flow.

## Evidence Fusion

Detector likelihood ratios are converted to Dempster-Shafer mass functions. Fraud mass, legitimate mass, and uncertainty mass sum to one.

Implementation: `threatlib/signals/base.py` and `threatlib/fusion/dempster_shafer.py`.

## Risk Score

The composite score is:

```text
r = fraud_mass / (fraud_mass + legitimate_mass)
```

When both fraud and legitimate mass are zero, the engine returns `0.5` as maximum uncertainty.

Implementation: `threatlib/risk/synthesis.py`.

## Temporal Decay and Signal Weights

Temporal decay halves evidence after the configured signal half-life. Signal weighting uses a bounded transform so adjusted masses remain in `[0, 1]`.

Implementation: `threatlib/fusion/dempster_shafer.py`.

## Conformal Prediction

Conformal prediction wraps the score with a calibrated interval when enough labels exist. During cold start, the DS band remains the source of truth.

Implementation: `threatlib/risk/conformal.py`.

## Replay Determinism

Replay disables score jitter by setting the jitter scale to zero on a replay policy copy. This preserves production scoring semantics while making replay comparisons reproducible.

Implementation: `threatlib/replay/engine.py`.
