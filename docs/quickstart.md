# ThreatLib Quickstart

This guide starts ThreatLib locally, scores sample accounts, runs replay, and shows where to inspect metrics.

## Docker Startup

```bash
docker compose up --build
```

The API is available at `http://127.0.0.1:8000`. The dashboard is available at `http://127.0.0.1:8501`.

Check service health:

```bash
curl http://127.0.0.1:8000/health
```

The default policy uses `shadow_mode: true`, so every returned action is `monitor` even when the score is high. This is intentional.

## Local Python Startup

```bash
pip install -e .
threatlib-server --config threatlib.yaml --host 0.0.0.0 --port 8000
```

In another shell:

```bash
threatlib-dashboard --config threatlib.yaml
```

## Score a Demo Account

```bash
curl -X POST http://127.0.0.1:8000/score \
  -H "Content-Type: application/json" \
  --data @examples/score_bot.json
```

The response includes `risk_score`, `confidence_band`, `action`, `threat_tier`, detector results, quorum state, and structured explainability.

## Run Replay

```bash
threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl
```

Replay runs deterministically by default and uses an isolated graph unless explicitly configured otherwise through the API.

## Inspect Policy and Presets

```bash
threatlib-policy lint --config threatlib.yaml
threatlib-policy explain --config threatlib.yaml
threatlib-preset list
threatlib-preset show fintech_risk
```

Presets are overlays. They do not replace the safety invariants in the base policy.
