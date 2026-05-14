# Replay and Policy Simulation

Replay is the operational mechanism for testing policies before changing production behavior. It accepts historical records, runs them through the same scoring engine, and reports score evolution without requiring live traffic.

## Supported Inputs

Replay supports:

- JSON arrays
- JSONL
- NDJSON
- CSV
- gzip-compressed files
- zip archives containing a supported file

## Record Types

Score record:

```json
{"type": "score", "account_data": {"account_id": "acct", "email_domain": "example.com"}}
```

Event record:

```json
{"type": "event", "account_id": "acct", "event_type": "send_dm", "event_data": {"has_link": true}}
```

Report record:

```json
{"type": "report", "target_account_id": "acct", "reporter_account_id": "reporter", "category": "spam", "reporter_trust_score": 0.8}
```

Feedback record:

```json
{"type": "feedback", "account_id": "acct", "outcome": "false_positive", "risk_score": 0.82}
```

## CLI Usage

```bash
threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl --output replay-output.json
```

The output contains a `timeline` and a `summary`. The summary includes action distribution, threat-tier distribution, detector activation counts, average uncertainty, quorum rate, detector disagreement, policy version, and policy hash.

## API Usage

```bash
curl -X POST http://127.0.0.1:8000/replay \
  -H "Content-Type: application/json" \
  -d '{"records":[{"type":"score","account_data":{"account_id":"acct"}}]}'
```

By default, the API replay endpoint uses an isolated in-memory graph. Set `persist: true` only when intentionally using replay to seed the configured store.

## Determinism

Replay disables score jitter by default. This makes policy comparison reproducible and keeps threshold sensitivity tests stable.
