# Benchmarks

ThreatLib benchmark work should measure scoring latency, replay throughput, detector uncertainty rate, and storage growth.

## Local Score Timing

```bash
python -m timeit -n 20 -r 3 "from threatlib.config.policy import PolicyLoader; from threatlib.risk.synthesis import RiskSynthesizer; import json; p=PolicyLoader.load('threatlib.yaml'); p.graph.db_path=':memory:'; s=RiskSynthesizer(p); a=json.load(open('examples/score_bot.json')); s.score(a)"
```

## Replay Throughput

```bash
threatlib-replay --config threatlib.yaml --input examples/replay/demo.jsonl --output replay-output.json
```

For larger datasets, run replay from a compressed JSONL archive and track records per second externally.

## Production Metrics

Use `/metrics/prometheus` for continuous measurement. Track:

- score requests per second
- audit events
- replay score count
- replay quorum rate
- graph edge count
- action distribution

Benchmark changes should be run with the same policy hash and deterministic replay input.
