# Observability Guide

ThreatLib exposes JSON metrics for direct inspection and Prometheus text metrics for production monitoring.

## JSON Metrics

```bash
curl http://127.0.0.1:8000/metrics
curl http://127.0.0.1:8000/metrics/model
curl http://127.0.0.1:8000/metrics/detectors
curl http://127.0.0.1:8000/metrics/replay
```

`/metrics/detectors` reports per-detector count, non-trivial activations, uncertainty rate, average masses, and last seen timestamp.

`/metrics/replay` reports the latest replay summary recorded by the API process.

`/metrics/model` reports confusion matrix and performance metrics from submitted feedback labels.

## Prometheus

```bash
curl http://127.0.0.1:8000/metrics/prometheus
```

Starter Grafana JSON is available at `deployment/grafana/threatlib-overview.json`.

## Recommended Alerts

Alert when detector uncertainty rate rises sharply for a detector that normally has data.

Alert when false-positive rate exceeds the deployment target.

Alert when audit event growth stops while request volume continues.

Alert when replay quorum rate drops after a policy change.
