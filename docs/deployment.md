# Deployment Guide

ThreatLib supports local SQLite deployments and production deployments where storage, queues, and workers are managed externally.

## Local Mode

Local mode uses `threatlib.yaml` and SQLite:

```bash
pip install -e .
threatlib-server --config threatlib.yaml
```

This mode is suitable for development, replay, demonstrations, and low-volume pilots.

## Docker Compose

```bash
docker compose up --build
```

Compose starts the API and dashboard. It is intended for local onboarding rather than high-availability production use.

## Kubernetes

Starter manifests are in `deployment/kubernetes`. Helm starter files are in `deployment/helm/threatlib`.

Before production rollout:

1. Keep `shadow_mode: true`.
2. Configure persistent storage and backups.
3. Configure service-level objectives for API latency and replay jobs.
4. Export `/metrics/prometheus` to Prometheus.
5. Review detector uncertainty rates and false-positive candidates.
6. Move to active enforcement only after policy review and outcome validation.

## Scaling

The default repository implementation remains SQLite and single-process. Enterprise deployments should place ingestion behind an idempotent queue, run replay workers separately from the API, and keep detector execution stateless where possible. Distributed storage backends should be introduced through storage interfaces without changing detector contracts or scoring semantics.

## Disaster Recovery

Back up policy versions, audit logs, feedback labels, and replay archives. Audit logs are append-only and should be restored before replaying dependent operational reports.
