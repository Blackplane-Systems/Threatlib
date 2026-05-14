"""Replay historical records through ThreatLib without changing scoring semantics."""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import random
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from threatlib.adapters import AdapterRegistry
from threatlib.config.policy import Policy, PolicyLoader
from threatlib.graph.account_graph import AccountGraph
from threatlib.policy.versioning import policy_hash
from threatlib.risk.synthesis import RiskSynthesizer


REPLAY_JITTER_SCALE = 0.0  # REF: Deterministic replay requirement - disable action jitter during simulation.


class ReplayEngine:
    """Apply score, event, report, and feedback records to an isolated graph by default."""

    def __init__(self, policy: Policy, graph: AccountGraph | None = None, deterministic: bool = True) -> None:
        self.policy = policy.model_copy(deep=True)
        if deterministic:
            self.policy.adversarial_robustness.score_jitter_laplace_scale = REPLAY_JITTER_SCALE
        self.graph = graph or AccountGraph(":memory:")
        self.rng = random.Random(0) if deterministic else random.Random()
        self.adapter = AdapterRegistry.from_policy(self.policy)
        self.synthesizer = RiskSynthesizer(self.policy, graph=self.graph, rng=self.rng)
        self.deterministic = deterministic

    def replay(self, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
        started = time.time()
        timeline: list[dict[str, Any]] = []
        actions: Counter[str] = Counter()
        tiers: Counter[str] = Counter()
        detector_activations: Counter[str] = Counter()
        uncertainty_progression: list[float] = []
        quorum_met = 0
        detector_disagreement: list[dict[str, Any]] = []

        for index, raw_record in enumerate(records):
            record = dict(raw_record)
            record_type = str(record.pop("type", record.pop("record_type", "score"))).lower()
            if record_type == "score":
                account_data = record.get("account_data") or record
                account_data = self.adapter.preprocess_account_data(dict(account_data))
                result = self.synthesizer.score(account_data)
                actions[result["action"]] += 1
                tiers[result["threat_tier"]] += 1
                for name, detector in result["detectors"].items():
                    if detector["fraud_mass"] + detector["legitimate_mass"] > 0.05:
                        detector_activations[name] += 1
                uncertainty_progression.append(float(result["combined"]["uncertainty_mass"]))
                if result["quorum"]["met"]:
                    quorum_met += 1
                detector_disagreement.append(_detector_disagreement(index, result["detectors"]))
                timeline.append(_score_timeline(index, result, self.policy))
            elif record_type == "event":
                event_type, event_data = self.adapter.translate_event(
                    str(record["event_type"]),
                    dict(record.get("event_data") or {}),
                )
                self.graph.record_event(
                    str(record["account_id"]),
                    event_type,
                    event_data,
                    record.get("session_id"),
                    _optional_float(record.get("timestamp")),
                )
                timeline.append({"index": index, "type": "event", "account_id": record["account_id"], "event_type": event_type})
            elif record_type == "report":
                self.graph.add_report(
                    str(record["target_account_id"]),
                    str(record.get("reporter_account_id", "replay_reporter")),
                    str(record["category"]),
                    float(record.get("reporter_trust_score", 0.5)),
                    _optional_float(record.get("timestamp")),
                )
                timeline.append({"index": index, "type": "report", "account_id": record["target_account_id"], "category": record["category"]})
            elif record_type == "feedback":
                self.graph.record_feedback_label(
                    str(record["account_id"]),
                    str(record["outcome"]),
                    source=str(record.get("source", "replay")),
                    risk_score=_optional_float(record.get("risk_score")),
                    threshold=_optional_float(record.get("threshold")),
                    notes=record.get("notes"),
                    created_at=_optional_float(record.get("timestamp")),
                )
                timeline.append({"index": index, "type": "feedback", "account_id": record["account_id"], "outcome": record["outcome"]})
            else:
                timeline.append({"index": index, "type": "ignored", "reason": f"unknown record type {record_type}"})

        score_count = sum(actions.values())
        summary = {
            "record_count": len(timeline),
            "score_count": score_count,
            "action_distribution": dict(actions),
            "threat_tier_distribution": dict(tiers),
            "detector_activation_counts": dict(detector_activations),
            "average_uncertainty": sum(uncertainty_progression) / len(uncertainty_progression) if uncertainty_progression else None,
            "quorum_met_count": quorum_met,
            "quorum_met_rate": quorum_met / score_count if score_count else 0.0,
            "detector_disagreement": detector_disagreement,
            "policy_version": self.policy.version,
            "policy_hash": policy_hash(self.policy),
            "deterministic": self.deterministic,
            "started_at": started,
            "finished_at": time.time(),
        }
        return {"summary": summary, "timeline": timeline}


def load_replay_file(path: str | Path) -> list[dict[str, Any]]:
    replay_path = Path(path)
    data = replay_path.read_bytes()
    if replay_path.suffix == ".gz":
        data = gzip.decompress(data)
        name = replay_path.with_suffix("").name
    elif replay_path.suffix == ".zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            candidates = [item for item in archive.namelist() if item.endswith((".jsonl", ".ndjson", ".csv", ".json"))]
            if not candidates:
                raise ValueError("replay archive contains no supported replay file")
            name = candidates[0]
            data = archive.read(name)
    else:
        name = replay_path.name
    text = data.decode("utf-8")
    if name.endswith(".json"):
        payload = json.loads(text)
        return payload if isinstance(payload, list) else payload.get("records", [])
    if name.endswith(".csv"):
        return [_parse_csv_row(row) for row in csv.DictReader(io.StringIO(text))]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _parse_csv_row(row: dict[str, str]) -> dict[str, Any]:
    parsed: dict[str, Any] = {key: value for key, value in row.items() if value not in (None, "")}
    for key in ("account_data", "event_data"):
        if key in parsed:
            parsed[key] = json.loads(parsed[key])
    return parsed


def _score_timeline(index: int, result: dict[str, Any], policy: Policy) -> dict[str, Any]:
    return {
        "index": index,
        "type": "score",
        "account_id": result["account_id"],
        "risk_score": result["risk_score"],
        "action": result["action"],
        "threat_tier": result["threat_tier"],
        "confidence_band": result["confidence_band"],
        "quorum": result["quorum"],
        "feature_restrictions": result["restrictions"],
        "policy_version": policy.version,
        "policy_hash": policy_hash(policy),
        "replay_trace_id": f"replay-step-{index}",
    }


def _detector_disagreement(index: int, detectors: dict[str, dict[str, Any]]) -> dict[str, Any]:
    fraud_masses = [float(item["fraud_mass"]) for item in detectors.values()]
    legitimate_masses = [float(item["legitimate_mass"]) for item in detectors.values()]
    fraud_peak = max(fraud_masses) if fraud_masses else 0.0
    legitimate_peak = max(legitimate_masses) if legitimate_masses else 0.0
    return {
        "index": index,
        "fraud_peak": fraud_peak,
        "legitimate_peak": legitimate_peak,
        "conflict_proxy": min(fraud_peak, legitimate_peak),
    }


def _optional_float(value: Any) -> float | None:
    return None if value is None or value == "" else float(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay ThreatLib events and scores")
    parser.add_argument("--config", default="threatlib.yaml")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")
    parser.add_argument("--non-deterministic", action="store_true")
    args = parser.parse_args()
    result = ReplayEngine(
        PolicyLoader.load(args.config),
        deterministic=not args.non_deterministic,
    ).replay(load_replay_file(args.input))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
