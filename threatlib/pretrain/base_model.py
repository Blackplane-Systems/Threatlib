"""Train a compact public-dataset baseline model without storing raw source rows."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import networkx as nx
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from threatlib.intel.feeds import text_message_features


SMS_FEATURE_NAMES = [
    "length",
    "token_count",
    "url_count",
    "digit_fraction",
    "uppercase_fraction",
    "urgency_term_count",
    "exclamation_count",
]
RANDOM_STATE = 42  # REF: Reproducible public baseline training split.
TEST_SIZE = 0.25  # REF: Standard small-corpus holdout fraction for SMS model validation.
MAX_TRANCO_ROWS = 1_000_000  # REF: Tranco top-1M published dataset size.
MAX_DOMAIN_TLD_BUCKETS = 50  # REF: Compact artifact limit to avoid storing a domain dictionary.


def train_base_model(
    tranco_path: str | Path,
    facebook_path: str | Path,
    sms_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    tranco_file = _resolve_dataset_file(tranco_path, "top-1m.csv")
    facebook_file = _resolve_dataset_file(facebook_path, "facebook_combined.txt")
    sms_file = _resolve_dataset_file(sms_path, "SMSSpamCollection")

    model = {
        "model_name": "threatlib_public_base_model",
        "schema_version": 1,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "contains_raw_training_data": False,
        "privacy": {
            "stores_raw_domains": False,
            "stores_raw_sms": False,
            "stores_raw_graph_edges": False,
            "stores_plaintext_malicious_indicators": False,
        },
        "sources": {
            "tranco_top_domains": _source_metadata(tranco_file),
            "snap_ego_facebook": _source_metadata(facebook_file),
            "uci_sms_spam": _source_metadata(sms_file),
        },
        "domain_rank_baseline": _train_domain_rank_baseline(tranco_file),
        "graph_structure_baseline": _train_graph_structure_baseline(facebook_file),
        "sms_spam_numeric_logistic": _train_sms_spam_numeric_model(sms_file),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(model, indent=2, sort_keys=True), encoding="utf-8")
    return model


def _resolve_dataset_file(path: str | Path, preferred_name: str) -> Path:
    candidate = Path(path)
    if candidate.is_file():
        return candidate
    nested = candidate / preferred_name
    if nested.is_file():
        return nested
    raise FileNotFoundError(f"could not find {preferred_name} at {candidate}")


def _source_metadata(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    line_count = 0
    byte_count = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            byte_count += len(chunk)
            line_count += chunk.count(b"\n")
    return {
        "sha256": digest.hexdigest(),
        "line_count": line_count,
        "byte_count": byte_count,
    }


def _train_domain_rank_baseline(path: Path) -> dict[str, Any]:
    lengths: list[int] = []
    entropy_values: list[float] = []
    rank_buckets = {"top_1k": 0, "top_10k": 0, "top_100k": 0, "top_1m": 0}
    tld_counts: dict[str, int] = {}
    rows = 0
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            domain = row[1].strip().lower().rstrip(".")
            if not domain:
                continue
            rows += 1
            lengths.append(len(domain))
            entropy_values.append(_shannon_entropy(domain))
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            if tld:
                tld_counts[tld] = tld_counts.get(tld, 0) + 1
            if rank <= 1_000:  # REF: Tranco rank bucket for most established domains.
                rank_buckets["top_1k"] += 1
            elif rank <= 10_000:  # REF: Tranco rank bucket for high-traffic domains.
                rank_buckets["top_10k"] += 1
            elif rank <= 100_000:  # REF: Tranco rank bucket for broad legitimacy calibration.
                rank_buckets["top_100k"] += 1
            elif rank <= MAX_TRANCO_ROWS:
                rank_buckets["top_1m"] += 1
            if rows >= MAX_TRANCO_ROWS:
                break
    top_tlds = sorted(tld_counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_DOMAIN_TLD_BUCKETS]
    return {
        "rows_used": rows,
        "rank_buckets": rank_buckets,
        "domain_length": _summary(lengths),
        "domain_entropy": _summary(entropy_values),
        "top_tlds": [{"tld": tld, "count": count} for tld, count in top_tlds],
    }


def _train_graph_structure_baseline(path: Path) -> dict[str, Any]:
    graph = nx.Graph()
    edge_rows = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) != 2:
                continue
            graph.add_edge(parts[0], parts[1])
            edge_rows += 1
    component_sizes = sorted((len(component) for component in nx.connected_components(graph)), reverse=True)
    degree_values = [degree for _, degree in graph.degree()]
    return {
        "rows_used": edge_rows,
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "density": nx.density(graph),
        "transitivity": nx.transitivity(graph),
        "average_clustering": nx.average_clustering(graph) if graph.number_of_nodes() else 0.0,
        "connected_components": len(component_sizes),
        "largest_component_nodes": component_sizes[0] if component_sizes else 0,
        "degree": _summary(degree_values),
    }


def _train_sms_spam_numeric_model(path: Path) -> dict[str, Any]:
    features: list[list[float]] = []
    labels: list[int] = []
    label_counts = {"ham": 0, "spam": 0}
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            label, _, message = line.partition("\t")
            label = label.strip().lower()
            if label not in {"ham", "spam"} or not message:
                continue
            row = text_message_features(message)
            features.append([float(row[name]) for name in SMS_FEATURE_NAMES])
            labels.append(1 if label == "spam" else 0)
            label_counts[label] += 1
    if len(set(labels)) != 2:
        raise ValueError("SMS dataset must contain both ham and spam labels")
    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=int)
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)
    classifier = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,  # REF: Numeric logistic regression convergence ceiling for small SMS corpus.
        random_state=RANDOM_STATE,
    )
    classifier.fit(x_train_scaled, y_train)
    probabilities = classifier.predict_proba(x_test_scaled)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)  # REF: Standard logistic decision boundary for balanced holdout metrics.
    return {
        "model_type": "standardized_numeric_logistic_regression",
        "feature_names": SMS_FEATURE_NAMES,
        "label_counts": label_counts,
        "rows_used": int(len(y)),
        "positive_label": "spam",
        "negative_label": "ham",
        "scaler_mean": _round_list(scaler.mean_),
        "scaler_scale": _round_list(scaler.scale_),
        "coefficients": _round_list(classifier.coef_[0]),
        "intercept": round(float(classifier.intercept_[0]), 8),
        "decision_threshold": 0.5,
        "holdout_metrics": {
            "test_size": TEST_SIZE,
            "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
            "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
            "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
            "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 6),
            "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 6),
        },
    }


def _summary(values: list[int] | list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    numeric = [float(value) for value in values]
    return {
        "count": len(numeric),
        "mean": round(float(mean(numeric)), 6),
        "std": round(float(pstdev(numeric)), 6),
        "min": round(float(min(numeric)), 6),
        "max": round(float(max(numeric)), 6),
    }


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _round_list(values: Any) -> list[float]:
    return [round(float(value), 8) for value in values]
