"""CLI helper for submitting confirmed TP/TN/FP/FN feedback labels."""

from __future__ import annotations

import argparse
import json

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit a ThreatLib confirmed outcome label")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--outcome", required=True, choices=["tp", "tn", "fp", "fn", "true_positive", "true_negative", "false_positive", "false_negative"])
    parser.add_argument("--source", default="manual")
    parser.add_argument("--risk-score", type=float)
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--notes")
    args = parser.parse_args()

    payload = {
        "account_id": args.account_id,
        "outcome": args.outcome,
        "source": args.source,
        "risk_score": args.risk_score,
        "threshold": args.threshold,
        "notes": args.notes,
    }
    payload = {key: value for key, value in payload.items() if value is not None}
    response = httpx.post(f"{args.api_url.rstrip('/')}/feedback", json=payload, timeout=10.0)
    response.raise_for_status()
    print(json.dumps(response.json(), sort_keys=True))


if __name__ == "__main__":
    main()
