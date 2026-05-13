"""Command-line entry point for public baseline model training."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from threatlib.pretrain.base_model import train_base_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the compact ThreatLib public baseline model")
    parser.add_argument("--tranco", required=True, type=Path)
    parser.add_argument("--facebook", required=True, type=Path)
    parser.add_argument("--sms", required=True, type=Path)
    parser.add_argument("--output", default=Path("threatlib/models/base_model.json"), type=Path)
    args = parser.parse_args()

    model = train_base_model(args.tranco, args.facebook, args.sms, args.output)
    print(
        json.dumps(
            {
                "status": "ok",
                "output": str(args.output),
                "contains_raw_training_data": model["contains_raw_training_data"],
                "sms_rows": model["sms_spam_numeric_logistic"]["rows_used"],
                "domain_rows": model["domain_rank_baseline"]["rows_used"],
                "graph_edges": model["graph_structure_baseline"]["edge_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
