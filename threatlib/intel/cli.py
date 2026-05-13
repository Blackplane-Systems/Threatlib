"""Command-line entry point for safe threat-intelligence imports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from threatlib.config.policy import PolicyLoader
from threatlib.graph.account_graph import AccountGraph
from threatlib.intel.feeds import ThreatIntelIngestor


def main() -> None:
    parser = argparse.ArgumentParser(description="Import safe ThreatLib threat-intelligence datasets")
    parser.add_argument("--config", default="threatlib.yaml")
    parser.add_argument("--retention-days", type=float, default=None)
    parser.add_argument("--fetch", action="append", choices=["tor_exit_nodes", "urlhaus_recent"], default=[])
    parser.add_argument("--tranco", type=Path)
    parser.add_argument("--facebook", type=Path)
    parser.add_argument("--sms", type=Path)
    parser.add_argument("--prune-expired", action="store_true")
    args = parser.parse_args()

    policy = PolicyLoader.load(args.config)
    graph = AccountGraph(policy.graph_db_path())
    retention_days = args.retention_days if args.retention_days is not None else policy.threat_intel.retention_days
    ingestor = ThreatIntelIngestor(graph, retention_days=retention_days)

    results: list[dict[str, Any]] = []
    try:
        if args.prune_expired:
            results.append({"source": "prune_expired", "deleted_rows": graph.prune_expired_intel()})
        for feed in args.fetch:
            if feed not in policy.threat_intel.allowed_remote_feeds:
                raise ValueError(f"remote feed disabled by policy: {feed}")
            results.append(ingestor.fetch_and_ingest(feed).__dict__)
        if args.tranco:
            results.append(ingestor.ingest_tranco_csv(args.tranco).__dict__)
        if args.facebook:
            results.append(ingestor.ingest_snap_facebook_graph(args.facebook).__dict__)
        if args.sms:
            results.append(ingestor.ingest_sms_spam_collection(args.sms).__dict__)
        print(json.dumps({"status": "ok", "results": results}, sort_keys=True))
    finally:
        graph.close()


if __name__ == "__main__":
    main()
