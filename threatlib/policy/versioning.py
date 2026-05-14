"""Policy hashing, diffing, and validation helpers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from threatlib.config.policy import Policy, PolicyLoader


def policy_hash(policy: Policy | dict[str, Any]) -> str:
    """Return a stable SHA-256 policy fingerprint."""

    import hashlib

    raw = policy.model_dump(mode="json") if isinstance(policy, Policy) else policy
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def policy_summary(policy: Policy) -> dict[str, Any]:
    """Expose safe policy metadata for operators and audit responses."""

    return {
        "platform": policy.platform,
        "version": policy.version,
        "environment": policy.environment,
        "shadow_mode": policy.shadow_mode,
        "platform_adapter": policy.platform_adapter,
        "minimum_detectors_required": policy.minimum_detectors_required,
        "enabled_signals": sorted(name for name in policy.signals if policy.is_signal_enabled(name)),
        "enabled_detectors": sorted(name for name in policy.detectors if policy.is_signal_enabled(name)),
        "policy_hash": policy_hash(policy),
    }


def lint_policy(policy: Policy) -> dict[str, Any]:
    """Return deployment warnings without mutating the policy."""

    errors: list[str] = []
    warnings: list[str] = []
    if policy.minimum_detectors_required < 2:
        errors.append("minimum_detectors_required should be at least 2 for quorum safety")
    if not policy.shadow_mode and policy.environment == "production":
        warnings.append("production policy is not in shadow mode")
    if policy.fast_deploy.enabled and policy.shadow_mode:
        warnings.append("fast_deploy is enabled but shadow_mode still forces all actions to monitor")
    if policy.threat_intel.retention_days > 30:
        warnings.append("threat_intel.retention_days is above the recommended 20-30 day operating window")
    if policy.jitter_scale() == 0:
        warnings.append("score jitter is disabled; threshold probing protection is reduced")
    if "csam" not in policy.reporting.severe_category_immediate_review:
        errors.append("reporting.severe_category_immediate_review must include csam")
    return {"valid": not errors, "errors": errors, "warnings": warnings, "policy_hash": policy_hash(policy)}


def diff_policies(left: Policy | dict[str, Any], right: Policy | dict[str, Any]) -> list[dict[str, Any]]:
    """Produce a deterministic structural diff between two policies."""

    left_raw = left.model_dump(mode="json") if isinstance(left, Policy) else left
    right_raw = right.model_dump(mode="json") if isinstance(right, Policy) else right
    diffs: list[dict[str, Any]] = []
    _diff_values((), left_raw, right_raw, diffs)
    return diffs


def _diff_values(path: tuple[str, ...], left: Any, right: Any, diffs: list[dict[str, Any]]) -> None:
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            _diff_values(path + (str(key),), left.get(key), right.get(key), diffs)
        return
    if left != right:
        diffs.append({"path": ".".join(path), "left": left, "right": right})


def _load_raw(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatLib policy operations")
    sub = parser.add_subparsers(dest="command", required=True)
    lint = sub.add_parser("lint")
    lint.add_argument("--config", default="threatlib.yaml")
    explain = sub.add_parser("explain")
    explain.add_argument("--config", default="threatlib.yaml")
    diff = sub.add_parser("diff")
    diff.add_argument("--left", required=True)
    diff.add_argument("--right", required=True)
    args = parser.parse_args()

    if args.command == "lint":
        print(json.dumps(lint_policy(PolicyLoader.load(args.config)), indent=2, sort_keys=True))
    elif args.command == "explain":
        print(json.dumps(policy_summary(PolicyLoader.load(args.config)), indent=2, sort_keys=True))
    else:
        print(json.dumps(diff_policies(_load_raw(Path(args.left)), _load_raw(Path(args.right))), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
