"""Preset loading and merge helpers."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from threatlib.config.policy import Policy, PolicyLoader
from threatlib.policy.versioning import policy_hash


PRESET_DIR = Path(__file__).resolve().parent


def list_presets() -> list[str]:
    return sorted(path.stem for path in PRESET_DIR.glob("*.yaml"))


def load_preset(name: str) -> dict[str, Any]:
    path = PRESET_DIR / f"{name}.yaml"
    if not path.exists():
        raise ValueError(f"unknown preset: {name}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def apply_preset(base: Policy | dict[str, Any], name: str) -> Policy:
    base_raw = {"threatlib": base.model_dump(mode="json")} if isinstance(base, Policy) else deepcopy(base)
    merged = deep_merge(base_raw, load_preset(name))
    return PolicyLoader.from_dict(merged)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatLib deployment presets")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("name")
    apply_cmd = sub.add_parser("apply")
    apply_cmd.add_argument("name")
    apply_cmd.add_argument("--base", default="threatlib.yaml")
    apply_cmd.add_argument("--output")
    args = parser.parse_args()

    if args.command == "list":
        print(json.dumps(list_presets(), indent=2))
    elif args.command == "show":
        print(yaml.safe_dump(load_preset(args.name), sort_keys=False))
    else:
        policy = apply_preset(PolicyLoader.load(args.base), args.name)
        payload = {"threatlib": policy.model_dump(mode="json")}
        text = yaml.safe_dump(payload, sort_keys=False)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
        print(json.dumps({"preset": args.name, "policy_hash": policy_hash(policy)}, sort_keys=True))


if __name__ == "__main__":
    main()
