"""Command line helpers for ML model plugin validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from threatlib.config.policy import MLModelConfig, PolicyLoader
from threatlib.ml.plugins import model_catalog, validate_model_config


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate ThreatLib ML model plugin declarations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser("catalog", help="List supported built-in ML plugin architectures")
    catalog.set_defaults(func=_catalog)

    validate = subparsers.add_parser("validate", help="Validate a model declaration against a sample account")
    validate.add_argument("--config", default="threatlib.yaml")
    validate.add_argument("--model", help="Path to a standalone MLModelConfig JSON file")
    validate.add_argument("--model-name", help="Name of a model declared in the policy")
    validate.add_argument("--sample", required=True, help="Path to sample account JSON")
    validate.set_defaults(func=_validate)

    args = parser.parse_args()
    args.func(args)


def _catalog(_args: argparse.Namespace) -> None:
    print(json.dumps(model_catalog(), indent=2, sort_keys=True))


def _validate(args: argparse.Namespace) -> None:
    with Path(args.sample).open("r", encoding="utf-8") as handle:
        sample = json.load(handle)
    model_config = _load_model_config(args)
    print(json.dumps(validate_model_config(model_config, sample), indent=2, sort_keys=True))


def _load_model_config(args: argparse.Namespace) -> MLModelConfig:
    if args.model:
        with Path(args.model).open("r", encoding="utf-8") as handle:
            raw: dict[str, Any] = json.load(handle)
        return MLModelConfig.model_validate(raw)
    policy = PolicyLoader.load(args.config)
    if not args.model_name:
        if len(policy.ml_models) != 1:
            raise SystemExit("--model-name is required when the policy declares zero or multiple ML models")
        return policy.ml_models[0]
    for model in policy.ml_models:
        if model.name == args.model_name:
            return model
    raise SystemExit(f"model not found in policy: {args.model_name}")


if __name__ == "__main__":
    main()
