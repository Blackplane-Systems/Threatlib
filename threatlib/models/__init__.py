"""Bundled compact ThreatLib model artifacts."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any


def load_base_model(path: str | Path | None = None) -> dict[str, Any]:
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    model_file = resources.files(__package__).joinpath("base_model.json")
    return json.loads(model_file.read_text(encoding="utf-8"))
