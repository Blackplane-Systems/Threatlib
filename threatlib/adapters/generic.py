"""Generic fallback adapter."""

from threatlib.adapters.base import BaseAdapter


class GenericAdapter(BaseAdapter):
    platform_name = "generic"
    available_signals = ["account_id", "metadata"]
    relevant_attack_vectors = ["ALL"]
    event_map = {}
    feature_restriction_map = {}

