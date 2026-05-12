"""Platform adapter contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar


UNIVERSAL_EVENT_TYPES = {
    "search",
    "view_profile",
    "view_content",
    "send_dm",
    "send_dm_with_link",
    "post_content",
    "post_comment",
    "follow_user",
    "join_group",
    "share_content",
    "share_external_link",
    "click_external_link",
    "report_user",
    "create_listing",
    "initiate_payment",
    "add_contact",
    "view_story",
    "screen_capture",
    "screen_record_detected",
    "create_group",
    "forward_message",
    "platform_custom",
}


@dataclass
class BaseAdapter:
    platform_name: ClassVar[str] = "generic"
    platform_version: ClassVar[str] = "2.0"
    available_signals: ClassVar[list[str]] = []
    relevant_attack_vectors: ClassVar[list[str]] = ["ALL"]
    event_map: ClassVar[dict[str, str]] = {}
    field_map: ClassVar[dict[str, str]] = {}
    feature_restriction_map: ClassVar[dict[str, dict[str, float]]] = {}

    def translate_event(self, platform_event_type: str, platform_event_data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        event_type = platform_event_type if platform_event_type in UNIVERSAL_EVENT_TYPES else self.event_map.get(platform_event_type, "platform_custom")
        data = dict(platform_event_data or {})
        data.setdefault("platform_event_type", platform_event_type)
        if event_type not in UNIVERSAL_EVENT_TYPES:
            event_type = "platform_custom"
        return event_type, data

    def preprocess_account_data(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        data = dict(raw_data)
        for platform_field, universal_field in self.field_map.items():
            if platform_field in data and universal_field not in data:
                data[universal_field] = data[platform_field]
        return data

    def get_feature_restriction_map(self) -> dict[str, dict[str, float]]:
        return dict(self.feature_restriction_map)
