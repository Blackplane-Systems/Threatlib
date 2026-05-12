"""Messaging-first adapter."""

from threatlib.adapters.base import BaseAdapter


class WhatsAppAdapter(BaseAdapter):
    platform_name = "whatsapp"
    available_signals = ["account_id", "device_hash", "ip_prefix", "friend_ids", "metadata"]
    relevant_attack_vectors = ["AV-01", "AV-04", "AV-05", "AV-06", "AV-09", "AV-11", "AV-12", "AV-14"]
    event_map = {
        "whatsapp_send_message": "send_dm",
        "whatsapp_forward_message": "forward_message",
        "whatsapp_create_group": "create_group",
        "whatsapp_add_to_group": "join_group",
        "whatsapp_link_click": "click_external_link",
        "whatsapp_report": "report_user",
        "whatsapp_screen_record": "screen_record_detected",
    }
    feature_restriction_map = {
        "view_chat": {"threshold": 0.90, "steepness": 5.0},
        "send_message": {"threshold": 0.35, "steepness": 10.0},
        "forward_message": {"threshold": 0.25, "steepness": 12.0},
        "create_group": {"threshold": 0.20, "steepness": 15.0},
        "add_to_group": {"threshold": 0.30, "steepness": 12.0},
        "share_link": {"threshold": 0.35, "steepness": 10.0},
        "voice_call": {"threshold": 0.50, "steepness": 8.0},
        "video_call": {"threshold": 0.55, "steepness": 8.0},
        "broadcast_message": {"threshold": 0.15, "steepness": 15.0},
    }

