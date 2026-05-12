"""Health-community adapter."""

from threatlib.adapters.base import BaseAdapter


class HealthAdapter(BaseAdapter):
    platform_name = "health"
    available_signals = ["account_id", "device_hash", "ip_prefix", "metadata"]
    relevant_attack_vectors = ["AV-03", "AV-04", "AV-08", "AV-09", "AV-13", "AV-14"]
    event_map = {
        "log_symptom": "platform_custom",
        "join_community": "join_group",
        "post_community": "post_content",
        "message_member": "send_dm",
        "share_health_data": "share_content",
        "recommend_treatment": "post_content",
        "health_report": "report_user",
    }
    feature_restriction_map = {
        "read_articles": {"threshold": 0.90, "steepness": 5.0},
        "log_health_data": {"threshold": 0.75, "steepness": 6.0},
        "join_community": {"threshold": 0.50, "steepness": 8.0},
        "post_in_community": {"threshold": 0.35, "steepness": 10.0},
        "message_member": {"threshold": 0.30, "steepness": 12.0},
        "share_health_data": {"threshold": 0.45, "steepness": 9.0},
        "claim_professional_status": {"threshold": 0.20, "steepness": 15.0},
        "recommend_treatment": {"threshold": 0.15, "steepness": 15.0},
    }

