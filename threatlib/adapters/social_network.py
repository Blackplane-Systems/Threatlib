"""Generic social-network adapter."""

from threatlib.adapters.base import BaseAdapter


class SocialNetworkAdapter(BaseAdapter):
    platform_name = "social_network"
    available_signals = [
        "account_id",
        "email_domain",
        "username_raw",
        "device_hash",
        "ip_prefix",
        "timing_field_intervals",
        "friend_ids",
        "first_search_query",
        "metadata",
    ]
    relevant_attack_vectors = ["AV-01", "AV-03", "AV-04", "AV-05", "AV-06", "AV-08", "AV-09", "AV-11", "AV-12"]
    event_map = {
        "profile_view": "view_profile",
        "view_profile": "view_profile",
        "search": "search",
        "follow": "follow_user",
        "follow_user": "follow_user",
        "dm_send": "send_dm",
        "send_message": "send_dm",
        "post": "post_content",
        "comment": "post_comment",
        "share": "share_content",
        "external_click": "click_external_link",
        "report": "report_user",
    }
    field_map = {"profile_username": "username_raw", "profile_display_name": "display_name_raw"}
    feature_restriction_map = {
        "read_content": {"threshold": 0.90, "steepness": 5.0},
        "search": {"threshold": 0.85, "steepness": 5.0},
        "react": {"threshold": 0.60, "steepness": 6.0},
        "follow_user": {"threshold": 0.45, "steepness": 9.0},
        "post_content": {"threshold": 0.50, "steepness": 8.0},
        "send_dm": {"threshold": 0.35, "steepness": 10.0},
        "create_group": {"threshold": 0.25, "steepness": 12.0},
        "mass_invite": {"threshold": 0.15, "steepness": 15.0},
    }

