"""Content-primary adapter."""

from threatlib.adapters.base import BaseAdapter


class YouTubeAdapter(BaseAdapter):
    platform_name = "youtube"
    available_signals = ["account_id", "email_domain", "device_hash", "ip_prefix", "metadata"]
    relevant_attack_vectors = ["AV-01", "AV-04", "AV-05", "AV-06", "AV-08", "AV-11", "AV-15"]
    event_map = {
        "youtube_view": "view_content",
        "youtube_comment": "post_comment",
        "youtube_upload": "post_content",
        "youtube_subscribe": "follow_user",
        "youtube_share": "share_content",
        "youtube_redirect": "click_external_link",
        "youtube_report": "report_user",
    }
    feature_restriction_map = {
        "view_video": {"threshold": 0.90, "steepness": 5.0},
        "comment": {"threshold": 0.40, "steepness": 10.0},
        "upload_video": {"threshold": 0.55, "steepness": 8.0},
        "live_chat": {"threshold": 0.35, "steepness": 12.0},
        "share_link": {"threshold": 0.35, "steepness": 10.0},
    }

