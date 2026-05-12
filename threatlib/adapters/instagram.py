"""Instagram-like adapter."""

from threatlib.adapters.social_network import SocialNetworkAdapter


class InstagramAdapter(SocialNetworkAdapter):
    platform_name = "instagram"
    event_map = {
        **SocialNetworkAdapter.event_map,
        "instagram_story_view": "view_story",
        "instagram_reel_view": "view_content",
        "instagram_dm_send": "send_dm",
        "instagram_story_link_click": "click_external_link",
        "instagram_follow": "follow_user",
    }
    field_map = {
        **SocialNetworkAdapter.field_map,
        "instagram_username": "username_raw",
        "instagram_display_name": "display_name_raw",
    }

