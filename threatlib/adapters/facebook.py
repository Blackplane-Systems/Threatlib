"""Facebook-like adapter."""

from threatlib.adapters.social_network import SocialNetworkAdapter


class FacebookAdapter(SocialNetworkAdapter):
    platform_name = "facebook"
    event_map = {
        **SocialNetworkAdapter.event_map,
        "facebook_group_join": "join_group",
        "facebook_group_create": "create_group",
        "facebook_marketplace_listing": "create_listing",
        "facebook_message_send": "send_dm",
        "facebook_share": "share_content",
    }

