"""X/Twitter-like adapter."""

from threatlib.adapters.social_network import SocialNetworkAdapter


class TwitterXAdapter(SocialNetworkAdapter):
    platform_name = "twitter_x"
    event_map = {
        **SocialNetworkAdapter.event_map,
        "tweet_create": "post_content",
        "retweet": "share_content",
        "quote_tweet": "share_content",
        "x_dm_send": "send_dm",
        "x_follow": "follow_user",
        "x_link_click": "click_external_link",
    }

