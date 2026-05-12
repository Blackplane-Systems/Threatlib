from __future__ import annotations

from threatlib.adapters import AdapterRegistry
from threatlib.adapters.base import UNIVERSAL_EVENT_TYPES


EVENTS = {
    "social_network": ["profile_view", "search", "follow", "dm_send", "post"],
    "instagram": ["instagram_story_view", "instagram_reel_view", "instagram_dm_send", "instagram_story_link_click", "instagram_follow"],
    "facebook": ["facebook_group_join", "facebook_group_create", "facebook_marketplace_listing", "facebook_message_send", "facebook_share"],
    "twitter_x": ["tweet_create", "retweet", "quote_tweet", "x_dm_send", "x_follow"],
    "whatsapp": ["whatsapp_send_message", "whatsapp_forward_message", "whatsapp_create_group", "whatsapp_add_to_group", "whatsapp_link_click"],
    "youtube": ["youtube_view", "youtube_comment", "youtube_upload", "youtube_subscribe", "youtube_redirect"],
    "payment": ["gpay_initiate_transfer", "send_payment", "receive_payment", "request_money", "add_payee"],
    "health": ["log_symptom", "join_community", "post_community", "message_member", "share_health_data"],
    "marketplace": ["create_listing", "contact_seller", "payment_request", "marketplace_link_click", "marketplace_report"],
    "generic": ["unknown_a", "unknown_b", "unknown_c", "unknown_d", "unknown_e"],
}


def test_adapter_registry_names():
    assert set(EVENTS).issubset(set(AdapterRegistry.names()))


def test_each_adapter_translates_five_events_without_data_loss():
    for name, events in EVENTS.items():
        adapter = AdapterRegistry.get(name)
        for event_type in events:
            translated, data = adapter.translate_event(event_type, {"amount": 10, "link_domain": "example.test"})
            assert translated in UNIVERSAL_EVENT_TYPES
            assert data["amount"] == 10
            assert data["link_domain"] == "example.test"
            assert data["platform_event_type"] == event_type

