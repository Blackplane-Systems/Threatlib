"""Marketplace adapter."""

from threatlib.adapters.base import BaseAdapter


class MarketplaceAdapter(BaseAdapter):
    platform_name = "marketplace"
    available_signals = ["account_id", "device_hash", "ip_prefix", "metadata"]
    relevant_attack_vectors = ["AV-01", "AV-04", "AV-05", "AV-10", "AV-11"]
    event_map = {
        "create_listing": "create_listing",
        "contact_seller": "send_dm",
        "payment_request": "initiate_payment",
        "marketplace_link_click": "click_external_link",
        "marketplace_report": "report_user",
    }
    feature_restriction_map = {
        "view_listing": {"threshold": 0.90, "steepness": 5.0},
        "create_listing": {"threshold": 0.35, "steepness": 10.0},
        "contact_seller": {"threshold": 0.30, "steepness": 12.0},
        "external_payment_link": {"threshold": 0.20, "steepness": 15.0},
        "payment_request": {"threshold": 0.40, "steepness": 10.0},
    }

