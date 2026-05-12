"""Payment-first adapter."""

from threatlib.adapters.base import BaseAdapter


class PaymentAdapter(BaseAdapter):
    platform_name = "payment"
    available_signals = ["account_id", "device_hash", "ip_prefix", "metadata"]
    relevant_attack_vectors = ["AV-02", "AV-07", "AV-11", "AV-12", "AV-15"]
    event_map = {
        "gpay_initiate_transfer": "initiate_payment",
        "send_payment": "initiate_payment",
        "receive_payment": "platform_custom",
        "request_money": "platform_custom",
        "qr_create": "platform_custom",
        "add_payee": "add_contact",
        "payment_report": "report_user",
    }
    feature_restriction_map = {
        "view_balance": {"threshold": 0.90, "steepness": 5.0},
        "receive_payment": {"threshold": 0.65, "steepness": 7.0},
        "request_money": {"threshold": 0.40, "steepness": 10.0},
        "send_payment_small": {"threshold": 0.50, "steepness": 8.0},
        "send_payment_large": {"threshold": 0.35, "steepness": 12.0},
        "add_payee": {"threshold": 0.30, "steepness": 12.0},
        "create_qr": {"threshold": 0.40, "steepness": 10.0},
        "withdraw_bank": {"threshold": 0.25, "steepness": 15.0},
        "send_to_new_contact": {"threshold": 0.35, "steepness": 12.0},
    }

