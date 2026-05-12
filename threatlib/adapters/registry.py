"""Adapter registry."""

from __future__ import annotations

from threatlib.adapters.base import BaseAdapter
from threatlib.adapters.facebook import FacebookAdapter
from threatlib.adapters.generic import GenericAdapter
from threatlib.adapters.health import HealthAdapter
from threatlib.adapters.instagram import InstagramAdapter
from threatlib.adapters.marketplace import MarketplaceAdapter
from threatlib.adapters.payment import PaymentAdapter
from threatlib.adapters.social_network import SocialNetworkAdapter
from threatlib.adapters.twitter_x import TwitterXAdapter
from threatlib.adapters.whatsapp import WhatsAppAdapter
from threatlib.adapters.youtube import YouTubeAdapter


class AdapterRegistry:
    _adapters: dict[str, type[BaseAdapter]] = {
        "generic": GenericAdapter,
        "social_network": SocialNetworkAdapter,
        "instagram": InstagramAdapter,
        "facebook": FacebookAdapter,
        "twitter_x": TwitterXAdapter,
        "whatsapp": WhatsAppAdapter,
        "youtube": YouTubeAdapter,
        "payment": PaymentAdapter,
        "health": HealthAdapter,
        "marketplace": MarketplaceAdapter,
    }

    @classmethod
    def register(cls, adapter_cls: type[BaseAdapter]) -> None:
        cls._adapters[adapter_cls.platform_name] = adapter_cls

    @classmethod
    def get(cls, name: str) -> BaseAdapter:
        return cls._adapters.get(name, GenericAdapter)()

    @classmethod
    def from_policy(cls, policy: object) -> BaseAdapter:
        return cls.get(getattr(policy, "platform_adapter", "generic"))

    @classmethod
    def names(cls) -> list[str]:
        return sorted(cls._adapters)
