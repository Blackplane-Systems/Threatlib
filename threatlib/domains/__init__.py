"""Domain mode profiles for product-specific ThreatLib deployments."""

from __future__ import annotations

from typing import Any


def apply_domain_mode(*args: Any, **kwargs: Any) -> Any:
    from threatlib.domains.profiles import apply_domain_mode as inner

    return inner(*args, **kwargs)


def domain_calibration_plan(*args: Any, **kwargs: Any) -> Any:
    from threatlib.domains.profiles import domain_calibration_plan as inner

    return inner(*args, **kwargs)


def domain_policy_preview(*args: Any, **kwargs: Any) -> Any:
    from threatlib.domains.profiles import domain_policy_preview as inner

    return inner(*args, **kwargs)


def get_domain_profile(*args: Any, **kwargs: Any) -> Any:
    from threatlib.domains.profiles import get_domain_profile as inner

    return inner(*args, **kwargs)


def list_domain_modes(*args: Any, **kwargs: Any) -> Any:
    from threatlib.domains.profiles import list_domain_modes as inner

    return inner(*args, **kwargs)
