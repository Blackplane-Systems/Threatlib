"""Composable deployment presets."""

__all__ = ["apply_preset", "list_presets", "load_preset"]


def __getattr__(name):
    if name in __all__:
        from threatlib.presets.loader import apply_preset, list_presets, load_preset

        return {"apply_preset": apply_preset, "list_presets": list_presets, "load_preset": load_preset}[name]
    raise AttributeError(name)
