"""Deterministic event replay and policy simulation."""

__all__ = ["ReplayEngine", "load_replay_file"]


def __getattr__(name):
    if name in __all__:
        from threatlib.replay.engine import ReplayEngine, load_replay_file

        return {"ReplayEngine": ReplayEngine, "load_replay_file": load_replay_file}[name]
    raise AttributeError(name)
