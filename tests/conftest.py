from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlib.config.policy import PolicyLoader
from threatlib.graph.account_graph import AccountGraph


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def policy():
    loaded = PolicyLoader.load(ROOT / "threatlib.yaml").model_copy(deep=True)
    loaded.graph.db_path = ":memory:"
    return loaded


@pytest.fixture()
def active_policy(policy):
    policy.shadow_mode = False
    policy.environment = "staging"
    return policy


@pytest.fixture()
def graph():
    store = AccountGraph(":memory:")
    yield store
    store.close()


def load_fixture(name: str) -> dict:
    with (ROOT / "tests" / "fixtures" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture()
def bot_fixture():
    return load_fixture("synthetic_bot.json")


@pytest.fixture()
def human_fixture():
    return load_fixture("synthetic_human.json")


@pytest.fixture()
def ato_fixture():
    return load_fixture("synthetic_ato.json")

