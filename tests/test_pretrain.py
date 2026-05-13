from __future__ import annotations

import json
from pathlib import Path

from threatlib.models import load_base_model
from threatlib.pretrain.base_model import train_base_model


def test_base_model_training_uses_derived_features_only(tmp_path):
    tranco = tmp_path / "top-1m.csv"
    tranco.write_text("1,google.com\n2,example.org\n1001,known.net\n", encoding="utf-8")

    facebook = tmp_path / "facebook_combined.txt"
    facebook.write_text("1 2\n2 3\n3 1\n3 4\n", encoding="utf-8")

    sms_dir = tmp_path / "sms+spam+collection"
    sms_dir.mkdir()
    sms = sms_dir / "SMSSpamCollection"
    sms.write_text(
        "\n".join(
            [
                "ham\tSee you at lunch",
                "ham\tProject meeting is at five",
                "ham\tPlease call when free",
                "ham\tCan you review the notes",
                "spam\tURGENT claim your free prize now! http://bad.example",
                "spam\tWinner selected call now to claim reward",
                "spam\tFree entry text WIN to 80000",
                "spam\tClaim bonus prize today!!!",
            ]
        ),
        encoding="utf-8",
    )

    output = tmp_path / "base_model.json"
    model = train_base_model(tranco, facebook, sms_dir, output)
    stored = output.read_text(encoding="utf-8")

    assert model["contains_raw_training_data"] is False
    assert model["sms_spam_numeric_logistic"]["rows_used"] == 8
    assert model["graph_structure_baseline"]["edge_count"] == 4
    assert model["domain_rank_baseline"]["rows_used"] == 3
    assert "coefficients" in model["sms_spam_numeric_logistic"]
    assert json.loads(stored)["privacy"]["stores_raw_sms"] is False

    assert "See you at lunch" not in stored
    assert "bad.example" not in stored
    assert "google.com" not in stored
    assert "1 2" not in stored


def test_committed_base_model_is_compact_and_sanitized():
    model_path = Path(__file__).resolve().parents[1] / "threatlib" / "models" / "base_model.json"
    assert model_path.exists()
    assert model_path.stat().st_size < 100_000

    model = load_base_model(model_path)
    stored = model_path.read_text(encoding="utf-8")

    assert model["contains_raw_training_data"] is False
    assert model["domain_rank_baseline"]["rows_used"] == 1_000_000
    assert model["graph_structure_baseline"]["edge_count"] == 88_234
    assert model["sms_spam_numeric_logistic"]["rows_used"] == 5_574
    assert model["sms_spam_numeric_logistic"]["holdout_metrics"]["roc_auc"] > 0.95

    forbidden_fragments = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "http://",
        "https://",
        "FreeMsg",
        "URGENT",
    ]
    for fragment in forbidden_fragments:
        assert fragment not in stored
