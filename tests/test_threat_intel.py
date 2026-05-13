from __future__ import annotations

import json

import pytest

from threatlib.intel.feeds import FeedValidationError, SafeFeedClient, ThreatIntelIngestor
from threatlib.signals.external_link_pattern import ExternalLinkPatternDetector


def _dump_table(graph, table: str) -> str:
    rows = graph.conn.execute(f"SELECT * FROM {table}").fetchall()
    return json.dumps([dict(row) for row in rows], sort_keys=True)


def test_safe_feed_client_rejects_unallowlisted_feed():
    client = SafeFeedClient()
    with pytest.raises(FeedValidationError):
        client.fetch("https://malware.example/payload.exe")


def test_tor_feed_is_hashed_and_expires(graph):
    ingestor = ThreatIntelIngestor(graph, retention_days=30.0)
    result = ingestor.ingest_tor_exit_list("171.25.193.25\nnot-an-ip\n")

    assert result.rows_seen == 2
    assert result.rows_stored == 1
    assert result.rejected_rows == 1
    assert graph.threat_indicator_exists("tor_exit_ip", "171.25.193.25")
    assert graph.threat_indicator_exists("tor_exit_ip_prefix", "171.25.193")

    stored = _dump_table(graph, "threat_indicators")
    assert "171.25.193.25" not in stored
    assert "171.25.193" not in stored

    deleted = graph.prune_expired_intel(timestamp=10**12)
    assert deleted >= 2
    assert graph.threat_indicator_count() == 0


def test_urlhaus_csv_is_parsed_as_inert_indicators(graph, policy):
    body = """################################################################
# abuse.ch URLhaus Database Dump
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-05-13 08:25:10","http://bad.example/bin.sh","online","2026-05-13 08:25:10","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/1/","tester"
"""
    result = ThreatIntelIngestor(graph).ingest_urlhaus_recent(body)

    assert result.rows_seen == 1
    assert result.rows_stored == 1
    assert graph.threat_indicator_exists("urlhaus_host", "bad.example")
    assert graph.threat_indicator_exists("urlhaus_url", "http://bad.example/bin.sh")

    stored_indicators = _dump_table(graph, "threat_indicators")
    stored_imports = _dump_table(graph, "dataset_imports")
    assert "http://bad.example/bin.sh" not in stored_indicators
    assert "bad.example" not in stored_indicators
    assert "http://bad.example/bin.sh" not in stored_imports

    graph.record_event("acct", "send_dm", {"has_link": True, "link_domain": "bad.example"})
    detector_result = ExternalLinkPatternDetector(policy=policy, graph=graph).score({"account_id": "acct"})
    assert detector_result.fraud_mass > 0.5


def test_local_training_datasets_store_features_not_plaintext(tmp_path, graph):
    tranco = tmp_path / "top-1m.csv"
    tranco.write_text("1,google.com\n2,example.org\nbad,row\n", encoding="utf-8")
    sms = tmp_path / "SMSSpamCollection"
    sms.write_text(
        "ham\tSee you at lunch\nspam\tURGENT claim your free prize now! http://bad.example\n",
        encoding="utf-8",
    )
    facebook = tmp_path / "facebook_combined.txt"
    facebook.write_text("1 2\n2 3\n3 1\n", encoding="utf-8")

    ingestor = ThreatIntelIngestor(graph)
    assert ingestor.ingest_tranco_csv(tranco).rows_stored == 2
    assert ingestor.ingest_sms_spam_collection(sms).rows_stored == 2
    assert ingestor.ingest_snap_facebook_graph(facebook).rows_stored == 1

    stored_features = _dump_table(graph, "training_feature_rows")
    assert "google.com" not in stored_features
    assert "See you at lunch" not in stored_features
    assert "bad.example" not in stored_features
    assert "URGENT claim your free prize" not in stored_features
    assert graph.training_feature_count() == 5
