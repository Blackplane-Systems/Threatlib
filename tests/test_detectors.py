from __future__ import annotations

import time

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.behavioral_timing import BehavioralTimingDetector, ks_test_vs_baseline
from threatlib.signals.content_signal import ContentSignalDetector
from threatlib.signals.device_fingerprint import DeviceFingerprintDetector
from threatlib.signals.email_entropy import EmailEntropyDetector
from threatlib.signals.graph_distance import GraphDistanceDetector
from threatlib.signals.imu_motion import IMUMotionDetector
from threatlib.signals.ip_network import IPNetworkDetector
from threatlib.signals.new_account_prior import NewAccountPriorDetector
from threatlib.signals.psycholinguistic import PsycholinguisticDetector, compute_entropy
from threatlib.signals.registration_velocity import RegistrationVelocityDetector
from threatlib.signals.report_history import ReportHistoryDetector
from threatlib.signals.session_anomaly import SessionAnomalyDetector


DETECTORS = [
    EmailEntropyDetector,
    PsycholinguisticDetector,
    DeviceFingerprintDetector,
    IMUMotionDetector,
    BehavioralTimingDetector,
    IPNetworkDetector,
    RegistrationVelocityDetector,
    GraphDistanceDetector,
    NewAccountPriorDetector,
    ReportHistoryDetector,
    SessionAnomalyDetector,
    ContentSignalDetector,
]


def test_absent_data_returns_uncertain(policy, graph):
    for detector_cls in DETECTORS:
        result = detector_cls(policy=policy, graph=graph).safe_score({})
        assert result.is_uncertain(), detector_cls.__name__


def test_direct_bot_detectors_emit_fraud(policy, graph, bot_fixture):
    graph.upsert_account(bot_fixture)
    detector_classes = [
        EmailEntropyDetector,
        PsycholinguisticDetector,
        DeviceFingerprintDetector,
        IMUMotionDetector,
        BehavioralTimingDetector,
        IPNetworkDetector,
        ContentSignalDetector,
    ]
    for detector_cls in detector_classes:
        result = detector_cls(policy=policy, graph=graph).safe_score(bot_fixture)
        assert result.fraud_mass > 0.5, (detector_cls.__name__, result)


def test_human_detectors_legitimate_or_uncertain(policy, graph, human_fixture):
    old = time.time() - 9 * ONE_DAY_SECONDS
    graph.upsert_account(human_fixture, created_at=old)
    for index in range(5):
        graph.record_event(human_fixture["account_id"], "view_profile", {"count": index}, timestamp=old + index)
    for detector_cls in DETECTORS:
        result = detector_cls(policy=policy, graph=graph).safe_score(human_fixture)
        assert result.legitimate_mass > 0.3 or result.is_uncertain(), (detector_cls.__name__, result)


def test_velocity_graph_report_and_session_bot_cases(policy, graph, bot_fixture, ato_fixture):
    now = time.time()
    for index in range(5):
        graph.upsert_account(
            {
                "account_id": f"burst_{index}",
                "ip_prefix": bot_fixture["ip_prefix"],
                "device_model": bot_fixture["device_model"],
            },
            created_at=now - 60,
        )
    assert RegistrationVelocityDetector(policy=policy, graph=graph).safe_score(bot_fixture).fraud_mass > 0.5

    graph.set_account_status("harmful_anchor_hash", "auto_banned", human_review_confirmed=True)
    assert GraphDistanceDetector(policy=policy, graph=graph).safe_score(bot_fixture).fraud_mass > 0.5

    for index in range(4):
        graph.add_report(bot_fixture["account_id"], f"reporter_{index}", "scam", 0.95, created_at=now - index)
    assert ReportHistoryDetector(policy=policy, graph=graph).safe_score(bot_fixture).fraud_mass > 0.5

    graph.record_session(
        account_id=ato_fixture["account_id"],
        session_id="old",
        device_hash="known_device",
        ip_prefix="203.0.113",
        ip_geo_country="US",
        device_timezone="America/New_York",
        created_at=now - 1800,
    )
    assert SessionAnomalyDetector(policy=policy, graph=graph).safe_score(ato_fixture).fraud_mass > 0.5


def test_new_account_prior(policy, graph, bot_fixture):
    result = NewAccountPriorDetector(policy=policy, graph=graph).safe_score(bot_fixture)
    assert result.fraud_mass == 0.15
    assert result.uncertainty_mass == 0.85


def test_username_entropy_values():
    assert compute_entropy("aaaaaaaa") == 0.0
    assert compute_entropy("abcd") == 2.0


def test_timing_ks_rejects_uniform():
    _, pvalue = ks_test_vs_baseline([10, 10, 10, 10, 10, 10, 10], {"shape": 1.5, "scale_ms": 180})
    assert pvalue < 0.05

