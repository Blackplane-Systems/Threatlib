"""Risk synthesis pipeline."""

from __future__ import annotations

import math
import random
from typing import Any

from threatlib.action.feature_restrictor import check_emergency_bypass, compute_restrictions
from threatlib.audit.log import AuditLogger
from threatlib.fusion.dempster_shafer import (
    apply_temporal_decay,
    apply_weight,
    combine_many,
    non_trivial_count,
)
from threatlib.graph.account_graph import AccountGraph
from threatlib.policy.versioning import policy_hash
from threatlib.risk.conformal import ConformalPredictor
from threatlib.risk.feedback import apply_fast_deploy_action_policy
from threatlib.signals.base import DetectorResult
from threatlib.signals.behavioral_timing import BehavioralTimingDetector
from threatlib.signals.content_signal import ContentSignalDetector
from threatlib.signals.device_fingerprint import DeviceFingerprintDetector
from threatlib.signals.email_entropy import EmailEntropyDetector
from threatlib.signals.graph_distance import GraphDistanceDetector
from threatlib.signals.imu_motion import IMUMotionDetector
from threatlib.signals.ip_network import IPNetworkDetector
from threatlib.signals.new_account_prior import NewAccountPriorDetector
from threatlib.signals.psycholinguistic import PsycholinguisticDetector
from threatlib.signals.registration_velocity import RegistrationVelocityDetector
from threatlib.signals.report_history import ReportHistoryDetector
from threatlib.signals.session_anomaly import SessionAnomalyDetector


DETECTOR_CLASSES = {
    "email_entropy": EmailEntropyDetector,
    "psycholinguistic": PsycholinguisticDetector,
    "device_fingerprint": DeviceFingerprintDetector,
    "imu_motion": IMUMotionDetector,
    "behavioral_timing": BehavioralTimingDetector,
    "ip_network": IPNetworkDetector,
    "registration_velocity": RegistrationVelocityDetector,
    "graph_distance": GraphDistanceDetector,
    "new_account_prior": NewAccountPriorDetector,
    "report_history": ReportHistoryDetector,
    "session_anomaly": SessionAnomalyDetector,
    "content_signal": ContentSignalDetector,
}


ACTION_ORDER = [
    "auto_ban",
    "suspend",
    "hard_restrict",
    "soft_restrict",
    "review_queue",
    "audience_narrow",
    "velocity_throttle",
    "monitor",
]


class RiskSynthesizer:
    def __init__(
        self,
        policy: Any,
        graph: AccountGraph | None = None,
        rng: random.Random | None = None,
        conformal: ConformalPredictor | None = None,
    ) -> None:
        self.policy = policy
        self.graph = graph or AccountGraph(policy.graph_db_path())
        self.rng = rng or random.Random()
        self.audit = AuditLogger(self.graph)
        self.conformal = conformal or ConformalPredictor(
            policy.conformal_prediction.min_calibration_set_size,
            policy.conformal_prediction.coverage,
        )

    def run_all_detectors(self, account_data: dict[str, Any]) -> dict[str, DetectorResult]:
        from threatlib.signals.orchestrator import DetectorOrchestrator

        return DetectorOrchestrator(self.policy, self.graph).run(account_data)

    def apply_decay_and_weights(self, results: dict[str, DetectorResult]) -> dict[str, DetectorResult]:
        adjusted: dict[str, DetectorResult] = {}
        for name, result in results.items():
            decayed = apply_temporal_decay(result, self.policy.signal_halflife(name), result.age_days)
            adjusted[name] = apply_weight(decayed, self.policy.signal_weight(name))
        return adjusted

    def check_quorum(self, results: dict[str, DetectorResult], min_required: int | None = None) -> bool:
        required = min_required if min_required is not None else self.policy.minimum_detectors_required
        return non_trivial_count(results.values()) >= required

    def score(self, account_data: dict[str, Any]) -> dict[str, Any]:
        if "account_id" not in account_data or not account_data["account_id"]:
            raise ValueError("account_id is required")
        self.graph.upsert_account(account_data)
        emergency_action = check_emergency_bypass(self.graph.reports_for_account(account_data["account_id"], 0.0))
        raw_results = self.run_all_detectors(account_data)
        adjusted_results = self.apply_decay_and_weights(raw_results)
        direct_signal_fields = set(account_data) - {"account_id", "_detector_results"}
        has_quorum = self.check_quorum(adjusted_results) and bool(direct_signal_fields)
        combined = combine_many(adjusted_results.values())
        risk_score, ds_low, ds_high = compute_risk_score(combined)
        band_low, band_high, band_source = self.conformal.band_or_ds(risk_score, ds_low, ds_high)
        jittered_score = apply_jitter(risk_score, self.policy.jitter_scale(), self.rng)
        restrictions = compute_restrictions(jittered_score, self.policy)
        threat_tier = "scored" if has_quorum else "insufficient_evidence"
        coordinated = adjusted_results.get("coordinated_behavior")
        if coordinated and coordinated.fraud_mass > 0.5:
            threat_tier = "tier_3_cluster"
        action = compute_action(jittered_score, self.policy) if has_quorum else "monitor"
        action = apply_fast_deploy_action_policy(action, self.policy, self.graph)
        if emergency_action:
            action = emergency_action
            threat_tier = "emergency_escalation"
        if self.policy.shadow_mode:
            action = "monitor"
            restrictions = {feature: 0.0 for feature in restrictions}
        explainability = build_explainability(
            adjusted_results,
            combined,
            has_quorum,
            action,
            threat_tier,
            self.policy,
        )
        audit_id = self.audit.log_score(
            account_id=account_data["account_id"],
            detector_results=adjusted_results,
            final_score=risk_score,
            action=action,
            threat_tier=threat_tier,
            restrictions=restrictions,
        )
        return {
            "account_id": account_data["account_id"],
            "risk_score": risk_score,
            "risk_score_jittered": jittered_score,
            "confidence_band": {"low": band_low, "high": band_high, "source": band_source},
            "action": action,
            "threat_tier": threat_tier,
            "restrictions": restrictions,
            "detectors": {name: result.to_dict() for name, result in adjusted_results.items()},
            "combined": combined.to_dict(),
            "quorum": {
                "met": has_quorum,
                "non_trivial_detectors": non_trivial_count(adjusted_results.values()),
                "minimum_required": self.policy.minimum_detectors_required,
            },
            "explainability": explainability,
            "audit_id": audit_id,
            "shadow_mode": self.policy.shadow_mode,
        }


def run_all_detectors(account_data: dict[str, Any], policy: Any, graph: AccountGraph | None = None) -> dict[str, DetectorResult]:
    return RiskSynthesizer(policy, graph=graph).run_all_detectors(account_data)


def apply_decay_and_weights(results: dict[str, DetectorResult], policy: Any) -> dict[str, DetectorResult]:
    graph = AccountGraph(":memory:")
    return RiskSynthesizer(policy, graph=graph).apply_decay_and_weights(results)


def check_quorum(results: dict[str, DetectorResult], min_required: int) -> bool:
    return non_trivial_count(results.values()) >= min_required


def compute_risk_score(combined_result: DetectorResult) -> tuple[float, float, float]:
    denominator = combined_result.fraud_mass + combined_result.legitimate_mass
    if denominator == 0.0:
        risk = 0.5  # REF: Section E.2 - maximum uncertainty equal prior.
    else:
        risk = combined_result.fraud_mass / denominator
    return risk, combined_result.fraud_mass, combined_result.fraud_mass + combined_result.uncertainty_mass


def compute_action(risk_score: float, policy: Any) -> str:
    if policy.shadow_mode:
        return "monitor"
    for action in ACTION_ORDER:
        threshold = policy.action_thresholds[action]
        if risk_score >= threshold:
            return action
    return "monitor"


def apply_jitter(risk_score: float, scale: float = 0.01, rng: random.Random | None = None) -> float:
    if scale <= 0:
        return max(0.0, min(1.0, risk_score))
    generator = rng or random.Random()
    u = generator.random() - 0.5
    noise = -scale * math.copysign(math.log(1.0 - 2.0 * abs(u)), u)
    return max(0.0, min(1.0, risk_score + noise))


def score_account(account_data: dict[str, Any], policy: Any, graph: AccountGraph | None = None) -> dict[str, Any]:
    return RiskSynthesizer(policy, graph=graph).score(account_data)


def build_explainability(
    results: dict[str, DetectorResult],
    combined: DetectorResult,
    quorum_met: bool,
    action: str,
    threat_tier: str,
    policy: Any,
) -> dict[str, Any]:
    """Create a structured, non-PII explanation for score consumers."""

    detector_rows = []
    missing_inputs: dict[str, list[str]] = {}
    for name, result in results.items():
        detector_rows.append(
            {
                "detector": name,
                "fraud_mass": result.fraud_mass,
                "legitimate_mass": result.legitimate_mass,
                "uncertainty_mass": result.uncertainty_mass,
                "reason": result.reason,
            }
        )
        missing = result.metadata.get("missing_fields") if isinstance(result.metadata, dict) else None
        if missing:
            missing_inputs[name] = list(missing)
    top_fraud = sorted(detector_rows, key=lambda item: item["fraud_mass"], reverse=True)[:5]
    top_legitimate = sorted(detector_rows, key=lambda item: item["legitimate_mass"], reverse=True)[:5]
    uncertainty = sorted(detector_rows, key=lambda item: item["uncertainty_mass"], reverse=True)[:5]
    conflict = [
        item
        for item in sorted(detector_rows, key=lambda row: min(row["fraud_mass"], row["legitimate_mass"]), reverse=True)
        if item["fraud_mass"] > 0.0 or item["legitimate_mass"] > 0.0
    ][:5]
    return {
        "top_fraud_contributors": top_fraud,
        "top_legitimate_contributors": top_legitimate,
        "uncertainty_contributors": uncertainty,
        "missing_required_inputs": missing_inputs,
        "detector_conflicts": conflict,
        "combined_conflict_k": combined.conflict_k,
        "combination_rule": combined.combination_rule,
        "quorum": {
            "met": quorum_met,
            "non_trivial_detectors": non_trivial_count(results.values()),
            "minimum_required": policy.minimum_detectors_required,
        },
        "action_reason": _action_reason(action, threat_tier, quorum_met, policy),
        "policy": {
            "version": policy.version,
            "environment": policy.environment,
            "shadow_mode": policy.shadow_mode,
            "policy_hash": policy_hash(policy),
        },
    }


def _action_reason(action: str, threat_tier: str, quorum_met: bool, policy: Any) -> str:
    if policy.shadow_mode:
        return "shadow_mode_forces_monitor"
    if threat_tier == "emergency_escalation":
        return "emergency_bypass"
    if not quorum_met:
        return "insufficient_evidence_quorum_not_met"
    return f"threshold_action:{action}"
