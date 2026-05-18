"""YAML policy loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
import yaml


class SignalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    weight: float = Field(ge=0.0)
    enabled: bool
    decay_halflife_days: float | None = Field(default=None, ge=0.0)


class FeatureRestriction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threshold: float = Field(ge=0.0, le=1.0)
    steepness: float = Field(gt=0.0)


class ColdStartConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase1_days: int = Field(gt=0)
    phase2_days: int = Field(gt=0)
    min_accounts_for_platform_baseline: int = Field(gt=0)
    published_prior_weight_in_stable: float = Field(ge=0.0, le=1.0)


class ReportingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reports_to_trigger_review: int = Field(gt=0)
    reporter_trust_weighted: bool
    min_reporter_account_age_days: int = Field(ge=0)
    severe_category_immediate_review: list[str]
    severe_category_count: int = Field(gt=0)


class RobustnessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score_jitter_laplace_scale: float = Field(ge=0.0)
    signal_rotation_probability: float = Field(ge=0.0, le=1.0)
    canary_check_interval_hours: int = Field(gt=0)


class TimingConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    keystroke_human_prior: dict[str, Any]
    field_correction_factors: dict[str, float] = Field(default_factory=dict)
    ks_mode: str = "analytical"


class GraphConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: str
    db_path: str
    bfs_max_depth: int = Field(gt=0)
    bfs_weight_k1: float = Field(gt=0.0)
    bfs_weight_k2: float = Field(gt=0.0)
    bfs_weight_k3: float = Field(gt=0.0)


class WebhookConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    high_risk_alert: str
    alert_threshold: float = Field(ge=0.0, le=1.0)
    canary_drift_alert: str


class SurvivalModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    cold_start_weibull_shape: float = Field(gt=0.0)
    cold_start_weibull_scale_hours: float = Field(gt=0.0)


class ConformalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    coverage: float = Field(gt=0.0, lt=1.0)
    min_calibration_set_size: int = Field(gt=0)


class AppealConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    appeal_enabled: bool
    prior_learning_rate: float = Field(ge=0.0, le=1.0)
    false_positive_label_confidence: float = Field(ge=0.0, le=1.0)
    max_appeals_per_account: int = Field(gt=0)


class AttackVectorsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: list[str] = Field(default_factory=lambda: ["ALL"])
    disabled: list[str] = Field(default_factory=list)


class PaymentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    velocity_threshold: int = Field(default=20, ge=0)
    variance_floor: float = Field(default=100.0, ge=0.0)
    new_account_limit: float = Field(default=10000.0, ge=0.0)


class HMMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    states: list[str] = Field(default_factory=lambda: ["benign", "watching", "escalating", "acting"])
    min_events: int = Field(default=5, gt=0)
    cold_start_framework: str = "birdnest"


class ContagionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = "all"
    propagation_depth: int = Field(default=3, gt=0)
    sir_beta: float = Field(default=0.08, ge=0.0)
    sir_gamma: float = Field(default=0.10, gt=0.0)
    ising_coupling_base: float = Field(default=0.05, ge=0.0)
    belief_propagation_max_iter: int = Field(default=50, gt=0)
    belief_propagation_convergence: float = Field(default=0.001, gt=0.0)


class CommunityDetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: str = "leidenalg"
    min_cluster_size: int = Field(default=5, gt=0)
    cluster_creation_window_hours: int = Field(default=24, gt=0)
    spectral_gap_threshold: float = Field(default=0.3, ge=0.0)
    mutual_info_threshold: float = Field(default=0.3, ge=0.0)
    granger_pvalue: float = Field(default=0.05, ge=0.0, le=1.0)


class FederationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    partner_endpoints: list[str] = Field(default_factory=list)
    shared_signal_types: list[str] = Field(default_factory=lambda: ["graph_distance", "registration_velocity"])
    differential_privacy_epsilon: float = Field(default=1.0, gt=0.0)


class NetworkIsolationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    isolation_mode: str = "silent"
    demote_search_results: bool = True
    demote_recommendations: bool = True
    restrict_new_followers: bool = True


class PersistentHomologyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    filtration: str = "vietoris_rips"
    max_dimension: int = Field(default=1, ge=0)


class CanaryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accounts: list[dict[str, Any]] = Field(default_factory=list)
    check_interval_hours: int = Field(default=12, gt=0)
    alert_threshold: float = Field(default=0.50, ge=0.0, le=1.0)


class ThreatIntelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    retention_days: float = Field(default=30.0, ge=1.0, le=90.0)  # REF: Operator requirement - retain hashed abuse data for 20-30 days.
    allowed_remote_feeds: list[str] = Field(default_factory=lambda: ["tor_exit_nodes", "urlhaus_recent"])


class FastDeployConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    observation_hours: float = Field(default=24.0, gt=0.0)  # REF: Day-2 operator workflow - require one day of shadow observation.
    min_scores: int = Field(default=25, ge=0)  # REF: Fast-deploy minimum score volume for low-traffic deployments.
    min_labels: int = Field(default=10, ge=0)  # REF: Fast-deploy minimum confirmed outcomes before action escalation.
    max_false_positive_rate: float = Field(default=0.10, ge=0.0, le=1.0)  # REF: Conservative early false-positive guardrail.
    max_false_negative_rate: float = Field(default=0.35, ge=0.0, le=1.0)  # REF: Early deployment tolerates recall tuning while surfacing misses.
    min_precision: float = Field(default=0.70, ge=0.0, le=1.0)  # REF: Fast-deploy precision guardrail.
    min_recall: float = Field(default=0.60, ge=0.0, le=1.0)  # REF: Fast-deploy recall guardrail.
    active_action_cap: str = "soft_restrict"


class MLModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = True
    architecture: str = "json_logistic_v1"
    feature_map: dict[str, str] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    output_mapping: dict[str, str] = Field(
        default_factory=lambda: {
            "score": "score",
            "label": "label",
            "confidence": "confidence",
            "reason": "reason",
        }
    )
    model_path: str | None = None
    inline_model: dict[str, Any] = Field(default_factory=dict)
    weight: float = Field(default=1.0, ge=0.0)
    confidence: float = Field(default=0.65, ge=0.0, le=1.0)  # REF: Conservative default confidence for externally supplied model outputs.
    required_features: list[str] = Field(default_factory=list)
    tenant_scope: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str
    version: str
    environment: str
    shadow_mode: bool
    domain_mode: str = "generic"
    cold_start: ColdStartConfig
    minimum_detectors_required: int = Field(gt=0)
    signals: dict[str, SignalConfig]
    plugins: list[str] = Field(default_factory=list)
    action_thresholds: dict[str, float]
    feature_restrictions: dict[str, FeatureRestriction]
    topic_gates: list[dict[str, Any]] = Field(default_factory=list)
    reporting: ReportingConfig
    adversarial_robustness: RobustnessConfig
    timing: TimingConfig
    graph: GraphConfig
    suspicious_tlds: list[str]
    url_shortener_list: list[str]
    topic_sensitivity_list: list[str]
    webhooks: WebhookConfig
    survival_model: SurvivalModelConfig
    conformal_prediction: ConformalConfig
    appeal: AppealConfig
    platform_adapter: str = "generic"
    attack_vectors: AttackVectorsConfig = Field(default_factory=AttackVectorsConfig)
    detectors: dict[str, SignalConfig] = Field(default_factory=dict)
    payment: PaymentConfig = Field(default_factory=PaymentConfig)
    high_impact_actions: list[str] = Field(
        default_factory=lambda: [
            "send_dm",
            "create_group",
            "initiate_payment",
            "create_listing",
            "broadcast_message",
            "claim_professional_status",
            "recommend_treatment",
        ]
    )
    giveaway_terms: list[str] = Field(
        default_factory=lambda: [
            "free giveaway",
            "click the link",
            "limited time",
            "winner selected",
            "claim your prize",
            "crypto giveaway",
        ]
    )
    hmm: HMMConfig = Field(default_factory=HMMConfig)
    contagion: ContagionConfig = Field(default_factory=ContagionConfig)
    community_detection: CommunityDetectionConfig = Field(default_factory=CommunityDetectionConfig)
    federation: FederationConfig = Field(default_factory=FederationConfig)
    network_isolation: NetworkIsolationConfig = Field(default_factory=NetworkIsolationConfig)
    persistent_homology: PersistentHomologyConfig = Field(default_factory=PersistentHomologyConfig)
    canary: CanaryConfig = Field(default_factory=CanaryConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    fast_deploy: FastDeployConfig = Field(default_factory=FastDeployConfig)
    ml_models: list[MLModelConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_thresholds(self) -> "Policy":
        for name, threshold in self.action_thresholds.items():
            if threshold < 0.0 or threshold > 1.0:
                raise ValueError(f"action_thresholds.{name} must be in [0, 1]")
        return self

    def signal_config(self, name: str) -> SignalConfig:
        return self.detectors.get(name) or self.signals[name]

    def is_signal_enabled(self, name: str) -> bool:
        config = self.detectors.get(name) or self.signals.get(name)
        if not config:
            return False
        disabled = set(self.attack_vectors.disabled)
        if disabled and detector_attack_vectors(name) & disabled:
            return False
        return config.enabled

    def signal_weight(self, name: str) -> float:
        config = self.detectors.get(name) or self.signals.get(name)
        if not config or not config.enabled:
            return 0.0
        disabled = set(self.attack_vectors.disabled)
        if disabled and detector_attack_vectors(name) & disabled:
            return 0.0
        enabled_vectors = set(self.attack_vectors.enabled)
        if enabled_vectors and "ALL" not in enabled_vectors and not (detector_attack_vectors(name) & enabled_vectors):
            return config.weight * 0.5
        return config.weight

    def signal_halflife(self, name: str) -> float | None:
        config = self.detectors.get(name) or self.signals.get(name)
        return config.decay_halflife_days if config else None

    def graph_db_path(self) -> str:
        return self.graph.db_path

    def jitter_scale(self) -> float:
        return self.adversarial_robustness.score_jitter_laplace_scale


class PolicyEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threatlib: Policy


class PolicyLoader:
    """Load and validate ThreatLib YAML policies."""

    @staticmethod
    def load(path: str | Path) -> Policy:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        return PolicyLoader.from_dict(raw)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> Policy:
        try:
            if "threatlib" in raw:
                return PolicyEnvelope.model_validate(raw).threatlib
            return Policy.model_validate(raw)
        except ValidationError as exc:
            raise ValueError(f"invalid ThreatLib policy: {exc}") from exc


def detector_attack_vectors(name: str) -> set[str]:
    mapping = {
        "email_entropy": {"AV-01", "AV-03"},
        "psycholinguistic": {"AV-01", "AV-03", "AV-11", "AV-13"},
        "device_fingerprint": {"AV-01", "AV-02", "AV-11", "AV-15"},
        "imu_motion": {"AV-01"},
        "behavioral_timing": {"AV-01", "AV-02", "AV-15"},
        "ip_network": {"AV-01", "AV-02", "AV-06", "AV-11", "AV-15"},
        "registration_velocity": {"AV-01", "AV-06", "AV-11"},
        "graph_distance": {"AV-06", "AV-11", "AV-04", "AV-07"},
        "new_account_prior": {"AV-01", "AV-03", "AV-10", "AV-11"},
        "report_history": {"AV-04", "AV-08", "AV-09", "AV-14"},
        "session_anomaly": {"AV-02", "AV-12", "AV-15"},
        "content_signal": {"AV-04", "AV-05", "AV-08", "AV-09", "AV-14"},
        "cross_entropy_coherence": {"AV-03", "AV-11"},
        "account_age_velocity": {"AV-10", "AV-03", "AV-06"},
        "external_link_pattern": {"AV-05", "AV-04", "AV-08", "AV-10"},
        "payment_signal": {"AV-07", "AV-11"},
        "hawkes_burst_v2": {"AV-01", "AV-06", "AV-11"},
        "community_detection": {"AV-06", "AV-11", "AV-01"},
        "cross_signal_coherence_v2": {"AV-03", "AV-11", "AV-12"},
        "survival_analysis": {"AV-02", "AV-04", "AV-12"},
        "hmm_intent": {"AV-04", "AV-09", "AV-12", "AV-13", "AV-14"},
        "sir_contagion": {"AV-06", "AV-11", "AV-08"},
        "coordinated_behavior": {"AV-06", "AV-05", "AV-08", "AV-09", "AV-11"},
        "ml_model": {
            "AV-01",
            "AV-02",
            "AV-03",
            "AV-04",
            "AV-05",
            "AV-06",
            "AV-07",
            "AV-08",
            "AV-09",
            "AV-10",
            "AV-11",
            "AV-12",
            "AV-13",
            "AV-14",
            "AV-15",
        },
    }
    return mapping.get(name, set())
