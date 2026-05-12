# ThreatLib v1.0 — Core Formula and Logic Index
# Purpose: Cross-reference every formula to its implementation for verification.

## How to use this file
Find the formula name. Go to the file and function listed. Run the test listed to verify.

---

## 1. Dempster-Shafer Mass Function Conversion
Formula: m({fraud}) = (LR-1)/(LR+1) * confidence when LR > 1; m({legitimate}) = (1-LR)/(1+LR) * confidence when LR < 1
File: threatlib/signals/base.py
Function: DetectorResult.from_likelihood_ratio(lr, confidence)
Test: tests/test_contracts.py::test_from_likelihood_ratio_contract

## 2. Dempster Combination Rule
Formula: m12(A) = 1/(1-K) * sum of m1(B) * m2(C) where B intersection C = A
File: threatlib/fusion/dempster_shafer.py
Function: combine(m1, m2) -> DetectorResult
Test: tests/test_dempster_shafer.py::test_combine_two_mass_functions

## 3. Conflict Measure K
Formula: K = m1({fraud}) * m2({legitimate}) + m1({legitimate}) * m2({fraud})
File: threatlib/fusion/dempster_shafer.py
Function: _compute_conflict(m1, m2) -> float
Test: tests/test_dempster_shafer.py::test_high_conflict_murphy_fallback

## 4. Murphy Averaging Fallback
Formula: m_avg(A) = (1/N) * sum_d m_d(A), then combine m_avg with itself N times
File: threatlib/fusion/dempster_shafer.py
Function: _murphy_average(results, conflict_k)
Test: tests/test_dempster_shafer.py::test_high_conflict_murphy_fallback

## 5. Quorum Check
Formula: non-trivial detector count = count(fraud_mass + legitimate_mass > 0.05)
File: threatlib/fusion/dempster_shafer.py
Function: non_trivial_count(results) -> int
Test: tests/test_risk_synthesis.py::test_quorum_function

## 6. Composite Risk Score
Formula: r = m_combined({fraud}) / (m_combined({fraud}) + m_combined({legitimate}))
File: threatlib/risk/synthesis.py
Function: compute_risk_score(combined_result) -> tuple[float, float, float]
Test: tests/test_risk_synthesis.py::test_risk_score_range

## 7. Feature Restriction Formula
Formula: restriction(feature, r) = sigma(steepness_f * (r - threshold_f))
File: threatlib/action/feature_restrictor.py
Function: compute_restriction(feature, risk_score, policy) -> float
Test: tests/test_action_engine.py::test_feature_restriction_logistic

## 8. Score Jitter
Formula: r_jittered = clip(r + Laplace(0, scale), 0, 1)
File: threatlib/risk/synthesis.py
Function: apply_jitter(risk_score, scale, rng) -> float
Test: tests/test_risk_synthesis.py::test_jitter_range

## 9. Temporal Decay
Formula: m_eff = m_orig * exp(-ln(2) / halflife_days * age_days)
File: threatlib/fusion/dempster_shafer.py
Function: apply_temporal_decay(result, halflife_days, age_days) -> DetectorResult
Test: tests/test_dempster_shafer.py::test_temporal_decay_halves_at_halflife

## 10. Signal Weight Transform
Formula: m_weighted = tanh(weight * atanh(m_orig))
File: threatlib/fusion/dempster_shafer.py
Function: apply_weight(result, weight) -> DetectorResult
Test: tests/test_dempster_shafer.py::test_weight_zero_produces_uncertain

## 11. Shannon Entropy
Formula: H = -sum p(c) * log2(p(c))
File: threatlib/signals/common.py
Function: shannon_entropy(value) -> float
Test: tests/test_detectors.py::test_username_entropy_values

## 12. Bigram Transition Entropy
Formula: H(c2|c1) averaged over observed previous-character buckets
File: threatlib/signals/common.py
Function: bigram_transition_entropy(value) -> float
Test: tests/test_detectors.py::test_human_detectors_legitimate_or_uncertain

## 13. Levenshtein Distance
Formula: dynamic-programming edit distance over username pattern features
File: threatlib/signals/common.py
Function: levenshtein(left, right) -> int
Test: tests/test_detectors.py::test_direct_bot_detectors_emit_fraud

## 14. KS Test for Behavioral Timing
Formula: D = sup_x |F_empirical(x) - F_weibull(x)|
File: threatlib/signals/behavioral_timing.py
Function: ks_test_vs_baseline(intervals, baseline_params) -> tuple[float, float]
Test: tests/test_detectors.py::test_timing_ks_rejects_uniform

## 15. Weibull Baseline CDF
Formula: F(x) = 1 - exp(-(x / scale)^shape)
File: threatlib/signals/behavioral_timing.py
Function: weibull_cdf(x, shape, scale) -> float
Test: tests/test_detectors.py::test_timing_ks_rejects_uniform

## 16. Cold Start Blended Prior
Formula: theta_blend = (1-w) * theta_published + w * theta_platform, w = min(1, n_accounts / n_threshold)
File: threatlib/cold_start/priors.py
Function: blend_prior(published, platform, n_accounts, n_threshold) -> float
Test: tests/test_risk_synthesis.py::test_cold_start_blending

## 17. Conformal Prediction Band
Formula: q = quantile at level (1-alpha) * (1 + 1/n); r_low = r - q; r_high = r + q
File: threatlib/risk/conformal.py
Function: compute_band(risk_score, calibration_scores, alpha) -> tuple[float, float]
Test: tests/test_risk_synthesis.py::test_conformal_band_coverage

## 18. Report Temporal Decay
Formula: report_weight_eff = report_weight * exp(-ln(2) / 90 * age_days)
File: threatlib/signals/report_history.py
Function: ReportHistoryDetector.score(account_data)
Test: tests/test_detectors.py::test_velocity_graph_report_and_session_bot_cases

## 19. Impossible Travel Distance
Formula: haversine great-circle distance, compared against distance / 900 km/h
File: threatlib/signals/session_anomaly.py
Function: _country_distance_km(left, right) -> float | None
Test: tests/test_detectors.py::test_velocity_graph_report_and_session_bot_cases

## 20. Content-to-Consume Ratio
Formula: content_posted_count / max(content_consumed_count, 1)
File: threatlib/signals/content_signal.py
Function: ContentSignalDetector.score(account_data)
Test: tests/test_detectors.py::test_direct_bot_detectors_emit_fraud
