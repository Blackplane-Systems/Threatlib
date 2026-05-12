"""One-shot username and display-name analysis."""

from __future__ import annotations

import re
from typing import Any
from collections import Counter

from threatlib.graph.account_graph import username_pattern
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import bigram_transition_entropy, levenshtein, mini_ds_from_lrs, shannon_entropy


DIGIT_SUFFIX_RE = re.compile(r"\d{2,}$")  # REF: Section D.2 - bot farm digit suffix pattern.


def compute_entropy(value: str) -> float:
    return shannon_entropy(value)


class PsycholinguisticDetector(BaseDetector):
    name = "psycholinguistic"
    required_fields = ()

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        return bool(account_data.get("username_raw") or account_data.get("display_name_raw"))

    def missing_fields(self, account_data: dict[str, Any]) -> list[str]:
        return [] if self.has_required_data(account_data) else ["username_raw OR display_name_raw"]

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        raw_value = str(account_data.get("username_raw") or account_data.get("display_name_raw") or "")
        value = raw_value.strip()
        if not value:
            return DetectorResult.uncertain(self.name, "empty username/display name")

        entropy = shannon_entropy(value)
        bigram_entropy = bigram_transition_entropy(value)
        digit_suffix = bool(DIGIT_SUFFIX_RE.search(value))
        hapax_rate = sum(1 for char in set(value) if value.count(char) == 1) / len(value)
        repeated_context = any(count >= 3 for count in Counter(value[:-1]).values())
        pattern = username_pattern(value)
        lrs: list[tuple[float, str]] = []

        if entropy < 1.5:
            lrs.append((8.0, "low username entropy"))  # REF: Section D.2 - keyboard walk/repeated char LR.
        elif entropy > 4.2:
            lrs.append((5.0, "high username entropy"))  # REF: Section D.2 - random string LR.
        elif 2.0 <= entropy <= 3.4:
            lrs.append((0.6, "username entropy in human range"))  # REF: Section D.2 - human entropy range.

        if (bigram_entropy < 0.8 and repeated_context) or bigram_entropy > 3.5:
            lrs.append((6.0, "bigram transition entropy abnormal"))  # REF: Section D.2 - robotic/uniform transitions.
        elif 1.8 <= bigram_entropy <= 2.8 or not repeated_context:
            lrs.append((0.7, "bigram transition entropy in human range"))  # REF: Section D.2 - human bigram range.

        if digit_suffix:
            lrs.append((2.5, "digit suffix present"))  # REF: Section D.2 - bot farm sequential suffix LR.
        else:
            lrs.append((0.8, "no digit suffix"))  # REF: Section D.2 - absence is weak legitimacy evidence.

        if (hapax_rate > 0.90 and len(value) >= 10) or hapax_rate < 0.20:
            lrs.append((3.0, "hapax rate outside human range"))  # REF: Section D.2 - random/repetitive chars.
        elif 0.40 <= hapax_rate <= 0.75:
            lrs.append((0.8, "hapax rate in human range"))  # REF: Section D.2 - human hapax range.

        if self.graph and account_data.get("account_id"):
            recent_patterns = [item for item in self.graph.recent_username_patterns() if item != pattern]
            if recent_patterns:
                min_distance = min(levenshtein(pattern, item) for item in recent_patterns)
                if min_distance <= 2:
                    lrs.append((10.0, "near-duplicate recent username pattern"))  # REF: Section D.2 - campaign pattern LR.
                elif min_distance >= 5:
                    lrs.append((1.0, "recent username pattern distance neutral"))
            self.graph.store_username_features(account_data["account_id"], entropy, bigram_entropy, digit_suffix, pattern)

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "psycholinguistic username analysis",
            {
                "username_entropy": entropy,
                "username_bigram_entropy": bigram_entropy,
                "username_digit_suffix": digit_suffix,
                "username_hapax_rate": hapax_rate,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )
