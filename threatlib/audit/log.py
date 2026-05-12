"""Append-only score audit logging."""

from __future__ import annotations

import time
import uuid
from typing import Any

from threatlib.graph.account_graph import AccountGraph
from threatlib.signals.base import DetectorResult


class AuditLogger:
    def __init__(self, graph: AccountGraph) -> None:
        self.graph = graph

    def log_score(
        self,
        account_id: str,
        detector_results: dict[str, DetectorResult],
        final_score: float,
        action: str,
        threat_tier: str,
        restrictions: dict[str, Any],
    ) -> str:
        audit_id = str(uuid.uuid4())
        self.graph.append_audit(
            audit_id=audit_id,
            account_id=account_id,
            detector_names=detector_results.keys(),
            masses={name: result.to_dict() for name, result in detector_results.items()},
            final_score=final_score,
            action=action,
            threat_tier=threat_tier,
            restrictions=restrictions,
            timestamp=time.time(),
        )
        return audit_id

