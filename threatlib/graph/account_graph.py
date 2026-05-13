"""SQLite storage and graph traversal for ThreatLib."""

from __future__ import annotations

from collections import deque
import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Iterable


ONE_DAY_SECONDS = 86400.0  # REF: Unix time conversion for temporal SQL windows.
DEFAULT_BFS_DEPTH = 3  # REF: Section D.8 - graph traversal depth k=3.


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def username_pattern(username: str) -> str:
    pattern = []
    for char in username:
        if char.isdigit():
            pattern.append("0")
        elif char.isalpha():
            pattern.append("a")
        else:
            pattern.append("_")
    return "".join(pattern)


def sanitize_event_data(event_data: dict[str, Any] | None) -> dict[str, Any]:
    """Keep only non-PII event features; hash identifiers and content-like strings."""

    if not event_data:
        return {}
    safe: dict[str, Any] = {}
    for key, value in event_data.items():
        lowered = key.lower()
        if isinstance(value, bool) or isinstance(value, (int, float)):
            safe[key] = value
        elif lowered in {"domain", "tld", "recipient_type", "category", "link_domain"} and isinstance(value, str):
            safe[key] = value[:255]
        elif "id" in lowered and isinstance(value, str):
            safe[key] = hash_value(value) if len(value) < 64 else value[:128]
        elif isinstance(value, str):
            safe[f"{key}_sha256"] = hash_value(value)
            safe[f"{key}_length"] = len(value)
        elif isinstance(value, list):
            safe[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            safe[f"{key}_keys"] = sorted(str(item) for item in value.keys())[:20]
    return safe


class AccountGraph:
    """Small SQLite repository with append-only audit enforcement."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock, self.conn:
            self.conn.executescript(
                """
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    email_domain TEXT,
                    ip_prefix TEXT,
                    device_hash TEXT,
                    device_model TEXT,
                    status TEXT DEFAULT 'active',
                    human_review_confirmed INTEGER DEFAULT 0,
                    username_entropy REAL,
                    username_bigram_entropy REAL,
                    username_digit_suffix INTEGER,
                    username_pattern TEXT,
                    metadata_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS signal_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data_json TEXT NOT NULL,
                    session_id TEXT,
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    session_id TEXT,
                    created_at REAL NOT NULL,
                    device_hash TEXT,
                    ip_prefix TEXT,
                    ip_geo_country TEXT,
                    device_timezone TEXT,
                    duration_s REAL,
                    event_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_account_id TEXT NOT NULL,
                    reporter_account_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    reporter_trust_score REAL NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS appeals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    appeal_text_hash TEXT,
                    status TEXT DEFAULT 'open',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    detector_names_json TEXT NOT NULL,
                    masses_json TEXT NOT NULL,
                    final_score REAL NOT NULL,
                    action TEXT NOT NULL,
                    threat_tier TEXT NOT NULL,
                    restrictions_json TEXT NOT NULL,
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_account_id TEXT NOT NULL,
                    target_account_id TEXT NOT NULL,
                    weight REAL NOT NULL,
                    edge_type TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (source_account_id, target_account_id, edge_type)
                );

                CREATE TABLE IF NOT EXISTS canary_accounts (
                    account_id TEXT PRIMARY KEY,
                    expected_tier TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS isolation_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    cluster_id TEXT,
                    action_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS calibration_labels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    true_label INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS federation_exports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signal_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_type TEXT NOT NULL,
                    indicator_hash TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    metadata_json TEXT NOT NULL,
                    PRIMARY KEY (indicator_type, indicator_hash, source)
                );

                CREATE INDEX IF NOT EXISTS idx_threat_indicators_lookup
                ON threat_indicators(indicator_type, indicator_hash, expires_at);

                CREATE TABLE IF NOT EXISTS training_feature_rows (
                    feature_hash TEXT NOT NULL,
                    source TEXT NOT NULL,
                    label TEXT NOT NULL,
                    feature_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (feature_hash, source)
                );

                CREATE TABLE IF NOT EXISTS dataset_imports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    source_uri_hash TEXT NOT NULL,
                    rows_seen INTEGER NOT NULL,
                    rows_stored INTEGER NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    imported_at REAL NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS audit_log_no_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'audit_log is append-only');
                END;
                """
            )

    def close(self) -> None:
        self.conn.close()

    def upsert_account(self, account_data: dict[str, Any], created_at: float | None = None) -> None:
        account_id = account_data["account_id"]
        now = created_at if created_at is not None else time.time()
        metadata_json = json.dumps(
            {key: account_data[key] for key in ("ip_asn",) if key in account_data},
            sort_keys=True,
        )
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO accounts (
                    account_id, created_at, email_domain, ip_prefix, device_hash, device_model,
                    status, human_review_confirmed, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, 'active'), COALESCE(?, 0), ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    email_domain = COALESCE(excluded.email_domain, accounts.email_domain),
                    ip_prefix = COALESCE(excluded.ip_prefix, accounts.ip_prefix),
                    device_hash = COALESCE(excluded.device_hash, accounts.device_hash),
                    device_model = COALESCE(excluded.device_model, accounts.device_model),
                    status = COALESCE(excluded.status, accounts.status),
                    human_review_confirmed = COALESCE(excluded.human_review_confirmed, accounts.human_review_confirmed),
                    metadata_json = CASE WHEN excluded.metadata_json != '{}' THEN excluded.metadata_json ELSE accounts.metadata_json END
                """,
                (
                    account_id,
                    now,
                    account_data.get("email_domain"),
                    account_data.get("ip_prefix"),
                    account_data.get("device_hash"),
                    account_data.get("device_model"),
                    account_data.get("status"),
                    1 if account_data.get("human_review_confirmed") else 0,
                    metadata_json,
                ),
            )
        self._add_edges_from_account_data(account_data)

    def set_account_status(self, account_id: str, status: str, human_review_confirmed: bool = False) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO accounts(account_id, created_at, status, human_review_confirmed)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(account_id) DO UPDATE SET
                    status = excluded.status,
                    human_review_confirmed = excluded.human_review_confirmed
                """,
                (account_id, time.time(), status, 1 if human_review_confirmed else 0),
            )

    def get_account(self, account_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()

    def account_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM accounts").fetchone()
        return int(row["count"])

    def count_events(self, account_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS count FROM signal_events WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        return int(row["count"])

    def count_accounts_since(self, since_ts: float) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM accounts WHERE created_at >= ?", (since_ts,)).fetchone()
        return int(row["count"])

    def count_by_ip_prefix(self, ip_prefix: str, since_ts: float, exclude_account_id: str | None = None) -> int:
        query = "SELECT COUNT(DISTINCT account_id) AS count FROM accounts WHERE ip_prefix = ? AND created_at >= ?"
        params: list[Any] = [ip_prefix, since_ts]
        if exclude_account_id:
            query += " AND account_id != ?"
            params.append(exclude_account_id)
        row = self.conn.execute(query, params).fetchone()
        return int(row["count"])

    def count_by_device_hash(self, device_hash: str, since_ts: float, exclude_account_id: str | None = None) -> int:
        query = "SELECT COUNT(DISTINCT account_id) AS count FROM accounts WHERE device_hash = ? AND created_at >= ?"
        params: list[Any] = [device_hash, since_ts]
        if exclude_account_id:
            query += " AND account_id != ?"
            params.append(exclude_account_id)
        row = self.conn.execute(query, params).fetchone()
        return int(row["count"])

    def count_by_device_model(self, device_model: str, since_ts: float, exclude_account_id: str | None = None) -> int:
        query = "SELECT COUNT(DISTINCT account_id) AS count FROM accounts WHERE device_model = ? AND created_at >= ?"
        params: list[Any] = [device_model, since_ts]
        if exclude_account_id:
            query += " AND account_id != ?"
            params.append(exclude_account_id)
        row = self.conn.execute(query, params).fetchone()
        return int(row["count"])

    def count_by_asn(self, ip_asn: str, since_ts: float) -> int:
        rows = self.conn.execute(
            "SELECT metadata_json FROM accounts WHERE created_at >= ?",
            (since_ts,),
        ).fetchall()
        count = 0
        for row in rows:
            try:
                if json.loads(row["metadata_json"]).get("ip_asn") == ip_asn:
                    count += 1
            except json.JSONDecodeError:
                continue
        return count

    def store_username_features(
        self,
        account_id: str,
        entropy: float,
        bigram_entropy: float,
        digit_suffix: bool,
        pattern: str,
    ) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """
                UPDATE accounts
                SET username_entropy = ?, username_bigram_entropy = ?, username_digit_suffix = ?, username_pattern = ?
                WHERE account_id = ?
                """,
                (entropy, bigram_entropy, 1 if digit_suffix else 0, pattern, account_id),
            )

    def recent_username_patterns(self, limit: int = 50, since_seconds: float = 3600.0) -> list[str]:
        since_ts = time.time() - since_seconds
        rows = self.conn.execute(
            """
            SELECT username_pattern FROM accounts
            WHERE username_pattern IS NOT NULL AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (since_ts, limit),
        ).fetchall()
        return [row["username_pattern"] for row in rows]

    def add_edge(self, source: str, target: str, weight: float, edge_type: str) -> None:
        if source == target:
            return
        left, right = sorted([source, target])
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO graph_edges(source_account_id, target_account_id, weight, edge_type, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (left, right, weight, edge_type, time.time()),
            )

    def _add_edges_from_account_data(self, account_data: dict[str, Any]) -> None:
        account_id = account_data["account_id"]
        now = time.time()
        for field, weight, edge_type in (
            ("device_hash", 1.0, "shared_device"),
            ("ip_prefix", 0.7, "shared_ip_prefix"),
        ):
            value = account_data.get(field)
            if not value:
                continue
            rows = self.conn.execute(
                f"SELECT account_id FROM accounts WHERE {field} = ? AND account_id != ? AND created_at >= ?",
                (value, account_id, now - 30.0 * ONE_DAY_SECONDS),
            ).fetchall()
            for row in rows:
                self.add_edge(account_id, row["account_id"], weight, edge_type)
        for friend_id in account_data.get("friend_ids") or []:
            self.add_edge(account_id, str(friend_id), 0.3, "friend")
        if account_data.get("referrer_account_id"):
            self.add_edge(account_id, str(account_data["referrer_account_id"]), 0.6, "referrer")

    def harmful_anchors(self) -> list[str]:
        rows = self.conn.execute(
            """
            SELECT account_id FROM accounts
            WHERE status IN ('suspended', 'auto_banned') AND human_review_confirmed = 1
            """
        ).fetchall()
        return [row["account_id"] for row in rows]

    def neighbors(self, account_id: str) -> list[str]:
        rows = self.conn.execute(
            """
            SELECT target_account_id AS neighbor FROM graph_edges WHERE source_account_id = ?
            UNION
            SELECT source_account_id AS neighbor FROM graph_edges WHERE target_account_id = ?
            """,
            (account_id, account_id),
        ).fetchall()
        return [row["neighbor"] for row in rows]

    def distance_to_harmful(self, account_id: str, max_depth: int = DEFAULT_BFS_DEPTH) -> int | None:
        anchors = set(self.harmful_anchors())
        if not anchors:
            return None
        if account_id in anchors:
            return 0
        queue: deque[tuple[str, int]] = deque((anchor, 0) for anchor in anchors)
        visited = set(anchors)
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.neighbors(current):
                if neighbor in visited:
                    continue
                next_depth = depth + 1
                if neighbor == account_id:
                    return next_depth
                visited.add(neighbor)
                queue.append((neighbor, next_depth))
        return None

    def record_event(
        self,
        account_id: str,
        event_type: str,
        event_data: dict[str, Any] | None,
        session_id: str | None = None,
        timestamp: float | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        self.upsert_account({"account_id": account_id}, created_at=ts)
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO signal_events(account_id, event_type, event_data_json, session_id, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (account_id, event_type, json.dumps(sanitize_event_data(event_data), sort_keys=True), session_id, ts),
            )

    def recent_events(self, account_id: str, since_ts: float | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM signal_events WHERE account_id = ?"
        params: list[Any] = [account_id]
        if since_ts is not None:
            query += " AND timestamp >= ?"
            params.append(since_ts)
        query += " ORDER BY timestamp DESC"
        return self.conn.execute(query, params).fetchall()

    def all_recent_events(self, since_ts: float | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM signal_events"
        params: list[Any] = []
        if since_ts is not None:
            query += " WHERE timestamp >= ?"
            params.append(since_ts)
        query += " ORDER BY timestamp DESC"
        return self.conn.execute(query, params).fetchall()

    def record_session(
        self,
        account_id: str,
        session_id: str | None,
        device_hash: str | None,
        ip_prefix: str | None,
        ip_geo_country: str | None,
        device_timezone: str | None,
        duration_s: float | None = None,
        event_count: int = 0,
        created_at: float | None = None,
    ) -> None:
        ts = created_at if created_at is not None else time.time()
        self.upsert_account({"account_id": account_id, "device_hash": device_hash, "ip_prefix": ip_prefix}, created_at=ts)
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO sessions(
                    account_id, session_id, created_at, device_hash, ip_prefix, ip_geo_country,
                    device_timezone, duration_s, event_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (account_id, session_id, ts, device_hash, ip_prefix, ip_geo_country, device_timezone, duration_s, event_count),
            )

    def last_sessions(self, account_id: str, limit: int = 10) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM sessions WHERE account_id = ? ORDER BY created_at DESC LIMIT ?",
            (account_id, limit),
        ).fetchall()

    def add_report(
        self,
        target_account_id: str,
        reporter_account_id: str,
        category: str,
        reporter_trust_score: float,
        created_at: float | None = None,
    ) -> None:
        ts = created_at if created_at is not None else time.time()
        reporter_hash = reporter_account_id if len(reporter_account_id) >= 64 else hash_value(reporter_account_id)
        self.upsert_account({"account_id": target_account_id}, created_at=ts)
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO reports(target_account_id, reporter_account_id, category, reporter_trust_score, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target_account_id, reporter_hash, category, reporter_trust_score, ts),
            )

    def reports_for_account(self, account_id: str, since_ts: float) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM reports WHERE target_account_id = ? AND created_at >= ? ORDER BY created_at DESC",
            (account_id, since_ts),
        ).fetchall()

    def append_audit(
        self,
        audit_id: str,
        account_id: str,
        detector_names: Iterable[str],
        masses: dict[str, Any],
        final_score: float,
        action: str,
        threat_tier: str,
        restrictions: dict[str, Any],
        timestamp: float | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO audit_log(
                    audit_id, account_id, detector_names_json, masses_json, final_score,
                    action, threat_tier, restrictions_json, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    account_id,
                    json.dumps(list(detector_names), sort_keys=True),
                    json.dumps(masses, sort_keys=True),
                    final_score,
                    action,
                    threat_tier,
                    json.dumps(restrictions, sort_keys=True),
                    ts,
                ),
            )

    def audit_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM audit_log").fetchone()
        return int(row["count"])

    def latest_risk_score(self, account_id: str) -> float | None:
        row = self.conn.execute(
            "SELECT final_score FROM audit_log WHERE account_id = ? ORDER BY timestamp DESC LIMIT 1",
            (account_id,),
        ).fetchone()
        return float(row["final_score"]) if row else None

    def all_accounts(self, since_ts: float | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM accounts"
        params: list[Any] = []
        if since_ts is not None:
            query += " WHERE created_at >= ?"
            params.append(since_ts)
        return self.conn.execute(query, params).fetchall()

    def all_edges(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM graph_edges").fetchall()

    def edge_weights_for_account(self, account_id: str, max_depth: int = 3) -> list[tuple[str, float]]:
        seen = {account_id}
        frontier = [(account_id, 0, 1.0)]
        neighbours: list[tuple[str, float]] = []
        while frontier:
            current, depth, carried_weight = frontier.pop(0)
            if depth >= max_depth:
                continue
            rows = self.conn.execute(
                """
                SELECT target_account_id AS other, weight FROM graph_edges WHERE source_account_id = ?
                UNION ALL
                SELECT source_account_id AS other, weight FROM graph_edges WHERE target_account_id = ?
                """,
                (current, current),
            ).fetchall()
            for row in rows:
                other = row["other"]
                if other in seen:
                    continue
                seen.add(other)
                weight = carried_weight * float(row["weight"])
                neighbours.append((other, weight))
                frontier.append((other, depth + 1, weight))
        return neighbours

    def record_isolation_action(self, account_id: str, cluster_id: str | None, action: dict[str, Any]) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO isolation_actions(account_id, cluster_id, action_json, created_at) VALUES (?, ?, ?, ?)",
                (account_id, cluster_id, json.dumps(action, sort_keys=True), time.time()),
            )

    def record_calibration_label(self, account_id: str, risk_score: float, true_label: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO calibration_labels(account_id, risk_score, true_label, created_at) VALUES (?, ?, ?, ?)",
                (account_id, risk_score, 1 if true_label else 0, time.time()),
            )

    def calibration_scores(self) -> list[float]:
        rows = self.conn.execute("SELECT risk_score, true_label FROM calibration_labels").fetchall()
        return [abs(float(row["risk_score"]) - float(row["true_label"])) for row in rows]

    def append_federation_export(self, signal_type: str, payload: dict[str, Any]) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO federation_exports(signal_type, payload_json, created_at) VALUES (?, ?, ?)",
                (signal_type, json.dumps(payload, sort_keys=True), time.time()),
            )

    def upsert_threat_indicator(
        self,
        indicator_type: str,
        canonical_value: str,
        source: str,
        retention_days: float,
        metadata: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> str:
        ts = timestamp if timestamp is not None else time.time()
        ttl_seconds = retention_days * ONE_DAY_SECONDS
        indicator_hash = hash_value(canonical_value)
        safe_metadata = _safe_indicator_metadata(metadata or {})
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO threat_indicators(
                    indicator_type, indicator_hash, source, first_seen, last_seen, expires_at, metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_type, indicator_hash, source) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires_at = excluded.expires_at,
                    metadata_json = excluded.metadata_json
                """,
                (
                    indicator_type,
                    indicator_hash,
                    source,
                    ts,
                    ts,
                    ts + ttl_seconds,
                    json.dumps(safe_metadata, sort_keys=True),
                ),
            )
        return indicator_hash

    def threat_indicator_exists(
        self,
        indicator_type: str,
        canonical_value: str,
        source: str | None = None,
        timestamp: float | None = None,
    ) -> bool:
        ts = timestamp if timestamp is not None else time.time()
        indicator_hash = hash_value(canonical_value)
        query = """
            SELECT 1 FROM threat_indicators
            WHERE indicator_type = ? AND indicator_hash = ? AND expires_at >= ?
        """
        params: list[Any] = [indicator_type, indicator_hash, ts]
        if source is not None:
            query += " AND source = ?"
            params.append(source)
        row = self.conn.execute(query, params).fetchone()
        return row is not None

    def threat_indicator_count(self, indicator_type: str | None = None) -> int:
        if indicator_type is None:
            row = self.conn.execute("SELECT COUNT(*) AS count FROM threat_indicators").fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) AS count FROM threat_indicators WHERE indicator_type = ?",
                (indicator_type,),
            ).fetchone()
        return int(row["count"])

    def upsert_training_feature(
        self,
        source: str,
        label: str,
        feature_key: str,
        features: dict[str, Any],
        retention_days: float,
        timestamp: float | None = None,
    ) -> str:
        ts = timestamp if timestamp is not None else time.time()
        feature_hash = hash_value(feature_key)
        safe_features = _safe_indicator_metadata(features)
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO training_feature_rows(feature_hash, source, label, feature_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(feature_hash, source) DO UPDATE SET
                    label = excluded.label,
                    feature_json = excluded.feature_json,
                    expires_at = excluded.expires_at
                """,
                (
                    feature_hash,
                    source,
                    label,
                    json.dumps(safe_features, sort_keys=True),
                    ts,
                    ts + retention_days * ONE_DAY_SECONDS,
                ),
            )
        return feature_hash

    def training_feature_count(self, source: str | None = None) -> int:
        if source is None:
            row = self.conn.execute("SELECT COUNT(*) AS count FROM training_feature_rows").fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) AS count FROM training_feature_rows WHERE source = ?",
                (source,),
            ).fetchone()
        return int(row["count"])

    def record_dataset_import(
        self,
        source: str,
        source_uri: str,
        rows_seen: int,
        rows_stored: int,
        source_sha256: str,
        timestamp: float | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO dataset_imports(source, source_uri_hash, rows_seen, rows_stored, source_sha256, imported_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (source, hash_value(source_uri), rows_seen, rows_stored, source_sha256, ts),
            )

    def prune_expired_intel(self, timestamp: float | None = None) -> int:
        ts = timestamp if timestamp is not None else time.time()
        with self._lock, self.conn:
            indicator_count = self.conn.execute(
                "SELECT COUNT(*) AS count FROM threat_indicators WHERE expires_at < ?",
                (ts,),
            ).fetchone()["count"]
            feature_count = self.conn.execute(
                "SELECT COUNT(*) AS count FROM training_feature_rows WHERE expires_at < ?",
                (ts,),
            ).fetchone()["count"]
            self.conn.execute("DELETE FROM threat_indicators WHERE expires_at < ?", (ts,))
            self.conn.execute("DELETE FROM training_feature_rows WHERE expires_at < ?", (ts,))
        return int(indicator_count) + int(feature_count)


def _safe_indicator_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    blocked_tokens = ("url", "ip", "domain", "email", "username", "message", "text", "content")
    for key, value in metadata.items():
        lowered = key.lower()
        if any(token in lowered for token in blocked_tokens):
            if isinstance(value, str):
                safe[f"{key}_sha256"] = hash_value(value)
                safe[f"{key}_length"] = len(value)
            elif isinstance(value, list):
                safe[f"{key}_count"] = len(value)
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = value[:128]
        elif isinstance(value, list):
            safe[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            safe[f"{key}_keys"] = sorted(str(item) for item in value.keys())[:20]
    return safe
