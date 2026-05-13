"""Safe ingestion for public threat-intelligence and calibration datasets."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import ipaddress
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import urlparse

import httpx

from threatlib.graph.account_graph import AccountGraph


DEFAULT_RETENTION_DAYS = 30.0  # REF: Operator requirement in issue discussion - retain hashed abuse data for 20-30 days.
TOR_MAX_BYTES = 2 * 1024 * 1024  # REF: Tor bulk exit list is small text; 2 MiB cap prevents unexpected payload downloads.
URLHAUS_MAX_BYTES = 16 * 1024 * 1024  # REF: URLhaus recent CSV is a few MiB; 16 MiB allows growth without arbitrary bulk content.
HTTP_TIMEOUT_SECONDS = 20.0  # REF: Operational feed fetch timeout; fail closed instead of hanging ingestion.
MAX_SMS_MESSAGE_BYTES = 4096  # REF: SMS records are short; cap prevents large text blobs from entering feature extraction.
MAX_TRANCO_ROWS = 1_000_000  # REF: Tranco top-1M dataset has one million ranked domains.
SNAP_SAMPLE_EDGE_LIMIT = 250_000  # REF: SNAP combined graph is small; cap bounds accidental wrong-file imports.


@dataclass(frozen=True)
class RemoteFeed:
    name: str
    url: str
    max_bytes: int
    content_types: tuple[str, ...]


REMOTE_FEEDS: dict[str, RemoteFeed] = {
    "tor_exit_nodes": RemoteFeed(
        name="tor_exit_nodes",
        url="https://check.torproject.org/torbulkexitlist",
        max_bytes=TOR_MAX_BYTES,
        content_types=("text/plain", "application/octet-stream"),
    ),
    "urlhaus_recent": RemoteFeed(
        name="urlhaus_recent",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        max_bytes=URLHAUS_MAX_BYTES,
        content_types=("text/plain", "text/csv", "application/octet-stream"),
    ),
}


@dataclass(frozen=True)
class FeedImportResult:
    source: str
    rows_seen: int
    rows_stored: int
    rejected_rows: int
    source_sha256: str


class FeedValidationError(ValueError):
    """Raised when a feed source or payload does not match the allowlisted contract."""


class SafeFeedClient:
    """Fetch only exact allowlisted text feeds; never follow URLs embedded in those feeds."""

    def __init__(self, allowed_feeds: dict[str, RemoteFeed] | None = None) -> None:
        self.allowed_feeds = allowed_feeds or REMOTE_FEEDS

    def fetch(self, feed_name: str) -> bytes:
        if feed_name not in self.allowed_feeds:
            raise FeedValidationError(f"feed is not allowlisted: {feed_name}")
        feed = self.allowed_feeds[feed_name]
        parsed = urlparse(feed.url)
        if parsed.scheme != "https":
            raise FeedValidationError("remote feeds must use https")
        with httpx.Client(follow_redirects=False, timeout=HTTP_TIMEOUT_SECONDS) as client:
            response = client.get(feed.url)
        if 300 <= response.status_code < 400:
            raise FeedValidationError("redirects are not accepted for threat-intel feeds")
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type and content_type not in feed.content_types:
            raise FeedValidationError(f"unexpected content type for {feed_name}: {content_type}")
        body = response.content
        if len(body) > feed.max_bytes:
            raise FeedValidationError(f"feed exceeds configured size cap: {feed_name}")
        return body


class ThreatIntelIngestor:
    """Parse public datasets into hashed indicators and derived training features."""

    def __init__(self, graph: AccountGraph, retention_days: float = DEFAULT_RETENTION_DAYS) -> None:
        self.graph = graph
        self.retention_days = retention_days

    def fetch_and_ingest(self, feed_name: str, client: SafeFeedClient | None = None) -> FeedImportResult:
        feed_client = client or SafeFeedClient()
        body = feed_client.fetch(feed_name)
        if feed_name == "tor_exit_nodes":
            return self.ingest_tor_exit_list(body, source_uri=REMOTE_FEEDS[feed_name].url)
        if feed_name == "urlhaus_recent":
            return self.ingest_urlhaus_recent(body, source_uri=REMOTE_FEEDS[feed_name].url)
        raise FeedValidationError(f"no parser registered for feed: {feed_name}")

    def ingest_tor_exit_list(self, body: bytes | str, source_uri: str = "tor_exit_nodes") -> FeedImportResult:
        payload = _to_bytes(body, TOR_MAX_BYTES)
        rows_seen = rows_stored = rejected = 0
        for raw_line in payload.decode("utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            rows_seen += 1
            try:
                address = ipaddress.ip_address(line)
            except ValueError:
                rejected += 1
                continue
            metadata = {"version": address.version}
            self.graph.upsert_threat_indicator(
                "tor_exit_ip",
                str(address),
                "tor_exit_nodes",
                self.retention_days,
                metadata,
            )
            prefix = ip_prefix(str(address))
            if prefix:
                self.graph.upsert_threat_indicator(
                    "tor_exit_ip_prefix",
                    prefix,
                    "tor_exit_nodes",
                    self.retention_days,
                    {"version": address.version},
                )
            rows_stored += 1
        result = _result("tor_exit_nodes", rows_seen, rows_stored, rejected, payload)
        self.graph.record_dataset_import(result.source, source_uri, rows_seen, rows_stored, result.source_sha256)
        return result

    def ingest_urlhaus_recent(self, body: bytes | str, source_uri: str = "urlhaus_recent") -> FeedImportResult:
        payload = _to_bytes(body, URLHAUS_MAX_BYTES)
        text = payload.decode("utf-8", errors="ignore")
        rows_seen = rows_stored = rejected = 0
        for row in _csv_rows_without_comments(text):
            rows_seen += 1
            if len(row) < 9 or row[0] == "id":
                continue
            url = row[2].strip()
            status = row[3].strip().lower()
            threat = row[5].strip().lower()
            tags = [tag for tag in row[6].split(",") if tag and tag.lower() != "none"]
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if not host or parsed.scheme not in {"http", "https"}:
                rejected += 1
                continue
            # URLhaus rows are indicators. The importer hashes the URL string and never requests it.
            self.graph.upsert_threat_indicator(
                "urlhaus_url",
                _canonical_url(url),
                "urlhaus_recent",
                self.retention_days,
                {"status": status, "threat": threat, "tag_count": len(tags)},
            )
            self.graph.upsert_threat_indicator(
                "urlhaus_host",
                host,
                "urlhaus_recent",
                self.retention_days,
                {"status": status, "threat": threat, "host_kind": _host_kind(host)},
            )
            prefix = ip_prefix(host)
            if prefix:
                self.graph.upsert_threat_indicator(
                    "urlhaus_ip_prefix",
                    prefix,
                    "urlhaus_recent",
                    self.retention_days,
                    {"status": status, "threat": threat},
                )
            rows_stored += 1
        result = _result("urlhaus_recent", rows_seen, rows_stored, rejected, payload)
        self.graph.record_dataset_import(result.source, source_uri, rows_seen, rows_stored, result.source_sha256)
        return result

    def ingest_tranco_csv(self, path: str | Path) -> FeedImportResult:
        source_path = Path(path)
        rows_seen = rows_stored = rejected = 0
        digest = hashlib.sha256()
        with source_path.open("rb") as raw:
            for line in raw:
                digest.update(line)
        with source_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                rows_seen += 1
                if rows_seen > MAX_TRANCO_ROWS:
                    break
                if len(row) < 2:
                    rejected += 1
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    rejected += 1
                    continue
                domain = _normalize_domain(row[1])
                if not domain:
                    rejected += 1
                    continue
                self.graph.upsert_training_feature(
                    "tranco_top_domains",
                    "benign_domain",
                    domain,
                    {"rank": rank, "rank_bucket": _rank_bucket(rank)},
                    self.retention_days,
                )
                rows_stored += 1
        result = FeedImportResult("tranco_top_domains", rows_seen, rows_stored, rejected, digest.hexdigest())
        self.graph.record_dataset_import(result.source, str(source_path), rows_seen, rows_stored, result.source_sha256)
        return result

    def ingest_sms_spam_collection(self, path: str | Path) -> FeedImportResult:
        source_path = Path(path)
        if source_path.is_dir():
            source_path = source_path / "SMSSpamCollection"
        rows_seen = rows_stored = rejected = 0
        digest = hashlib.sha256()
        with source_path.open("rb") as raw:
            for line in raw:
                digest.update(line)
        with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle):
                rows_seen += 1
                label, _, message = line.partition("\t")
                label = label.strip().lower()
                if label not in {"spam", "ham"} or not message:
                    rejected += 1
                    continue
                message = message[:MAX_SMS_MESSAGE_BYTES]
                features = text_message_features(message)
                self.graph.upsert_training_feature(
                    "uci_sms_spam",
                    label,
                    f"{index}:{label}:{hashlib.sha256(message.encode('utf-8')).hexdigest()}",
                    features,
                    self.retention_days,
                )
                rows_stored += 1
        result = FeedImportResult("uci_sms_spam", rows_seen, rows_stored, rejected, digest.hexdigest())
        self.graph.record_dataset_import(result.source, str(source_path), rows_seen, rows_stored, result.source_sha256)
        return result

    def ingest_snap_facebook_graph(self, path: str | Path) -> FeedImportResult:
        source_path = Path(path)
        rows_seen = rows_stored = rejected = 0
        digest = hashlib.sha256()
        degrees: dict[str, int] = {}
        with source_path.open("rb") as raw:
            for line in raw:
                digest.update(line)
        with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if rows_seen >= SNAP_SAMPLE_EDGE_LIMIT:
                    break
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                rows_seen += 1
                parts = stripped.split()
                if len(parts) != 2:
                    rejected += 1
                    continue
                left, right = parts
                degrees[left] = degrees.get(left, 0) + 1
                degrees[right] = degrees.get(right, 0) + 1
                rows_stored += 1
        node_count = len(degrees)
        avg_degree = sum(degrees.values()) / max(node_count, 1)
        max_degree = max(degrees.values()) if degrees else 0
        self.graph.upsert_training_feature(
            "snap_ego_facebook",
            "organic_graph_summary",
            f"{source_path}:{rows_stored}:{node_count}",
            {
                "node_count": node_count,
                "edge_count": rows_stored,
                "avg_degree": avg_degree,
                "max_degree": max_degree,
            },
            self.retention_days,
        )
        result = FeedImportResult("snap_ego_facebook", rows_seen, 1 if rows_stored else 0, rejected, digest.hexdigest())
        self.graph.record_dataset_import(result.source, str(source_path), rows_seen, result.rows_stored, result.source_sha256)
        return result


def ip_prefix(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version == 4:
        parts = str(address).split(".")
        return ".".join(parts[:3])
    network = ipaddress.ip_network(f"{address}/64", strict=False)
    return str(network)


def text_message_features(message: str) -> dict[str, Any]:
    lowered = message.lower()
    url_count = len(re.findall(r"https?://|www\.", lowered))
    digit_count = sum(char.isdigit() for char in message)
    uppercase_count = sum(char.isupper() for char in message)
    urgency_terms = ("urgent", "claim", "winner", "free", "prize", "call", "txt", "stop")
    # REF: UCI SMS spam corpus common campaign terms; count only, never store message text.
    return {
        "length": len(message),
        "token_count": len(message.split()),
        "url_count": url_count,
        "digit_fraction": digit_count / max(len(message), 1),
        "uppercase_fraction": uppercase_count / max(len(message), 1),
        "urgency_term_count": sum(1 for term in urgency_terms if term in lowered),
        "exclamation_count": message.count("!"),
    }


def _to_bytes(body: bytes | str, max_bytes: int) -> bytes:
    payload = body.encode("utf-8") if isinstance(body, str) else body
    if len(payload) > max_bytes:
        raise FeedValidationError("feed payload exceeds parser size limit")
    return payload


def _csv_rows_without_comments(text: str) -> Iterable[list[str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    return csv.reader(lines)


def _canonical_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{host}{port}{path}{query}"


def _normalize_domain(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if not value or "/" in value or " " in value:
        return ""
    return value


def _rank_bucket(rank: int) -> str:
    if rank <= 1_000:  # REF: Tranco rank bucket for highly established domains.
        return "top_1k"
    if rank <= 10_000:  # REF: Tranco rank bucket for established high-traffic domains.
        return "top_10k"
    if rank <= 100_000:  # REF: Tranco rank bucket for broad legitimacy calibration.
        return "top_100k"
    return "top_1m"


def _host_kind(host: str) -> str:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "domain"
    return "ip"


def _result(source: str, rows_seen: int, rows_stored: int, rejected: int, payload: bytes) -> FeedImportResult:
    return FeedImportResult(source, rows_seen, rows_stored, rejected, hashlib.sha256(payload).hexdigest())
