"""
Shared ingestion utilities — normalization, validation, dedup, batched upsert.

Used by every feed ingester so that:
  - URLs are normalised to registrable hostnames consistently,
  - invalid hosts (IPs, malformed, over-long) are dropped (data quality),
  - domains are deduplicated within a run (MERGE dedups across runs),
  - writes happen in batched UNWIND transactions (fast at 1000s of domains).

No engine logic here — pure ingestion plumbing.
"""
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger("sentinel.ingest.common")

# A registrable hostname: dotted labels, ASCII, total length <= 253.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Batched upsert: MERGE domain + MERGE (source)-[:FLAGGED]->(domain) per row.
_BATCH_UPSERT = """
UNWIND $rows AS row
MERGE (d:Domain {name: row.domain})
ON CREATE SET d.first_seen = row.first_seen,
              d.confidence = row.confidence,
              d.source = row.source,
              d.url = row.url,
              d.threat_type = row.threat_type
ON MATCH SET  d.confidence = CASE WHEN row.confidence > coalesce(d.confidence, 0.0)
                                  THEN row.confidence ELSE d.confidence END
WITH d, row
MATCH (s:ScamSource {name: row.source})
MERGE (s)-[r:FLAGGED]->(d)
ON CREATE SET r.first_seen = row.first_seen,
              r.confidence = row.confidence,
              r.threat_type = row.threat_type
"""

_UPSERT_SOURCE = """
MERGE (s:ScamSource {name: $name})
SET s.source_type = $source_type, s.url = $url
"""


def extract_domain(value: str | None) -> str | None:
    """Normalise a URL or bare host into a lowercase registrable hostname."""
    if not value:
        return None
    value = value.strip().lower()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    try:
        host = urlparse(value).hostname or ""
    except Exception:
        return None
    return host.removeprefix("www.") or None


def is_valid_domain(host: str | None) -> bool:
    """Data-quality gate: reject IPs, malformed, and over-long hosts."""
    if not host or _IPV4_RE.match(host) or len(host) > 253:
        return False
    return bool(_DOMAIN_RE.match(host))


def normalise_records(raw, confidence: float, threat_key: str | None = None) -> list[dict]:
    """
    Turn raw feed items (URL strings or dicts) into validated, deduped rows:
    {domain, url, confidence, threat_type}.
    """
    seen: set[str] = set()
    rows: list[dict] = []
    for item in raw:
        if isinstance(item, str):
            url, tt, conf = item, None, confidence
        else:
            url = item.get("url") or item.get("domain")
            tt = item.get(threat_key) if threat_key else None
            conf = item.get("confidence", confidence)
        domain = extract_domain(url)
        if domain and is_valid_domain(domain) and domain not in seen:
            seen.add(domain)
            rows.append({
                "domain": domain,
                "url": url if (url and str(url).startswith("http")) else None,
                "confidence": conf,
                "threat_type": tt,
            })
    return rows


def upsert_source(session, name: str, source_type: str, url: str) -> None:
    session.run(_UPSERT_SOURCE, name=name, source_type=source_type, url=url)


def batch_upsert(session, name, source_type, source_url, rows, now, batch_size=500) -> dict:
    """Upsert the source once, then UNWIND-write domains/edges in batches."""
    upsert_source(session, name, source_type, source_url)
    written = 0
    for i in range(0, len(rows), batch_size):
        batch = [{**r, "first_seen": now, "source": name} for r in rows[i:i + batch_size]]
        try:
            session.run(_BATCH_UPSERT, rows=batch)
            written += len(batch)
        except Exception as e:
            logger.warning("Batch upsert failed for %s (rows %d-%d): %s",
                           name, i, i + len(batch), e)
    return {"source": name, "inserted_or_updated_count": written}
