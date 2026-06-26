"""
PhishTank ingestion — pulls recent phishing domains into the Sentinel graph.

Live feed requires PHISHTANK_API_KEY in .env.
Falls back to curated sample data when the key is absent or the request fails.
"""
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.ingest.phishtank")

PHISHTANK_URL = "https://data.phishtank.com/data/{api_key}/online-valid.json"

# Curated fallback — real PhishTank-style phishing domains
FALLBACK_DOMAINS = [
    {"url": "http://secure-bankofamerica-login.com/verify", "confidence": 0.92},
    {"url": "http://paypal-security-alert.net/update", "confidence": 0.95},
    {"url": "http://apple-id-suspended.com/recover", "confidence": 0.88},
    {"url": "http://amazon-prime-renew.net/billing", "confidence": 0.91},
    {"url": "http://microsoft-account-locked.com/signin", "confidence": 0.89},
    {"url": "http://halifax-secure-login.com/auth", "confidence": 0.94},
    {"url": "http://lloyds-bank-verify.net/confirm", "confidence": 0.93},
    {"url": "http://hmrc-tax-refund-2024.com/claim", "confidence": 0.97},
    {"url": "http://natwest-online-banking.net/secure", "confidence": 0.90},
    {"url": "http://netflix-billing-update.com/payment", "confidence": 0.87},
]

UPSERT_SOURCE = """
MERGE (s:ScamSource {name: $name})
SET s.source_type = $source_type,
    s.url = $url
"""

UPSERT_DOMAIN_AND_LINK = """
MERGE (d:Domain {name: $domain})
ON CREATE SET d.first_seen = $first_seen,
              d.confidence = $confidence,
              d.source = $source
ON MATCH SET  d.confidence = CASE
                WHEN $confidence > d.confidence THEN $confidence
                ELSE d.confidence
              END

WITH d
MATCH (s:ScamSource {name: $source})
MERGE (s)-[r:FLAGGED]->(d)
ON CREATE SET r.first_seen = $first_seen,
              r.confidence = $confidence
"""


def _extract_domain(url: str) -> str | None:
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().removeprefix("www.")
        return host if host else None
    except Exception:
        return None


def _fetch_live(api_key: str) -> list[dict]:
    url = PHISHTANK_URL.format(api_key=api_key)
    logger.info("Fetching PhishTank live feed...")
    resp = requests.get(url, timeout=30, headers={"User-Agent": "sentinel-poc/1.0"})
    resp.raise_for_status()
    entries = resp.json()
    logger.info("Retrieved %d raw entries from PhishTank.", len(entries))
    return [
        {"url": e["url"], "confidence": 0.90}
        for e in entries
        if e.get("verified") == "yes"
    ]


def _normalise(raw_entries: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for entry in raw_entries:
        domain = _extract_domain(entry["url"])
        if domain and domain not in seen:
            seen.add(domain)
            result.append({"domain": domain, "confidence": entry.get("confidence", 0.85)})
    return result


def ingest(session, domains: list[dict], now: str) -> int:
    session.run(
        UPSERT_SOURCE,
        name="PhishTank",
        source_type="phishing_feed",
        url="https://www.phishtank.com",
    )

    count = 0
    for entry in domains:
        try:
            session.run(
                UPSERT_DOMAIN_AND_LINK,
                domain=entry["domain"],
                first_seen=now,
                confidence=entry["confidence"],
                source="PhishTank",
            )
            count += 1
        except Exception as e:
            logger.warning("Failed to upsert domain '%s': %s", entry["domain"], e)

    return count


def main():
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()
    now = datetime.now(timezone.utc).isoformat()

    raw: list[dict] = []

    if api_key and api_key not in ("SONRA_DOLDURURUZ", ""):
        try:
            raw = _fetch_live(api_key)
        except Exception as e:
            logger.warning("Live feed failed (%s) — using fallback data.", e)
            raw = FALLBACK_DOMAINS
    else:
        logger.info("No PHISHTANK_API_KEY set — using fallback sample data.")
        raw = FALLBACK_DOMAINS

    domains = _normalise(raw)
    logger.info("%d unique domains after normalisation.", len(domains))

    driver = get_driver()
    try:
        with driver.session() as session:
            count = ingest(session, domains, now)
        logger.info("PhishTank ingestion complete. Domains written: %d", count)
        print(f"\n✓ PhishTank — {count} domains ingested into Sentinel graph.")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
