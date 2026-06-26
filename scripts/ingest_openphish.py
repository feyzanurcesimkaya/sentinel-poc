"""
OpenPhish ingestion — phishing domains into the Sentinel graph.

Live feed: https://openphish.com/feed.txt (plain text, one URL per line, no key).
Falls back to a curated sample when unavailable (logged). Batched upsert.

Creates ScamSource {name: "OpenPhish"} and (OpenPhish)-[:FLAGGED]->(Domain).
"""
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver
from ingest_common import normalise_records, batch_upsert

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.ingest.openphish")

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
CONFIDENCE = 0.87
MAX_DOMAINS = 1000

FALLBACK_URLS = [
    "http://wellsfargo-secure-alert.com/login",
    "http://chase-account-verify.net/auth",
    "http://hsbc-online-secure.com/verify",
    "http://barclays-card-services.net/update",
    "http://santander-secure-login.com/access",
    "http://coinbase-wallet-verify.com/unlock",
    "http://binance-account-alert.net/secure",
    "http://dhl-parcel-redelivery.com/track",
    "http://royalmail-fee-pending.co.uk/pay",
    "http://outlook-mail-quota.com/reverify",
]


def _fetch_live() -> list[str]:
    logger.info("Fetching OpenPhish live feed...")
    resp = requests.get(OPENPHISH_FEED_URL, timeout=45,
                        headers={"User-Agent": "sentinel-poc/1.0"})
    resp.raise_for_status()
    urls = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
    logger.info("Retrieved %d raw URLs from OpenPhish.", len(urls))
    return urls


def main():
    now = datetime.now(timezone.utc).isoformat()
    try:
        raw = _fetch_live()
        mode = "LIVE"
    except Exception as e:
        logger.warning("FALLBACK MODE — OpenPhish live fetch failed (%s); using sample data.", e)
        raw, mode = FALLBACK_URLS, "FALLBACK"

    rows = normalise_records(raw, CONFIDENCE)[:MAX_DOMAINS]
    logger.info("[%s] %d raw -> %d valid unique domains (capped %d).",
                mode, len(raw), len(rows), MAX_DOMAINS)

    driver = get_driver()
    try:
        with driver.session() as session:
            summary = batch_upsert(session, "OpenPhish", "phishing_feed",
                                   "https://openphish.com", rows, now)
        summary.update(mode=mode, fetched_count=len(raw),
                       skipped_count=len(raw) - summary["inserted_or_updated_count"])
        logger.info("OpenPhish ingestion complete: %s", summary)
        print(f"\n✓ OpenPhish [{mode}] — fetched={summary['fetched_count']} "
              f"inserted/updated={summary['inserted_or_updated_count']}")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
