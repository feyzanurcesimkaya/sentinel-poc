"""
USOM ingestion — Turkish national CERT malicious URL list.

Live feed: https://www.usom.gov.tr/url-list.txt (public, one URL/host per line).
Falls back to a curated sample when unavailable (logged). Batched upsert.

Creates ScamSource {name: "USOM"} and (USOM)-[:FLAGGED]->(Domain).
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
logger = logging.getLogger("sentinel.ingest.usom")

USOM_FEED_URL = "https://www.usom.gov.tr/url-list.txt"
CONFIDENCE = 0.85
MAX_DOMAINS = 2500

FALLBACK_URLS = [
    "http://turkiye-vergi-iadesi.com/basvuru",
    "http://e-devlet-giris-dogrula.com/login",
    "http://ptt-kargo-odeme.net/takip",
    "http://garanti-bbva-guvenlik.com/onay",
    "http://akbank-sifre-yenile.net/giris",
    "http://isbank-hesap-dogrulama.com/verify",
    "http://ziraat-internet-subesi-guvenli.com/login",
    "http://trendyol-hediye-ceki.net/kazan",
    "http://turkcell-fatura-iade.com/odeme",
    "http://btk-ceza-odeme-online.com/pay",
]


def _fetch_live() -> list[str]:
    logger.info("Fetching USOM url-list...")
    resp = requests.get(USOM_FEED_URL, timeout=45,
                        headers={"User-Agent": "sentinel-poc/1.0"})
    resp.raise_for_status()
    urls = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
    logger.info("Retrieved %d raw entries from USOM.", len(urls))
    return urls


def main():
    now = datetime.now(timezone.utc).isoformat()
    try:
        raw = _fetch_live()
        mode = "LIVE"
    except Exception as e:
        logger.warning("FALLBACK MODE — USOM live fetch failed (%s); using sample data.", e)
        raw = FALLBACK_URLS
        mode = "FALLBACK"

    rows = normalise_records(raw, CONFIDENCE)[:MAX_DOMAINS]
    logger.info("[%s] %d raw -> %d valid unique domains (capped %d).",
                mode, len(raw), len(rows), MAX_DOMAINS)

    driver = get_driver()
    try:
        with driver.session() as session:
            summary = batch_upsert(session, "USOM", "national_cert",
                                   "https://www.usom.gov.tr", rows, now)
        summary.update(mode=mode, fetched_count=len(raw),
                       skipped_count=len(raw) - summary["inserted_or_updated_count"])
        logger.info("USOM ingestion complete: %s", summary)
        print(f"\n✓ USOM [{mode}] — fetched={summary['fetched_count']} "
              f"inserted/updated={summary['inserted_or_updated_count']}")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
