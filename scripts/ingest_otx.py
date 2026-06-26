"""
OTX ingestion — AlienVault OTX subscribed-pulse domain/hostname indicators.

Live feed requires OTX_API_KEY in .env (header X-OTX-API-KEY). Falls back to a
curated sample when the key is absent or the request fails (logged).

Creates ScamSource {name: "AlienVault OTX"} and (OTX)-[:FLAGGED]->(Domain).
"""
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver
from ingest_common import normalise_records, batch_upsert

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.ingest.otx")

OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
CONFIDENCE = 0.86
MAX_DOMAINS = 1500
_DOMAIN_TYPES = {"domain", "hostname"}

FALLBACK_URLS = [
    "http://office365-login-secure.com/auth",
    "http://docusign-document-view.net/sign",
    "http://dropbox-shared-file.com/access",
    "http://linkedin-job-offer-verify.com/apply",
    "http://fedex-shipment-track.net/parcel",
    "http://irs-tax-refund-portal.com/claim",
    "http://whatsapp-web-verify.net/login",
    "http://telegram-premium-gift.com/claim",
    "http://meta-business-suspended.com/appeal",
    "http://steam-trade-offer-secure.net/login",
]


def _fetch_live(api_key: str) -> list[str]:
    logger.info("Fetching OTX subscribed pulses...")
    urls: list[str] = []
    page = OTX_PULSES_URL + "?limit=50"
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": "sentinel-poc/1.0"}
    for _ in range(10):  # cap pagination
        resp = requests.get(page, timeout=45, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                if ind.get("type", "").lower() in _DOMAIN_TYPES:
                    urls.append(ind["indicator"])
        page = data.get("next")
        if not page:
            break
    logger.info("Retrieved %d domain/hostname indicators from OTX.", len(urls))
    return urls


def main():
    now = datetime.now(timezone.utc).isoformat()
    api_key = os.getenv("OTX_API_KEY", "").strip()

    if api_key and api_key not in ("", "SONRA_DOLDURURUZ"):
        try:
            raw = _fetch_live(api_key)
            mode = "LIVE"
        except Exception as e:
            logger.warning("FALLBACK MODE — OTX live fetch failed (%s); using sample data.", e)
            raw, mode = FALLBACK_URLS, "FALLBACK"
    else:
        logger.info("No OTX_API_KEY set — using fallback sample data.")
        raw, mode = FALLBACK_URLS, "FALLBACK"

    rows = normalise_records(raw, CONFIDENCE)[:MAX_DOMAINS]
    logger.info("[%s] %d raw -> %d valid unique domains.", mode, len(raw), len(rows))

    driver = get_driver()
    try:
        with driver.session() as session:
            summary = batch_upsert(session, "AlienVault OTX", "threat_exchange",
                                   "https://otx.alienvault.com", rows, now)
        summary.update(mode=mode, fetched_count=len(raw),
                       skipped_count=len(raw) - summary["inserted_or_updated_count"])
        logger.info("OTX ingestion complete: %s", summary)
        print(f"\n✓ AlienVault OTX [{mode}] — fetched={summary['fetched_count']} "
              f"inserted/updated={summary['inserted_or_updated_count']}")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
