"""
URLHaus ingestion — malicious URLs (malware/phishing) into the Sentinel graph.

Live feed: https://urlhaus.abuse.ch/downloads/csv_recent/ (CSV, '#'-comment lines).
Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter.
Falls back to a curated sample when unavailable (logged). Batched upsert.

Creates ScamSource {name: "URLHaus"} and (URLHaus)-[:FLAGGED {threat_type}]->(Domain).
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
logger = logging.getLogger("sentinel.ingest.urlhaus")

# Full historical URL dump (streamed) — far more distinct domains than the
# 30-day "recent" CSV, needed to drive bulk coverage past 5000.
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text/"
CONFIDENCE = 0.89
MAX_DOMAINS = 5000          # valid unique domains to ingest this run
RAW_FETCH_LIMIT = 250000    # stream at most this many raw URLs (then stop)

FALLBACK_ENTRIES = [
    {"url": "http://malware-dropper-cdn.ru/payload.exe", "threat_type": "malware_download"},
    {"url": "http://emotet-c2-panel.net/gate.php", "threat_type": "botnet_cc"},
    {"url": "http://fakeinvoice-download.com/invoice.zip", "threat_type": "malware_download"},
    {"url": "http://trojan-update-server.cc/update.bin", "threat_type": "malware_download"},
    {"url": "http://phish-kit-host.xyz/login", "threat_type": "phishing"},
    {"url": "http://cryptominer-inject.io/m.js", "threat_type": "malware_download"},
    {"url": "http://ransomware-portal-pay.com/pay", "threat_type": "ransomware"},
    {"url": "http://stealer-logs-upload.net/up.php", "threat_type": "botnet_cc"},
    {"url": "http://fake-flashplayer-update.com/setup.exe", "threat_type": "malware_download"},
    {"url": "http://banking-trojan-loader.su/load", "threat_type": "malware_download"},
]


def _fetch_live() -> list[dict]:
    """Stream the full URLHaus URL dump, stopping after RAW_FETCH_LIMIT URLs."""
    logger.info("Fetching URLHaus full URL feed (streaming)...")
    entries: list[dict] = []
    with requests.get(URLHAUS_FEED_URL, timeout=90, stream=True,
                      headers={"User-Agent": "sentinel-poc/1.0"}) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines(decode_unicode=True):
            if not line or line.startswith("#"):
                continue
            entries.append({"url": line.strip(), "threat_type": "malware_url"})
            if len(entries) >= RAW_FETCH_LIMIT:
                break
    logger.info("Collected %d raw URLs from URLHaus full feed.", len(entries))
    return entries


def main():
    now = datetime.now(timezone.utc).isoformat()
    try:
        raw = _fetch_live()
        mode = "LIVE"
    except Exception as e:
        logger.warning("FALLBACK MODE — URLHaus live fetch failed (%s); using sample data.", e)
        raw, mode = FALLBACK_ENTRIES, "FALLBACK"

    rows = normalise_records(raw, CONFIDENCE, threat_key="threat_type")[:MAX_DOMAINS]
    logger.info("[%s] %d raw -> %d valid unique domains (capped %d).",
                mode, len(raw), len(rows), MAX_DOMAINS)

    driver = get_driver()
    try:
        with driver.session() as session:
            summary = batch_upsert(session, "URLHaus", "malware_url_feed",
                                   "https://urlhaus.abuse.ch", rows, now)
        summary.update(mode=mode, fetched_count=len(raw),
                       skipped_count=len(raw) - summary["inserted_or_updated_count"])
        logger.info("URLHaus ingestion complete: %s", summary)
        print(f"\n✓ URLHaus [{mode}] — fetched={summary['fetched_count']} "
              f"inserted/updated={summary['inserted_or_updated_count']}")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
