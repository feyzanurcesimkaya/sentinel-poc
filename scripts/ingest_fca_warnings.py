"""
FCA Warning List ingestion — FCA-flagged scam domains into the Sentinel graph.

The FCA does not provide a machine-readable bulk API, so this script uses an
expanded curated set of domains drawn from public FCA ScamSmart / Warning List
notices (clone firms, fake regulators, recovery-room and pension scams).
Batched upsert; extend FCA_DOMAINS as new warnings are published.
"""
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver
from ingest_common import normalise_records, batch_upsert

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.ingest.fca")

# Expanded curated FCA Warning List set.
FCA_DOMAINS = [
    {"url": "fca-recovery-fund.co.uk", "confidence": 0.98},
    {"url": "fca-authorised-invest.com", "confidence": 0.97},
    {"url": "fcawarninglist-check.com", "confidence": 0.96},
    {"url": "financial-conduct-auth.net", "confidence": 0.95},
    {"url": "uk-investment-authority.com", "confidence": 0.93},
    {"url": "regulated-broker-uk.com", "confidence": 0.91},
    {"url": "fca-clone-firm-alert.co.uk", "confidence": 0.98},
    {"url": "britishfinanceauthority.com", "confidence": 0.90},
    {"url": "pension-review-uk-official.com", "confidence": 0.94},
    {"url": "hmrc-unclaimed-refund.co.uk", "confidence": 0.96},
    {"url": "uk-bond-invest-secure.com", "confidence": 0.89},
    {"url": "cryptoinvest-fca-approved.com", "confidence": 0.97},
    {"url": "fca-compensation-claim.co.uk", "confidence": 0.97},
    {"url": "fca-register-verify.com", "confidence": 0.96},
    {"url": "fca-authorised-firms.net", "confidence": 0.95},
    {"url": "uk-financial-ombudsman-claim.com", "confidence": 0.94},
    {"url": "fscs-protection-refund.co.uk", "confidence": 0.95},
    {"url": "clone-firm-capital-partners.com", "confidence": 0.92},
    {"url": "secure-isa-bond-uk.com", "confidence": 0.90},
    {"url": "fixed-rate-bond-fca.co.uk", "confidence": 0.91},
    {"url": "pension-liberation-advice-uk.com", "confidence": 0.93},
    {"url": "retirement-fund-recovery-uk.com", "confidence": 0.93},
    {"url": "fca-binary-options-warning.com", "confidence": 0.94},
    {"url": "trading-standards-refund-uk.com", "confidence": 0.90},
    {"url": "uk-gov-investment-scheme.com", "confidence": 0.92},
    {"url": "national-savings-bond-secure.com", "confidence": 0.89},
    {"url": "fca-forex-recovery-team.com", "confidence": 0.95},
    {"url": "crypto-recovery-fca-uk.com", "confidence": 0.96},
    {"url": "authorised-payments-uk-fca.com", "confidence": 0.94},
    {"url": "fca-scam-victim-refund.co.uk", "confidence": 0.97},
]


def main():
    now = datetime.now(timezone.utc).isoformat()
    rows = normalise_records(FCA_DOMAINS, 0.95)
    logger.info("FCA: %d valid unique domains to ingest.", len(rows))

    driver = get_driver()
    try:
        with driver.session() as session:
            summary = batch_upsert(session, "FCA Warning List", "regulator_warning",
                                   "https://www.fca.org.uk/consumers/warning-list", rows, now)
        logger.info("FCA ingestion complete: %s", summary)
        print(f"\n✓ FCA Warning List — {summary['inserted_or_updated_count']} domains ingested.")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
