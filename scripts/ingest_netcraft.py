"""
Netcraft ingestion + campaign extraction.

Netcraft has no free bulk feed, so this ingester uses a curated sample of
brand-impersonation phishing domains. Beyond flagging domains, it EXTRACTS
campaigns: domains are grouped by impersonated brand into Campaign nodes, which
improves campaign attribution quality.

Creates:
  ScamSource {name: "Netcraft"} -[:FLAGGED]-> Domain
  Campaign {campaign_id: "NC-<BRAND>"} -[:USES_DOMAIN]-> Domain
"""
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver
from ingest_common import extract_domain, is_valid_domain, upsert_source

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.ingest.netcraft")

CONFIDENCE = 0.90

# Curated brand-impersonation samples: (url, brand, scam_type, risk)
SAMPLE = [
    ("http://microsoft365-login-alert.com/auth", "Microsoft", "credential_phishing", 0.92),
    ("http://ms-office-account-verify.net/signin", "Microsoft", "credential_phishing", 0.92),
    ("http://outlook-mail-reauth.com/login", "Microsoft", "credential_phishing", 0.92),
    ("http://dhl-express-redelivery-fee.com/pay", "DHL", "delivery_scam", 0.90),
    ("http://dhl-parcel-customs-hold.net/release", "DHL", "delivery_scam", 0.90),
    ("http://amazon-prime-billing-update.com/account", "Amazon", "account_phishing", 0.91),
    ("http://amazon-order-cancel-refund.net/claim", "Amazon", "account_phishing", 0.91),
    ("http://paypal-resolution-center-secure.com/case", "PayPal", "payment_phishing", 0.93),
    ("http://paypal-account-limited-appeal.net/verify", "PayPal", "payment_phishing", 0.93),
    ("http://netflix-payment-declined-update.com/billing", "Netflix", "subscription_scam", 0.88),
    ("http://coinbase-wallet-security-verify.com/unlock", "Coinbase", "crypto_phishing", 0.94),
    ("http://coinbase-2fa-reset-secure.net/auth", "Coinbase", "crypto_phishing", 0.94),
]

UPSERT = """
UNWIND $rows AS row
MERGE (d:Domain {name: row.domain})
ON CREATE SET d.first_seen = $now, d.confidence = $conf, d.source = 'Netcraft', d.url = row.url
ON MATCH SET  d.confidence = CASE WHEN $conf > coalesce(d.confidence, 0.0) THEN $conf ELSE d.confidence END
WITH d, row
MATCH (s:ScamSource {name: 'Netcraft'})
MERGE (s)-[r:FLAGGED]->(d)
ON CREATE SET r.first_seen = $now, r.confidence = $conf
WITH d, row
MERGE (c:Campaign {campaign_id: row.campaign_id})
ON CREATE SET c.name = row.campaign_name, c.scam_type = row.scam_type, c.risk_score = row.risk
MERGE (c)-[:USES_DOMAIN]->(d)
"""


def main():
    now = datetime.now(timezone.utc).isoformat()
    rows, seen = [], set()
    for url, brand, scam_type, risk in SAMPLE:
        domain = extract_domain(url)
        if domain and is_valid_domain(domain) and domain not in seen:
            seen.add(domain)
            rows.append({
                "domain": domain, "url": url,
                "campaign_id": f"NC-{brand.upper()}",
                "campaign_name": f"{brand} Impersonation Phishing",
                "scam_type": scam_type, "risk": risk,
            })

    campaigns = sorted({r["campaign_id"] for r in rows})
    logger.info("Netcraft: %d valid domains across %d extracted campaigns.",
                len(rows), len(campaigns))

    driver = get_driver()
    try:
        with driver.session() as session:
            upsert_source(session, "Netcraft", "phishing_takedown", "https://www.netcraft.com")
            session.run(UPSERT, rows=rows, now=now, conf=CONFIDENCE)
        logger.info("Netcraft ingestion complete: %d domains, campaigns=%s",
                    len(rows), campaigns)
        print(f"\n✓ Netcraft — {len(rows)} domains, {len(campaigns)} campaigns extracted "
              f"({', '.join(campaigns)})")
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
