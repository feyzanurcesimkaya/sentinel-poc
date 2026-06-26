import json
import logging
import sys
from pathlib import Path

from db_connect import get_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.seed")

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "seed_campaigns.json"

UPSERT_CAMPAIGN = """
MERGE (c:Campaign {campaign_id: $campaign_id})
SET c.name = $campaign_name,
    c.risk_score = $risk_score,
    c.scam_type = $scam_type

MERGE (d:Domain {name: $domain})

MERGE (p:Platform {name: $platform})

MERGE (c)-[:USES_DOMAIN]->(d)
MERGE (c)-[:PROMOTED_ON]->(p)
"""


def load_campaigns(session, campaigns):
    for camp in campaigns:
        try:
            session.run(
                UPSERT_CAMPAIGN,
                campaign_id=camp["campaign_id"],
                campaign_name=camp["campaign_name"],
                domain=camp["domain"],
                platform=camp["platform"],
                risk_score=camp["risk_score"],
                scam_type=camp["scam_type"],
            )
            logger.info("Seeded campaign: %s", camp["campaign_id"])
        except Exception as e:
            logger.error("Failed to seed campaign %s: %s", camp.get("campaign_id"), e)
            raise


def main():
    logger.info("Loading seed data from %s", DATA_PATH)
    try:
        with open(DATA_PATH, encoding="utf-8") as f:
            campaigns = json.load(f)
    except FileNotFoundError:
        logger.error("Seed file not found: %s", DATA_PATH)
        sys.exit(1)

    logger.info("Seeding %d campaigns into Neo4j...", len(campaigns))
    driver = get_driver()
    try:
        with driver.session() as session:
            load_campaigns(session, campaigns)
        logger.info("Seeding complete.")
    except Exception as e:
        logger.error("Seeding failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
