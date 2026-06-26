import logging
import sys

from db_connect import get_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.schema")

CONSTRAINTS = [
    (
        "campaign_id_unique",
        "CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS "
        "FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
    ),
    (
        "domain_name_unique",
        "CREATE CONSTRAINT domain_name_unique IF NOT EXISTS "
        "FOR (d:Domain) REQUIRE d.name IS UNIQUE",
    ),
    (
        "platform_name_unique",
        "CREATE CONSTRAINT platform_name_unique IF NOT EXISTS "
        "FOR (p:Platform) REQUIRE p.name IS UNIQUE",
    ),
    (
        "scamsource_name_unique",
        "CREATE CONSTRAINT scamsource_name_unique IF NOT EXISTS "
        "FOR (s:ScamSource) REQUIRE s.name IS UNIQUE",
    ),
]


def apply_constraints(session):
    for name, cypher in CONSTRAINTS:
        try:
            session.run(cypher)
            logger.info("Constraint applied: %s", name)
        except Exception as e:
            logger.error("Failed to apply constraint %s: %s", name, e)
            raise


def main():
    logger.info("Applying schema constraints...")
    driver = get_driver()
    try:
        with driver.session() as session:
            apply_constraints(session)
        logger.info("Schema setup complete.")
    except Exception as e:
        logger.error("Schema setup failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
