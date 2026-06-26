import logging
import sys

from rich.console import Console
from rich.table import Table

from db_connect import get_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.query")
console = Console()

LOOKUP_DOMAIN_QUERY = """
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain {name: $domain})
MATCH (c)-[:PROMOTED_ON]->(p:Platform)
RETURN c.name AS campaign, p.name AS platform, c.risk_score AS risk_score
"""


def lookup_domain(session, domain: str) -> list[dict]:
    result = session.run(LOOKUP_DOMAIN_QUERY, domain=domain)
    records = [
        {
            "campaign": r["campaign"],
            "platform": r["platform"],
            "risk_score": r["risk_score"],
        }
        for r in result
    ]
    return records


def display_results(domain: str, records: list[dict]):
    if not records:
        console.print(f"[yellow]No campaigns found for domain:[/yellow] {domain}")
        return

    table = Table(title=f"Sentinel — Domain Lookup: {domain}", show_lines=True)
    table.add_column("Campaign", style="cyan")
    table.add_column("Platform", style="magenta")
    table.add_column("Risk Score", style="red", justify="right")

    for r in records:
        table.add_row(r["campaign"], r["platform"], f"{r['risk_score']:.2f}")

    console.print(table)


def main():
    demo_domains = [
        "quantum-ai-invest.com",
        "martinlewis-crypto.net",
        "bbc-cryptonews.org",
        "fca-recovery-fund.co.uk",
        "turkiye-yatirim-kripto.com",
    ]

    driver = get_driver()
    try:
        with driver.session() as session:
            for domain in demo_domains:
                logger.info("Looking up domain: %s", domain)
                records = lookup_domain(session, domain)
                display_results(domain, records)
    except Exception as e:
        logger.error("Query failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
