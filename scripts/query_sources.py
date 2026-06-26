"""
query_sources.py — display all intelligence-sourced domains in the Sentinel graph.

Shows: domain, source, confidence, first_seen.
"""
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.query_sources")
console = Console()

QUERY = """
MATCH (s:ScamSource)-[r:FLAGGED]->(d:Domain)
RETURN
    d.name        AS domain,
    s.name        AS source,
    s.source_type AS source_type,
    r.confidence  AS confidence,
    r.first_seen  AS first_seen
ORDER BY r.confidence DESC, d.name ASC
"""


def fetch_flagged_domains(session) -> list[dict]:
    result = session.run(QUERY)
    return [
        {
            "domain":      r["domain"],
            "source":      r["source"],
            "source_type": r["source_type"],
            "confidence":  r["confidence"],
            "first_seen":  (r["first_seen"] or "")[:19].replace("T", " "),
        }
        for r in result
    ]


def display(records: list[dict]):
    if not records:
        console.print("[yellow]No sourced domains found. Run the ingestion scripts first.[/yellow]")
        return

    table = Table(
        title=f"Sentinel — Intelligence Sources ({len(records)} domains)",
        show_lines=True,
    )
    table.add_column("Domain",       style="cyan",    no_wrap=True)
    table.add_column("Source",       style="magenta")
    table.add_column("Type",         style="blue")
    table.add_column("Confidence",   style="red",     justify="right")
    table.add_column("First Seen",   style="dim")

    for r in records:
        conf = r["confidence"]
        conf_str = f"{conf:.2f}" if conf is not None else "—"
        table.add_row(
            r["domain"],
            r["source"],
            r["source_type"],
            conf_str,
            r["first_seen"] or "—",
        )

    console.print(table)


def main():
    driver = get_driver()
    try:
        with driver.session() as session:
            records = fetch_flagged_domains(session)
        logger.info("Retrieved %d sourced domain records.", len(records))
        display(records)
    except Exception as e:
        logger.error("Query failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
