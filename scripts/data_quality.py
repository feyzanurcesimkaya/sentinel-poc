"""
Data quality + normalization pass for the Sentinel graph.

Runnable maintenance step (no engine logic):
  - validate & remove malformed Domain nodes (IPs, bad hostnames),
  - report duplicate / orphan domains (MERGE already prevents dup nodes),
  - normalize Campaign nodes (snake_case scam_type, trimmed names, default risk),
  - print a quality summary with final counts.

run_quality_checks(session) -> dict
"""
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_connect import get_driver
from ingest_common import is_valid_domain

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.data_quality")


def validate_and_clean_domains(session) -> dict:
    """Remove Domain nodes whose name is not a valid registrable hostname."""
    names = [r["name"] for r in session.run("MATCH (d:Domain) RETURN d.name AS name")]
    invalid = [n for n in names if not is_valid_domain(n)]
    for name in invalid:
        session.run("MATCH (d:Domain {name: $n}) DETACH DELETE d", n=name)
    if invalid:
        logger.info("Removed %d invalid domains: %s", len(invalid), invalid[:10])
    return {"total_before": len(names), "invalid_removed": len(invalid)}


def report_duplicates_and_orphans(session) -> dict:
    # Domain uniqueness is enforced by constraint; report orphans (no evidence edges).
    orphans = session.run(
        "MATCH (d:Domain) WHERE NOT (d)<-[:FLAGGED]-() AND NOT ()-[:USES_DOMAIN]->(d) "
        "RETURN count(d) AS n"
    ).single()["n"]
    dup_names = session.run(
        "MATCH (d:Domain) WITH d.name AS name, count(*) AS c WHERE c > 1 RETURN count(name) AS n"
    ).single()["n"]
    return {"orphan_domains": orphans, "duplicate_domain_names": dup_names}


def normalize_campaigns(session) -> dict:
    """Standardise scam_type (snake_case), trim names, default missing risk."""
    rows = list(session.run(
        "MATCH (c:Campaign) RETURN c.campaign_id AS id, c.name AS name, "
        "c.scam_type AS scam_type, c.risk_score AS risk"
    ))
    changed = 0
    for r in rows:
        scam_type = re.sub(r"[^a-z0-9]+", "_", (r["scam_type"] or "unspecified").strip().lower()).strip("_")
        name = (r["name"] or r["id"] or "Unnamed Campaign").strip()
        risk = r["risk"] if r["risk"] is not None else 0.5
        if (scam_type != r["scam_type"]) or (name != r["name"]) or (risk != r["risk"]):
            session.run(
                "MATCH (c:Campaign {campaign_id: $id}) "
                "SET c.scam_type = $st, c.name = $name, c.risk_score = $risk",
                id=r["id"], st=scam_type, name=name, risk=risk,
            )
            changed += 1
    return {"campaigns_total": len(rows), "campaigns_normalized": changed}


def graph_counts(session) -> dict:
    return {
        "domains": session.run("MATCH (d:Domain) RETURN count(d) AS n").single()["n"],
        "sources": session.run("MATCH (s:ScamSource) RETURN count(s) AS n").single()["n"],
        "campaigns": session.run("MATCH (c:Campaign) RETURN count(c) AS n").single()["n"],
        "flagged": session.run("MATCH ()-[r:FLAGGED]->() RETURN count(r) AS n").single()["n"],
    }


def run_quality_checks(session) -> dict:
    cleaned = validate_and_clean_domains(session)
    dup = report_duplicates_and_orphans(session)
    camp = normalize_campaigns(session)
    counts = graph_counts(session)
    result = {**cleaned, **dup, **camp, "counts": counts}
    logger.info("Data quality summary: %s", result)
    return result


def main():
    driver = get_driver()
    try:
        with driver.session() as session:
            res = run_quality_checks(session)
        c = res["counts"]
        print("\n=== Sentinel Data Quality Report ===")
        print(f"  invalid domains removed : {res['invalid_removed']}")
        print(f"  duplicate domain names  : {res['duplicate_domain_names']}")
        print(f"  orphan domains          : {res['orphan_domains']}")
        print(f"  campaigns normalized    : {res['campaigns_normalized']}/{res['campaigns_total']}")
        print(f"  FINAL: domains={c['domains']} sources={c['sources']} "
              f"campaigns={c['campaigns']} flagged={c['flagged']}")
    except Exception as e:
        logger.error("Data quality run failed: %s", e)
        sys.exit(1)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
