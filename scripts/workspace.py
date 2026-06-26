"""
Investigation Workspace — multi-domain case aggregation for Sentinel.

Pure functions (no Streamlit, no reportlab) that turn a list of single-domain
investigation reports (from attribution_engine.build_report) into a case-level
view: combined metrics, a fraud-network narrative, a merged timeline, a
graph-row list for the combined PyVis graph, and JSON/Markdown export payloads.
"""
from collections import Counter


# ---------------------------------------------------------------------------
# Graph rows (schema matches dashboard build_network: ltype/lname/lprop/rel/
# rtype/rname/confidence) — merging shared nodes happens inside build_network.
# ---------------------------------------------------------------------------

def report_to_graph_rows(report: dict) -> list[dict]:
    """Convert one investigation report into combined-graph edge rows."""
    domain = report["domain"]
    rows: list[dict] = [
        # Standalone domain node (guarantees the domain shows even with no edges).
        {"ltype": "domain", "lname": domain, "lprop": "",
         "rel": "", "rtype": "", "rname": "",
         "confidence": report.get("confidence_score", 0.0)},
    ]

    for s in report["intelligence_sources"]:
        rows.append({
            "ltype": "source", "lname": s["name"], "lprop": s.get("source_type") or "",
            "rel": "FLAGGED", "rtype": "domain", "rname": domain,
            "confidence": s.get("confidence") or 0.0,
        })

    for c in report["connected_campaigns"]:
        rows.append({
            "ltype": "campaign", "lname": c["name"], "lprop": c.get("scam_type") or "",
            "rel": "USES_DOMAIN", "rtype": "domain", "rname": domain,
            "confidence": c.get("risk_score") or 0.0,
        })
        for p in c["platforms"]:
            rows.append({
                "ltype": "campaign", "lname": c["name"], "lprop": c.get("scam_type") or "",
                "rel": "PROMOTED_ON", "rtype": "platform", "rname": p,
                "confidence": 0.0,
            })

    return rows


def workspace_graph_rows(reports: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for r in reports:
        rows.extend(report_to_graph_rows(r))
    return rows


# ---------------------------------------------------------------------------
# Metrics + narrative
# ---------------------------------------------------------------------------

def aggregate_metrics(reports: list[dict]) -> dict:
    campaigns: set[str] = set()
    platforms: set[str] = set()
    sources: set[str] = set()
    confs: list[float] = []

    for r in reports:
        confs.append(float(r.get("confidence_score") or 0.0))
        for c in r["connected_campaigns"]:
            if c.get("name"):
                campaigns.add(c["name"])
        for p in r["connected_platforms"]:
            platforms.add(p)
        for s in r["intelligence_sources"]:
            sources.add(s["name"])

    avg = round(sum(confs) / len(confs), 4) if confs else 0.0
    return {
        "total_domains": len(reports),
        "total_campaigns": len(campaigns),
        "total_platforms": len(platforms),
        "total_sources": len(sources),
        "average_confidence": avg,
        "campaigns": sorted(campaigns),
        "platforms": sorted(platforms),
        "sources": sorted(sources),
    }


def fraud_network_summary(reports: list[dict], metrics: dict) -> str:
    """Short analyst narrative describing the case-level fraud picture."""
    if not reports:
        return "No domains have been added to this case yet."

    n_d = metrics["total_domains"]
    n_c = metrics["total_campaigns"]
    n_p = metrics["total_platforms"]

    # Detect shared infrastructure: a campaign or source touching >1 domain.
    camp_counter: Counter = Counter()
    src_counter: Counter = Counter()
    for r in reports:
        for c in r["connected_campaigns"]:
            if c.get("name"):
                camp_counter[c["name"]] += 1
        for s in r["intelligence_sources"]:
            src_counter[s["name"]] += 1
    shared = sorted(
        {k for k, v in camp_counter.items() if v > 1}
        | {k for k, v in src_counter.items() if v > 1}
    )

    parts = [
        f"This case contains {n_d} domain(s) linked to {n_c} campaign(s) "
        f"and {n_p} platform(s)."
    ]
    if shared:
        parts.append(
            "Multiple domains share infrastructure patterns ("
            + ", ".join(shared[:5])
            + "), suggesting a coordinated fraud operation."
        )
    elif n_d > 1:
        parts.append(
            "No shared campaigns or sources were detected across these domains; "
            "they may be independent or part of separate operations."
        )
    parts.append(
        f"Average attribution confidence across the case is "
        f"{metrics['average_confidence']:.2f}."
    )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Merged timeline
# ---------------------------------------------------------------------------

def merge_timeline(reports: list[dict]) -> list[dict]:
    """Combine all per-domain timelines into one chronological list."""
    events: list[dict] = []
    for r in reports:
        for e in r.get("timeline", []):
            events.append({
                "date": e["date"],
                "event_type": e["event_type"],
                "domain": r["domain"],
                "entity": e["entity"],
                "description": e["description"],
                "confidence": e.get("confidence"),
            })
    events.sort(key=lambda x: x["date"])
    return events


# ---------------------------------------------------------------------------
# Export payload + Markdown
# ---------------------------------------------------------------------------

def build_workspace_payload(case: dict, reports: list[dict]) -> dict:
    """Assemble the full case-level export payload."""
    metrics = aggregate_metrics(reports)
    return {
        "case_id": case["case_id"],
        "status": case["status"],
        "severity": case["severity"],
        "created": case["created"],
        "metrics": metrics,
        "fraud_network_summary": fraud_network_summary(reports, metrics),
        "timeline": merge_timeline(reports),
        "domains": reports,
    }


def _cell(value) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ")


def workspace_to_markdown(payload: dict) -> str:
    """Render the workspace payload as an analyst Markdown case file."""
    m = payload["metrics"]
    lines: list[str] = [
        "# Sentinel Investigation Workspace",
        "",
        f"**Case ID:** {payload['case_id']}",
        "",
        f"**Status:** {payload['status']}",
        "",
        f"**Severity:** {payload['severity']}",
        "",
        f"**Created:** {payload['created']}",
        "",
        "## Fraud Network Summary",
        "",
        payload["fraud_network_summary"],
        "",
        "## Investigation Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Domains | {m['total_domains']} |",
        f"| Total Campaigns | {m['total_campaigns']} |",
        f"| Total Platforms | {m['total_platforms']} |",
        f"| Total Sources | {m['total_sources']} |",
        f"| Average Confidence | {m['average_confidence']:.2f} |",
        "",
        "## Domains",
        "",
    ]

    if payload["domains"]:
        lines.append("| Domain | Verdict | Confidence | Recommended Action |")
        lines.append("|--------|---------|------------|--------------------|")
        for r in payload["domains"]:
            lines.append(
                f"| {_cell(r['domain'])} | {r['verdict']} "
                f"| {r['confidence_score']:.2f} "
                f"| {_cell(r.get('recommended_action'))} |"
            )
    else:
        lines.append("_No domains in case._")

    lines += ["", "## Case Timeline", ""]
    if payload["timeline"]:
        lines.append("| Date | Event Type | Domain | Entity | Description | Confidence |")
        lines.append("|------|-----------|--------|--------|-------------|------------|")
        for e in payload["timeline"]:
            conf = e.get("confidence")
            conf_s = f"{conf:.2f}" if conf is not None else "—"
            lines.append(
                f"| {e['date']} | {e['event_type']} | {_cell(e['domain'])} "
                f"| {_cell(e['entity'])} | {_cell(e['description'])} | {conf_s} |"
            )
    else:
        lines.append("_No timeline events recorded._")

    lines.append("")
    return "\n".join(lines)
