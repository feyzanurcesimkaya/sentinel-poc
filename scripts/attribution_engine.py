"""
Sentinel Attribution Engine
===========================

Given a domain, assembles a structured investigation report from the ScamGraph:

    - why the domain is suspicious            -> reasons[]
    - which intelligence sources flagged it   -> intelligence_sources[]
    - connected scam campaigns                -> connected_campaigns[]
    - connected social platforms              -> connected_platforms[]
    - similar domains                         -> similar_domains[]
    - an aggregated confidence score          -> confidence_score
    - a human-readable verdict + narrative    -> verdict, summary

The engine is deterministic and rule-based so it runs offline with no LLM
dependency.  `build_report(session, domain)` is the single entry point and is
imported by both `api.py` (POST /investigate) and the Streamlit dashboard.
"""
import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.attribution")

# ---------------------------------------------------------------------------
# Cypher
# ---------------------------------------------------------------------------

_DOMAIN_NODE_QUERY = """
MATCH (d:Domain {name: $domain})
RETURN d.name AS name,
       d.confidence AS confidence,
       d.first_seen AS first_seen,
       d.source AS source
"""

_SOURCES_QUERY = """
MATCH (s:ScamSource)-[r:FLAGGED]->(d:Domain {name: $domain})
RETURN s.name AS name,
       s.source_type AS source_type,
       s.url AS url,
       r.confidence AS confidence,
       r.first_seen AS first_seen
ORDER BY r.confidence DESC
"""

_CAMPAIGNS_QUERY = """
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain {name: $domain})
OPTIONAL MATCH (c)-[:PROMOTED_ON]->(p:Platform)
RETURN c.campaign_id AS campaign_id,
       c.name AS name,
       c.scam_type AS scam_type,
       c.risk_score AS risk_score,
       collect(DISTINCT p.name) AS platforms
"""

# Similar domains: shared campaign OR shared intelligence source.
_SIMILAR_BY_LINK_QUERY = """
MATCH (d:Domain {name: $domain})
MATCH (other:Domain)
WHERE other.name <> $domain
OPTIONAL MATCH (c:Campaign)-[:USES_DOMAIN]->(d)
OPTIONAL MATCH (c)-[:USES_DOMAIN]->(other)
WITH d, other, count(DISTINCT c) AS shared_campaigns
OPTIONAL MATCH (s:ScamSource)-[:FLAGGED]->(d)
OPTIONAL MATCH (s)-[:FLAGGED]->(other)
WITH other, shared_campaigns, count(DISTINCT s) AS shared_sources
WHERE shared_campaigns > 0 OR shared_sources > 0
RETURN other.name AS domain,
       other.confidence AS confidence,
       shared_campaigns,
       shared_sources
ORDER BY shared_campaigns DESC, shared_sources DESC
LIMIT 8
"""

# Candidate pool for lexical similarity when graph links are sparse.
_ALL_DOMAINS_QUERY = """
MATCH (d:Domain)
WHERE d.name <> $domain
RETURN d.name AS domain, d.confidence AS confidence
"""

# Generic scam keywords used for lexical similarity + reasoning hints.
_SCAM_KEYWORDS = {
    "crypto", "bitcoin", "invest", "investment", "quantum", "ai",
    "recovery", "fund", "refund", "tax", "hmrc", "fca", "secure",
    "login", "verify", "bank", "wallet", "giveaway", "bonus",
    "official", "authorised", "authority", "broker", "trading",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tokenize(domain: str) -> set[str]:
    """Split a domain into lowercase alphanumeric tokens (drops the TLD)."""
    stem = domain.lower().rsplit(".", 1)[0] if "." in domain else domain.lower()
    return {t for t in re.split(r"[^a-z0-9]+", stem) if len(t) >= 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _clean_ts(value) -> str | None:
    if not value:
        return None
    return str(value)[:19].replace("T", " ")


def _classify(score: float) -> str:
    if score >= 0.8:
        return "MALICIOUS"
    if score >= 0.5:
        return "SUSPICIOUS"
    if score > 0.0:
        return "LOW_RISK"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _compute_confidence(domain_conf, sources, campaigns) -> float:
    """
    Aggregate a single confidence score in [0, 1] from independent signals:

      - the domain's own ingested confidence
      - the strongest intelligence-source confidence
      - the highest connected campaign risk score
      - a small corroboration bonus when multiple sources agree
    """
    signals: list[float] = []

    if domain_conf is not None:
        signals.append(float(domain_conf))

    if sources:
        signals.append(max(float(s["confidence"] or 0.0) for s in sources))

    if campaigns:
        signals.append(max(float(c["risk_score"] or 0.0) for c in campaigns))

    if not signals:
        return 0.0

    base = max(signals)

    # Corroboration: each additional flagging source nudges confidence up.
    corroboration = min(0.10, 0.03 * max(0, len(sources) - 1))

    return round(min(1.0, base + corroboration), 4)


# ---------------------------------------------------------------------------
# Similar domains
# ---------------------------------------------------------------------------

def _find_similar(session, domain: str, linked: list[dict]) -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set()

    # 1. Graph-linked domains (shared campaign or source) — strongest signal.
    for row in linked:
        name = row["domain"]
        if name in seen:
            continue
        seen.add(name)
        reasons = []
        if row.get("shared_campaigns", 0) > 0:
            reasons.append(f"{row['shared_campaigns']} shared campaign(s)")
        if row.get("shared_sources", 0) > 0:
            reasons.append(f"{row['shared_sources']} shared source(s)")
        results.append({
            "domain": name,
            "confidence": float(row["confidence"]) if row.get("confidence") is not None else None,
            "similarity": round(0.6 + 0.1 * len(reasons), 2),
            "reason": "; ".join(reasons) or "graph-linked",
        })

    # 2. Lexical similarity over the remaining domain pool.
    target_tokens = _tokenize(domain)
    if target_tokens:
        for row in session.run(_ALL_DOMAINS_QUERY, domain=domain):
            name = row["domain"]
            if name in seen:
                continue
            sim = _jaccard(target_tokens, _tokenize(name))
            if sim >= 0.34:  # at least a meaningful shared token
                seen.add(name)
                shared = target_tokens & _tokenize(name)
                results.append({
                    "domain": name,
                    "confidence": float(row["confidence"]) if row["confidence"] is not None else None,
                    "similarity": round(sim, 2),
                    "reason": f"shared tokens: {', '.join(sorted(shared))}",
                })

    results.sort(key=lambda r: r["similarity"], reverse=True)
    return results[:8]


# ---------------------------------------------------------------------------
# Narrative generation
# ---------------------------------------------------------------------------

def _build_reasons(domain, sources, campaigns, similar, keyword_hits) -> list[str]:
    reasons: list[str] = []

    if sources:
        names = ", ".join(s["name"] for s in sources)
        reasons.append(
            f"Flagged by {len(sources)} intelligence source(s): {names}."
        )

    for c in campaigns:
        plats = ", ".join(c["platforms"]) if c["platforms"] else "unknown platforms"
        reasons.append(
            f"Linked to scam campaign '{c['name']}' "
            f"(type: {c['scam_type'] or 'unspecified'}, "
            f"risk {float(c['risk_score'] or 0):.2f}) promoted on {plats}."
        )

    if keyword_hits:
        reasons.append(
            "Domain name contains high-risk scam keywords: "
            f"{', '.join(sorted(keyword_hits))}."
        )

    if similar:
        reasons.append(
            f"Resembles {len(similar)} other known domain(s) in the ScamGraph, "
            "suggesting a coordinated infrastructure cluster."
        )

    if not reasons:
        reasons.append(
            "No corroborating intelligence found in the ScamGraph for this domain."
        )

    return reasons


def _build_summary(domain, verdict, score, sources, campaigns, similar) -> str:
    if verdict == "UNKNOWN":
        return (
            f"Sentinel has no attribution data for '{domain}'. It does not appear "
            f"in any ingested intelligence feed or scam campaign. Treat as unverified "
            f"rather than safe — absence of evidence is not evidence of absence."
        )

    parts = [
        f"Sentinel assesses '{domain}' as {verdict} with an aggregated confidence "
        f"of {score:.2f}."
    ]

    if sources:
        src_types = sorted({s["source_type"] for s in sources if s["source_type"]})
        parts.append(
            f"It was independently flagged by {len(sources)} source(s)"
            + (f" ({', '.join(src_types)})" if src_types else "")
            + "."
        )

    if campaigns:
        camp_names = ", ".join(c["name"] for c in campaigns)
        parts.append(
            f"The domain is operationally tied to {len(campaigns)} scam campaign(s): "
            f"{camp_names}."
        )

    if similar:
        parts.append(
            f"It clusters with {len(similar)} similar domain(s), indicating it is "
            f"likely part of a larger fraud network rather than an isolated site."
        )

    parts.append(
        "Recommended action: block at the network edge and alert affected customers."
        if score >= 0.8 else
        "Recommended action: monitor and corroborate before enforcement."
    )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Timeline + recommended action
# ---------------------------------------------------------------------------

# Analyst playbook: one recommended action per verdict tier.
_RECOMMENDED_ACTION = {
    "MALICIOUS":  "Block domain immediately, alert affected customers, and escalate to fraud operations.",
    "SUSPICIOUS": "Escalate to fraud review and monitor related domains.",
    "LOW_RISK":   "Monitor only; no immediate blocking action recommended.",
    "UNKNOWN":    "Collect additional intelligence before enforcement.",
}


def _event_date(first_seen, fallback_date: str) -> str:
    """Return the YYYY-MM-DD date for an event, falling back when first_seen is missing."""
    if first_seen:
        return str(first_seen)[:10]
    return fallback_date


def _build_timeline(domain_first_seen, sources, campaigns, generated_at: str) -> list[dict]:
    """
    Construct a chronological list of investigation events from graph evidence.

    Event types:
      - SOURCE_FLAG   : an intelligence source flagged the domain
      - CAMPAIGN_LINK : the domain is linked to a scam campaign
      - PLATFORM_LINK : the campaign was promoted on a platform

    Dates use each entity's first_seen when present, otherwise the report's
    generation date. Returns [] when there is no evidence at all.
    """
    fallback = generated_at[:10]
    events: list[dict] = []

    for s in sources:
        events.append({
            "date": _event_date(s.get("first_seen"), fallback),
            "event_type": "SOURCE_FLAG",
            "entity": s["name"],
            "description": f"Domain was flagged by {s['name']}.",
            "confidence": s.get("confidence"),
        })

    for c in campaigns:
        # Campaign links inherit the domain's first_seen (no edge timestamp exists).
        c_date = _event_date(domain_first_seen, fallback)
        events.append({
            "date": c_date,
            "event_type": "CAMPAIGN_LINK",
            "entity": c["name"],
            "description": f"Domain is linked to campaign {c['name']}.",
            "confidence": c.get("risk_score"),
        })
        for p in c["platforms"]:
            events.append({
                "date": c_date,
                "event_type": "PLATFORM_LINK",
                "entity": p,
                "description": f"Campaign was promoted on {p}.",
            })

    events.sort(key=lambda e: e["date"])
    return events


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_report(session, domain: str) -> dict:
    """
    Run the full attribution investigation for `domain` and return a structured
    report dict. `session` is an open Neo4j session.
    """
    domain = domain.strip().lower()
    logger.info("Investigating domain: %s", domain)

    # --- Gather raw graph evidence ---------------------------------------
    node = session.run(_DOMAIN_NODE_QUERY, domain=domain).single()
    domain_known = node is not None

    sources = [
        {
            "name": r["name"],
            "source_type": r["source_type"],
            "url": r["url"],
            "confidence": float(r["confidence"]) if r["confidence"] is not None else None,
            "first_seen": _clean_ts(r["first_seen"]),
        }
        for r in session.run(_SOURCES_QUERY, domain=domain)
    ]

    campaigns = [
        {
            "campaign_id": r["campaign_id"],
            "name": r["name"],
            "scam_type": r["scam_type"],
            "risk_score": float(r["risk_score"]) if r["risk_score"] is not None else None,
            "platforms": [p for p in r["platforms"] if p],
        }
        for r in session.run(_CAMPAIGNS_QUERY, domain=domain)
    ]

    linked = [dict(r) for r in session.run(_SIMILAR_BY_LINK_QUERY, domain=domain)]
    similar = _find_similar(session, domain, linked)

    # --- Derive signals ---------------------------------------------------
    platforms = sorted({p for c in campaigns for p in c["platforms"]})
    keyword_hits = _tokenize(domain) & _SCAM_KEYWORDS

    domain_conf = node["confidence"] if domain_known else None
    confidence = _compute_confidence(domain_conf, sources, campaigns)

    # Keyword presence alone gives a weak floor when nothing else is known.
    if confidence == 0.0 and keyword_hits:
        confidence = round(min(0.45, 0.15 * len(keyword_hits)), 4)

    verdict = _classify(confidence)

    reasons = _build_reasons(domain, sources, campaigns, similar, keyword_hits)
    summary = _build_summary(domain, verdict, confidence, sources, campaigns, similar)

    generated_at = datetime.now(timezone.utc).isoformat()
    domain_first_seen = _clean_ts(node["first_seen"]) if domain_known else None
    timeline = _build_timeline(domain_first_seen, sources, campaigns, generated_at)
    recommended_action = _RECOMMENDED_ACTION.get(verdict, _RECOMMENDED_ACTION["UNKNOWN"])

    report = {
        "domain": domain,
        "known_to_sentinel": domain_known,
        "verdict": verdict,
        "confidence_score": confidence,
        "summary": summary,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "intelligence_sources": sources,
        "connected_campaigns": campaigns,
        "connected_platforms": platforms,
        "similar_domains": similar,
        "keyword_indicators": sorted(keyword_hits),
        "timeline": timeline,
        "generated_at": generated_at,
    }

    logger.info(
        "Investigation complete for '%s': verdict=%s confidence=%.2f "
        "(sources=%d campaigns=%d similar=%d)",
        domain, verdict, confidence, len(sources), len(campaigns), len(similar),
    )
    return report


# ---------------------------------------------------------------------------
# Report export helpers (shared by dashboard + API)
# ---------------------------------------------------------------------------

def slugify_domain(domain: str) -> str:
    """apple-id-suspended.com -> apple-id-suspended-com"""
    return re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")


def build_case_id(domain: str, generated_at: str) -> str:
    """CASE-{YYYYMMDD}-{domain-slug}"""
    yyyymmdd = generated_at[:10].replace("-", "")
    return f"CASE-{yyyymmdd}-{slugify_domain(domain)}"


def export_filename(domain: str, generated_at: str, ext: str) -> str:
    """sentinel_case_{domain-slug}_{YYYYMMDD}.{ext}"""
    yyyymmdd = generated_at[:10].replace("-", "")
    return f"sentinel_case_{slugify_domain(domain)}_{yyyymmdd}.{ext}"


def _md_cell(value) -> str:
    """Escape a value for safe use inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def report_to_markdown(report: dict) -> str:
    """
    Render an investigation report dict as a formatted analyst Markdown document.
    Handles empty sources/campaigns/platforms/timeline/similar gracefully.
    """
    case_id = build_case_id(report["domain"], report["generated_at"])
    conf_pct = f"{round(report['confidence_score'] * 100)}%"

    lines: list[str] = [
        "# Sentinel Investigation Case Report",
        "",
        f"**Case ID:** {case_id}",
        "",
        f"**Domain:** {report['domain']}",
        "",
        f"**Verdict:** {report['verdict']}",
        "",
        f"**Confidence:** {conf_pct}",
        "",
        f"**Generated:** {report['generated_at']}",
        "",
        "## Executive Summary",
        "",
        report.get("summary") or "_No summary available._",
        "",
        "## Recommended Action",
        "",
        report.get("recommended_action") or "_None._",
        "",
        "## Attribution Chain",
        "",
    ]

    src = ", ".join(s["name"] for s in report["intelligence_sources"]) or "—"
    camp = ", ".join(c["name"] for c in report["connected_campaigns"]) or "—"
    plat = ", ".join(report["connected_platforms"]) or "—"
    lines.append(f"{src} → {report['domain']} → {camp} → {plat}")
    lines += ["", "## Investigation Timeline", ""]

    if report.get("timeline"):
        lines.append("| Date | Event Type | Entity | Description | Confidence |")
        lines.append("|------|-----------|--------|-------------|------------|")
        for e in report["timeline"]:
            conf = e.get("confidence")
            conf_s = f"{conf:.2f}" if conf is not None else "—"
            lines.append(
                f"| {e['date']} | {e['event_type']} | {_md_cell(e['entity'])} "
                f"| {_md_cell(e['description'])} | {conf_s} |"
            )
    else:
        lines.append("_No timeline events recorded._")

    lines += ["", "## Evidence Summary", "", "### Intelligence Sources", ""]
    if report["intelligence_sources"]:
        lines.append("| Source | Type | Confidence | First Seen |")
        lines.append("|--------|------|------------|------------|")
        for s in report["intelligence_sources"]:
            conf = s.get("confidence")
            conf_s = f"{conf:.2f}" if conf is not None else "—"
            lines.append(
                f"| {_md_cell(s['name'])} | {s.get('source_type') or '—'} "
                f"| {conf_s} | {s.get('first_seen') or '—'} |"
            )
    else:
        lines.append("_None._")

    lines += ["", "### Connected Campaigns", ""]
    if report["connected_campaigns"]:
        lines.append("| Campaign | Scam Type | Risk | Platforms |")
        lines.append("|----------|-----------|------|-----------|")
        for c in report["connected_campaigns"]:
            risk = c.get("risk_score")
            risk_s = f"{risk:.2f}" if risk is not None else "—"
            plats = ", ".join(c["platforms"]) or "—"
            lines.append(
                f"| {_md_cell(c['name'])} | {c.get('scam_type') or '—'} "
                f"| {risk_s} | {_md_cell(plats)} |"
            )
    else:
        lines.append("_None._")

    lines += ["", "### Connected Platforms", ""]
    if report["connected_platforms"]:
        lines += [f"- {p}" for p in report["connected_platforms"]]
    else:
        lines.append("_None._")

    lines += ["", "### Similar Domains", ""]
    if report["similar_domains"]:
        lines.append("| Domain | Similarity | Confidence | Reason |")
        lines.append("|--------|-----------|------------|--------|")
        for s in report["similar_domains"]:
            conf = s.get("confidence")
            conf_s = f"{conf:.2f}" if conf is not None else "—"
            lines.append(
                f"| {_md_cell(s['domain'])} | {s['similarity']:.2f} "
                f"| {conf_s} | {_md_cell(s['reason'])} |"
            )
    else:
        lines.append("_None._")

    lines.append("")
    return "\n".join(lines)
