"""
Fraud Network Trend Intelligence
================================

Tracks growth, activity, and risk evolution of FraudClusters over time.

The only temporal signal in the graph is Domain.first_seen (set at ingestion).
This engine derives, per cluster, a deterministic trend view:

  first_seen / last_seen   — earliest / latest domain first_seen in the cluster
  domain/campaign/source_count
  growth_rate              — fraction of domains first seen within RECENT_DAYS
  activity_score           — recency + size + risk, in [0, 1]
  trend_status            — EMERGING / ACTIVE / EXPANDING / DORMANT (rule-based)
  narrative                — analyst sentence describing the evolution

No ML, no randomness — identical input graph yields identical trends. As real
longitudinal data accumulates (repeated ingestion across days), growth_rate and
the "expanded from X to Y" narrative become richer automatically.
"""
import logging
from datetime import date, datetime, timedelta, timezone

logger = logging.getLogger("sentinel.trend")

# Deterministic thresholds.
RECENT_DAYS = 14            # window that counts as "recent activity"
DORMANT_DAYS = 30           # no activity beyond this -> dormant
EMERGING_MAX_DOMAINS = 3    # "small" cluster
EMERGING_MIN_CONF = 0.8     # "high confidence"
EXPANDING_MIN_DOMAINS = 3
EXPANDING_MIN_GROWTH = 0.3


def _parse_date(value):
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _trend_status(domain_count, growth_rate, confidence, risk, dates, now) -> str:
    """Deterministic status from size, growth, recency, and risk."""
    if not dates:
        # No temporal signal (e.g. seed-only domains): fall back to risk.
        return "ACTIVE" if risk >= 0.8 else "DORMANT"

    age = (now - max(dates)).days
    is_recent = age <= RECENT_DAYS
    is_stale = age > DORMANT_DAYS

    if domain_count >= EXPANDING_MIN_DOMAINS and growth_rate >= EXPANDING_MIN_GROWTH:
        return "EXPANDING"
    if domain_count <= EMERGING_MAX_DOMAINS and confidence >= EMERGING_MIN_CONF and is_recent:
        return "EMERGING"
    if is_stale:
        return "DORMANT"
    return "ACTIVE"


def trend_narrative(t: dict) -> str:
    cid = t["cluster_id"]
    dc = t["domain_count"]
    base = t["baseline_domain_count"]
    rec = t["recent_domain_count"]
    tail = {
        "EXPANDING": "and is an expanding fraud network",
        "ACTIVE":    "and remains an active fraud network",
        "EMERGING":  "and is an emerging fraud network to watch",
        "DORMANT":   "and is currently dormant",
    }[t["trend_status"]]

    if base > 0 and rec > 0:
        head = f"{cid} expanded from {base} to {dc} domains"
    elif rec == dc and dc > 1:
        head = f"{cid} newly formed with {dc} domains appearing recently"
    elif dc == 1:
        head = f"{cid} consists of a single domain"
    else:
        head = f"{cid} holds steady at {dc} domains"
    return f"{head} {tail}."


def analyze_cluster(cluster: dict, now: date) -> dict:
    members = cluster.get("members", [])
    dates = [d for d in (_parse_date(m.get("first_seen")) for m in members) if d]

    dc = cluster["domain_count"]
    recent_cut = now - timedelta(days=RECENT_DAYS)
    recent = sum(1 for d in dates if d >= recent_cut)
    baseline = dc - recent
    growth_rate = round(recent / dc, 4) if dc else 0.0

    if dates:
        age = (now - max(dates)).days
        recency = max(0.0, 1.0 - age / DORMANT_DAYS)
    else:
        recency = 0.0
    size_factor = min(1.0, dc / 10.0)
    activity = round(0.5 * recency + 0.3 * size_factor + 0.2 * cluster["risk_score"], 4)

    status = _trend_status(dc, growth_rate, cluster["confidence"], cluster["risk_score"], dates, now)

    trend = {
        "cluster_id": cluster["cluster_id"],
        "risk_score": cluster["risk_score"],
        "confidence": cluster["confidence"],
        "first_seen": min(dates).isoformat() if dates else None,
        "last_seen": max(dates).isoformat() if dates else None,
        "domain_count": dc,
        "campaign_count": cluster["campaign_count"],
        "source_count": cluster["source_count"],
        "baseline_domain_count": baseline,
        "recent_domain_count": recent,
        "growth_rate": growth_rate,
        "activity_score": activity,
        "trend_status": status,
    }
    trend["narrative"] = trend_narrative(trend)
    return trend


def compute_trends(clusters: list[dict], now: date | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc).date()
    trends = [analyze_cluster(c, now) for c in clusters]
    logger.info("Computed trends for %d clusters (now=%s)", len(trends), now)
    return trends


def emerging_networks(trends: list[dict]) -> list[dict]:
    """Small, high-confidence, recently-active clusters worth early attention."""
    return [t for t in trends if t["trend_status"] == "EMERGING"]


# ---------------------------------------------------------------------------
# Export payload + Markdown
# ---------------------------------------------------------------------------

def trends_payload(trends: list[dict]) -> dict:
    emerging = emerging_networks(trends)
    status_counts: dict[str, int] = {}
    for t in trends:
        status_counts[t["trend_status"]] = status_counts.get(t["trend_status"], 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cluster_count": len(trends),
        "status_counts": status_counts,
        "emerging_count": len(emerging),
        "emerging_networks": [t["cluster_id"] for t in emerging],
        "trends": trends,
    }


def trends_to_markdown(payload: dict) -> str:
    lines = [
        "# Sentinel Fraud Network Trend Intelligence",
        "",
        f"**Generated:** {payload['generated_at']}",
        "",
        f"**Total Clusters:** {payload['cluster_count']}  ",
        f"**Emerging Networks:** {payload['emerging_count']}",
        "",
        "## Trend Overview",
        "",
        "| Cluster | Status | Domains | Growth Rate | Activity | First Seen | Last Seen |",
        "|---------|--------|---------|-------------|----------|------------|-----------|",
    ]
    for t in payload["trends"]:
        lines.append(
            f"| {t['cluster_id']} | {t['trend_status']} | {t['domain_count']} "
            f"| {t['growth_rate']:.2f} | {t['activity_score']:.2f} "
            f"| {t['first_seen'] or '—'} | {t['last_seen'] or '—'} |"
        )

    lines += ["", "## Emerging Networks", ""]
    emerging = [t for t in payload["trends"] if t["trend_status"] == "EMERGING"]
    if emerging:
        for t in emerging:
            lines.append(
                f"- **{t['cluster_id']}** — {t['domain_count']} domain(s), "
                f"confidence {t['confidence']:.2f}, activity {t['activity_score']:.2f}"
            )
    else:
        lines.append("_No emerging networks at this time._")

    lines += ["", "## Trend Narratives", ""]
    for t in payload["trends"]:
        lines.append(f"- {t['narrative']}")

    lines.append("")
    return "\n".join(lines)
