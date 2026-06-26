"""
Fraud Cluster Intelligence Engine
=================================

Groups related domains/campaigns/sources into deterministic FraudClusters.

A FraudCluster is a connected component over the ScamGraph, built to maximise
*fraud-network precision* rather than cluster size. Two domains are linked iff:

  1. they share a Campaign — (Campaign)-[:USES_DOMAIN]->(Domain) — direct,
     curated attribution and the strongest signal; OR
  2. they share a DISTINCTIVE name anchor token AND that link is corroborated by
     either strong name similarity (lexical Jaccard) OR a common ScamSource.

A "distinctive anchor" is a domain token that is not generic phishing filler
(login/secure/verify/...) and not so common across the corpus that it carries no
discriminating power (a document-frequency cap). Crucially, **sharing a
ScamSource alone is NOT sufficient to merge** — a feed flags thousands of
unrelated domains, so source membership only corroborates a real name anchor.
This prevents a single bulk feed (e.g. OpenPhish/URLHaus) collapsing into one
mega-cluster, and stops generic-token chaining across unrelated brands.

No ML model — clustering is a deterministic union-find over those edges, so the
same graph always yields the same clusters. FraudClusters are computed on demand
and are NOT persisted back to Neo4j (the graph schema is left unchanged).

Each cluster exposes: cluster_id, risk_score, status, confidence, domain_count,
campaign_count, source_count (+ the member domains/campaigns/sources/platforms
and an analyst summary).
"""
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution_engine import _tokenize, _jaccard  # reuse similarity primitives

logger = logging.getLogger("sentinel.cluster")

_DEFAULT_SIMILARITY = 0.5  # lexical Jaccard threshold for a strong standalone name link
_MAX_DF_RATIO = 0.05       # a token in >5% of domains is too common to anchor a merge

# Generic filler tokens common to phishing/malware domains — these never anchor a
# fraud-network merge (they carry no actor/infrastructure signal on their own).
_GENERIC_TOKENS = {
    "secure", "login", "logon", "signin", "sign", "verify", "verification",
    "update", "account", "accounts", "online", "alert", "alerts", "confirm",
    "auth", "authentication", "recover", "recovery", "billing", "payment", "pay",
    "service", "services", "support", "customer", "portal", "official", "help",
    "center", "centre", "web", "site", "page", "home", "index", "mail", "email",
    "user", "users", "app", "mobile", "www", "http", "https", "click", "link",
    "com", "net", "org", "info", "co", "uk", "ru", "cn", "xyz", "cc", "io", "su",
    "top", "new", "real", "live", "now", "get",
    # Shared hosting / SaaS platform tokens — common infrastructure, NOT actor
    # identity. Two unrelated scams hosted on the same platform are not one network.
    "vercel", "webflow", "github", "githubusercontent", "gitlab", "netlify",
    "pages", "page", "herokuapp", "heroku", "weebly", "blogspot", "blogger",
    "wordpress", "wix", "wixsite", "framer", "glitch", "repl", "replit",
    "workers", "firebaseapp", "firebase", "surge", "render", "onrender", "fly",
    "cloudfront", "amazonaws", "azurewebsites", "sharepoint", "sites", "google",
    "dev", "cyou", "cdn", "r2", "tem3", "vdd", "vwk",
}


def _is_anchor(token: str, df: dict, n_domains: int) -> bool:
    """A token is a valid merge anchor if it is specific and discriminative."""
    if len(token) < 3 or token.isdigit():
        return False
    if token in _GENERIC_TOKENS:
        return False
    # Document-frequency cap: a token appearing in a large fraction of all domains
    # (e.g. 'invest', 'bank') is non-discriminative and must not anchor merges.
    return df.get(token, 0) <= max(2, int(_MAX_DF_RATIO * n_domains))

_DOMAINS_QUERY = """
MATCH (d:Domain)
OPTIONAL MATCH (c:Campaign)-[:USES_DOMAIN]->(d)
OPTIONAL MATCH (s:ScamSource)-[:FLAGGED]->(d)
RETURN d.name AS domain,
       d.confidence AS confidence,
       d.first_seen AS first_seen,
       collect(DISTINCT c.name) AS campaigns,
       collect(DISTINCT s.name) AS sources
"""

_CAMPAIGNS_QUERY = """
MATCH (c:Campaign)
OPTIONAL MATCH (c)-[:PROMOTED_ON]->(p:Platform)
RETURN c.name AS name,
       c.risk_score AS risk,
       c.scam_type AS scam_type,
       collect(DISTINCT p.name) AS platforms
"""


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class _UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]  # path compression
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------

def _fetch(session):
    domains: dict[str, dict] = {}
    for r in session.run(_DOMAINS_QUERY):
        domains[r["domain"]] = {
            "domain": r["domain"],
            "confidence": float(r["confidence"]) if r["confidence"] is not None else None,
            "first_seen": r["first_seen"],
            "campaigns": [c for c in r["campaigns"] if c],
            "sources": [s for s in r["sources"] if s],
        }

    campaigns: dict[str, dict] = {}
    for r in session.run(_CAMPAIGNS_QUERY):
        campaigns[r["name"]] = {
            "name": r["name"],
            "risk": float(r["risk"]) if r["risk"] is not None else None,
            "scam_type": r["scam_type"],
            "platforms": [p for p in r["platforms"] if p],
        }
    return domains, campaigns


# ---------------------------------------------------------------------------
# Cluster construction
# ---------------------------------------------------------------------------

def _status_for(risk: float) -> str:
    if risk >= 0.8:
        return "ACTIVE"
    if risk >= 0.5:
        return "MONITORING"
    return "DORMANT"


def _cluster_summary(c: dict) -> str:
    base = (
        f"{c['cluster_id']} contains {c['domain_count']} domain(s) linked to "
        f"{c['campaign_count']} campaign(s) and {c['source_count']} intelligence "
        f"source(s)."
    )
    coordinated = c["domain_count"] > 1 and (c["campaign_count"] > 0 or c["source_count"] > 0)
    if coordinated:
        return base + (
            " The cluster demonstrates coordinated scam infrastructure and should "
            "be treated as an active fraud network."
        )
    return base + " Limited corroboration; monitor for emerging activity."


def build_clusters(session, similarity_threshold: float = _DEFAULT_SIMILARITY) -> list[dict]:
    """Compute deterministic FraudClusters from the live ScamGraph."""
    domains, campaigns = _fetch(session)
    names = sorted(domains)  # sorted -> deterministic union order

    uf = _UnionFind(names)

    # 1. Shared campaign — direct, curated attribution: strongest evidence.
    camp_members: dict[str, list[str]] = defaultdict(list)
    for n in names:
        for c in domains[n]["campaigns"]:
            camp_members[c].append(n)
    for members in camp_members.values():
        for other in members[1:]:
            uf.union(members[0], other)

    # Precompute tokens, source sets, and corpus document-frequency for anchors.
    tokens = {n: _tokenize(n) for n in names}
    src_sets = {n: set(domains[n]["sources"]) for n in names}
    n_domains = len(names)
    df: dict[str, int] = defaultdict(int)
    for n in names:
        for t in tokens[n]:
            df[t] += 1

    # 2. Name-pattern merge (precision-first). Only domains that share a
    #    DISTINCTIVE anchor token are ever compared; within that group they merge
    #    when names are strongly similar OR a source corroborates. Shared source
    #    alone (no distinctive anchor) can never merge — this is what dissolves
    #    the single-feed mega-cluster.
    anchor_index: dict[str, list[str]] = defaultdict(list)
    for n in names:
        for t in tokens[n]:
            if _is_anchor(t, df, n_domains):
                anchor_index[t].append(n)

    for members in anchor_index.values():
        for i in range(len(members)):
            a = members[i]
            for j in range(i + 1, len(members)):
                b = members[j]
                if uf.find(a) == uf.find(b):
                    continue
                strong_name = _jaccard(tokens[a], tokens[b]) >= similarity_threshold
                shared_source = bool(src_sets[a] & src_sets[b])
                if strong_name or shared_source:
                    uf.union(a, b)

    # Group members by component root
    groups: dict[str, list[str]] = defaultdict(list)
    for n in names:
        groups[uf.find(n)].append(n)

    clusters: list[dict] = []
    for member_domains in groups.values():
        member_domains = sorted(member_domains)
        members = [domains[d] for d in member_domains]

        camp_names = sorted({c for m in members for c in m["campaigns"]})
        src_names = sorted({s for m in members for s in m["sources"]})
        camp_details = [campaigns[c] for c in camp_names if c in campaigns]
        plat_names = sorted({p for cd in camp_details for p in cd["platforms"]})

        # Risk = worst-case signal; confidence = mean signal across the cluster.
        signals: list[float] = [m["confidence"] for m in members if m["confidence"] is not None]
        signals += [cd["risk"] for cd in camp_details if cd["risk"] is not None]
        risk = round(max(signals), 4) if signals else 0.0
        conf = round(sum(signals) / len(signals), 4) if signals else 0.0

        clusters.append({
            "risk_score": risk,
            "confidence": conf,
            "status": _status_for(risk),
            "domain_count": len(member_domains),
            "campaign_count": len(camp_names),
            "source_count": len(src_names),
            "domains": member_domains,
            "campaigns": camp_names,
            "sources": src_names,
            "platforms": plat_names,
            "members": members,            # per-domain detail (for precise graph edges)
            "campaign_details": camp_details,
        })

    # Deterministic ordering + id assignment: highest risk / largest first.
    clusters.sort(key=lambda c: (-c["risk_score"], -c["domain_count"], c["domains"][0]))
    for i, c in enumerate(clusters, 1):
        c["cluster_id"] = f"CLUSTER-{i:03d}"
        c["summary"] = _cluster_summary(c)

    logger.info("Built %d fraud clusters from %d domains", len(clusters), len(names))
    return clusters


# ---------------------------------------------------------------------------
# Cluster graph rows (schema matches dashboard build_network)
#   FraudCluster -> Domain -> Campaign -> Platform  (+ Source -> Domain)
# ---------------------------------------------------------------------------

def cluster_to_graph_rows(cluster: dict) -> list[dict]:
    rows: list[dict] = []
    cid = cluster["cluster_id"]
    camp_by_name = {c["name"]: c for c in cluster["campaign_details"]}

    for mem in cluster["members"]:
        dn = mem["domain"]
        rows.append({
            "ltype": "cluster", "lname": cid, "lprop": cluster["status"],
            "rel": "CONTAINS", "rtype": "domain", "rname": dn,
            "confidence": cluster["risk_score"],
        })
        for cn in mem["campaigns"]:
            cd = camp_by_name.get(cn, {})
            rows.append({
                "ltype": "campaign", "lname": cn, "lprop": cd.get("scam_type") or "",
                "rel": "USES_DOMAIN", "rtype": "domain", "rname": dn,
                "confidence": cd.get("risk") or 0.0,
            })
            for p in cd.get("platforms", []):
                rows.append({
                    "ltype": "campaign", "lname": cn, "lprop": cd.get("scam_type") or "",
                    "rel": "PROMOTED_ON", "rtype": "platform", "rname": p,
                    "confidence": 0.0,
                })
        for sn in mem["sources"]:
            rows.append({
                "ltype": "source", "lname": sn, "lprop": "",
                "rel": "FLAGGED", "rtype": "domain", "rname": dn,
                "confidence": 0.0,
            })
    return rows


# ---------------------------------------------------------------------------
# Export payload + Markdown
# ---------------------------------------------------------------------------

def _public_view(cluster: dict) -> dict:
    """Cluster dict without internal helper fields (members/campaign_details)."""
    return {
        "cluster_id": cluster["cluster_id"],
        "status": cluster["status"],
        "risk_score": cluster["risk_score"],
        "confidence": cluster["confidence"],
        "domain_count": cluster["domain_count"],
        "campaign_count": cluster["campaign_count"],
        "source_count": cluster["source_count"],
        "domains": cluster["domains"],
        "campaigns": cluster["campaigns"],
        "sources": cluster["sources"],
        "platforms": cluster["platforms"],
        "summary": cluster["summary"],
    }


def clusters_payload(clusters: list[dict]) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cluster_count": len(clusters),
        "clusters": [_public_view(c) for c in clusters],
    }


def _cell(value) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ")


def clusters_to_markdown(payload: dict) -> str:
    lines = [
        "# Sentinel Fraud Cluster Intelligence",
        "",
        f"**Generated:** {payload['generated_at']}",
        "",
        f"**Total Clusters:** {payload['cluster_count']}",
        "",
        "## Overview",
        "",
        "| Cluster | Status | Risk | Confidence | Domains | Campaigns | Sources |",
        "|---------|--------|------|------------|---------|-----------|---------|",
    ]
    for c in payload["clusters"]:
        lines.append(
            f"| {c['cluster_id']} | {c['status']} | {c['risk_score']:.2f} "
            f"| {c['confidence']:.2f} | {c['domain_count']} "
            f"| {c['campaign_count']} | {c['source_count']} |"
        )

    lines += ["", "## Cluster Details", ""]
    for c in payload["clusters"]:
        lines.append(f"### {c['cluster_id']} — {c['status']}")
        lines.append("")
        lines.append(c["summary"])
        lines.append("")
        lines.append(f"- **Risk Score:** {c['risk_score']:.2f}")
        lines.append(f"- **Confidence:** {c['confidence']:.2f}")
        lines.append(f"- **Domains:** {', '.join(_cell(d) for d in c['domains']) or '—'}")
        lines.append(f"- **Campaigns:** {', '.join(_cell(x) for x in c['campaigns']) or '—'}")
        lines.append(f"- **Sources:** {', '.join(_cell(x) for x in c['sources']) or '—'}")
        lines.append(f"- **Platforms:** {', '.join(_cell(x) for x in c['platforms']) or '—'}")
        lines.append("")

    return "\n".join(lines)
