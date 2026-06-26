"""
Threat Similarity Engine
========================

Predicts whether a *previously unseen* domain likely belongs to existing fraud
infrastructure — before any direct attribution (campaign/source link) exists.

Deterministic, no machine learning. For each FraudCluster it combines five
signals into a similarity score:

  lexical              — token Jaccard vs cluster member domain names
  keyword_overlap      — shared high-risk scam keywords
  campaign_similarity  — token overlap with the cluster's campaign text
  source_similarity    — resemblance to source-flagged member domains
  cluster_risk         — the cluster's existing risk (prior threat level)

The best-scoring cluster becomes the predicted cluster; risk and confidence are
derived from the match strength and the margin over the runner-up. The same
graph + domain always yields the same prediction.

Entry point: predict_threat(session, domain) -> dict.
"""
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution_engine import _tokenize, _jaccard, _SCAM_KEYWORDS
from cluster_engine import build_clusters

logger = logging.getLogger("sentinel.similarity")

# Signal weights for the similarity score (sum = 1.0).
_W_LEXICAL = 0.40
_W_KEYWORD = 0.25
_W_CAMPAIGN = 0.20
_W_SOURCE = 0.15

_SIM_THRESHOLD = 0.15   # below this, no confident cluster is claimed


def _words(text: str) -> set[str]:
    if not text:
        return set()
    return {w for w in re.split(r"[^a-z0-9]+", text.lower()) if len(w) >= 2}


def _campaign_tokens(cluster: dict) -> set[str]:
    """All meaningful tokens from a cluster's campaign names + scam types."""
    toks: set[str] = set()
    for cd in cluster.get("campaign_details", []):
        toks |= _words(cd.get("name") or "")
        toks |= _words(cd.get("scam_type") or "")
    return toks


def _cluster_keywords(cluster: dict) -> set[str]:
    """Scam keywords present across the cluster's member domains."""
    kw: set[str] = set()
    for m in cluster["members"]:
        kw |= (_tokenize(m["domain"]) & _SCAM_KEYWORDS)
    return kw


def _score_cluster(toks_u: set[str], kw_u: set[str], cluster: dict) -> dict:
    """Compute the five signals and the weighted similarity for one cluster."""
    members = cluster["members"]

    # 1. lexical — best name match against any member
    lexical = max((_jaccard(toks_u, _tokenize(m["domain"])) for m in members), default=0.0)

    # 2. keyword overlap — fraction of the unknown's scam keywords seen in cluster
    cluster_kw = _cluster_keywords(cluster) | _campaign_tokens(cluster) & _SCAM_KEYWORDS
    keyword_overlap = (len(kw_u & cluster_kw) / len(kw_u)) if kw_u else 0.0

    # 3. campaign similarity — token overlap with campaign text
    campaign_similarity = _jaccard(toks_u, _campaign_tokens(cluster))

    # 4. source similarity — resemblance to source-flagged member domains
    src_members = [m for m in members if m.get("sources")]
    source_similarity = max(
        (_jaccard(toks_u, _tokenize(m["domain"])) for m in src_members), default=0.0
    )

    similarity = round(
        _W_LEXICAL * lexical
        + _W_KEYWORD * keyword_overlap
        + _W_CAMPAIGN * campaign_similarity
        + _W_SOURCE * source_similarity,
        4,
    )

    return {
        "cluster_id": cluster["cluster_id"],
        "status": cluster["status"],
        "cluster_risk": cluster["risk_score"],
        "similarity": similarity,
        "signals": {
            "lexical": round(lexical, 4),
            "keyword_overlap": round(keyword_overlap, 4),
            "campaign_similarity": round(campaign_similarity, 4),
            "source_similarity": round(source_similarity, 4),
            "cluster_risk": cluster["risk_score"],
        },
    }


def _verdict(risk: float) -> str:
    if risk >= 0.7:
        return "LIKELY_MALICIOUS"
    if risk >= 0.4:
        return "SUSPICIOUS"
    if risk > 0.0:
        return "LOW_SIMILARITY"
    return "UNKNOWN"


def _explain(predicted, similarity, top, nearest, kw_u, risk, confidence) -> str:
    parts: list[str] = []
    if predicted:
        parts.append(
            f"Closest match is {predicted} (similarity {similarity:.2f}, "
            f"cluster risk {top['cluster_risk']:.2f})."
        )
        sig = top["signals"]
        drivers = []
        if sig["lexical"] > 0:
            drivers.append(f"lexical name similarity {sig['lexical']:.2f}")
        if sig["keyword_overlap"] > 0:
            drivers.append(f"keyword overlap {sig['keyword_overlap']:.2f}")
        if sig["campaign_similarity"] > 0:
            drivers.append(f"campaign-text similarity {sig['campaign_similarity']:.2f}")
        if sig["source_similarity"] > 0:
            drivers.append(f"source-domain similarity {sig['source_similarity']:.2f}")
        if drivers:
            parts.append("Driven by " + ", ".join(drivers) + ".")
        if nearest:
            parts.append(
                f"Most similar known domain: {nearest[0]['domain']} "
                f"({nearest[0]['lexical']:.2f}, in {nearest[0]['cluster_id']})."
            )
    else:
        parts.append("No existing fraud cluster is a confident match for this domain.")

    if kw_u:
        parts.append("Domain name contains high-risk scam keywords: " + ", ".join(kw_u) + ".")

    parts.append(f"Predicted threat risk {risk:.2f} with confidence {confidence:.2f}.")
    if risk >= 0.7:
        parts.append("Recommend proactive blocking and monitoring as likely scam infrastructure.")
    elif risk >= 0.4:
        parts.append("Recommend monitoring and corroboration before enforcement.")
    else:
        parts.append("Insufficient similarity to flag; no action recommended yet.")
    return " ".join(parts)


def predict_threat(session, domain: str, clusters: list[dict] | None = None) -> dict:
    """Predict the most likely fraud cluster + threat profile for an unseen domain."""
    domain = domain.strip().lower()
    if clusters is None:
        clusters = build_clusters(session)

    toks_u = _tokenize(domain)
    kw_u = sorted(toks_u & _SCAM_KEYWORDS)
    known = any(domain == m["domain"] for c in clusters for m in c["members"])

    candidates = [_score_cluster(toks_u, set(kw_u), c) for c in clusters]
    candidates.sort(key=lambda x: (-x["similarity"], x["cluster_id"]))

    # Nearest individual known domains (across all clusters).
    nearest: list[dict] = []
    for c in clusters:
        for m in c["members"]:
            lex = _jaccard(toks_u, _tokenize(m["domain"]))
            if lex > 0:
                nearest.append({"domain": m["domain"], "lexical": round(lex, 4),
                                "cluster_id": c["cluster_id"]})
    nearest.sort(key=lambda x: (-x["lexical"], x["domain"]))
    nearest = nearest[:5]

    top = candidates[0] if candidates else None
    similarity = top["similarity"] if top else 0.0
    second = candidates[1]["similarity"] if len(candidates) > 1 else 0.0
    margin = round(similarity - second, 4)
    cluster_risk = top["cluster_risk"] if top else 0.0

    # Risk: match strength scaled by the matched cluster's risk, with a keyword floor.
    kw_floor = round(min(0.45, 0.15 * len(kw_u)), 4)
    risk = round(max(similarity * cluster_risk, kw_floor), 4)

    # Confidence: strong + well-separated top match -> high confidence.
    confidence = round(min(1.0, 0.7 * similarity + 0.3 * margin), 4)

    predicted = top["cluster_id"] if (top and similarity >= _SIM_THRESHOLD) else None
    verdict = _verdict(risk)
    explanation = _explain(predicted, similarity, top, nearest, kw_u, risk, confidence)

    result = {
        "domain": domain,
        "known_to_sentinel": known,
        "predicted_cluster": predicted,
        "similarity_score": similarity,
        "risk_score": risk,
        "confidence": confidence,
        "verdict": verdict,
        "matched_keywords": kw_u,
        "signal_breakdown": top["signals"] if top else {
            "lexical": 0.0, "keyword_overlap": 0.0, "campaign_similarity": 0.0,
            "source_similarity": 0.0, "cluster_risk": 0.0,
        },
        "nearest_domains": nearest,
        "candidates": [
            {"cluster_id": c["cluster_id"], "status": c["status"],
             "similarity": c["similarity"], "cluster_risk": c["cluster_risk"]}
            for c in candidates[:3]
        ],
        "explanation": explanation,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "Threat prediction for '%s': predicted=%s similarity=%.2f risk=%.2f verdict=%s",
        domain, predicted, similarity, risk, verdict,
    )
    return result
