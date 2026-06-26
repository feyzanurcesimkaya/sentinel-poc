"""
Analyst Copilot — deterministic explainability layer.
=====================================================

NOT an LLM and NOT a chatbot. Given the outputs Sentinel already produces — an
investigation report (attribution_engine.build_report), a threat prediction
(similarity_engine.predict_threat), and the matched cluster (cluster_engine) —
this module composes analyst-facing explanations from fixed templates.

It answers four questions deterministically:

  1. Why was this domain flagged?      -> why_flagged
  2. Why was this cluster selected?     -> why_cluster
  3. Why is the risk score high?        -> why_risk
  4. What action should be taken?       -> recommended_action

plus a one-paragraph analyst_summary. Same inputs always yield the same text.
No new scoring, no new intelligence — pure restatement of existing evidence.
"""


def _join(items) -> str:
    """Join a list as 'a', 'a and b', or 'a, b and c'."""
    items = [str(i) for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _first_sentence(text: str) -> str:
    if not text:
        return ""
    period = text.find(". ")
    return text[: period + 1] if period != -1 else text


def _why_flagged(report: dict, prediction: dict) -> str:
    domain = prediction.get("domain") or report.get("domain", "the domain")
    parts: list[str] = []

    kws = prediction.get("matched_keywords") or report.get("keyword_indicators") or []
    if kws:
        parts.append(
            f"The domain name '{domain}' contains high-risk scam keywords "
            f"({_join(kws)}), a common signal of brand impersonation or fraud."
        )
    else:
        parts.append(f"The domain name '{domain}' contains no obvious scam keywords on its own.")

    nearest = prediction.get("nearest_domains") or []
    if nearest:
        n = nearest[0]
        parts.append(
            f"Its name closely resembles a known flagged domain, {n['domain']} "
            f"(lexical similarity {n['lexical']:.2f})."
        )

    if report.get("intelligence_sources"):
        names = _join([s["name"] for s in report["intelligence_sources"]])
        parts.append(f"It has already been flagged by intelligence source(s): {names}.")

    if prediction.get("known_to_sentinel") or report.get("known_to_sentinel"):
        parts.append("It is already present in Sentinel's intelligence graph.")
    else:
        parts.append(
            "It has not been directly observed before, so it was assessed by "
            "similarity to known fraud infrastructure rather than by direct attribution."
        )
    return " ".join(parts)


def _why_cluster(prediction: dict, cluster: dict | None) -> str:
    cid = prediction.get("predicted_cluster")
    if not cid:
        return (
            "No existing fraud cluster matched with sufficient confidence "
            f"(best similarity {prediction.get('similarity_score', 0.0):.2f}). "
            "The domain appears to be novel infrastructure and should be treated "
            "as a potential first observed instance."
        )

    sb = prediction.get("signal_breakdown", {})
    drivers = []
    if sb.get("lexical", 0) > 0:
        drivers.append(f"name similarity ({sb['lexical']:.2f})")
    if sb.get("keyword_overlap", 0) > 0:
        drivers.append(f"shared scam keywords ({sb['keyword_overlap']:.2f})")
    if sb.get("campaign_similarity", 0) > 0:
        drivers.append(f"campaign-text overlap ({sb['campaign_similarity']:.2f})")
    if sb.get("source_similarity", 0) > 0:
        drivers.append(f"resemblance to source-flagged domains ({sb['source_similarity']:.2f})")

    text = (
        f"Sentinel matched the domain to {cid} with an overall similarity of "
        f"{prediction.get('similarity_score', 0.0):.2f}"
    )
    text += f", driven primarily by {_join(drivers)}." if drivers else "."

    if cluster:
        text += (
            f" {cid} is a {cluster['status']} fraud network of "
            f"{cluster['domain_count']} domain(s) spanning "
            f"{cluster['campaign_count']} campaign(s) and "
            f"{cluster['source_count']} source(s), carrying a cluster risk of "
            f"{cluster['risk_score']:.2f}."
        )
    return text


def _why_risk(report: dict, prediction: dict, cluster: dict | None) -> str:
    risk = prediction.get("risk_score", 0.0)
    sim = prediction.get("similarity_score", 0.0)
    crisk = prediction.get("signal_breakdown", {}).get("cluster_risk", 0.0)
    kws = prediction.get("matched_keywords") or []

    parts = [f"The predicted risk score is {risk:.2f}."]

    # Risk = similarity x cluster_risk, with a keyword floor (mirrors the engine).
    sim_component = round(sim * crisk, 4)
    kw_floor = round(min(0.45, 0.15 * len(kws)), 4)

    if prediction.get("predicted_cluster") and sim_component >= kw_floor:
        parts.append(
            f"It reflects the {sim:.2f} similarity to a known cluster scaled by "
            f"that cluster's prior risk of {crisk:.2f}."
        )
    elif kw_floor > 0:
        parts.append(
            f"A baseline risk was applied because the domain contains "
            f"{len(kws)} scam keyword(s), even though no strong cluster match exists."
        )
    else:
        parts.append("It is low because no scam keywords or cluster similarity were found.")

    parts.append(
        f"Independent investigation assigns a confidence of "
        f"{report.get('confidence_score', 0.0):.2f} (verdict: {report.get('verdict', 'UNKNOWN')})."
    )
    if cluster and cluster.get("risk_score", 0.0) >= 0.8:
        parts.append(
            f"The matched network is itself high-risk ({cluster['risk_score']:.2f}), "
            "which raises the threat posed by any domain resembling it."
        )
    return " ".join(parts)


def _recommended_action(report: dict, cluster: dict | None) -> str:
    action = report.get("recommended_action", "Collect additional intelligence before enforcement.")
    if cluster and cluster.get("risk_score", 0.0) >= 0.8:
        action += (
            f" The matched network {cluster['cluster_id']} is high-risk "
            f"({cluster['risk_score']:.2f}, {cluster['status']}); monitor its "
            f"{cluster['domain_count']} member domain(s) and escalate immediately "
            "if this domain begins serving content."
        )
    return action


def _analyst_summary(report: dict, prediction: dict, cluster: dict, action: str) -> str:
    domain = prediction.get("domain") or report.get("domain", "the domain")
    verdict = (prediction.get("verdict") or "unknown").replace("_", " ").lower()
    cid = prediction.get("predicted_cluster")

    cluster_phrase = ""
    if cid and cluster:
        cluster_phrase = (
            f" It resembles {cid}, a {cluster['status'].lower()} "
            f"{cluster['domain_count']}-domain fraud network (risk {cluster['risk_score']:.2f})."
        )
    elif cid:
        cluster_phrase = f" It resembles cluster {cid}."
    else:
        cluster_phrase = " It does not match any known cluster and may be novel infrastructure."

    return (
        f"{domain} is assessed as {verdict} with a predicted risk of "
        f"{prediction.get('risk_score', 0.0):.2f}.{cluster_phrase} "
        f"Recommended: {_first_sentence(action)}"
    )


def generate_explanation(report: dict, prediction: dict, cluster: dict | None) -> dict:
    """Compose deterministic analyst explanations from existing engine outputs."""
    action = _recommended_action(report, cluster)
    return {
        "why_flagged": _why_flagged(report, prediction),
        "why_cluster": _why_cluster(prediction, cluster),
        "why_risk": _why_risk(report, prediction, cluster),
        "recommended_action": action,
        "analyst_summary": _analyst_summary(report, prediction, cluster, action),
    }
