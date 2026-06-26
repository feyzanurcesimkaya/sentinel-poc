"""
Validation Engine — credibility metrics for the Threat Similarity Engine.
========================================================================

Evaluation only. Does NOT change similarity scoring, clustering, or prediction —
it runs the *existing* predict_threat over deterministic built-in test sets and
measures detection vs false positives.

Test sets (no external datasets required):
  - scam-like domains  (expected: flagged SUSPICIOUS or above)
  - benign domains     (expected: NOT flagged -> LOW_SIMILARITY / UNKNOWN)

run_validation(session) -> dict of metrics + per-case results.
"""
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cluster_engine import build_clusters
from similarity_engine import predict_threat

logger = logging.getLogger("sentinel.validation")

# Deterministic, built-in test cases.
_MALICIOUS = [
    "fca-investment-recovery.com",
    "wellsfargo-secure-login.com",
    "quantum-ai-investment.com",
    "apple-id-security-check.net",
    "crypto-wallet-verify.net",
]
_BENIGN = [
    "totally-unrelated-blog.com",
    "mypersonalportfolio.dev",
    "university-course-notes.org",
    "localbakeryistanbul.com",
    "example-newsletter.net",
]

# Verdict severity ranking; "flagged" means SUSPICIOUS or above.
_RANK = {"UNKNOWN": 0, "LOW_SIMILARITY": 1, "SUSPICIOUS": 2, "LIKELY_MALICIOUS": 3}


def _is_flagged(verdict: str) -> bool:
    return _RANK.get(verdict, 0) >= 2


def _evaluate(session, domain: str, expected: str, clusters: list[dict]) -> dict:
    pred = predict_threat(session, domain, clusters=clusters)
    verdict = pred["verdict"]
    flagged = _is_flagged(verdict)
    # malicious cases should be flagged; benign cases should not be.
    passed = flagged if expected == "malicious" else (not flagged)
    return {
        "domain": domain,
        "expected_label": expected,
        "predicted_verdict": verdict,
        "predicted_cluster": pred["predicted_cluster"],
        "similarity_score": pred["similarity_score"],
        "risk_score": pred["risk_score"],
        "passed": passed,
        "explanation": pred["explanation"],
    }


def run_validation(session) -> dict:
    """Run the deterministic validation suite and return metrics + cases."""
    clusters = build_clusters(session)

    cases = [_evaluate(session, d, "malicious", clusters) for d in _MALICIOUS]
    cases += [_evaluate(session, d, "benign", clusters) for d in _BENIGN]

    total = len(cases)
    malicious = [c for c in cases if c["expected_label"] == "malicious"]
    benign = [c for c in cases if c["expected_label"] == "benign"]

    flagged_all = sum(1 for c in cases if _is_flagged(c["predicted_verdict"]))
    unknown = sum(1 for c in cases if c["predicted_verdict"] == "UNKNOWN")
    false_positives = [c for c in benign if _is_flagged(c["predicted_verdict"])]
    detected = sum(1 for c in malicious if _is_flagged(c["predicted_verdict"]))
    passed = sum(1 for c in cases if c["passed"])

    verdict_distribution = dict(Counter(c["predicted_verdict"] for c in cases))
    top_clusters = Counter(c["predicted_cluster"] for c in cases if c["predicted_cluster"])

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_tested": total,
        "malicious_tested": len(malicious),
        "benign_tested": len(benign),
        "passed_count": passed,
        "accuracy": round(passed / total, 4) if total else 0.0,
        "detection_rate": round(detected / len(malicious), 4) if malicious else 0.0,
        "suspicious_or_above_rate": round(flagged_all / total, 4) if total else 0.0,
        "unknown_rate": round(unknown / total, 4) if total else 0.0,
        "false_positive_count": len(false_positives),
        "false_positive_rate": round(len(false_positives) / len(benign), 4) if benign else 0.0,
        "average_risk_score": round(sum(c["risk_score"] for c in cases) / total, 4) if total else 0.0,
        "average_similarity_score": round(sum(c["similarity_score"] for c in cases) / total, 4) if total else 0.0,
        "verdict_distribution": verdict_distribution,
        "top_predicted_clusters": top_clusters.most_common(5),
        "cases": cases,
    }

    logger.info(
        "Validation: %d cases, detection=%.2f, FP_rate=%.2f, accuracy=%.2f",
        total, result["detection_rate"], result["false_positive_rate"], result["accuracy"],
    )
    return result


def validation_to_markdown(result: dict) -> str:
    lines = [
        "# Sentinel — Threat Similarity Validation",
        "",
        f"**Generated:** {result['generated_at']}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total tested | {result['total_tested']} |",
        f"| Malicious tested | {result['malicious_tested']} |",
        f"| Benign tested | {result['benign_tested']} |",
        f"| Accuracy | {result['accuracy']:.2f} |",
        f"| Detection rate (malicious flagged) | {result['detection_rate']:.2f} |",
        f"| Suspicious-or-above rate | {result['suspicious_or_above_rate']:.2f} |",
        f"| Unknown rate | {result['unknown_rate']:.2f} |",
        f"| False positives | {result['false_positive_count']} |",
        f"| False positive rate | {result['false_positive_rate']:.2f} |",
        f"| Average risk score | {result['average_risk_score']:.2f} |",
        f"| Average similarity score | {result['average_similarity_score']:.2f} |",
        "",
        "## Verdict distribution",
        "",
    ]
    for v, n in result["verdict_distribution"].items():
        lines.append(f"- {v}: {n}")

    lines += ["", "## Cases", "",
              "| Domain | Expected | Verdict | Cluster | Similarity | Risk | Passed |",
              "|--------|----------|---------|---------|------------|------|--------|"]
    for c in result["cases"]:
        lines.append(
            f"| {c['domain']} | {c['expected_label']} | {c['predicted_verdict']} "
            f"| {c['predicted_cluster'] or '—'} | {c['similarity_score']:.2f} "
            f"| {c['risk_score']:.2f} | {'✓' if c['passed'] else '✗'} |"
        )
    lines.append("")
    return "\n".join(lines)
