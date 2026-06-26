import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, field_validator

# Allow sibling imports when run via `uvicorn scripts.api:app` from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db_connect import get_driver
from attribution_engine import build_report, report_to_markdown, export_filename
from report_export import report_to_pdf_bytes
from similarity_engine import predict_threat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel.api")

app = FastAPI(title="Sentinel API", version="0.1.0")

# Single shared driver — created once at startup, closed at shutdown
_driver = None


@app.on_event("startup")
def startup():
    global _driver
    logger.info("Initialising Neo4j driver...")
    _driver = get_driver()


@app.on_event("shutdown")
def shutdown():
    if _driver:
        _driver.close()
        logger.info("Neo4j driver closed.")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class LookupRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("domain must not be empty")
        return v


class LookupResponse(BaseModel):
    domain: str
    matched: bool
    campaign: str | None = None
    platform: str | None = None
    risk_score: float = 0.0


class InvestigateRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("domain must not be empty")
        return v


class IntelligenceSource(BaseModel):
    name: str
    source_type: str | None = None
    url: str | None = None
    confidence: float | None = None
    first_seen: str | None = None


class ConnectedCampaign(BaseModel):
    campaign_id: str | None = None
    name: str | None = None
    scam_type: str | None = None
    risk_score: float | None = None
    platforms: list[str] = []


class SimilarDomain(BaseModel):
    domain: str
    confidence: float | None = None
    similarity: float
    reason: str


class TimelineEvent(BaseModel):
    date: str
    event_type: str
    entity: str
    description: str
    confidence: float | None = None


class PredictRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("domain must not be empty")
        return v


class SignalBreakdown(BaseModel):
    lexical: float
    keyword_overlap: float
    campaign_similarity: float
    source_similarity: float
    cluster_risk: float


class NearestDomain(BaseModel):
    domain: str
    lexical: float
    cluster_id: str


class ClusterCandidate(BaseModel):
    cluster_id: str
    status: str
    similarity: float
    cluster_risk: float


class ThreatPrediction(BaseModel):
    domain: str
    known_to_sentinel: bool
    predicted_cluster: str | None = None
    similarity_score: float
    risk_score: float
    confidence: float
    verdict: str
    matched_keywords: list[str]
    signal_breakdown: SignalBreakdown
    nearest_domains: list[NearestDomain]
    candidates: list[ClusterCandidate]
    explanation: str
    generated_at: str


class InvestigationReport(BaseModel):
    domain: str
    known_to_sentinel: bool
    verdict: str
    confidence_score: float
    summary: str
    recommended_action: str
    reasons: list[str]
    intelligence_sources: list[IntelligenceSource]
    connected_campaigns: list[ConnectedCampaign]
    connected_platforms: list[str]
    similar_domains: list[SimilarDomain]
    keyword_indicators: list[str]
    timeline: list[TimelineEvent]
    generated_at: str


# ---------------------------------------------------------------------------
# Cypher
# ---------------------------------------------------------------------------

_LOOKUP_QUERY = """
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain {name: $domain})
MATCH (c)-[:PROMOTED_ON]->(p:Platform)
RETURN c.name AS campaign, p.name AS platform, c.risk_score AS risk_score
LIMIT 1
"""


def _query_domain(domain: str) -> LookupResponse:
    try:
        with _driver.session() as session:
            result = session.run(_LOOKUP_QUERY, domain=domain)
            record = result.single()
    except Exception as e:
        logger.error("Neo4j query error for domain '%s': %s", domain, e)
        raise HTTPException(status_code=503, detail="Database query failed")

    if record is None:
        logger.info("No match for domain: %s", domain)
        return LookupResponse(domain=domain, matched=False)

    logger.info(
        "Match found for domain '%s': campaign=%s risk=%.2f",
        domain,
        record["campaign"],
        record["risk_score"],
    )
    return LookupResponse(
        domain=domain,
        matched=True,
        campaign=record["campaign"],
        platform=record["platform"],
        risk_score=record["risk_score"],
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-api"}


@app.post("/lookup", response_model=LookupResponse)
def lookup(request: LookupRequest):
    logger.info("POST /lookup — domain=%s", request.domain)
    return _query_domain(request.domain)


@app.post("/investigate", response_model=InvestigationReport)
def investigate(request: InvestigateRequest):
    logger.info("POST /investigate — domain=%s", request.domain)
    try:
        with _driver.session() as session:
            report = build_report(session, request.domain)
    except Exception as e:
        logger.error("Investigation failed for '%s': %s", request.domain, e)
        raise HTTPException(status_code=503, detail="Investigation failed")
    return report


@app.post("/predict", response_model=ThreatPrediction)
def predict(request: PredictRequest):
    """Predict likely fraud-cluster membership + threat profile for an unseen domain."""
    logger.info("POST /predict — domain=%s", request.domain)
    try:
        with _driver.session() as session:
            prediction = predict_threat(session, request.domain)
    except Exception as e:
        logger.error("Prediction failed for '%s': %s", request.domain, e)
        raise HTTPException(status_code=503, detail="Prediction failed")
    return prediction


@app.get("/investigate/{domain}/export")
def investigate_export(domain: str, format: str = "json"):
    """Export a full investigation report as a downloadable json, markdown, or pdf file."""
    fmt = format.lower()
    if fmt not in ("json", "markdown", "pdf"):
        raise HTTPException(status_code=400, detail="format must be 'json', 'markdown', or 'pdf'")

    logger.info("GET /investigate/%s/export — format=%s", domain, fmt)
    try:
        with _driver.session() as session:
            report = build_report(session, domain)
    except Exception as e:
        logger.error("Export failed for '%s': %s", domain, e)
        raise HTTPException(status_code=503, detail="Export failed")

    if fmt == "markdown":
        fname = export_filename(domain, report["generated_at"], "md")
        return PlainTextResponse(
            report_to_markdown(report),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    if fmt == "pdf":
        fname = export_filename(domain, report["generated_at"], "pdf")
        return Response(
            report_to_pdf_bytes(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    fname = export_filename(domain, report["generated_at"], "json")
    return JSONResponse(
        report,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
