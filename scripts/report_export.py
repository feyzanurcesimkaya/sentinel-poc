"""
PDF export for Sentinel investigation case reports.

Isolated from attribution_engine.py so the engine stays importable without
reportlab. Single entry point: report_to_pdf_bytes(report) -> bytes.

Design: clean professional layout, Helvetica only, no external images/assets,
empty sections handled gracefully.
"""
import logging
import sys
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution_engine import build_case_id

logger = logging.getLogger("sentinel.report_export")

# Verdict → accent colour for the header banner.
_VERDICT_COLOR = {
    "MALICIOUS":  colors.HexColor("#c0392b"),
    "SUSPICIOUS": colors.HexColor("#d68910"),
    "LOW_RISK":   colors.HexColor("#1e8449"),
    "UNKNOWN":    colors.HexColor("#566573"),
}

_HEADER_BG = colors.HexColor("#16213e")
_HEADER_FG = colors.white
_GRID = colors.HexColor("#b0b8c4")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        "SentinelTitle", parent=ss["Title"],
        fontName="Helvetica-Bold", fontSize=18, spaceAfter=4,
        textColor=colors.HexColor("#0f3460"),
    ))
    ss.add(ParagraphStyle(
        "SectionH", parent=ss["Heading2"],
        fontName="Helvetica-Bold", fontSize=12, spaceBefore=12, spaceAfter=4,
        textColor=colors.HexColor("#0f3460"),
    ))
    ss.add(ParagraphStyle(
        "SubH", parent=ss["Heading3"],
        fontName="Helvetica-Bold", fontSize=10, spaceBefore=8, spaceAfter=2,
        textColor=colors.HexColor("#16213e"),
    ))
    ss.add(ParagraphStyle(
        "Body", parent=ss["BodyText"],
        fontName="Helvetica", fontSize=9.5, leading=13, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        "Cell", parent=ss["BodyText"],
        fontName="Helvetica", fontSize=8.5, leading=11,
    ))
    ss.add(ParagraphStyle(
        "CellHead", parent=ss["BodyText"],
        fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=_HEADER_FG,
    ))
    ss.add(ParagraphStyle(
        "Empty", parent=ss["BodyText"],
        fontName="Helvetica-Oblique", fontSize=9, textColor=colors.HexColor("#7f8c8d"),
    ))
    return ss


def _p(text, style) -> Paragraph:
    """Escaped Paragraph (reportlab treats cell text as mini-XML)."""
    return Paragraph(escape("" if text is None else str(text)), style)


def _conf(value) -> str:
    return f"{value:.2f}" if value is not None else "—"


def _make_table(headers, rows, col_widths, ss) -> Table:
    """Build a styled table; header row + body rows are all wrapped Paragraphs."""
    head_style = ss["CellHead"]
    cell_style = ss["Cell"]
    data = [[_p(h, head_style) for h in headers]]
    for row in rows:
        data.append([_p(c, cell_style) for c in row])

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f2f4f7")]),
    ]))
    return tbl


def report_to_pdf_bytes(report: dict) -> bytes:
    """Render an investigation report dict to PDF bytes."""
    ss = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="Sentinel Investigation Case Report",
    )

    case_id = build_case_id(report["domain"], report["generated_at"])
    verdict = report["verdict"]
    conf_pct = f"{round(report['confidence_score'] * 100)}%"
    accent = _VERDICT_COLOR.get(verdict, _VERDICT_COLOR["UNKNOWN"])

    story = []

    # --- Title -----------------------------------------------------------
    story.append(_p("Sentinel Investigation Case Report", ss["SentinelTitle"]))
    story.append(HRFlowable(width="100%", thickness=1.2, color=accent, spaceAfter=8))

    # --- Header info block (key/value table) -----------------------------
    info_rows = [
        ["Case ID", case_id],
        ["Domain", report["domain"]],
        ["Verdict", verdict],
        ["Confidence", conf_pct],
        ["Generated", report["generated_at"]],
    ]
    info_tbl = Table(
        [[_p(k, ss["CellHead"]), _p(v, ss["Cell"])] for k, v in info_rows],
        colWidths=[1.4 * inch, 5.1 * inch],
    )
    info_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(info_tbl)

    # --- Executive Summary ----------------------------------------------
    story.append(_p("Executive Summary", ss["SectionH"]))
    story.append(_p(report.get("summary") or "No summary available.", ss["Body"]))

    # --- Recommended Action ---------------------------------------------
    story.append(_p("Recommended Action", ss["SectionH"]))
    story.append(_p(report.get("recommended_action") or "None.", ss["Body"]))

    # --- Attribution Chain ----------------------------------------------
    story.append(_p("Attribution Chain", ss["SectionH"]))
    src = ", ".join(s["name"] for s in report["intelligence_sources"]) or "—"
    camp = ", ".join(c["name"] for c in report["connected_campaigns"]) or "—"
    plat = ", ".join(report["connected_platforms"]) or "—"
    story.append(_p(f"{src}  →  {report['domain']}  →  {camp}  →  {plat}", ss["Body"]))

    # --- Investigation Timeline -----------------------------------------
    story.append(_p("Investigation Timeline", ss["SectionH"]))
    if report.get("timeline"):
        rows = [
            [e["date"], e["event_type"], e["entity"], e["description"], _conf(e.get("confidence"))]
            for e in report["timeline"]
        ]
        story.append(_make_table(
            ["Date", "Event Type", "Entity", "Description", "Conf."],
            rows,
            [0.85 * inch, 1.0 * inch, 1.5 * inch, 2.45 * inch, 0.5 * inch],
            ss,
        ))
    else:
        story.append(_p("No timeline events recorded.", ss["Empty"]))

    # --- Evidence Summary -----------------------------------------------
    story.append(_p("Evidence Summary", ss["SectionH"]))

    story.append(_p("Intelligence Sources", ss["SubH"]))
    if report["intelligence_sources"]:
        rows = [
            [s["name"], s.get("source_type") or "—", _conf(s.get("confidence")), s.get("first_seen") or "—"]
            for s in report["intelligence_sources"]
        ]
        story.append(_make_table(
            ["Source", "Type", "Conf.", "First Seen"], rows,
            [1.6 * inch, 1.5 * inch, 0.7 * inch, 2.5 * inch], ss,
        ))
    else:
        story.append(_p("None.", ss["Empty"]))

    story.append(_p("Connected Campaigns", ss["SubH"]))
    if report["connected_campaigns"]:
        rows = [
            [c["name"], c.get("scam_type") or "—", _conf(c.get("risk_score")),
             ", ".join(c["platforms"]) or "—"]
            for c in report["connected_campaigns"]
        ]
        story.append(_make_table(
            ["Campaign", "Scam Type", "Risk", "Platforms"], rows,
            [2.1 * inch, 1.6 * inch, 0.6 * inch, 2.0 * inch], ss,
        ))
    else:
        story.append(_p("None.", ss["Empty"]))

    story.append(_p("Connected Platforms", ss["SubH"]))
    if report["connected_platforms"]:
        story.append(_p(", ".join(report["connected_platforms"]), ss["Body"]))
    else:
        story.append(_p("None.", ss["Empty"]))

    story.append(_p("Similar Domains", ss["SubH"]))
    if report["similar_domains"]:
        rows = [
            [s["domain"], f"{s['similarity']:.2f}", _conf(s.get("confidence")), s["reason"]]
            for s in report["similar_domains"]
        ]
        story.append(_make_table(
            ["Domain", "Similarity", "Conf.", "Reason"], rows,
            [1.9 * inch, 0.85 * inch, 0.6 * inch, 2.95 * inch], ss,
        ))
    else:
        story.append(_p("None.", ss["Empty"]))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_GRID, spaceAfter=4))
    story.append(_p(
        "Generated by Sentinel — Scam Attribution Intelligence Platform.",
        ss["Empty"],
    ))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    logger.info("PDF generated for '%s' (%d bytes)", report["domain"], len(pdf))
    return pdf


def workspace_to_pdf_bytes(payload: dict) -> bytes:
    """Render a multi-domain workspace payload (from workspace.build_workspace_payload) to PDF."""
    ss = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="Sentinel Investigation Workspace",
    )

    m = payload["metrics"]
    story = []

    # --- Title -----------------------------------------------------------
    story.append(_p("Sentinel Investigation Workspace", ss["SentinelTitle"]))
    story.append(HRFlowable(width="100%", thickness=1.2,
                            color=colors.HexColor("#0f3460"), spaceAfter=8))

    # --- Case header -----------------------------------------------------
    info_rows = [
        ["Case ID", payload["case_id"]],
        ["Status", payload["status"]],
        ["Severity", payload["severity"]],
        ["Created", payload["created"]],
        ["Domains", str(m["total_domains"])],
    ]
    info_tbl = Table(
        [[_p(k, ss["CellHead"]), _p(v, ss["Cell"])] for k, v in info_rows],
        colWidths=[1.4 * inch, 5.1 * inch],
    )
    info_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(info_tbl)

    # --- Fraud Network Summary ------------------------------------------
    story.append(_p("Fraud Network Summary", ss["SectionH"]))
    story.append(_p(payload["fraud_network_summary"], ss["Body"]))

    # --- Investigation Metrics ------------------------------------------
    story.append(_p("Investigation Metrics", ss["SectionH"]))
    story.append(_make_table(
        ["Domains", "Campaigns", "Platforms", "Sources", "Avg Confidence"],
        [[m["total_domains"], m["total_campaigns"], m["total_platforms"],
          m["total_sources"], f"{m['average_confidence']:.2f}"]],
        [1.3 * inch, 1.3 * inch, 1.3 * inch, 1.1 * inch, 1.5 * inch],
        ss,
    ))

    # --- Domain verdicts -------------------------------------------------
    story.append(_p("Domain Verdicts", ss["SectionH"]))
    if payload["domains"]:
        rows = [
            [r["domain"], r["verdict"], f"{r['confidence_score']:.2f}",
             r.get("recommended_action") or "—"]
            for r in payload["domains"]
        ]
        story.append(_make_table(
            ["Domain", "Verdict", "Conf.", "Recommended Action"], rows,
            [1.7 * inch, 1.0 * inch, 0.6 * inch, 3.2 * inch], ss,
        ))
    else:
        story.append(_p("No domains in case.", ss["Empty"]))

    # --- Case Timeline ---------------------------------------------------
    story.append(_p("Case Timeline", ss["SectionH"]))
    if payload["timeline"]:
        rows = [
            [e["date"], e["event_type"], e["domain"], e["entity"],
             e["description"], _conf(e.get("confidence"))]
            for e in payload["timeline"]
        ]
        story.append(_make_table(
            ["Date", "Event", "Domain", "Entity", "Description", "Conf."], rows,
            [0.75 * inch, 0.85 * inch, 1.25 * inch, 1.15 * inch, 1.6 * inch, 0.45 * inch],
            ss,
        ))
    else:
        story.append(_p("No timeline events recorded.", ss["Empty"]))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_GRID, spaceAfter=4))
    story.append(_p(
        "Generated by Sentinel — Scam Attribution Intelligence Platform.",
        ss["Empty"],
    ))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    logger.info("Workspace PDF generated for '%s' (%d bytes)", payload["case_id"], len(pdf))
    return pdf


def clusters_to_pdf_bytes(payload: dict) -> bytes:
    """Render a fraud-cluster intelligence payload (from cluster_engine.clusters_payload) to PDF."""
    ss = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="Sentinel Fraud Cluster Intelligence",
    )

    story = [
        _p("Sentinel Fraud Cluster Intelligence", ss["SentinelTitle"]),
        HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#0f3460"), spaceAfter=8),
        _p(f"Generated: {payload['generated_at']}", ss["Body"]),
        _p(f"Total Clusters: {payload['cluster_count']}", ss["Body"]),
    ]

    # --- Overview table --------------------------------------------------
    story.append(_p("Cluster Overview", ss["SectionH"]))
    if payload["clusters"]:
        rows = [
            [c["cluster_id"], c["status"], f"{c['risk_score']:.2f}",
             f"{c['confidence']:.2f}", c["domain_count"], c["campaign_count"], c["source_count"]]
            for c in payload["clusters"]
        ]
        story.append(_make_table(
            ["Cluster", "Status", "Risk", "Conf.", "Domains", "Campaigns", "Sources"],
            rows,
            [1.1 * inch, 1.0 * inch, 0.6 * inch, 0.6 * inch, 0.85 * inch, 1.0 * inch, 0.85 * inch],
            ss,
        ))
    else:
        story.append(_p("No clusters found.", ss["Empty"]))

    # --- Per-cluster detail ---------------------------------------------
    story.append(_p("Cluster Details", ss["SectionH"]))
    for c in payload["clusters"]:
        story.append(_p(f"{c['cluster_id']} — {c['status']}", ss["SubH"]))
        story.append(_p(c["summary"], ss["Body"]))
        story.append(_p("Domains: " + (", ".join(c["domains"]) or "—"), ss["Cell"]))
        story.append(_p("Campaigns: " + (", ".join(c["campaigns"]) or "—"), ss["Cell"]))
        story.append(_p("Sources: " + (", ".join(c["sources"]) or "—"), ss["Cell"]))
        story.append(_p("Platforms: " + (", ".join(c["platforms"]) or "—"), ss["Cell"]))
        story.append(Spacer(1, 6))

    story.append(HRFlowable(width="100%", thickness=0.5, color=_GRID, spaceAfter=4))
    story.append(_p(
        "Generated by Sentinel — Scam Attribution Intelligence Platform.",
        ss["Empty"],
    ))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    logger.info("Clusters PDF generated (%d clusters, %d bytes)",
                payload["cluster_count"], len(pdf))
    return pdf


def trends_to_pdf_bytes(payload: dict) -> bytes:
    """Render a fraud-network trend payload (from trend_engine.trends_payload) to PDF."""
    ss = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="Sentinel Fraud Network Trend Intelligence",
    )

    story = [
        _p("Sentinel Fraud Network Trend Intelligence", ss["SentinelTitle"]),
        HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#0f3460"), spaceAfter=8),
        _p(f"Generated: {payload['generated_at']}", ss["Body"]),
        _p(f"Total Clusters: {payload['cluster_count']}   |   "
           f"Emerging Networks: {payload['emerging_count']}", ss["Body"]),
    ]

    # --- Trend overview table -------------------------------------------
    story.append(_p("Trend Overview", ss["SectionH"]))
    if payload["trends"]:
        rows = [
            [t["cluster_id"], t["trend_status"], t["domain_count"],
             f"{t['growth_rate']:.2f}", f"{t['activity_score']:.2f}",
             t["first_seen"] or "—", t["last_seen"] or "—"]
            for t in payload["trends"]
        ]
        story.append(_make_table(
            ["Cluster", "Status", "Domains", "Growth", "Activity", "First Seen", "Last Seen"],
            rows,
            [1.0 * inch, 0.95 * inch, 0.7 * inch, 0.65 * inch, 0.7 * inch, 1.0 * inch, 1.0 * inch],
            ss,
        ))
    else:
        story.append(_p("No clusters found.", ss["Empty"]))

    # --- Emerging networks ----------------------------------------------
    story.append(_p("Emerging Networks", ss["SectionH"]))
    emerging = [t for t in payload["trends"] if t["trend_status"] == "EMERGING"]
    if emerging:
        for t in emerging:
            story.append(_p(
                f"{t['cluster_id']} — {t['domain_count']} domain(s), "
                f"confidence {t['confidence']:.2f}, activity {t['activity_score']:.2f}",
                ss["Body"],
            ))
    else:
        story.append(_p("No emerging networks at this time.", ss["Empty"]))

    # --- Narratives ------------------------------------------------------
    story.append(_p("Trend Narratives", ss["SectionH"]))
    for t in payload["trends"]:
        story.append(_p(t["narrative"], ss["Body"]))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_GRID, spaceAfter=4))
    story.append(_p(
        "Generated by Sentinel — Scam Attribution Intelligence Platform.",
        ss["Empty"],
    ))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    logger.info("Trends PDF generated (%d clusters, %d bytes)", payload["cluster_count"], len(pdf))
    return pdf
