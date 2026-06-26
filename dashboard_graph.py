"""
Sentinel ScamGraph — single-page dashboard.  Pure Streamlit, no server code.

Run:  streamlit run dashboard_graph.py   (from sentinel-poc/ root)

NOT `python dashboard_graph.py` and NOT uvicorn — this file defines no ASGI app.
"""
import json
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st
from pyvis.network import Network

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from db_connect import get_driver  # noqa: E402
from attribution_engine import (  # noqa: E402
    build_report,
    build_case_id,
    export_filename,
    report_to_markdown,
)
from report_export import (  # noqa: E402
    report_to_pdf_bytes,
    workspace_to_pdf_bytes,
    clusters_to_pdf_bytes,
    trends_to_pdf_bytes,
)
from workspace import (  # noqa: E402
    build_workspace_payload,
    workspace_graph_rows,
    workspace_to_markdown,
)
from cluster_engine import (  # noqa: E402
    build_clusters,
    cluster_to_graph_rows,
    clusters_payload,
    clusters_to_markdown,
)
from trend_engine import (  # noqa: E402
    compute_trends,
    emerging_networks,
    trends_payload,
    trends_to_markdown,
)
from similarity_engine import predict_threat  # noqa: E402
from copilot_engine import generate_explanation  # noqa: E402
from validation_engine import run_validation, validation_to_markdown  # noqa: E402

# ---------------------------------------------------------------------------
# Page config — must be first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Sentinel — ScamGraph",
    page_icon="🕸️",
    layout="wide",
)

st.markdown(
    """
    <style>
    [data-testid="stMetric"] {
        background: #16213e;
        border: 1px solid #0f3460;
        border-radius: 10px;
        padding: 16px 20px;
    }
    [data-testid="stMetricLabel"] { color: #a0aec0; font-size: 0.85rem; }
    [data-testid="stMetricValue"] { color: #e2e8f0; font-size: 2rem; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Neo4j — one shared driver for the lifetime of the server process
# ---------------------------------------------------------------------------
@st.cache_resource(show_spinner="Connecting to Neo4j...")
def _driver():
    return get_driver()


def run_query(cypher: str, **params) -> list[dict]:
    with _driver().session() as session:
        return [dict(r) for r in session.run(cypher, **params)]


def run_investigation(domain: str) -> dict:
    """Run the Attribution Engine for a domain and return the report dict."""
    with _driver().session() as session:
        return build_report(session, domain)


def run_clusters() -> list[dict]:
    """Compute deterministic fraud clusters from the live graph."""
    with _driver().session() as session:
        return build_clusters(session)


def run_prediction(domain: str) -> dict:
    """Predict fraud-cluster membership for an unseen domain."""
    with _driver().session() as session:
        return predict_threat(session, domain)


def run_validation_suite() -> dict:
    """Run the deterministic validation suite over the live graph."""
    with _driver().session() as session:
        return run_validation(session)


# ---------------------------------------------------------------------------
# Cypher
# ---------------------------------------------------------------------------
_COUNT_DOMAINS   = "MATCH (n:Domain)     RETURN count(n) AS n"
_COUNT_CAMPAIGNS = "MATCH (n:Campaign)   RETURN count(n) AS n"
_COUNT_SOURCES   = "MATCH (n:ScamSource) RETURN count(n) AS n"

_TOP_RISK_QUERY = """
MATCH (d:Domain)
WHERE d.confidence IS NOT NULL
RETURN d.name AS domain, d.confidence AS confidence, d.source AS source
ORDER BY d.confidence DESC
LIMIT 10
"""

_LATEST_QUERY = """
MATCH (d:Domain)
WHERE d.first_seen IS NOT NULL
RETURN
    d.name AS domain,
    replace(left(d.first_seen, 19), 'T', ' ') AS first_seen,
    d.source AS source
ORDER BY d.first_seen DESC
LIMIT 10
"""

_FULL_GRAPH_QUERY = """
MATCH (s:ScamSource)-[r:FLAGGED]->(d:Domain)
RETURN
    'source'  AS ltype, s.name AS lname, s.source_type AS lprop,
    'FLAGGED' AS rel,
    'domain'  AS rtype, d.name AS rname,
    coalesce(r.confidence, d.confidence, 0.0) AS confidence
LIMIT 80
UNION ALL
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain)
RETURN
    'campaign'    AS ltype, c.name AS lname, coalesce(c.scam_type,'') AS lprop,
    'USES_DOMAIN' AS rel,
    'domain'      AS rtype, d.name AS rname,
    coalesce(c.risk_score, 0.0) AS confidence
LIMIT 40
UNION ALL
MATCH (c:Campaign)-[:PROMOTED_ON]->(p:Platform)
RETURN
    'campaign'    AS ltype, c.name AS lname, coalesce(c.scam_type,'') AS lprop,
    'PROMOTED_ON' AS rel,
    'platform'    AS rtype, p.name AS rname,
    0.0           AS confidence
LIMIT 40
"""

_DOMAIN_SUBGRAPH_QUERY = """
MATCH (s:ScamSource)-[r:FLAGGED]->(d:Domain {name: $domain})
RETURN
    'source'  AS ltype, s.name AS lname, s.source_type AS lprop,
    'FLAGGED' AS rel,
    'domain'  AS rtype, d.name AS rname,
    coalesce(r.confidence, 0.0) AS confidence
UNION ALL
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain {name: $domain})
RETURN
    'campaign'    AS ltype, c.name AS lname, coalesce(c.scam_type,'') AS lprop,
    'USES_DOMAIN' AS rel,
    'domain'      AS rtype, d.name AS rname,
    coalesce(c.risk_score, 0.0) AS confidence
UNION ALL
MATCH (c:Campaign)-[:USES_DOMAIN]->(d:Domain {name: $domain})
MATCH (c)-[:PROMOTED_ON]->(p:Platform)
RETURN
    'campaign'    AS ltype, c.name AS lname, coalesce(c.scam_type,'') AS lprop,
    'PROMOTED_ON' AS rel,
    'platform'    AS rtype, p.name AS rname,
    0.0           AS confidence
"""

# ---------------------------------------------------------------------------
# Graph rendering helpers
# ---------------------------------------------------------------------------
NODE_CFG = {
    "domain":   {"color": "#e84545", "shape": "dot",     "size": 20},
    "source":   {"color": "#f5a623", "shape": "diamond", "size": 26},
    "campaign": {"color": "#4a90d9", "shape": "box",     "size": 22},
    "platform": {"color": "#7ed321", "shape": "ellipse", "size": 18},
    "cluster":  {"color": "#9b59b6", "shape": "star",    "size": 32},
}
EDGE_CFG = {
    "FLAGGED":      {"color": "#e84545", "dashes": False, "width": 2},
    "USES_DOMAIN":  {"color": "#f5a623", "dashes": True,  "width": 1},
    "PROMOTED_ON":  {"color": "#7ed321", "dashes": True,  "width": 1},
    "CONTAINS":     {"color": "#9b59b6", "dashes": False, "width": 2},
}
_PHYSICS = """{
  "physics": {
    "barnesHut": {
      "gravitationalConstant": -9000,
      "centralGravity": 0.25,
      "springLength": 150
    },
    "stabilization": {"iterations": 200, "fit": true}
  },
  "interaction": {"hover": true, "navigationButtons": true, "keyboard": true},
  "nodes": {"font": {"size": 13, "color": "#ffffff"}, "borderWidth": 2},
  "edges": {"font": {"size": 11, "color": "#cccccc", "align": "middle"},
            "smooth": {"type": "dynamic"}}
}"""


def build_network(rows: list[dict], height: str = "540px") -> Network:
    net = Network(height=height, width="100%", bgcolor="#0d1117", font_color="#e0e0e0")
    net.set_options(_PHYSICS)

    nodes: dict[str, dict] = {}
    edge_list: list[tuple] = []

    for row in rows:
        ltype = row.get("ltype", "")
        lname = row.get("lname", "")
        rtype = row.get("rtype", "")
        rname = row.get("rname", "")
        rel   = row.get("rel", "")
        conf  = float(row.get("confidence") or 0.0)
        lprop = row.get("lprop") or ""

        if lname:
            lid = f"{ltype}::{lname}"
            nodes.setdefault(lid, {"type": ltype, "label": lname, "conf": conf, "prop": lprop})
        if rname and rel:
            rid = f"{rtype}::{rname}"
            nodes.setdefault(rid, {"type": rtype, "label": rname, "conf": None, "prop": None})
            edge_list.append((lid, rid, rel, conf))

    for nid, nd in nodes.items():
        cfg   = NODE_CFG.get(nd["type"], {"color": "#888", "shape": "dot", "size": 14})
        short = nd["label"][:23] + "…" if len(nd["label"]) > 26 else nd["label"]
        lines = [f"<b>{nd['label']}</b>", f"Type: {nd['type']}"]
        if nd.get("prop"):
            lines.append(f"Category: {nd['prop']}")
        if nd.get("conf"):
            lines.append(f"Confidence: {nd['conf']:.2f}")
        net.add_node(nid, label=short, title="<br>".join(lines), **cfg)

    for lid, rid, rel, conf in edge_list:
        cfg = EDGE_CFG.get(rel, {"color": "#888", "dashes": False, "width": 1})
        tip = f"{rel}" + (f" | {conf:.2f}" if conf else "")
        net.add_edge(lid, rid, title=tip, label=rel, **cfg)

    return net


def render_network(net: Network, height_px: int = 560):
    with tempfile.NamedTemporaryFile(
        suffix=".html", delete=False, mode="w", encoding="utf-8"
    ) as f:
        net.save_graph(f.name)
        html = Path(f.name).read_text(encoding="utf-8")
    st.components.v1.html(html, height=height_px, scrolling=False)


def _safe_count(query: str) -> int | str:
    try:
        rows = run_query(query)
        return rows[0]["n"] if rows else 0
    except Exception:
        traceback.print_exc()
        return "—"


# ===========================================================================
# SECTIONS — each is a plain function; the runner at the bottom calls them
# in order, and any exception prints a full traceback to the terminal AND
# shows in the browser without killing the rest of the page.
# ===========================================================================

def render_sidebar():
    with st.sidebar:
        st.title("🕸️ Sentinel")
        st.caption("ScamGraph Intelligence")
        st.divider()
        st.markdown("""
**Node types**
🔴 Domain
🟡 ScamSource
🔵 Campaign
🟢 Platform

**Edges**
━━ FLAGGED
╌╌ USES_DOMAIN
╌╌ PROMOTED_ON
        """)
        st.divider()
        st.markdown("""
| Day | Status |
|-----|--------|
| Day 1 — Graph DB       | ✅ |
| Day 2 — REST API       | ✅ |
| Day 3 — Dashboard      | ✅ |
| Day 4 — Ingestion      | ✅ |
| Day 5 — ScamGraph      | ✅ |
| Day 6 — Investigation  | ✅ |
        """)


def render_header():
    st.title("🕸️ Sentinel — ScamGraph")
    st.caption("Live Neo4j knowledge graph")


def render_kpis():
    print("Rendering KPI section")
    st.markdown("---")
    st.subheader("📊 Graph Overview")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("🌐 Total Domains",   _safe_count(_COUNT_DOMAINS))
    k2.metric("🎯 Total Campaigns", _safe_count(_COUNT_CAMPAIGNS))
    k3.metric("📡 Intel Sources",   _safe_count(_COUNT_SOURCES))
    k4.metric("🔗 Graph Layers",    "4")


def render_graph_explorer():
    print("Rendering Graph Explorer section")
    st.markdown("---")
    st.subheader("🕸️ Graph Explorer")
    st.caption(
        "Interactive ScamGraph. Hover a node to inspect properties. "
        "Drag to reposition. Scroll to zoom."
    )

    graph_rows = run_query(_FULL_GRAPH_QUERY)
    print(f"  graph_rows returned: {len(graph_rows)}")

    if graph_rows:
        net = build_network(graph_rows, height="580px")
        render_network(net, height_px=600)
        n_edges = sum(1 for r in graph_rows if r.get("rel"))
        n_nodes = len({r.get("lname") for r in graph_rows if r.get("lname")} |
                      {r.get("rname") for r in graph_rows if r.get("rname")})
        st.caption(f"{n_nodes} nodes · {n_edges} edges")
    else:
        st.info(
            "No graph data found. Run the ingestion scripts first:\n\n"
            "```\ncd scripts\npython seed_graph.py\npython ingest_phishtank.py\npython ingest_fca_warnings.py\n```"
        )


def render_domain_lookup():
    print("Rendering Domain Lookup section")
    st.markdown("---")
    st.subheader("🔍 Domain Lookup")
    st.caption("Search any domain to see its attribution subgraph and chain.")

    examples = [
        "quantum-ai-invest.com",
        "fca-recovery-fund.co.uk",
        "martinlewis-crypto.net",
        "hmrc-tax-refund-2024.com",
        "bbc-cryptonews.org",
    ]

    st.markdown("**Quick examples**")
    ex_cols = st.columns(len(examples))
    picked = None
    for col, dom in zip(ex_cols, examples):
        if col.button(dom, use_container_width=True, key=f"btn_{dom}"):
            picked = dom

    input_val = picked or st.session_state.get("_domain_key", "")
    domain_input = st.text_input(
        "domain_input",
        value=input_val,
        placeholder="e.g. fca-recovery-fund.co.uk",
        key="_domain_key",
        label_visibility="collapsed",
    )

    if not st.button("🔍 Analyze", type="primary"):
        return

    q = (domain_input or "").strip()
    if not q:
        st.warning("Enter a domain name first.")
        return

    print(f"  domain lookup: {q}")
    with st.spinner(f"Querying graph for {q}..."):
        sub_rows = run_query(_DOMAIN_SUBGRAPH_QUERY, domain=q)

    if not sub_rows:
        st.info(f"No graph connections found for **{q}**.")
        return

    sub_net = build_network(sub_rows, height="400px")
    render_network(sub_net, height_px=420)
    st.markdown("**Attribution chain**")
    for r in sub_rows:
        if not (r.get("lname") and r.get("rel")):
            continue
        conf = r.get("confidence")
        cs   = f"  _(confidence: {conf:.2f})_" if conf else ""
        st.markdown(
            f"- `{r['ltype'].upper()}` **{r['lname']}**"
            f" → `{r['rel']}` →"
            f" `{r['rtype'].upper()}` **{r['rname']}**{cs}"
        )


_VERDICT_STYLE = {
    "MALICIOUS":  ("#e84545", "🔴"),
    "SUSPICIOUS": ("#f5a623", "🟠"),
    "LOW_RISK":   ("#7ed321", "🟢"),
    "UNKNOWN":    ("#6c7a89", "⚪"),
}


def render_investigation():
    print("Rendering Investigation Report section")
    st.markdown("---")
    st.subheader("🕵️ Investigation Dashboard — Attribution Engine")
    st.caption(
        "Run a full AI attribution investigation: why a domain is suspicious, "
        "which sources flagged it, connected campaigns/platforms, and similar domains."
    )

    examples = [
        "quantum-ai-invest.com",
        "fca-recovery-fund.co.uk",
        "hmrc-tax-refund-2024.com",
        "martinlewis-crypto.net",
        "turkiye-yatirim-kripto.com",
    ]
    st.markdown("**Quick examples**")
    ex_cols = st.columns(len(examples))
    picked = None
    for col, dom in zip(ex_cols, examples):
        if col.button(dom, use_container_width=True, key=f"inv_{dom}"):
            picked = dom

    input_val = picked or st.session_state.get("_invest_key", "")
    domain_input = st.text_input(
        "investigate_input",
        value=input_val,
        placeholder="e.g. fca-recovery-fund.co.uk",
        key="_invest_key",
        label_visibility="collapsed",
    )

    if not st.button("🕵️ Investigate", type="primary", key="investigate_btn"):
        return

    q = (domain_input or "").strip()
    if not q:
        st.warning("Enter a domain name first.")
        return

    print(f"  investigating: {q}")
    with st.spinner(f"Running attribution investigation for {q}..."):
        report = run_investigation(q)

    color, icon = _VERDICT_STYLE.get(report["verdict"], ("#6c7a89", "⚪"))
    score = report["confidence_score"]

    # --- Verdict banner --------------------------------------------------
    st.markdown(
        f"""
        <div style="background:{color}22;border:1px solid {color};
                    border-radius:10px;padding:16px 20px;margin:8px 0;">
            <span style="font-size:1.4rem;font-weight:700;color:{color};">
                {icon} {report['verdict']}
            </span>
            <span style="float:right;font-size:1.2rem;color:#e2e8f0;">
                Confidence: <b>{score:.2f}</b>
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(min(1.0, score), text=f"Aggregated confidence score: {score:.2f}")

    # --- Executive summary ----------------------------------------------
    st.markdown("#### 📋 Executive Summary")
    st.info(report["summary"])

    # --- Why suspicious --------------------------------------------------
    st.markdown("#### ⚠️ Why This Domain Is Suspicious")
    for reason in report["reasons"]:
        st.markdown(f"- {reason}")

    if report["keyword_indicators"]:
        st.caption("Keyword indicators: " + ", ".join(f"`{k}`" for k in report["keyword_indicators"]))

    # --- Evidence columns ------------------------------------------------
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### 📡 Intelligence Sources")
        if report["intelligence_sources"]:
            df_src = pd.DataFrame(report["intelligence_sources"])
            df_src = df_src.rename(columns={
                "name": "Source", "source_type": "Type",
                "confidence": "Confidence", "first_seen": "First Seen",
            })
            keep = [c for c in ["Source", "Type", "Confidence", "First Seen"] if c in df_src.columns]
            st.dataframe(df_src[keep], use_container_width=True, hide_index=True)
        else:
            st.caption("No intelligence feed has flagged this domain directly.")

        st.markdown("#### 📱 Connected Platforms")
        if report["connected_platforms"]:
            st.markdown(" ".join(f"`{p}`" for p in report["connected_platforms"]))
        else:
            st.caption("No platforms linked.")

    with col_b:
        st.markdown("#### 🎯 Connected Campaigns")
        if report["connected_campaigns"]:
            rows = [
                {
                    "Campaign": c["name"],
                    "Scam Type": c["scam_type"],
                    "Risk": f"{(c['risk_score'] or 0):.2f}",
                    "Platforms": ", ".join(c["platforms"]) or "—",
                }
                for c in report["connected_campaigns"]
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.caption("No scam campaigns linked.")

    # --- Similar domains -------------------------------------------------
    st.markdown("#### 🧬 Similar Domains (Infrastructure Cluster)")
    if report["similar_domains"]:
        rows = [
            {
                "Domain": s["domain"],
                "Similarity": f"{s['similarity']:.2f}",
                "Confidence": f"{s['confidence']:.2f}" if s.get("confidence") is not None else "—",
                "Why": s["reason"],
            }
            for s in report["similar_domains"]
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No similar domains found in the ScamGraph.")

    # --- Analyst Case Report --------------------------------------------
    render_case_report(report, color)

    # --- Raw JSON --------------------------------------------------------
    with st.expander("🔧 Raw structured report (JSON)"):
        st.json(report)


def render_case_report(report: dict, color: str):
    """Consolidated analyst-style case report panel for an investigation."""
    st.markdown("---")
    st.markdown("## 📁 Analyst Case Report")

    case_id = build_case_id(report["domain"], report["generated_at"])
    st.code(case_id, language=None)

    # Header metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Domain", report["domain"])
    c2.metric("Verdict", report["verdict"])
    c3.metric("Confidence", f"{report['confidence_score']:.2f}")
    c4.metric("Generated", report["generated_at"][:19].replace("T", " "))

    # Executive summary
    st.markdown("#### 📋 Executive Summary")
    st.info(report["summary"])

    # Recommended action — styled by verdict severity
    st.markdown("#### 🚨 Recommended Action")
    action = report.get("recommended_action", "—")
    if report["verdict"] == "MALICIOUS":
        st.error(action)
    elif report["verdict"] == "SUSPICIOUS":
        st.warning(action)
    else:
        st.success(action)

    # Attribution chain (textual: ScamSource → Domain → Campaign → Platform)
    st.markdown("#### 🔗 Attribution Chain")
    src_names = ", ".join(s["name"] for s in report["intelligence_sources"]) or "—"
    camp_names = ", ".join(c["name"] for c in report["connected_campaigns"]) or "—"
    plat_names = ", ".join(report["connected_platforms"]) or "—"
    st.markdown(
        f"`ScamSource` **{src_names}**"
        f" → `Domain` **{report['domain']}**"
        f" → `Campaign` **{camp_names}**"
        f" → `Platform` **{plat_names}**"
    )

    # Investigation timeline
    st.markdown("#### 🕒 Investigation Timeline")
    if report.get("timeline"):
        rows = [
            {
                "Date": e["date"],
                "Event Type": e["event_type"],
                "Entity": e["entity"],
                "Description": e["description"],
                "Confidence": f"{e['confidence']:.2f}" if e.get("confidence") is not None else "—",
            }
            for e in report["timeline"]
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No timeline events — domain has no recorded intelligence.")

    # Evidence summary
    st.markdown("#### 📊 Evidence Summary")
    e1, e2, e3, e4 = st.columns(4)
    e1.metric("Sources", len(report["intelligence_sources"]))
    e2.metric("Campaigns", len(report["connected_campaigns"]))
    e3.metric("Platforms", len(report["connected_platforms"]))
    e4.metric("Related Domains", len(report["similar_domains"]))

    # Export — JSON (full report), Markdown (analyst document), PDF (printable)
    st.markdown("#### ⬇️ Export Case Report")
    json_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    md_text = report_to_markdown(report)
    pdf_bytes = report_to_pdf_bytes(report)
    dl1, dl2, dl3 = st.columns(3)
    dl1.download_button(
        "Download JSON",
        data=json_bytes,
        file_name=export_filename(report["domain"], report["generated_at"], "json"),
        mime="application/json",
        use_container_width=True,
    )
    dl2.download_button(
        "Download Markdown",
        data=md_text,
        file_name=export_filename(report["domain"], report["generated_at"], "md"),
        mime="text/markdown",
        use_container_width=True,
    )
    dl3.download_button(
        "Download PDF",
        data=pdf_bytes,
        file_name=export_filename(report["domain"], report["generated_at"], "pdf"),
        mime="application/pdf",
        use_container_width=True,
    )


def render_intel_tables():
    print("Rendering Intel Tables section")
    st.markdown("---")
    tl, tr = st.columns(2)

    with tl:
        print("Rendering Top Risk Domains")
        st.subheader("🔴 Top Risk Domains")
        top_rows = run_query(_TOP_RISK_QUERY)
        print(f"  top_risk returned {len(top_rows)} rows")
        if top_rows:
            df = pd.DataFrame(top_rows)
            df["Risk"] = df["confidence"].apply(
                lambda x: "🔴 High" if x >= 0.8 else ("🟠 Medium" if x >= 0.5 else "🟢 Low")
            )
            df["confidence"] = df["confidence"].map("{:.2f}".format)
            df = df.rename(columns={"domain": "Domain", "confidence": "Score", "source": "Source"})
            st.dataframe(df[["Domain", "Score", "Risk", "Source"]],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No scored domains. Run the ingestion scripts.")

    with tr:
        print("Rendering Latest Ingested Domains")
        st.subheader("🕐 Latest Ingested Domains")
        latest_rows = run_query(_LATEST_QUERY)
        print(f"  latest returned {len(latest_rows)} rows")
        if latest_rows:
            df = pd.DataFrame(latest_rows).rename(columns={
                "domain": "Domain", "first_seen": "First Seen", "source": "Source"
            })
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No ingested domains. Run the ingestion scripts.")


_WS_EXAMPLES = [
    "quantum-ai-invest.com",
    "bbc-cryptonews.org",
    "fca-authorised-invest.com",
    "martinlewis-crypto.net",
    "apple-id-suspended.com",
]


def _init_workspace_state():
    if "ws_case" not in st.session_state:
        now = datetime.now(timezone.utc)
        st.session_state.ws_case = {
            "case_id": f"CASE-{now.strftime('%Y%m%d')}-001",
            "status": "OPEN",
            "severity": "MEDIUM",
            "created": now.isoformat(),
        }
    if "ws_reports" not in st.session_state:
        st.session_state.ws_reports = []  # list of investigation report dicts


def render_workspace():
    print("Rendering Investigation Workspace section")
    st.markdown("---")
    st.subheader("📁 Investigation Workspace")
    st.caption("Investigate multiple domains inside a single fraud case.")

    _init_workspace_state()
    case = st.session_state.ws_case
    reports = st.session_state.ws_reports

    # --- Case header -----------------------------------------------------
    h1, h2, h3, h4 = st.columns([2, 1, 1, 2])
    h1.text_input("Case ID", value=case["case_id"], disabled=True, key="ws_caseid")
    statuses = ["OPEN", "REVIEW", "CLOSED"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    case["status"] = h2.selectbox("Status", statuses, index=statuses.index(case["status"]))
    case["severity"] = h3.selectbox("Severity", severities, index=severities.index(case["severity"]))
    h4.metric("Created", case["created"][:19].replace("T", " "))

    # --- Add domains -----------------------------------------------------
    st.markdown("**Add domains to the case**")
    ex_cols = st.columns(len(_WS_EXAMPLES))
    picked = None
    for col, dom in zip(ex_cols, _WS_EXAMPLES):
        if col.button(dom, key=f"ws_ex_{dom}", use_container_width=True):
            picked = dom

    add_val = picked or st.session_state.get("ws_add_input", "")
    add_domain = st.text_input(
        "ws_add", value=add_val, key="ws_add_input",
        placeholder="e.g. fca-authorised-invest.com", label_visibility="collapsed",
    )
    b1, b2 = st.columns([1, 1])
    if b1.button("➕ Add Domain", type="primary", key="ws_add_btn"):
        d = (add_domain or "").strip().lower()
        if not d:
            st.warning("Enter a domain first.")
        elif any(r["domain"] == d for r in reports):
            st.info(f"{d} is already in the case.")
        else:
            print(f"  workspace add: {d}")
            with st.spinner(f"Investigating {d}..."):
                reports.append(run_investigation(d))
            st.success(f"Added {d} to {case['case_id']}.")
    if b2.button("🗑️ Clear Workspace", key="ws_clear_btn"):
        st.session_state.ws_reports = []
        reports = st.session_state.ws_reports

    if not reports:
        st.info("No domains in the case yet. Add a domain above to begin.")
        return

    st.markdown("**Domains in case:** " + ", ".join(f"`{r['domain']}`" for r in reports))

    # Build the case-level payload once; reused by metrics, timeline, exports.
    payload = build_workspace_payload(case, reports)
    m = payload["metrics"]

    # --- Investigation Metrics ------------------------------------------
    st.markdown("### 📊 Investigation Metrics")
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Domains", m["total_domains"])
    k2.metric("Campaigns", m["total_campaigns"])
    k3.metric("Platforms", m["total_platforms"])
    k4.metric("Sources", m["total_sources"])
    k5.metric("Avg Confidence", f"{m['average_confidence']:.2f}")

    # --- Fraud Network Summary ------------------------------------------
    st.markdown("### 🧠 Fraud Network Summary")
    st.info(payload["fraud_network_summary"])

    # --- Combined Attribution Graph -------------------------------------
    st.markdown("### 🕸️ Combined Attribution Graph")
    st.caption("ScamSource → Domain → Campaign → Platform, with shared nodes merged.")
    rows = workspace_graph_rows(reports)
    if rows:
        net = build_network(rows, height="560px")
        render_network(net, height_px=580)

    # --- Domain Verdicts -------------------------------------------------
    st.markdown("### 🔎 Domain Verdicts")
    st.dataframe(
        pd.DataFrame([
            {
                "Domain": r["domain"],
                "Verdict": r["verdict"],
                "Confidence": f"{r['confidence_score']:.2f}",
                "Sources": len(r["intelligence_sources"]),
                "Campaigns": len(r["connected_campaigns"]),
            }
            for r in reports
        ]),
        use_container_width=True, hide_index=True,
    )

    # --- Case Timeline ---------------------------------------------------
    st.markdown("### 🕒 Case Timeline")
    if payload["timeline"]:
        st.dataframe(
            pd.DataFrame([
                {
                    "Date": e["date"],
                    "Event Type": e["event_type"],
                    "Domain": e["domain"],
                    "Entity": e["entity"],
                    "Description": e["description"],
                    "Confidence": f"{e['confidence']:.2f}" if e.get("confidence") is not None else "—",
                }
                for e in payload["timeline"]
            ]),
            use_container_width=True, hide_index=True,
        )
    else:
        st.caption("No timeline events for the domains in this case.")

    # --- Export Workspace -----------------------------------------------
    st.markdown("### ⬇️ Export Workspace")
    fname_base = f"sentinel_workspace_{case['case_id']}"
    ws_json = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    ws_md = workspace_to_markdown(payload)
    ws_pdf = workspace_to_pdf_bytes(payload)
    e1, e2, e3 = st.columns(3)
    e1.download_button(
        "Export Workspace JSON", data=ws_json,
        file_name=f"{fname_base}.json", mime="application/json",
        use_container_width=True, key="ws_dl_json",
    )
    e2.download_button(
        "Export Workspace Markdown", data=ws_md,
        file_name=f"{fname_base}.md", mime="text/markdown",
        use_container_width=True, key="ws_dl_md",
    )
    e3.download_button(
        "Export Workspace PDF", data=ws_pdf,
        file_name=f"{fname_base}.pdf", mime="application/pdf",
        use_container_width=True, key="ws_dl_pdf",
    )


def render_clusters():
    print("Rendering Fraud Cluster Intelligence section")
    st.markdown("---")
    st.subheader("🧠 Fraud Cluster Intelligence")
    st.caption(
        "Automatically groups related domains, campaigns, and sources into "
        "deterministic fraud clusters — coordinated scam networks at a glance."
    )

    with st.spinner("Computing fraud clusters..."):
        try:
            clusters = run_clusters()
        except Exception as e:
            st.error(f"Cluster computation failed: {e}")
            return

    if not clusters:
        st.info("No clusters found. Seed the graph and run the ingestion scripts first.")
        return

    payload = clusters_payload(clusters)

    # --- Cluster KPIs ----------------------------------------------------
    active = sum(1 for c in clusters if c["status"] == "ACTIVE")
    largest = max(c["domain_count"] for c in clusters)
    k1, k2, k3 = st.columns(3)
    k1.metric("Total Clusters", len(clusters))
    k2.metric("Active Networks", active)
    k3.metric("Largest Cluster", f"{largest} domains")

    # --- Overview table --------------------------------------------------
    st.markdown("### 📋 Cluster Overview")
    st.dataframe(
        pd.DataFrame([
            {
                "Cluster ID": c["cluster_id"],
                "Status": c["status"],
                "Risk Score": f"{c['risk_score']:.2f}",
                "Confidence": f"{c['confidence']:.2f}",
                "Domains": c["domain_count"],
                "Campaigns": c["campaign_count"],
                "Sources": c["source_count"],
            }
            for c in clusters
        ]),
        use_container_width=True, hide_index=True,
    )

    # --- Cluster inspector ----------------------------------------------
    st.markdown("### 🔬 Cluster Inspector")
    ids = [c["cluster_id"] for c in clusters]
    chosen = st.selectbox("Select a cluster", ids, key="cluster_select")
    cluster = next(c for c in clusters if c["cluster_id"] == chosen)

    badge = {"ACTIVE": "🔴", "MONITORING": "🟠", "DORMANT": "🟢"}.get(cluster["status"], "⚪")
    st.markdown(f"#### {badge} {cluster['cluster_id']} — {cluster['status']}")
    st.info(cluster["summary"])

    d1, d2, d3 = st.columns(3)
    d1.metric("Risk Score", f"{cluster['risk_score']:.2f}")
    d2.metric("Confidence", f"{cluster['confidence']:.2f}")
    d3.metric("Domains", cluster["domain_count"])

    # Cluster graph: FraudCluster -> Domains -> Campaigns -> Platforms
    st.markdown("**Cluster Attribution Graph**")
    rows = cluster_to_graph_rows(cluster)
    if rows:
        net = build_network(rows, height="520px")
        render_network(net, height_px=540)

    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown("**Campaigns**")
        st.markdown("\n".join(f"- {c}" for c in cluster["campaigns"]) or "_None_")
    with cc2:
        st.markdown("**Sources / Platforms**")
        st.markdown(
            "Sources: " + (", ".join(cluster["sources"]) or "—") + "  \n"
            "Platforms: " + (", ".join(cluster["platforms"]) or "—")
        )

    # --- Exports ---------------------------------------------------------
    st.markdown("### ⬇️ Export Cluster Intelligence")
    cl_json = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    cl_md = clusters_to_markdown(payload)
    cl_pdf = clusters_to_pdf_bytes(payload)
    e1, e2, e3 = st.columns(3)
    e1.download_button(
        "Export Clusters JSON", data=cl_json,
        file_name="sentinel_fraud_clusters.json", mime="application/json",
        use_container_width=True, key="cl_dl_json",
    )
    e2.download_button(
        "Export Clusters Markdown", data=cl_md,
        file_name="sentinel_fraud_clusters.md", mime="text/markdown",
        use_container_width=True, key="cl_dl_md",
    )
    e3.download_button(
        "Export Clusters PDF", data=cl_pdf,
        file_name="sentinel_fraud_clusters.pdf", mime="application/pdf",
        use_container_width=True, key="cl_dl_pdf",
    )


_TREND_BADGE = {
    "EXPANDING": "🔺",
    "EMERGING":  "🚨",
    "ACTIVE":    "🔴",
    "DORMANT":   "🟢",
}


def render_trends():
    print("Rendering Fraud Network Trends section")
    st.markdown("---")
    st.subheader("📈 Fraud Network Trends")
    st.caption(
        "Growth, activity, and risk evolution of fraud clusters over time — "
        "so analysts watch networks, not just isolated domains."
    )

    with st.spinner("Computing fraud-network trends..."):
        try:
            clusters = run_clusters()
            trends = compute_trends(clusters)
        except Exception as e:
            st.error(f"Trend computation failed: {e}")
            return

    if not trends:
        st.info("No clusters to analyse yet. Seed the graph and run ingestion first.")
        return

    payload = trends_payload(trends)
    sc = payload["status_counts"]

    # --- Trend KPIs ------------------------------------------------------
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Clusters", payload["cluster_count"])
    k2.metric("Expanding", sc.get("EXPANDING", 0))
    k3.metric("Emerging", payload["emerging_count"])
    k4.metric("Dormant", sc.get("DORMANT", 0))

    # --- Trend table -----------------------------------------------------
    st.markdown("### 📊 Cluster Trend Metrics")
    st.dataframe(
        pd.DataFrame([
            {
                "Cluster ID": t["cluster_id"],
                "Domains": t["domain_count"],
                "Growth Rate": f"{t['growth_rate']:.2f}",
                "Activity Score": f"{t['activity_score']:.2f}",
                "Status": f"{_TREND_BADGE.get(t['trend_status'], '')} {t['trend_status']}",
                "First Seen": t["first_seen"] or "—",
                "Last Seen": t["last_seen"] or "—",
            }
            for t in trends
        ]),
        use_container_width=True, hide_index=True,
    )

    # --- Emerging Networks alerts ---------------------------------------
    st.markdown("### 🚨 Emerging Networks")
    emerging = emerging_networks(trends)
    if emerging:
        for t in emerging:
            st.warning(
                f"**{t['cluster_id']}** — {t['domain_count']} domain(s), "
                f"confidence {t['confidence']:.2f}, activity {t['activity_score']:.2f}. "
                f"{t['narrative']}"
            )
    else:
        st.success("No emerging networks right now — no small, high-confidence, recently-active clusters.")

    # --- Trend narratives -----------------------------------------------
    st.markdown("### 📝 Trend Narratives")
    for t in trends:
        st.markdown(f"- {t['narrative']}")

    # --- Exports ---------------------------------------------------------
    st.markdown("### ⬇️ Export Trend Intelligence")
    tr_json = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    tr_md = trends_to_markdown(payload)
    tr_pdf = trends_to_pdf_bytes(payload)
    e1, e2, e3 = st.columns(3)
    e1.download_button(
        "Export Trends JSON", data=tr_json,
        file_name="sentinel_fraud_trends.json", mime="application/json",
        use_container_width=True, key="tr_dl_json",
    )
    e2.download_button(
        "Export Trends Markdown", data=tr_md,
        file_name="sentinel_fraud_trends.md", mime="text/markdown",
        use_container_width=True, key="tr_dl_md",
    )
    e3.download_button(
        "Export Trends PDF", data=tr_pdf,
        file_name="sentinel_fraud_trends.pdf", mime="application/pdf",
        use_container_width=True, key="tr_dl_pdf",
    )


_PRED_VERDICT_STYLE = {
    "LIKELY_MALICIOUS": ("#e84545", "🔴"),
    "SUSPICIOUS":       ("#f5a623", "🟠"),
    "LOW_SIMILARITY":   ("#7ed321", "🟢"),
    "UNKNOWN":          ("#6c7a89", "⚪"),
}


def render_threat_similarity():
    print("Rendering Threat Similarity section")
    st.markdown("---")
    st.subheader("🔮 Threat Similarity — Predict Unseen Domains")
    st.caption(
        "Score a domain Sentinel has never attributed against known fraud clusters — "
        "flag likely scam infrastructure before a campaign or source link exists."
    )

    examples = [
        "fca-investment-recovery.com",
        "elon-musk-quantum-trade.net",
        "lloyds-secure-verify.com",
        "hmrc-rebate-claim.co.uk",
        "totally-unrelated-blog.com",
    ]
    st.markdown("**Quick examples (unseen domains)**")
    ex_cols = st.columns(len(examples))
    picked = None
    for col, dom in zip(ex_cols, examples):
        if col.button(dom, key=f"pred_{dom}", use_container_width=True):
            picked = dom

    val = picked or st.session_state.get("pred_input", "")
    domain_input = st.text_input(
        "predict_input", value=val, key="pred_input",
        placeholder="e.g. fca-investment-recovery.com", label_visibility="collapsed",
    )

    if not st.button("🔮 Predict Threat", type="primary", key="pred_btn"):
        return

    q = (domain_input or "").strip()
    if not q:
        st.warning("Enter a domain first.")
        return

    print(f"  predicting: {q}")
    with st.spinner(f"Scoring {q} against known fraud clusters..."):
        pred = run_prediction(q)

    color, icon = _PRED_VERDICT_STYLE.get(pred["verdict"], ("#6c7a89", "⚪"))

    st.markdown(
        f"""
        <div style="background:{color}22;border:1px solid {color};
                    border-radius:10px;padding:14px 18px;margin:8px 0;">
            <span style="font-size:1.3rem;font-weight:700;color:{color};">
                {icon} {pred['verdict'].replace('_', ' ')}
            </span>
            <span style="float:right;color:#e2e8f0;">
                Predicted cluster: <b>{pred['predicted_cluster'] or '—'}</b>
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if pred["known_to_sentinel"]:
        st.caption("⚠️ This domain already exists in the Sentinel graph (prediction shown for validation).")

    m1, m2, m3 = st.columns(3)
    m1.metric("Similarity", f"{pred['similarity_score']:.2f}")
    m2.metric("Predicted Risk", f"{pred['risk_score']:.2f}")
    m3.metric("Confidence", f"{pred['confidence']:.2f}")

    st.markdown("#### 🧾 Explanation")
    st.info(pred["explanation"])

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("#### 📐 Signal Breakdown")
        sb = pred["signal_breakdown"]
        st.dataframe(
            pd.DataFrame(
                [{"Signal": k.replace("_", " ").title(), "Score": f"{v:.2f}"} for k, v in sb.items()]
            ),
            use_container_width=True, hide_index=True,
        )
        if pred["matched_keywords"]:
            st.caption("Matched keywords: " + ", ".join(f"`{k}`" for k in pred["matched_keywords"]))

    with col_b:
        st.markdown("#### 🧬 Nearest Known Domains")
        if pred["nearest_domains"]:
            st.dataframe(
                pd.DataFrame([
                    {"Domain": n["domain"], "Lexical": f"{n['lexical']:.2f}", "Cluster": n["cluster_id"]}
                    for n in pred["nearest_domains"]
                ]),
                use_container_width=True, hide_index=True,
            )
        else:
            st.caption("No lexically similar known domains.")

    st.markdown("#### 🏷️ Candidate Clusters")
    if pred["candidates"]:
        st.dataframe(
            pd.DataFrame([
                {
                    "Cluster": c["cluster_id"],
                    "Status": c["status"],
                    "Similarity": f"{c['similarity']:.2f}",
                    "Cluster Risk": f"{c['cluster_risk']:.2f}",
                }
                for c in pred["candidates"]
            ]),
            use_container_width=True, hide_index=True,
        )

    st.download_button(
        "⬇️ Download Prediction JSON",
        data=json.dumps(pred, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name=f"sentinel_prediction_{pred['domain'].replace('.', '-')}.json",
        mime="application/json", key="pred_dl_json",
    )
    with st.expander("🔧 Raw prediction (JSON)"):
        st.json(pred)


# Predefined bank-demo scenarios — each maps a story to an unseen example domain.
_DEMO_SCENARIOS = {
    "🏛️ FCA Recovery Scam": "fca-investment-recovery.com",
    "🏦 Banking Verification Scam": "wellsfargo-secure-login.com",
    "₿ Crypto Investment Scam": "quantum-ai-investment.com",
}


def render_bank_demo():
    """Guided 6-step analyst workflow that orchestrates the existing engines.

    No new business logic — reuses the Threat Similarity Engine, the Cluster
    Engine, the Investigation Engine, and the existing report exporters.
    """
    print("Rendering Bank Demo Scenario section")
    st.markdown("---")
    st.subheader("🏦 Bank Demo Scenario")
    st.caption(
        "Guided analyst workflow: from an unknown domain to an actionable, "
        "exportable fraud report — in under 3 minutes."
    )

    cols = st.columns(len(_DEMO_SCENARIOS))
    for col, (label, dom) in zip(cols, _DEMO_SCENARIOS.items()):
        if col.button(label, use_container_width=True, key=f"demo_{dom}"):
            st.session_state.demo_domain = dom

    domain = st.session_state.get("demo_domain")
    if not domain:
        st.info("▶️ Select a scenario above to run the guided fraud-attribution flow.")
        return

    with st.spinner(f"Running the Sentinel pipeline for {domain}..."):
        pred = run_prediction(domain)        # Threat Similarity Engine
        clusters = run_clusters()            # Cluster Engine
        report = run_investigation(domain)   # Investigation Engine
    cluster = next((c for c in clusters if c["cluster_id"] == pred["predicted_cluster"]), None)

    # Step 1 — domain observed
    st.markdown("##### 1️⃣ New domain observed")
    s1, s2 = st.columns(2)
    s1.metric("Domain", domain)
    s2.metric("Known to Sentinel?", "Yes" if pred["known_to_sentinel"] else "No")

    # Step 2 — automatic threat similarity
    st.markdown("##### 2️⃣ Threat Similarity (run automatically)")
    color, icon = _PRED_VERDICT_STYLE.get(pred["verdict"], ("#6c7a89", "⚪"))
    st.markdown(
        f"""
        <div style="background:{color}22;border:1px solid {color};
                    border-radius:10px;padding:12px 16px;margin:6px 0;">
            <span style="font-size:1.2rem;font-weight:700;color:{color};">
                {icon} {pred['verdict'].replace('_', ' ')}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Predicted Cluster", pred["predicted_cluster"] or "—")
    m2.metric("Similarity", f"{pred['similarity_score']:.2f}")
    m3.metric("Risk", f"{pred['risk_score']:.2f}")
    m4.metric("Verdict", pred["verdict"].replace("_", " "))

    # Step 3 — why it matched (reuse the engine's explanation)
    st.markdown("##### 3️⃣ Why it matched")
    st.info(pred["explanation"])

    # Step 4 — related fraud cluster (reuse the cluster engine)
    st.markdown("##### 4️⃣ Related Fraud Cluster")
    if cluster:
        d1, d2, d3, d4 = st.columns(4)
        d1.metric("Cluster ID", cluster["cluster_id"])
        d2.metric("Domains", cluster["domain_count"])
        d3.metric("Cluster Risk", f"{cluster['risk_score']:.2f}")
        d4.metric("Status", cluster["status"])
        members = ", ".join(cluster["domains"][:6]) + (" …" if cluster["domain_count"] > 6 else "")
        st.caption(f"Network members: {members}")
    else:
        st.caption("No related cluster — novel infrastructure (first observed instance).")

    # Step 5 — recommended action (reuse the investigation engine)
    st.markdown("##### 5️⃣ Recommended Action")
    action = report["recommended_action"]
    if report["verdict"] == "MALICIOUS":
        st.error(action)
    elif report["verdict"] == "SUSPICIOUS":
        st.warning(action)
    else:
        st.success(action)
    st.caption(report["summary"])

    # Step 6 — export investigation report (reuse existing exporters)
    st.markdown("##### 6️⃣ Export Investigation Report")
    pdf = report_to_pdf_bytes(report)
    md = report_to_markdown(report)
    js = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    x1, x2, x3 = st.columns(3)
    x1.download_button(
        "📄 PDF Report", data=pdf,
        file_name=export_filename(domain, report["generated_at"], "pdf"),
        mime="application/pdf", use_container_width=True, key="demo_pdf",
    )
    x2.download_button(
        "📝 Markdown", data=md,
        file_name=export_filename(domain, report["generated_at"], "md"),
        mime="text/markdown", use_container_width=True, key="demo_md",
    )
    x3.download_button(
        "🔧 JSON", data=js,
        file_name=export_filename(domain, report["generated_at"], "json"),
        mime="application/json", use_container_width=True, key="demo_json",
    )


def render_copilot():
    print("Rendering Analyst Copilot section")
    st.markdown("---")
    st.subheader("🧠 Analyst Copilot")
    st.caption(
        "Deterministic explainability — plain-English answers to why a domain was "
        "flagged, why a cluster matched, why the risk is what it is, and what to do. "
        "No LLM; explanations are composed from Sentinel's own engine outputs."
    )

    examples = [
        "fca-investment-recovery.com",
        "wellsfargo-secure-login.com",
        "quantum-ai-investment.com",
        "uphold-login-secure.com",
    ]
    st.markdown("**Quick examples**")
    ex_cols = st.columns(len(examples))
    picked = None
    for col, dom in zip(ex_cols, examples):
        if col.button(dom, key=f"cop_{dom}", use_container_width=True):
            picked = dom

    val = picked or st.session_state.get("copilot_input", "")
    domain_input = st.text_input(
        "copilot_input", value=val, key="copilot_input",
        placeholder="e.g. fca-investment-recovery.com", label_visibility="collapsed",
    )

    if not st.button("🧠 Explain", type="primary", key="copilot_btn"):
        return

    q = (domain_input or "").strip()
    if not q:
        st.warning("Enter a domain first.")
        return

    print(f"  copilot explaining: {q}")
    with st.spinner(f"Composing analyst explanation for {q}..."):
        prediction = run_prediction(q)
        clusters = run_clusters()
        report = run_investigation(q)
        cluster = next((c for c in clusters if c["cluster_id"] == prediction["predicted_cluster"]), None)
        explanation = generate_explanation(report, prediction, cluster)

    st.markdown("#### 🗒️ Analyst Summary")
    st.info(explanation["analyst_summary"])

    st.markdown("#### ❓ Why was this domain flagged?")
    st.write(explanation["why_flagged"])

    st.markdown("#### 🧩 Why was this cluster selected?")
    st.write(explanation["why_cluster"])

    st.markdown("#### 📊 Why is the risk score what it is?")
    st.write(explanation["why_risk"])

    st.markdown("#### ✅ What action should be taken?")
    if report["verdict"] == "MALICIOUS":
        st.error(explanation["recommended_action"])
    elif report["verdict"] == "SUSPICIOUS":
        st.warning(explanation["recommended_action"])
    else:
        st.success(explanation["recommended_action"])

    with st.expander("🔧 Raw explanation (JSON)"):
        st.json(explanation)


def render_validation():
    print("Rendering Validation Metrics section")
    st.markdown("---")
    st.subheader("📊 Validation Metrics")
    st.caption(
        "Credibility metrics for the Threat Similarity Engine, measured over a "
        "deterministic built-in test set (scam-like vs benign domains)."
    )

    with st.spinner("Running validation suite..."):
        try:
            res = run_validation_suite()
        except Exception as e:
            st.error(f"Validation failed: {e}")
            return

    # KPI cards
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Accuracy", f"{res['accuracy']:.0%}")
    k2.metric("Detection Rate", f"{res['detection_rate']:.0%}")
    k3.metric("False Positive Rate", f"{res['false_positive_rate']:.0%}")
    k4.metric("Avg Risk Score", f"{res['average_risk_score']:.2f}")

    k5, k6, k7, k8 = st.columns(4)
    k5.metric("Total Tested", res["total_tested"])
    k6.metric("Malicious", res["malicious_tested"])
    k7.metric("Benign", res["benign_tested"])
    k8.metric("Avg Similarity", f"{res['average_similarity_score']:.2f}")

    # Verdict distribution
    st.markdown("#### Verdict Distribution")
    vd = res["verdict_distribution"]
    st.dataframe(
        pd.DataFrame([{"Verdict": v, "Count": n} for v, n in vd.items()]),
        use_container_width=True, hide_index=True,
    )

    # Cases table
    st.markdown("#### Validation Cases")
    st.dataframe(
        pd.DataFrame([
            {
                "Domain": c["domain"],
                "Expected": c["expected_label"],
                "Verdict": c["predicted_verdict"],
                "Cluster": c["predicted_cluster"] or "—",
                "Similarity": f"{c['similarity_score']:.2f}",
                "Risk": f"{c['risk_score']:.2f}",
                "Result": "✅ Pass" if c["passed"] else "❌ Fail",
            }
            for c in res["cases"]
        ]),
        use_container_width=True, hide_index=True,
    )

    if res["false_positive_count"] == 0:
        st.success(f"✅ Zero false positives across {res['benign_tested']} benign domains.")
    else:
        st.warning(f"{res['false_positive_count']} false positive(s) on benign domains.")

    # Export
    st.markdown("#### ⬇️ Export Validation Results")
    v_json = json.dumps(res, indent=2, ensure_ascii=False).encode("utf-8")
    v_md = validation_to_markdown(res)
    c1, c2 = st.columns(2)
    c1.download_button(
        "Export Validation JSON", data=v_json,
        file_name="sentinel_validation.json", mime="application/json",
        use_container_width=True, key="val_dl_json",
    )
    c2.download_button(
        "Export Validation Markdown", data=v_md,
        file_name="sentinel_validation.md", mime="text/markdown",
        use_container_width=True, key="val_dl_md",
    )


# ---------------------------------------------------------------------------
# Runner — sections execute sequentially; a failure in one section prints the
# full traceback to the terminal, shows an error box in the browser, and the
# remaining sections still render.
# ---------------------------------------------------------------------------
SECTIONS = [
    render_sidebar,
    render_header,
    render_bank_demo,
    render_kpis,
    render_graph_explorer,
    render_domain_lookup,
    render_investigation,
    render_workspace,
    render_clusters,
    render_trends,
    render_threat_similarity,
    render_copilot,
    render_validation,
    render_intel_tables,
]

for _section in SECTIONS:
    try:
        _section()
    except Exception:
        print(f"\n--- EXCEPTION in {_section.__name__} ---", file=sys.stderr)
        traceback.print_exc()
        st.error(f"Section `{_section.__name__}` failed — full traceback printed to terminal.")

print("All sections rendered.")
