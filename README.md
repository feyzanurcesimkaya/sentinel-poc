# Sentinel POC

Fraud attribution infrastructure — traces social-media-originated scams to their source domains and platforms via a Neo4j knowledge graph.

---

## Setup

### 1. Prerequisites

- Python 3.12
- A running Neo4j AuraDB instance
- Environment variables configured in `.env`

### 2. Environment variables

Create a `.env` file in the project root (already present):

```
NEO4J_URI=neo4j+ssc://<your-instance>.databases.neo4j.io
NEO4J_USERNAME=<username>
NEO4J_PASSWORD=<password>
NEO4J_DATABASE=<database>
```

### 3. Install dependencies

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1          # Windows PowerShell
source venv/bin/activate             # macOS / Linux

# Install packages
pip install -r requirements.txt
```

---

## Execution order

All scripts must be run from the `scripts/` directory so that relative imports resolve correctly.

```bash
cd scripts

# Step 1 — Apply uniqueness constraints to the graph schema
python schema.py

# Step 2 — Load seed scam campaigns into Neo4j
python seed_graph.py

# Step 3 — Run domain lookup queries and display results
python query_demo.py
```

---

## Project structure

```
sentinel-poc/
├── scripts/
│   ├── db_connect.py   # Neo4j connection helper (context manager)
│   ├── schema.py       # Creates graph constraints
│   ├── seed_graph.py   # Loads seed_campaigns.json into Neo4j
│   └── query_demo.py   # lookup_domain() demo with Rich output
├── data/
│   └── seed_campaigns.json   # 5 real-world-inspired scam campaigns
├── .env
├── README.md
└── requirements.txt
```

---

## Graph model

```
(Campaign)-[:USES_DOMAIN]->(Domain)
(Campaign)-[:PROMOTED_ON]->(Platform)
```

### Campaign properties

| Property     | Type   | Description                          |
|--------------|--------|--------------------------------------|
| campaign_id  | string | Unique identifier                    |
| name         | string | Human-readable campaign name         |
| risk_score   | float  | 0.0–1.0, higher = more dangerous     |
| scam_type    | string | Taxonomy label (e.g. deepfake, etc.) |

---

## Day 19 — Intelligence Coverage Scaling + Data Quality

Scaled the graph from **464 → 5,314 domains** across **7 intelligence sources**,
with no UI, engine, or feature changes — coverage and data quality only.

### Shared ingestion layer ([`scripts/ingest_common.py`](scripts/ingest_common.py))

- URL→registrable-hostname normalisation,
- **validation gate** (rejects IPs, malformed, over-long hosts),
- per-run **deduplication** (MERGE dedups across runs),
- **batched UNWIND upsert** (writes thousands of domains in ~10 round-trips).

### New / expanded sources

| Source | Script | Mode | Notes |
|--------|--------|------|-------|
| URLHaus (full feed) | `ingest_urlhaus.py` | live, streamed | 75k URLs streamed → 5,000 valid unique (capped) |
| FCA Warning List | `ingest_fca_warnings.py` | curated | expanded to 30 domains |
| OpenPhish | `ingest_openphish.py` | live | 238 domains |
| USOM (TR CERT) | `ingest_usom.py` | live/fallback | public url-list |
| AlienVault OTX | `ingest_otx.py` | key/fallback | needs `OTX_API_KEY` for live |
| Netcraft | `ingest_netcraft.py` | curated | **campaign extraction** → 6 brand Campaign nodes |

### Data quality ([`scripts/data_quality.py`](scripts/data_quality.py))

Validates & removes malformed domains, reports duplicates/orphans, and
**normalizes campaigns** (snake_case `scam_type`, trimmed names, default risk).

Final: **5,314 domains · 7 sources · 11 campaigns · 5,310 FLAGGED · 0 invalid · 0 orphans · 0 duplicates**.
Engines still perform: `build_clusters` 0.96s, `predict_threat` 0.12s, all endpoints 200.

> ⚠️ **Known regression to address next:** at 5k+ domains the precision-first
> clustering produces a ~2,500-domain mega-cluster again — the 5%-of-corpus
> document-frequency cap lets common tokens anchor at scale, and shared-source
> corroboration chains them. Per this day's scope (no clustering-logic changes),
> it was left untouched; the fix is a clustering re-tune (absolute DF cap +
> drop shared-source corroboration for very large feeds).

---

## Day 18 — Validation Metrics

Credibility metrics for the Threat Similarity Engine — for TÜBİTAK, investors,
and bank pilots. Evaluation only; no engine was changed.

### Engine ([`scripts/validation_engine.py`](scripts/validation_engine.py))

`run_validation(session)` runs the existing `predict_threat` over a deterministic
built-in test set (5 scam-like + 5 benign domains, no external data) and reports:
`total_tested`, `malicious_tested`, `benign_tested`, `accuracy`, `detection_rate`,
`suspicious_or_above_rate`, `unknown_rate`, `false_positive_count`,
`false_positive_rate`, `average_risk_score`, `average_similarity_score`,
`verdict_distribution`, `top_predicted_clusters`, and per-case results
(domain, expected_label, predicted_verdict, predicted_cluster, similarity, risk,
passed, explanation). `validation_to_markdown()` exports it.

### Results on the live 464-domain graph

| Metric | Value |
|--------|-------|
| Accuracy | **0.90** (9/10) |
| Detection rate (malicious flagged) | **0.80** (4/5) |
| **False positive rate** | **0.00** (0/5 benign) |
| Avg risk / similarity | 0.21 / 0.19 |

The zero false-positive rate is the headline for pilots: Sentinel does not flag
benign domains. The one miss (`apple-id-security-check.net`) is reported
honestly rather than tuned away.

### Dashboard — 📊 Validation Metrics

KPI cards, verdict distribution, the full cases table, and JSON / Markdown export.

---

## Day 17 — Analyst Copilot (deterministic explainability)

A **deterministic explainability layer** — *no LLM, no API calls, no chatbot*. It
restates Sentinel's existing engine outputs as analyst-facing prose.

### Engine ([`scripts/copilot_engine.py`](scripts/copilot_engine.py))

`generate_explanation(report, prediction, cluster)` composes five fields from
fixed templates over the investigation report, threat prediction, and matched
cluster:

| Field | Answers |
|-------|---------|
| `why_flagged` | Why was this domain flagged? (keywords, nearest known domain, sources) |
| `why_cluster` | Why was this cluster selected? (which similarity signals drove it) |
| `why_risk` | Why is the risk score what it is? (similarity × cluster prior, or keyword floor) |
| `recommended_action` | What action to take? (investigation action + cluster escalation) |
| `analyst_summary` | One-paragraph synthesis |

Same inputs always yield the same text. The novel-domain (no cluster) path is
handled gracefully.

### Dashboard — 🧠 Analyst Copilot

Enter any domain (quick-example buttons included) → plain-English answers to all
four questions plus the summary, with the raw explanation JSON available. No
existing pages were changed.

---

## Day 16 — Bank Demo Flow

Productization, not new intelligence. A guided **🏦 Bank Demo Scenario** section
(top of the dashboard) lets a bank analyst, investor, or reviewer grasp
Sentinel's value in under 3 minutes. It orchestrates the *existing* engines into
a 6-step narrative — **no new business logic, no new algorithms**.

### Scenario selector → predefined unseen domains

| Button | Domain |
|--------|--------|
| 🏛️ FCA Recovery Scam | `fca-investment-recovery.com` |
| 🏦 Banking Verification Scam | `wellsfargo-secure-login.com` |
| ₿ Crypto Investment Scam | `quantum-ai-investment.com` |

### Guided flow (each step reuses a shipped component)

1. **New domain observed** — known to Sentinel? (No)
2. **Threat Similarity** (auto) — predicted cluster, similarity, risk, verdict
   *(Threat Similarity Engine)*
3. **Why it matched** — the engine's own explanation string
4. **Related Fraud Cluster** — id / domains / risk / status *(Cluster Engine)*
5. **Recommended Action** — *(Investigation Engine)*
6. **Export Investigation Report** — PDF / Markdown / JSON *(existing exporters)*

All existing sections (Investigation, Workspace, Clusters, Trends, Threat
Similarity, Intel tables) remain unchanged and below the demo. Dark theme kept.

---

## Day 15 — Clustering Precision Redesign

Bulk ingestion (Day 14) exposed a flaw: the original clustering merged on
**shared source** and **generic lexical overlap**, collapsing all 438
OpenPhish+URLHaus domains into one meaningless mega-cluster (single-linkage
chaining through tokens like `secure`/`login`).

Redesigned [`scripts/cluster_engine.py`](scripts/cluster_engine.py) for
**fraud-network precision over size**. Two domains now merge iff:

1. they share a **Campaign** (direct curated attribution), **or**
2. they share a **distinctive anchor token** *and* the link is corroborated by
   strong name similarity **or** a common source.

A distinctive anchor excludes (a) generic phishing filler, (b) shared
hosting/SaaS platform tokens (`vercel`, `webflow`, `github`, `pages`, …) — common
infrastructure is not actor identity — and (c) any token appearing in >5% of the
corpus (document-frequency cap). **Shared source alone never merges.**

Result on the live 464-domain graph:

| | Before | After |
|---|--------|-------|
| Largest cluster | 438 | **8** |
| Multi-domain networks | 1 blob | 31 coherent networks |

Clusters are now real fraud networks — e.g. an *uphold* and a *uniswap*
phishing cluster each span multiple hosting platforms but merge on the brand
token, while unrelated scams sharing only a host (or a feed) stay separate.
Deterministic; trends and the Threat Similarity Engine are unaffected.

---

## Day 14 — OpenPhish + URLHaus Ingestion

Adds two live threat feeds to widen graph coverage so the Threat Similarity
Engine has far more reference infrastructure to match against.

### New ingesters (same pattern as PhishTank/FCA)

| Script | Source node | Feed | Confidence | Notes |
|--------|-------------|------|------------|-------|
| [`scripts/ingest_openphish.py`](scripts/ingest_openphish.py) | `OpenPhish` (`phishing_feed`) | `openphish.com/feed.txt` | 0.87 | URL→domain, dedup |
| [`scripts/ingest_urlhaus.py`](scripts/ingest_urlhaus.py) | `URLHaus` (`malware_url_feed`) | `urlhaus.abuse.ch` CSV | 0.89 | stores `threat_type` on Domain + FLAGGED edge |

Both: live fetch with **graceful fallback** to a curated sample list (fallback
mode is logged), MERGE-based upsert (no duplicates), and a **capped per-run
volume** (`MAX_DOMAINS = 200`) — the URLHaus feed alone carries ~18k entries, so
the cap keeps the graph and the O(n²) cluster engine fast. Each run returns a
summary: `source`, `fetched_count`, `inserted_or_updated_count`, `skipped_count`.

```bash
python scripts/ingest_openphish.py
python scripts/ingest_urlhaus.py
```

No schema/dashboard changes were needed — `query_sources.py`, the dashboard KPIs,
and the intelligence tables are all label-generic, so the new sources/domains
appear automatically.

> Coverage after first run: **26 → 464 domains, 2 → 4 sources, 460 FLAGGED edges**
> (OpenPhish 238, URLHaus 200, FCA 12, PhishTank 10).

---

## Day 13 — Threat Similarity Engine

Predicts whether a **previously unseen** domain likely belongs to known fraud
infrastructure — *before* any campaign or source link exists. Deterministic, no ML.

### Engine ([`scripts/similarity_engine.py`](scripts/similarity_engine.py))

`predict_threat(session, domain)` scores the domain against every FraudCluster
by combining five signals into a weighted similarity:

| Signal | Weight | What it measures |
|--------|--------|------------------|
| Lexical | 0.40 | token Jaccard vs cluster member domain names |
| Keyword overlap | 0.25 | shared high-risk scam keywords |
| Campaign similarity | 0.20 | token overlap with the cluster's campaign text |
| Source similarity | 0.15 | resemblance to source-flagged member domains |
| Cluster risk | — | scales the predicted risk by the matched cluster's prior |

Output: `predicted_cluster`, `similarity_score`, `risk_score`, `confidence`
(top-match strength + margin over runner-up), `verdict`
(LIKELY_MALICIOUS / SUSPICIOUS / LOW_SIMILARITY / UNKNOWN), matched keywords,
per-signal breakdown, nearest known domains, candidate clusters, and a plain-
English explanation.

### API

`POST /predict` `{"domain": "..."}` → typed `ThreatPrediction` JSON.

### Dashboard — 🔮 Threat Similarity

Enter any unseen domain (quick-example buttons included): verdict banner,
similarity / risk / confidence metrics, explanation, signal breakdown, nearest
known domains, candidate clusters, and a prediction-JSON download.

> Examples: `fca-investment-recovery.com` → CLUSTER-001 (SUSPICIOUS);
> `lloyds-secure-verify.com` → CLUSTER-002; `totally-unrelated-blog.com` → no
> match (UNKNOWN).

---

## Day 12 — Fraud Network Trend Intelligence

Tracks the **growth, activity, and risk evolution** of fraud clusters over time —
turning static clusters into living networks an analyst can watch.

### Trend metrics ([`scripts/trend_engine.py`](scripts/trend_engine.py))

Per cluster (derived deterministically from `Domain.first_seen`): `first_seen`,
`last_seen`, `domain_count`, `campaign_count`, `source_count`, `growth_rate`
(fraction of domains seen within 14 days) and `activity_score`
(recency + size + risk, in [0, 1]).

### Trend status (deterministic rules)

- **EXPANDING** — ≥3 domains and growth_rate ≥ 0.30
- **EMERGING** — small (≤3 domains), high confidence (≥0.8), recently active
- **DORMANT** — no activity in 30 days (or no temporal signal + low risk)
- **ACTIVE** — anything else with current activity

### Dashboard — 📈 Fraud Network Trends

KPIs (Expanding / Emerging / Dormant counts), a trend table (Cluster / Domains /
Growth Rate / Activity Score / Status / First-Last seen), a **🚨 Emerging
Networks** alert panel, per-cluster narratives, and JSON / Markdown / PDF export.

> Example narrative: *"CLUSTER-001 expanded from 1 to 12 domains and is an
> expanding fraud network."*

As real longitudinal data accumulates (repeated ingestion across days),
`growth_rate` and the "expanded from X to Y" narrative sharpen automatically — no
code change required.

---

## Day 11 — Fraud Cluster Intelligence Engine

Automatically groups related domains/campaigns/sources into **FraudClusters** —
turning a flat list of flagged domains into named, prioritised fraud networks.

### FraudCluster entity (computed, deterministic — no DB schema change)

`cluster_id`, `risk_score`, `status` (ACTIVE / MONITORING / DORMANT),
`confidence`, `domain_count`, `campaign_count`, `source_count` (+ member
domains / campaigns / sources / platforms and an analyst summary).

### Clustering logic ([`scripts/cluster_engine.py`](scripts/cluster_engine.py))

Union-find connected components over the ScamGraph; two domains join a cluster
when they share a **campaign**, share a **source**, or have **similar name
patterns** (lexical Jaccard, reusing the attribution engine's primitives). No ML
model — the same graph always yields the same clusters. Risk = worst-case member
signal; confidence = mean signal.

> Example on seed + ingested data: **CLUSTER-001** = 12 FCA-family domains
> (shared FCA Warning List), **CLUSTER-002** = 10 PhishTank-flagged domains —
> each flagged as a coordinated active fraud network.

### Dashboard — 🧠 Fraud Cluster Intelligence

Cluster KPIs, an overview table (ID / Status / Risk / Confidence / Domains /
Campaigns / Sources), a cluster inspector with summary + a
`FraudCluster → Domains → Campaigns → Platforms` PyVis graph (purple ★ cluster
node), and JSON / Markdown / PDF export of all clusters.

---

## Day 10 — Investigation Workspace

Turns Sentinel from a single-domain lookup into a multi-domain **fraud case
workspace**. New dashboard section **📁 Investigation Workspace**.

### Case structure (Streamlit session state — no DB persistence yet)

`CASE-{YYYYMMDD}-001` with **Status** (OPEN / REVIEW / CLOSED), **Severity**
(LOW / MEDIUM / HIGH / CRITICAL), and a created timestamp.

### Multi-domain investigation

Add any number of domains (quick-example buttons + free text). Each reuses the
existing `build_report()` engine; duplicates are ignored.

### Case-level views

- **Investigation Metrics** — total domains / campaigns / platforms / sources +
  average confidence.
- **Fraud Network Summary** — generated narrative; flags shared campaigns/sources
  as a coordinated operation.
- **Combined Attribution Graph** — one PyVis graph merging shared
  ScamSource / Domain / Campaign / Platform nodes (reuses the existing graph
  styling).
- **Case Timeline** — all per-domain timelines merged and sorted chronologically
  (Date / Event Type / Domain / Entity / Description / Confidence).

### Workspace export

JSON, Markdown, and PDF of the whole case →
`sentinel_workspace_CASE-{YYYYMMDD}-001.{json|md|pdf}`. Aggregation lives in
[`scripts/workspace.py`](scripts/workspace.py); the PDF reuses the Day 9
reportlab helpers.

---

## Day 9 — PDF Export

Adds a printable PDF case report alongside the JSON and Markdown exports.

### Dependency

`reportlab` (pure-Python, Windows-friendly — no WeasyPrint/system libs).

### PDF helper ([`scripts/report_export.py`](scripts/report_export.py))

`report_to_pdf_bytes(report) -> bytes` builds a clean, professional one/two-page
PDF (Helvetica only, no external images): title, verdict-accented header block
(Case ID, Domain, Verdict, Confidence, Generated), Executive Summary,
Recommended Action, Attribution Chain, Investigation Timeline table, and the
full Evidence Summary (sources / campaigns / platforms / similar domains). Empty
sections render as italic placeholders. Kept in its own module so the engine
stays importable without reportlab.

### API

`GET /investigate/{domain}/export?format=pdf` → `application/pdf` attachment
(`sentinel_case_{domain-slug}_{YYYYMMDD}.pdf`). `json`/`markdown` unchanged;
invalid formats → 400.

### Dashboard

The Export Case Report row now has a third **Download PDF** button next to JSON
and Markdown.

---

## Day 8 — Export Investigation Case Report

Analysts can export any investigation as a downloadable file, in two formats.

### Dashboard (primary)

The **📁 Analyst Case Report** panel gains an **⬇️ Export Case Report** row with
two buttons:

- **Download JSON** — the full `build_report()` output (incl. `timeline` and
  `recommended_action`).
- **Download Markdown** — a formatted analyst document (summary, recommended
  action, attribution chain, timeline table, evidence tables).

Filenames: `sentinel_case_{domain-slug}_{YYYYMMDD}.{json|md}`
(e.g. `sentinel_case_apple-id-suspended-com_20260612.json`).

### API ([`scripts/api.py`](scripts/api.py))

`GET /investigate/{domain}/export?format=json|markdown` returns the same report
as a downloadable attachment (`Content-Disposition` set). Invalid formats → 400.

```bash
curl -OJ "http://127.0.0.1:8000/investigate/apple-id-suspended.com/export?format=markdown"
```

### Shared helpers ([`scripts/attribution_engine.py`](scripts/attribution_engine.py))

`slugify_domain()`, `build_case_id()`, `export_filename()`, and
`report_to_markdown()` — reused by both the dashboard and the API so the export
format has a single source of truth. (PDF export is planned for Day 9.)

---

## Day 7 — Analyst Case Report & Investigation Timeline

Turns each investigation into an analyst-style **case report** with a real
chronological timeline and a verdict-driven recommended action.

### Engine additions ([`scripts/attribution_engine.py`](scripts/attribution_engine.py))

Two new fields on the report (all existing fields preserved):

| Field | Meaning |
|-------|---------|
| `timeline[]` | Chronological events — `SOURCE_FLAG`, `CAMPAIGN_LINK`, `PLATFORM_LINK` — each with `date`, `event_type`, `entity`, `description`, optional `confidence`. Sorted ascending; uses `first_seen` where available, else the report date; `[]` when no evidence. |
| `recommended_action` | Verdict-driven analyst playbook action (MALICIOUS / SUSPICIOUS / LOW_RISK / UNKNOWN). |

### API ([`scripts/api.py`](scripts/api.py))

`POST /investigate` now returns `timeline` and `recommended_action` in addition
to all prior fields (new `TimelineEvent` model).

### Dashboard ([`dashboard_graph.py`](dashboard_graph.py))

The Investigation panel gains a **📁 Analyst Case Report** block: Case ID
(`CASE-{YYYYMMDD}-{domain-slug}`), domain/verdict/confidence/timestamp metrics,
executive summary, recommended action (severity-styled), attribution chain,
investigation timeline table (Date / Event Type / Entity / Description /
Confidence), and an evidence summary.

---

## Day 6 — Investigation Dashboard / Attribution Engine

An AI-style investigation engine that turns a single domain into a structured
intelligence report, explaining **why** a domain is suspicious rather than just
whether it matches.

### Engine

[`scripts/attribution_engine.py`](scripts/attribution_engine.py) — deterministic,
rule-based, runs offline (no LLM key required). Entry point:
`build_report(session, domain) -> dict`.

The report aggregates independent signals from the ScamGraph:

| Field | Meaning |
|-------|---------|
| `verdict` | MALICIOUS / SUSPICIOUS / LOW_RISK / UNKNOWN |
| `confidence_score` | 0.0–1.0, aggregated across all signals |
| `summary` | Human-readable narrative + recommended action |
| `reasons[]` | Why the domain is suspicious |
| `intelligence_sources[]` | Which feeds flagged it (PhishTank, FCA, …) |
| `connected_campaigns[]` | Linked scam campaigns + risk |
| `connected_platforms[]` | Social platforms used |
| `similar_domains[]` | Cluster peers (shared campaign/source + lexical similarity) |
| `keyword_indicators[]` | High-risk tokens in the domain name |

### API endpoint

`POST /investigate`

```bash
curl -X POST http://127.0.0.1:8000/investigate \
     -H "Content-Type: application/json" \
     -d '{"domain": "fca-recovery-fund.co.uk"}'
```

Returns the full structured `InvestigationReport` JSON.

### Dashboard panel

The **🕵️ Attribution Engine — Investigation Report** panel in
`dashboard_graph.py` renders the report inline: verdict banner, confidence bar,
executive summary, reasons, source/campaign/platform evidence tables, similar
domains, and the raw JSON. It calls the engine directly (no running API needed).

---

## Day 5 — ScamGraph Visualization

Interactive graph dashboard built on Neo4j + pyvis + Streamlit.

```bash
# Run from sentinel-poc/ project root
streamlit run dashboard_graph.py
```

Opens at `http://localhost:8501`.

Three pages:

| Page | Content |
|------|---------|
| **Graph Explorer** | Full ScamGraph — all sources, domains, campaigns, platforms |
| **Domain Search** | Enter any domain, see its subgraph and relationships |
| **Statistics** | Top risk domains (score bar) + latest ingested domains |

Node count metrics (Domains / Campaigns / Sources) appear on every page.

---

## Day 4 — Intelligence Ingestion

Moves Sentinel from static seed data to real external scam intelligence feeds.

### Execution order

Run from `sentinel-poc/scripts/`:

```bash
cd scripts

# Step 1 — Apply schema (adds ScamSource constraint if not already present)
python schema.py

# Step 2 — Ingest PhishTank phishing feed (live or fallback sample)
python ingest_phishtank.py

# Step 3 — Ingest FCA Warning List domains
python ingest_fca_warnings.py

# Step 4 — Query and display all sourced domains
python query_sources.py
```

### Graph model additions

```
(:ScamSource {name, source_type, url})
    -[:FLAGGED {first_seen, confidence}]->
(:Domain {name, first_seen, confidence, source})
```

### PhishTank live feed

Set `PHISHTANK_API_KEY` in `.env` to enable live ingestion.  
If the key is absent or set to `SONRA_DOLDURURUZ`, the script falls back to curated sample data automatically.

### FCA Warning List

The FCA does not publish a machine-readable bulk API.  `ingest_fca_warnings.py` uses a curated set of domains drawn from public FCA warning notices.  Extend `FCA_SAMPLE_DOMAINS` in the script as new warnings are published.

---

## Day 3 — Streamlit Dashboard

### Start the dashboard

The FastAPI server must be running first (see Day 2 below), then in a second terminal:

```bash
cd sentinel-poc
streamlit run dashboard.py
```

Opens at `http://localhost:8501`.

Features:
- Domain text input with one-click example domains
- Risk badge: 🔴 High / 🟠 Medium / 🟢 Low based on score
- Campaign name, platform, and risk score metrics
- Sidebar with About, MVP scope, and build status
- Graceful error if the API is not running

---

## Day 2 — REST API

### Start the API server

Run from the **project root** (`sentinel-poc/`):

```bash
uvicorn scripts.api:app --reload
```

The server starts at `http://127.0.0.1:8000`.

### Endpoints

#### `GET /health`

```bash
curl http://127.0.0.1:8000/health
```

```json
{"status": "ok", "service": "sentinel-api"}
```

#### `POST /lookup`

```bash
curl -X POST http://127.0.0.1:8000/lookup \
     -H "Content-Type: application/json" \
     -d '{"domain": "quantum-ai-invest.com"}'
```

Match found:

```json
{
  "domain": "quantum-ai-invest.com",
  "matched": true,
  "campaign": "Quantum AI Elon Musk Investment",
  "platform": "YouTube",
  "risk_score": 0.97
}
```

No match:

```json
{
  "domain": "unknown-domain.com",
  "matched": false,
  "risk_score": 0.0
}
```

Interactive docs: `http://127.0.0.1:8000/docs`

---

## Seed campaigns

| ID       | Campaign                              | Platform  | Risk  |
|----------|---------------------------------------|-----------|-------|
| CAMP-001 | Quantum AI Elon Musk Investment       | YouTube   | 0.97  |
| CAMP-002 | Martin Lewis Crypto Miracle           | Facebook  | 0.95  |
| CAMP-003 | BBC News Bitcoin Giveaway             | Twitter   | 0.93  |
| CAMP-004 | FCA Authorised Recovery Fund          | LinkedIn  | 0.98  |
| CAMP-005 | Turkish Finance Minister Deepfake     | Instagram | 0.96  |
