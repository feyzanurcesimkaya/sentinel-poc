import requests
import streamlit as st

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="Sentinel — Scam Attribution Intelligence",
    page_icon="🛡️",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Sentinel")
    st.caption("Fraud Attribution Infrastructure")
    st.divider()

    st.subheader("About")
    st.write(
        "Sentinel helps banks identify and attribute social-media-originated "
        "scams by tracing fraudulent domains back to known campaigns."
    )

    st.divider()
    st.subheader("MVP Scope")
    st.markdown(
        """
- Neo4j graph database
- 5 seed scam campaigns
- FastAPI lookup endpoint
- Streamlit visual dashboard
        """
    )

    st.divider()
    st.subheader("Build Status")
    st.markdown(
        """
| Day | Status |
|-----|--------|
| Day 1 — Graph DB | ✅ Done |
| Day 2 — REST API | ✅ Done |
| Day 3 — Dashboard | ✅ Done |
        """
    )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
st.title("Sentinel")
st.subheader("Scam Attribution Intelligence")
st.caption("Enter a domain to check if it is linked to a known scam campaign.")
st.divider()

# Example domains quick-select
EXAMPLES = [
    "quantum-ai-invest.com",
    "martinlewis-crypto.net",
    "bbc-cryptonews.org",
    "fca-recovery-fund.co.uk",
    "turkiye-yatirim-kripto.com",
]

st.markdown("**Quick examples**")
cols = st.columns(len(EXAMPLES))
selected_example = None
for col, domain in zip(cols, EXAMPLES):
    if col.button(domain, use_container_width=True):
        selected_example = domain

# Domain input
default_value = selected_example or st.session_state.get("domain_input", "")
domain_input = st.text_input(
    "Domain",
    value=default_value,
    placeholder="e.g. quantum-ai-invest.com",
    key="domain_input",
    label_visibility="collapsed",
)

analyze = st.button("🔍 Analyze Domain", type="primary", use_container_width=True)

st.divider()

# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------
if analyze and domain_input.strip():
    domain = domain_input.strip()

    with st.spinner(f"Querying Sentinel graph for **{domain}**..."):
        try:
            response = requests.post(
                f"{API_BASE}/lookup",
                json={"domain": domain},
                timeout=5,
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.ConnectionError:
            st.error(
                "Cannot reach the Sentinel API. "
                "Make sure it is running: `uvicorn scripts.api:app --reload`"
            )
            st.stop()
        except requests.exceptions.Timeout:
            st.error("API request timed out. Please try again.")
            st.stop()
        except requests.exceptions.HTTPError as e:
            st.error(f"API returned an error: {e}")
            st.stop()

    if data.get("matched"):
        risk_score = data["risk_score"]

        if risk_score >= 0.8:
            badge_color = "red"
            badge_label = "🔴 HIGH RISK"
        elif risk_score >= 0.5:
            badge_color = "orange"
            badge_label = "🟠 MEDIUM RISK"
        else:
            badge_color = "green"
            badge_label = "🟢 LOW RISK"

        st.success("Match found in Sentinel graph.")

        st.markdown(f"## {badge_label}")

        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", f"{risk_score:.2f}")
        col2.metric("Platform", data.get("platform", "—"))
        col3.metric("Matched", "Yes")

        st.markdown("### Campaign Details")
        st.markdown(
            f"""
| Field | Value |
|---|---|
| **Domain** | `{data['domain']}` |
| **Campaign** | {data.get('campaign', '—')} |
| **Platform** | {data.get('platform', '—')} |
| **Risk Score** | {risk_score:.2f} |
| **Risk Level** | {badge_label} |
            """
        )

    else:
        st.info(f"No known scam campaign is linked to **{domain}**.")
        col1, col2 = st.columns(2)
        col1.metric("Matched", "No")
        col2.metric("Risk Score", "0.00")

elif analyze and not domain_input.strip():
    st.warning("Please enter a domain before clicking Analyze.")
