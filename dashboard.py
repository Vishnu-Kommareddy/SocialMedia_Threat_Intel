# =====================================
# dashboard.py — Cyber Threat Intelligence Dashboard
# =====================================

import os
from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px
from sqlalchemy import create_engine, text
import streamlit.components.v1 as components

from config import PROJECT_ROOT, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME

OUTPUT_DIR = PROJECT_ROOT / "outputs"
NETWORK_DIR = OUTPUT_DIR / "network"

# ╭──────────────────────────────────────────────╮
# │ 1️⃣ Database connection (graceful if missing) │
# ╰──────────────────────────────────────────────╯
engine = None
if all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    try:
        engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        st.warning(f"⚠️ Database unavailable: {e}")
        engine = None


def read_sql_compat(query: str) -> pd.DataFrame:
    if engine is None:
        return pd.DataFrame()
    try:
        with engine.connect() as conn:
            result = conn.execute(text(query))
            df = pd.DataFrame(result.fetchall(), columns=result.keys())
            df.columns = [c.lower() for c in df.columns]
            return df
    except Exception:
        return pd.DataFrame()

# ╭──────────────────────────────────────────────╮
# │ 2️⃣ PAGE CONFIG                              │
# ╰──────────────────────────────────────────────╯
st.set_page_config(page_title="Cyber Threat Intelligence Dashboard", layout="wide")
st.title("🧠 Cyber Threat Intelligence Dashboard")

tab1, tab2, tab3, tab4 = st.tabs([
    "🌍 Threat Landscape",
    "🕸️ Entity Network",
    "🔥 Severity & Time Trends",
    "📄 LLM Threat Reports"
])

# ╭──────────────────────────────────────────────╮
# │ TAB 1 — THREAT LANDSCAPE                    │
# ╰──────────────────────────────────────────────╯
with tab1:
    st.subheader("🌍 Threat Classification Overview")
    df = read_sql_compat("SELECT * FROM cyber_tweets_hf ORDER BY created_at DESC LIMIT 500;")
    if not df.empty:
        label_col = next((c for c in df.columns if "label" in c), None)
        severity_col = next((c for c in df.columns if "severity" in c), None)
        text_col = next((c for c in df.columns if "tweet" in c), None)

        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
        df["date"] = df["created_at"].dt.date

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Mentions", len(df))
        c2.metric("Unique Threat Types", df[label_col].nunique() if label_col else 0)
        c3.metric("High Severity", (df[severity_col].str.lower() == "high").sum() if severity_col else 0)

        if label_col:
            counts = df[label_col].value_counts().reset_index()
            counts.columns = ["Threat Type", "Count"]
            st.plotly_chart(px.bar(counts, x="Threat Type", y="Count", color="Threat Type", text="Count"), use_container_width=True)

        st.markdown("### 🏆 Top Classified Tweets")
        if label_col and text_col:
            for _, row in df.head(10).iterrows():
                sev = row.get(severity_col, "N/A")
                st.write(f"🔹 **{row[label_col]} ({sev})** — {row[text_col]}")
        else:
            st.warning("⚠️ Missing required columns for tweet display.")
    else:
        st.warning("No data found in `cyber_tweets_hf`.")

# ╭──────────────────────────────────────────────╮
# │ TAB 2 — ENTITY NETWORK                      │
# ╰──────────────────────────────────────────────╯
with tab2:
    st.subheader("🕸️ Threat-Entity Network")

    html_path = NETWORK_DIR / "threat_network.html"

    nodes_df = read_sql_compat("SELECT * FROM cyber_threat_nodes LIMIT 50;")
    edges_df = read_sql_compat("SELECT * FROM cyber_threat_edges LIMIT 100;")

    c1, c2 = st.columns([1.2, 2.8])
    with c1:
        if not nodes_df.empty:
            node_col = next((c for c in nodes_df.columns if "node" in c), None)
            pr_col = next((c for c in nodes_df.columns if "pagerank" in c), None)
            deg_col = next((c for c in nodes_df.columns if "degree" in c), None)
            st.dataframe(nodes_df[[node_col, pr_col, deg_col]].sort_values(by=pr_col, ascending=False).head(15))
        else:
            st.warning("⚠️ No nodes found in DB.")
    with c2:
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                components.html(f.read(), height=650, scrolling=True)
        else:
            st.warning("⚠️ Threat network visualization not found.")

# ╭──────────────────────────────────────────────╮
# │ TAB 3 — SEVERITY & TIME TREND               │
# ╰──────────────────────────────────────────────╯
with tab3:
    st.subheader("🔥 Severity Trends Over Time")

    df_time = read_sql_compat("SELECT * FROM cyber_tweets_hf ORDER BY created_at ASC;")
    if not df_time.empty:
        df_time["created_at"] = pd.to_datetime(df_time["created_at"], errors="coerce")
        df_time["date"] = df_time["created_at"].dt.date
        label_col = next((c for c in df_time.columns if "label" in c), None)
        severity_col = next((c for c in df_time.columns if "severity" in c), None)

        if severity_col:
            trend = df_time.groupby(["date", severity_col]).size().reset_index(name="Count")
            st.plotly_chart(px.area(trend, x="date", y="Count", color=severity_col, title="Severity Evolution"), use_container_width=True)

        if label_col:
            top_labels = df_time[label_col].value_counts().head(10).reset_index()
            top_labels.columns = ["Threat Type", "Mentions"]
            st.plotly_chart(px.bar(top_labels, x="Threat Type", y="Mentions", color="Threat Type", title="Top 10 Threat Types"), use_container_width=True)
    else:
        st.warning("No temporal severity data found.")

# ╭──────────────────────────────────────────────╮
# │ TAB 4 — LLM SUMMARIES                      │
# ╰──────────────────────────────────────────────╯
with tab4:
    st.subheader("📄 AI-Generated Threat Intelligence Reports")

    df_sum = read_sql_compat("SELECT * FROM threat_summaries ORDER BY generated_at DESC LIMIT 5;")
    if not df_sum.empty:
        for i, r in df_sum.iterrows():
            summary_col = next((c for c in df_sum.columns if "summary" in c), None)
            time_col = next((c for c in df_sum.columns if "generated" in c or "created" in c), None)
            st.markdown(f"### 🧩 Report {i+1} — {r.get(time_col)}")
            st.info(r.get(summary_col))
            st.markdown("---")
    else:
        st.warning("No LLM summaries found.")
