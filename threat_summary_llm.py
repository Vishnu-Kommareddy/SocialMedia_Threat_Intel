import os, re, sys, pandas as pd
from sqlalchemy import create_engine, text
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from config import PROJECT_ROOT, OUTPUT_DIR, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME, OPENROUTER_API_KEY, OPENAI_API_BASE

# ╭──────────────────────────────────────────────╮
# │ 1️⃣  Environment Setup                       │
# ╰──────────────────────────────────────────────╯
engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
print(f"🔗 Connected to PostgreSQL at {DB_HOST}:{DB_PORT}")

OUTPUT_FILE = OUTPUT_DIR / "threat_daily_summary.txt"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ╭──────────────────────────────────────────────╮
# │ 2️⃣  Load classified data                     │
# ╰──────────────────────────────────────────────╯
try:
    # Auto-detect available columns
    sample_df = pd.read_sql("SELECT * FROM cyber_tweets_hf LIMIT 1;", engine)
    cols = [c.lower() for c in sample_df.columns]
    
    label_col = "hf_label" if "hf_label" in cols else "label" if "label" in cols else None
    severity_col = "hf_severity" if "hf_severity" in cols else "severity" if "severity" in cols else None
    
    if not label_col:
        raise KeyError("No label/hf_label column found.")
    if not severity_col:
        raise KeyError("No severity/hf_severity column found.")
    
    query_tweets = f"""
    SELECT tweet_text, {label_col} AS threat_type, {severity_col} AS severity, created_at
    FROM cyber_tweets_hf
    WHERE tweet_text IS NOT NULL
    ORDER BY created_at DESC
    LIMIT 300;
    """
    
    df = pd.read_sql(query_tweets, engine)
    print(f"📥 Loaded {len(df)} classified tweets from DB (cyber_tweets_hf).")

except Exception as e:
    print(f"⚠️ Table not found or SQL error: {e}")
    print("🔄 Falling back to local CSV...")
    hf_csv = OUTPUT_DIR / "cyber_tweets_hf_results.csv"
    if not os.path.exists(hf_csv):
        print(f"❌ CSV not found at {hf_csv}")
        sys.exit(1)
    df = pd.read_csv(hf_csv)
    print(f"📂 Loaded {len(df)} tweets from CSV fallback.")

if df.empty:
    print("⚠️ No threat data available.")
    sys.exit(0)

# ╭──────────────────────────────────────────────╮
# │ 3️⃣  Quick Statistics                        │
# ╰──────────────────────────────────────────────╯
category_counts = df["threat_type"].value_counts().reset_index()
category_counts.columns = ["Threat Type", "Mentions"]

severity_counts = df["severity"].value_counts().reset_index()
severity_counts.columns = ["Severity Level", "Count"]

try:
    top_nodes = pd.read_sql(
        "SELECT node, node_type, degree, pagerank FROM cyber_threat_nodes ORDER BY pagerank DESC LIMIT 10;",
        engine
    )
except Exception:
    top_nodes = pd.DataFrame(columns=["node","node_type","degree","pagerank"])

def df_to_markdown(df):
    if df.empty: return "(No data available)"
    out = "| " + " | ".join(df.columns) + " |\n"
    out += "| " + " | ".join(["---"]*len(df.columns)) + " |\n"
    for _, row in df.iterrows():
        out += "| " + " | ".join(str(x) for x in row.values) + " |\n"
    return out

category_md = df_to_markdown(category_counts)
severity_md = df_to_markdown(severity_counts)
entities_md = df_to_markdown(top_nodes)

# ╭──────────────────────────────────────────────╮
# │ 4️⃣  Clean and chunk tweets                   │
# ╰──────────────────────────────────────────────╯
def clean_text(t):
    t = re.sub(r"http\S+|@\S+|#\S+", "", str(t))
    return re.sub(r"\s+", " ", t).strip()

df["clean_text"] = df["tweet_text"].apply(clean_text)
chunks = [df["clean_text"].tolist()[i:i+25] for i in range(0, len(df), 25)]
print(f"✂️ Created {len(chunks)} text chunks for summarization.")

# ╭──────────────────────────────────────────────╮
# │ 5️⃣  Initialize OpenRouter LLM               │
# ╰──────────────────────────────────────────────╯
API_KEY, API_BASE = OPENROUTER_API_KEY, OPENAI_API_BASE
if not API_KEY or not API_BASE:
    print("❌ Missing OpenRouter credentials.")
    sys.exit(1)

llm = ChatOpenAI(
    model="mistralai/mixtral-8x7b-instruct",
    temperature=0.25,
    max_tokens=900,
    openai_api_key=API_KEY,
    openai_api_base=API_BASE
)
print("🤖 LLM ready.")

# ╭──────────────────────────────────────────────╮
# │ 6️⃣  Summarize Chunks                       │
# ╰──────────────────────────────────────────────╯
summaries=[]
for i,chunk in enumerate(chunks,1):
    prompt=(
        "Summarize these cybersecurity-related tweets. "
        "Identify key threat types, tactics, and entities mentioned. "
        "Focus on emerging or recurring incidents. Keep it factual and concise.\n\n"
        + "\n".join(chunk)
    )
    try:
        resp=llm.invoke([HumanMessage(content=prompt)])
        summaries.append(resp.content.strip())
        print(f"✅ Summarized chunk {i}/{len(chunks)}.")
    except Exception as e:
        summaries.append(f"[Error {i}: {e}]")

# ╭──────────────────────────────────────────────╮
# │ 7️⃣  Final Report Generation                 │
# ╰──────────────────────────────────────────────╯
meta_prompt = f"""
You are a cybersecurity threat intelligence analyst.

Using the following data:

**Category Frequencies:**
{category_md}

**Severity Distribution:**
{severity_md}

**Top Entities (from threat graph):**
{entities_md}

**Qualitative Summaries:**
{chr(10).join(summaries)}

Write a structured **Daily Cyber Threat Intelligence Report** in markdown format.

Include these sections:

# Daily Cyber Threat Intelligence Report

## 🧭 Overview
Brief macro-level summary of global threat tone.

## ⚔️ Top Threat Categories
Describe key attack types, frequency, and any noticeable changes.

## 🏢 Notable Entities
Mention significant organizations, domains, or actors.

## 📊 Severity Outlook
Summarize how severity levels distribute and what they imply.

## 🚀 Emerging Trends
Highlight new campaigns, vulnerabilities, or techniques.

## 🧩 Summary Tables
Reprint all key tables for quick reference.

Maintain a factual, analytical tone — concise but insightful.
"""

try:
    final_report = llm.invoke([HumanMessage(content=meta_prompt)]).content.strip()
except Exception as e:
    print(f"❌ Meta summary failed: {e}")
    sys.exit(1)

# ╭──────────────────────────────────────────────╮
# │ 8️⃣  Save results locally + in DB            │
# ╰──────────────────────────────────────────────╯
def clean_text_simple(t):
    t = re.sub(r"[^\x00-\x7F]+", " ", str(t))
    return re.sub(r"\s+", " ", t).strip()

final_report = clean_text_simple(final_report)
print("\n📜 FINAL CYBER REPORT\n" + "="*80)
print(final_report[:1500] + ("\n... (truncated)" if len(final_report)>1500 else ""))
print("="*80)

with open(OUTPUT_FILE,"w",encoding="utf-8") as f:
    f.write(final_report)
print(f"💾 Saved report → {OUTPUT_FILE}")

with engine.begin() as conn:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS threat_summaries (
            id SERIAL PRIMARY KEY,
            summary TEXT,
            generated_at TIMESTAMP DEFAULT NOW()
        );
    """))
    conn.execute(text("INSERT INTO threat_summaries (summary) VALUES (:s)"), {"s":final_report})
print("✅ Saved report to DB: threat_summaries")

print("🏁 Threat-intelligence LLM report generation complete.")
