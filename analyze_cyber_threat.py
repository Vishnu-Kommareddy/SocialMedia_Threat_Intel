import os
import re
import pandas as pd
from sqlalchemy import create_engine

from config import DATA_DIR, OUTPUT_DIR, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME


# ─────────────────────────────
# 1️⃣  Data directories
# ─────────────────────────────
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────
# 2️⃣  PostgreSQL connection
# ─────────────────────────────
engine = None
if all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"🔗 Connected to PostgreSQL at {DB_HOST}:{DB_PORT}")
else:
    print("⚠️ Missing DB credentials — skipping database operations.")

# ─────────────────────────────
# 5️⃣  Load cyber tweets CSV
# ─────────────────────────────
input_file = os.path.join(DATA_DIR, "cyber_tweets.csv")
if not os.path.exists(input_file):
    raise FileNotFoundError(f"❌ Input CSV not found: {input_file}")

tweets_df = pd.read_csv(input_file, encoding="utf-8")
print(f"📂 Loaded {len(tweets_df)} tweets from {input_file}")

# ─────────────────────────────
# 6️⃣  Fetch existing tweet IDs to prevent duplicates
# ─────────────────────────────
existing_ids = set()
if engine:
    try:
        existing_df = pd.read_sql("SELECT tweet_id FROM cyber_tweets_classified", engine)
        existing_ids = set(existing_df["tweet_id"])
        print(f"🧮 Found {len(existing_ids)} existing classified tweets.")
    except Exception:
        print("ℹ️ Table 'cyber_tweets_classified' not found — starting fresh.")

new_tweets_df = tweets_df[~tweets_df["tweet_id"].isin(existing_ids)]
if new_tweets_df.empty:
    print("✅ No new tweets to classify.")
    exit()

# ─────────────────────────────
# 7️⃣  Define rule-based threat categories & severity levels
# ─────────────────────────────
categories = {
    "phishing": [r"phish", r"credential", r"fake\s+login", r"suspicious\s+url"],
    "ransomware": [r"ransom", r"encrypt(ed|ion)", r"locker", r"decrypt"],
    "data_breach": [r"data\s*breach", r"leak", r"expos(ed|ure)", r"compromis"],
    "malware": [r"malware", r"trojan", r"virus", r"backdoor", r"infostealer"],
    "vulnerability": [r"cve-\d+", r"zero[-\s]?day", r"vulnerab", r"exploit"],
    "ddos": [r"ddos", r"botnet", r"traffic\s+attack"],
    "threat_actor": [r"threat\s+actor", r"hacker\s+group", r"apt\s*\d+"],
    "social_engineering": [r"scam", r"impersonat", r"social\s+engineer", r"fraud"]
}

def classify_category(text):
    text = str(text).lower()
    for cat, patterns in categories.items():
        for p in patterns:
            if re.search(p, text):
                return cat
    return "other"

def classify_severity(text):
    text = str(text).lower()
    if re.search(r"critical|massive|widespread|nation[-\s]?state|zero[-\s]?day", text):
        return "high"
    elif re.search(r"exploit|leak|attack|breach|infect|phish|ransom", text):
        return "medium"
    else:
        return "low"

# ─────────────────────────────
# 8️⃣  Apply classification
# ─────────────────────────────
print("🧠 Performing rule-based threat classification...")
new_tweets_df["category"] = new_tweets_df["tweet_text"].apply(classify_category)
new_tweets_df["severity"] = new_tweets_df["tweet_text"].apply(classify_severity)

# ─────────────────────────────
# 9️⃣  Insert into PostgreSQL
# ─────────────────────────────
if engine:
    try:
        new_tweets_df.to_sql("cyber_tweets_classified", engine, if_exists="append", index=False)
        print(f"✅ {len(new_tweets_df)} new records inserted into 'cyber_tweets_classified'.")
    except Exception as e:
        print(f"❌ Database insertion failed: {e}")
else:
    print("⚠️ Skipped DB insertion due to missing connection.")

# ─────────────────────────────
# 🔟  Local CSV backup
# ─────────────────────────────
output_file = os.path.join(OUTPUT_DIR, "cyber_tweets_classified.csv")
header = not os.path.exists(output_file)
new_tweets_df.to_csv(output_file, mode="a", index=False, header=header, encoding="utf-8")
print(f"📁 Backup saved to: {output_file}")
