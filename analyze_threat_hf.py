import os
import pandas as pd
from sqlalchemy import create_engine
from transformers import pipeline
from tqdm import tqdm

from config import DATA_DIR, OUTPUT_DIR, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME


# ─────────────────────────────
# 1️⃣  Data directories
# ─────────────────────────────
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────
# 2️⃣  Connect to PostgreSQL
# ─────────────────────────────
engine = None
if all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"🔗 Connected to PostgreSQL at {DB_HOST}:{DB_PORT}")
else:
    print("⚠️ Missing DB credentials — skipping DB connection.")

# ─────────────────────────────
# 5️⃣  Load cyber_tweets_classified.csv
# ─────────────────────────────
input_file = os.path.join(DATA_DIR, "cyber_tweets_classified.csv")
if not os.path.exists(input_file):
    alt_path = os.path.join(OUTPUT_DIR, "cyber_tweets_classified.csv")
    if os.path.exists(alt_path):
        print(f"⚠️ Data file not in /data, using backup from /outputs.")
        input_file = alt_path
    else:
        raise FileNotFoundError(f"❌ No classified tweets file found in {DATA_DIR} or {OUTPUT_DIR}.")

tweets_df = pd.read_csv(input_file, encoding="utf-8")
print(f"📂 Loaded {len(tweets_df)} records from {input_file}")

# ─────────────────────────────
# 6️⃣  Load public zero-shot model
# ─────────────────────────────
print("🧠 Loading model: MoritzLaurer/mDeBERTa-v3-base-mnli-xnli ...")
clf = pipeline("zero-shot-classification", model="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli")

candidate_labels = [
    "phishing", "ransomware", "malware", "data_breach",
    "vulnerability", "ddos", "threat_actor", "social_engineering", "benign"
]

# ─────────────────────────────
# 7️⃣  Apply model classification
# ─────────────────────────────
def classify_text(text):
    try:
        res = clf(text, candidate_labels=candidate_labels, multi_label=True)
        top_label = res["labels"][0]
        top_score = res["scores"][0]
        return top_label, round(float(top_score), 4)
    except Exception as e:
        return "error", 0.0

print("🚀 Running classification on tweets...")
tqdm.pandas(desc="Classifying")
tweets_df[["hf_label", "hf_confidence"]] = tweets_df["tweet_text"].progress_apply(
    lambda x: pd.Series(classify_text(x))
)

# ─────────────────────────────
# 8️⃣  Save to PostgreSQL and CSV
# ─────────────────────────────
if engine:
    try:
        tweets_df.to_sql("cyber_tweets_hf", engine, if_exists="replace", index=False)
        print("✅ Hugging Face classifications stored in table 'cyber_tweets_hf'.")
    except Exception as e:
        print(f"❌ Database insertion failed: {e}")
else:
    print("⚠️ Skipped DB insertion (no connection).")

output_file = os.path.join(OUTPUT_DIR, "cyber_tweets_hf_results.csv")
tweets_df.to_csv(output_file, index=False, encoding="utf-8")
print(f"📁 Results saved to: {output_file}")

print("🏁 Completed successfully.")
