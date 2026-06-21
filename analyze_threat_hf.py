import os
import platform
import pandas as pd
import subprocess
from sqlalchemy import create_engine
from dotenv import load_dotenv
from transformers import pipeline
from tqdm import tqdm

# ─────────────────────────────
# 1️⃣  Base path setup (Windows ↔ WSL aware)
# ─────────────────────────────
if platform.system() == "Windows":
    BASE_DIR = r"C:\Users\vishn\Downloads\Shift\Programming\code+lab\SocialMedia_Threat_Intel"
else:
    BASE_DIR = "/mnt/c/Users/vishn/Downloads/Shift/Programming/code+lab/SocialMedia_Threat_Intel"

DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────
# 2️⃣  Load environment variables
# ─────────────────────────────
env_path = os.path.join(BASE_DIR, ".env")
if not os.path.exists(env_path):
    raise FileNotFoundError(f"❌ .env file not found at: {env_path}")

load_dotenv(env_path)
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

# ─────────────────────────────
# 3️⃣  Auto-detect host IP (for WSL bridge)
# ─────────────────────────────
if platform.system() != "Windows":
    try:
        route_output = subprocess.check_output("ip route | grep default", shell=True).decode()
        wsl_host_ip = route_output.split("via")[1].split()[0].strip()
        DB_HOST = DB_HOST or wsl_host_ip
        print(f"🌐 Running in WSL — using host IP {DB_HOST}")
    except Exception as e:
        print(f"⚠️ Could not auto-detect Windows host IP: {e}")
else:
    DB_HOST = DB_HOST or "localhost"

# ─────────────────────────────
# 4️⃣  Connect to PostgreSQL
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
