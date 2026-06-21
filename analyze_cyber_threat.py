import os
import platform
import pandas as pd
from sqlalchemy import create_engine
from dotenv import load_dotenv
import re, subprocess

# ─────────────────────────────
# 1️⃣  Base path (Windows ↔ WSL aware)
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
        print(f"🌐 Running in WSL — using Windows host IP: {DB_HOST}")
    except Exception as e:
        print(f"⚠️ Could not auto-detect Windows host IP: {e}")
else:
    DB_HOST = DB_HOST or "localhost"

# ─────────────────────────────
# 4️⃣  PostgreSQL connection
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
