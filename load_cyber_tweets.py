import os
import platform
import subprocess

import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine

# ---- Config ----
if platform.system() == "Windows":
    BASE_DIR = r"C:\Users\vishn\Downloads\Shift\Programming\code+lab\SocialMedia_Threat_Intel"
else:
    BASE_DIR = "/mnt/c/Users/vishn/Downloads/Shift/Programming/code+lab/SocialMedia_Threat_Intel"

load_dotenv(os.path.join(BASE_DIR, ".env"))

DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

if platform.system() != "Windows" and not DB_HOST:
    try:
        route_output = subprocess.check_output("ip route | grep default", shell=True).decode()
        DB_HOST = route_output.split("via")[1].split()[0].strip()
    except Exception:
        DB_HOST = "localhost"

CSV_PATH = os.path.join(BASE_DIR, "data", "cyber_tweets.csv")

# ---- Load ----
print("📂 Reading CSV from:", CSV_PATH)
df = pd.read_csv(CSV_PATH)
print("✅ Loaded", len(df), "rows from CSV")

if not all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    raise ValueError("Missing database credentials in .env.")

engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

df.to_sql("cyber_tweets", engine, if_exists="append", index=False)
print("✅ Successfully inserted", len(df), "records into cyber_tweets table.")
