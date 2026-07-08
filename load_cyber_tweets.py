import pandas as pd
from sqlalchemy import create_engine

from config import DATA_DIR, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME

CSV_PATH = DATA_DIR / "cyber_tweets.csv"

# ---- Load ----
print("📂 Reading CSV from:", CSV_PATH)
df = pd.read_csv(CSV_PATH)
print("✅ Loaded", len(df), "rows from CSV")

if not all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    raise ValueError("Missing database credentials in .env.")

engine = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

df.to_sql("cyber_tweets", engine, if_exists="append", index=False)
print("✅ Successfully inserted", len(df), "records into cyber_tweets table.")
