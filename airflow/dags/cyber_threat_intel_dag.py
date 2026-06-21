# =====================================================
# cyber_threat_intel_dag.py ✅ FINAL SIMPLIFIED VERSION
# =====================================================

import os
import platform
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.bash import BashOperator

# ───────────────────────────────────────────────
# 1️⃣ Cross-Platform Path Setup
# ───────────────────────────────────────────────
if platform.system() == "Windows":
    PROJECT_DIR = r"C:\Users\vishn\Downloads\Shift\Programming\code+lab\SocialMedia_Threat_Intel"
else:
    PROJECT_DIR = "/mnt/c/Users/vishn/Downloads/Shift/Programming/code+lab/SocialMedia_Threat_Intel"

SCRIPTS_DIR = PROJECT_DIR  # all scripts are in main folder

# ───────────────────────────────────────────────
# 2️⃣ Airflow Default Args
# ───────────────────────────────────────────────
default_args = {
    "owner": "vishn",
    "depends_on_past": False,
    "email_on_failure": True,
    "email_on_retry": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=3),
}

# ───────────────────────────────────────────────
# 3️⃣ DAG Definition
# ───────────────────────────────────────────────
with DAG(
    dag_id="cyber_threat_intel_dag",
    default_args=default_args,
    description="End-to-end Cyber Threat Intelligence ETL + NLP + Graph + LLM Summary",
    schedule_interval=None,  # set e.g. "0 2 * * *" for daily
    start_date=datetime(2025, 10, 31),
    catchup=False,
    tags=["cyber", "intel", "ETL", "airflow"],
) as dag:

    # ───────────────────────────────────────────────
    # 4️⃣ ETL + Analysis Tasks (5 stages)
    # ───────────────────────────────────────────────

    # Step 1: Fetch + Load Tweets into PostgreSQL
    fetch_cyber_tweets = BashOperator(
        task_id="fetch_cyber_tweets",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'fetch_cyber_tweets.py')}'"
    )

    # Step 2: Run rule-based classification
    analyze_rule_based = BashOperator(
        task_id="analyze_rule_based",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'analyze_cyber_threat.py')}'"
    )

    # Step 3: Run Hugging Face transformer classification
    analyze_hf_model = BashOperator(
        task_id="analyze_hf_model",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'analyze_threat_hf.py')}'"
    )

    # Step 4: Build entity network (NetworkX → CSV/HTML)
    build_threat_network = BashOperator(
        task_id="build_threat_network",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'threat_network.py')}'"
    )

    # Step 5: Generate daily LLM threat summary
    llm_threat_summary = BashOperator(
        task_id="llm_threat_summary",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'threat_summary_llm.py')}'"
    )

    # ───────────────────────────────────────────────
    # 5️⃣ Task Dependencies
    # ───────────────────────────────────────────────
    (
        fetch_cyber_tweets
        >> analyze_rule_based
        >> analyze_hf_model
        >> build_threat_network
        >> llm_threat_summary
    )
