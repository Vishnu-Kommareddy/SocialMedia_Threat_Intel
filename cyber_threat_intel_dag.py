# =====================================================
# cyber_threat_intel_dag.py ✅ FINAL WORKING DAG
# =====================================================

import os
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.bash import BashOperator

# ───────────────────────────────────────────────
# 1️⃣ Project root (resolved relative to this file)
# ───────────────────────────────────────────────
from pathlib import Path
PROJECT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = PROJECT_DIR  # all scripts are in main folder

# ───────────────────────────────────────────────
# 2️⃣ Airflow default args
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
# 3️⃣ DAG definition
# ───────────────────────────────────────────────
with DAG(
    dag_id="cyber_threat_intel_dag",
    default_args=default_args,
    description="End-to-end Cyber Threat Intelligence ETL + NLP + Network + LLM Summary",
    schedule_interval=None,  # Run manually or set "0 2 * * *" for daily
    start_date=datetime(2025, 10, 31),
    catchup=False,
    tags=["cyber", "intel", "ETL", "airflow"],
) as dag:

    # ───────────────────────────────────────────────
    # 4️⃣ ETL + Analysis Tasks
    # ───────────────────────────────────────────────

    # Step 1: Fetch recent cyber-related tweets
    fetch_cyber_tweets = BashOperator(
        task_id="fetch_cyber_tweets",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'fetch_cyber_tweets.py')}'"
    )

    # Step 2: Load tweets into PostgreSQL
    load_cyber_tweets = BashOperator(
        task_id="load_cyber_tweets",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'load_cyber_tweets.py')}'"
    )

    # Step 3: Run rule-based classification
    analyze_rule_based = BashOperator(
        task_id="analyze_rule_based",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'analyze_cyber_threat.py')}'"
    )

    # Step 4: Run Hugging Face classification (LLM)
    analyze_hf_model = BashOperator(
        task_id="analyze_hf_model",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'analyze_threat_hf.py')}'"
    )

    # Step 5: Build entity graph (NetworkX → HTML + CSV)
    build_threat_network = BashOperator(
        task_id="build_threat_network",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'threat_network.py')}'"
    )

    # Step 6: Generate daily threat intelligence summary via LLM
    llm_threat_summary = BashOperator(
        task_id="llm_threat_summary",
        bash_command=f"python '{os.path.join(SCRIPTS_DIR, 'threat_summary_llm.py')}'"
    )

    # ───────────────────────────────────────────────
    # 5️⃣ Task Dependencies
    # ───────────────────────────────────────────────
    (
        fetch_cyber_tweets
        >> load_cyber_tweets
        >> analyze_rule_based
        >> analyze_hf_model
        >> build_threat_network
        >> llm_threat_summary
    )
