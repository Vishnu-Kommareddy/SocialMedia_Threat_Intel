# SocialMedia Threat Intel

Cyber threat intelligence pipeline that collects cybersecurity-related social posts, stores them in PostgreSQL, classifies threats, builds an entity network, generates LLM summaries, and exposes a Streamlit dashboard.

## Setup

1. Create a virtual environment and install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Create a local `.env` file from `.env.example` and fill in API/database credentials.

3. Run pipeline steps directly or through the Airflow DAG:

   ```bash
   python fetch_cyber_tweets.py
   python analyze_cyber_threat.py
   python analyze_threat_hf.py
   python threat_network.py
   python threat_summary_llm.py
   streamlit run dashboard.py
   ```

Local data, reports, Airflow logs, and secrets are intentionally ignored by git.
