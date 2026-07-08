# SocialMedia Threat Intel

Cyber threat intelligence pipeline that collects cybersecurity-related social posts, classifies threats using rule-based and Hugging Face zero-shot models, builds an entity relationship network, generates LLM-powered summaries, and visualizes everything in a Streamlit dashboard.

## Architecture

```
Twitter/X API → fetch_cyber_tweets.py → PostgreSQL → analyze_cyber_threat.py (rule-based)
                                                      → analyze_threat_hf.py (zero-shot)
                                                      → threat_network.py (entity graph)
                                                      → threat_summary_llm.py (LLM report)
                                                      → dashboard.py (Streamlit UI)
```

## Setup

```bash
git clone https://github.com/Vishnu-Kommareddy/SocialMedia_Threat_Intel.git
cd SocialMedia_Threat_Intel

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # Fill in your API keys and DB credentials
```

## Pipeline

Run each step sequentially:

```bash
python fetch_cyber_tweets.py      # Fetch tweets from Twitter/X API
python analyze_cyber_threat.py    # Rule-based threat classification
python analyze_threat_hf.py       # Hugging Face zero-shot classification
python threat_network.py          # Build entity relationship graph
python threat_summary_llm.py      # Generate LLM threat report
streamlit run dashboard.py        # Launch dashboard
```

Or use Airflow: deploy `cyber_threat_intel_dag.py` to trigger the full pipeline on a schedule.

## Data Flow

- **Input**: Twitter/X API (cybersecurity-related keywords)
- **Storage**: PostgreSQL tables — `cyber_tweets`, `cyber_tweets_classified`, `cyber_tweets_hf`, `cyber_threat_nodes`, `cyber_threat_edges`, `threat_summaries`
- **Output**: Streamlit dashboard, interactive entity network (HTML), CSV exports

## Requirements

- Python 3.10+
- PostgreSQL database
- Twitter/X API Bearer Token (free tier)
- OpenRouter API key (or OpenAI-compatible endpoint) for LLM summaries

## Deploy (Free — Dashboard Only)

The Streamlit dashboard can be deployed to **Streamlit Community Cloud** independently:

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with GitHub → **Deploy an app**
3. Select this repo, branch `main`, entry point `dashboard.py`
4. Add your `.env` values in Streamlit Cloud **Secrets** section (`Secrets > DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME`)
5. Click **Deploy**

> **Note**: The dashboard needs a running PostgreSQL database accessible from the cloud. Use a free tier from [Neon](https://neon.tech), [Railway](https://railway.app), or [Supabase](https://supabase.com). The pipeline scripts still run locally or via GitHub Actions.

## Project Structure

```
├── config.py                    # Shared config (paths, DB, env)
├── fetch_cyber_tweets.py        # Twitter/X API data collection
├── load_cyber_tweets.py         # Load tweets into PostgreSQL
├── analyze_cyber_threat.py      # Rule-based classification
├── analyze_threat_hf.py         # Hugging Face zero-shot classification
├── threat_network.py            # Entity relationship graph
├── threat_summary_llm.py        # LLM threat report generation
├── evaluation.py                # Compare rule vs HF classification
├── dashboard.py                 # Streamlit visualization
├── cyber_threat_intel_dag.py    # Airflow DAG
├── lib/                         # Frontend assets (vis.js, etc.)
├── airflow/                     # Airflow config & DAGs
└── .env.example                 # Environment variable template
```
