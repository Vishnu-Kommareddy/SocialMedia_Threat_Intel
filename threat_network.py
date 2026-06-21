import os
import re
import platform
import pandas as pd
import networkx as nx
import subprocess
from sqlalchemy import create_engine
from dotenv import load_dotenv

# ╭──────────────────────────────────────────────╮
# │ 1️⃣  Cross-platform base paths               │
# ╰──────────────────────────────────────────────╯
if platform.system() == "Windows":
    BASE_DIR = r"C:\Users\vishn\Downloads\Shift\Programming\code+lab\SocialMedia_Threat_Intel"
else:
    BASE_DIR = "/mnt/c/Users/vishn/Downloads/Shift/Programming/code+lab/SocialMedia_Threat_Intel"

OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
NETWORK_DIR = os.path.join(OUTPUT_DIR, "network")
os.makedirs(NETWORK_DIR, exist_ok=True)

# ╭──────────────────────────────────────────────╮
# │ 2️⃣  Environment + DB connection setup        │
# ╰──────────────────────────────────────────────╯
env_path = os.path.join(BASE_DIR, ".env")
if not os.path.exists(env_path):
    raise FileNotFoundError(f"❌ .env file not found at {env_path}")

load_dotenv(env_path)
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

# Auto-detect host IP when running inside WSL
if platform.system() != "Windows" and (not DB_HOST or DB_HOST in ["localhost", "127.0.0.1"]):
    try:
        route_output = subprocess.check_output("ip route | grep default", shell=True).decode()
        wsl_host_ip = route_output.split("via")[1].split()[0].strip()
        DB_HOST = wsl_host_ip
        print(f"🌐 Running in WSL — using host IP: {DB_HOST}")
    except Exception as e:
        print(f"⚠️ Could not auto-detect host IP: {e}")

# Connect to PostgreSQL
ENGINE = None
if all([DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME]):
    ENGINE = create_engine(f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"🔗 Connected to PostgreSQL at {DB_HOST}:{DB_PORT}")
else:
    print("⚠️ Missing DB credentials — skipping DB insertion.")

# ╭──────────────────────────────────────────────╮
# │ 3️⃣  Load Hugging Face classification data   │
# ╰──────────────────────────────────────────────╯
input_file = os.path.join(OUTPUT_DIR, "cyber_tweets_hf_results.csv")
if not os.path.exists(input_file):
    raise FileNotFoundError(f"❌ Input file not found: {input_file}")

df = pd.read_csv(input_file, encoding="utf-8")
print(f"📂 Loaded {len(df)} records from {input_file}")

# ╭──────────────────────────────────────────────╮
# │ 4️⃣  Regex-based entity extraction           │
# ╰──────────────────────────────────────────────╯
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
DOMAIN_PATTERN = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
ORG_PATTERN = re.compile(r"\b(Microsoft|Google|Cloudflare|Fortinet|Cisco|Meta|Apple|Huawei|IBM|Amazon|Palo Alto|Okta|CrowdStrike|Sophos|Check Point)\b", re.I)
CRYPTO_PATTERN = re.compile(r"\b(Bitcoin|Ethereum|Solana|USDT|BNB|Polygon)\b", re.I)

def extract_entities(text):
    text = str(text)
    entities = set()
    entities.update(CVE_PATTERN.findall(text))
    entities.update(DOMAIN_PATTERN.findall(text))
    entities.update([m.lower() for m in ORG_PATTERN.findall(text)])
    entities.update([c.lower() for c in CRYPTO_PATTERN.findall(text)])
    return list(entities)

df["entities"] = df["tweet_text"].apply(extract_entities)
print("🧩 Extracted CVEs, domains, orgs & crypto entities")

# ╭──────────────────────────────────────────────╮
# │ 5️⃣  Build Threat ↔ Entity edges             │
# ╰──────────────────────────────────────────────╯
edges = []
for _, row in df.iterrows():
    threat = row.get("hf_label", "unknown")
    conf = float(row.get("hf_confidence", 0.5))
    for ent in row["entities"]:
        edges.append((threat, ent, conf))

edges_df = pd.DataFrame(edges, columns=["source", "target", "weight"])
if edges_df.empty:
    print("⚠️ No threat–entity relations found. Check input data.")
    raise SystemExit

edges_df = edges_df.groupby(["source", "target"], as_index=False)["weight"].mean()
print(f"🕸️ Built {len(edges_df)} unique threat–entity edges")

# ╭──────────────────────────────────────────────╮
# │ 6️⃣  Construct NetworkX graph & metrics      │
# ╰──────────────────────────────────────────────╯
G = nx.Graph()
for _, r in edges_df.iterrows():
    G.add_edge(r["source"], r["target"], weight=r["weight"])

deg = nx.degree_centrality(G)
btw = nx.betweenness_centrality(G, normalized=True, weight="weight") if G.number_of_edges() else {}
pr = nx.pagerank(G, weight="weight") if G.number_of_edges() else {}

nodes_df = pd.DataFrame({
    "node": list(G.nodes()),
    "degree": [deg.get(n, 0) for n in G.nodes()],
    "betweenness": [btw.get(n, 0) for n in G.nodes()],
    "pagerank": [pr.get(n, 0) for n in G.nodes()]
}).sort_values("pagerank", ascending=False)

def node_type(n):
    s = str(n)
    if re.match(r"phishing|malware|ransomware|ddos|data_breach|vulnerability|threat_actor|social_engineering", s):
        return "threat"
    if s.startswith("cve-"):
        return "cve"
    if re.search(r"\.", s):
        return "domain"
    return "entity"

nodes_df["type"] = nodes_df["node"].apply(node_type)

# ╭──────────────────────────────────────────────╮
# │ 7️⃣  Save to CSV + PostgreSQL                │
# ╰──────────────────────────────────────────────╯
edges_csv = os.path.join(NETWORK_DIR, "threat_edges.csv")
nodes_csv = os.path.join(NETWORK_DIR, "threat_nodes.csv")
edges_df.to_csv(edges_csv, index=False)
nodes_df.to_csv(nodes_csv, index=False)
print(f"💾 Saved → {edges_csv} and {nodes_csv}")

if ENGINE is not None:
    try:
        edges_df.to_sql("cyber_threat_edges", ENGINE, if_exists="replace", index=False)
        nodes_df.to_sql("cyber_threat_nodes", ENGINE, if_exists="replace", index=False)
        print("✅ Data inserted into tables: cyber_threat_edges, cyber_threat_nodes")
    except Exception as e:
        print(f"❌ PostgreSQL insertion failed: {e}")

# ╭──────────────────────────────────────────────╮
# │ 8️⃣  Interactive HTML visualization (PyVis)  │
# ╰──────────────────────────────────────────────╯
try:
    from pyvis.network import Network
    net = Network(height="750px", width="100%", bgcolor="#0e1117", font_color="white")
    for node in G.nodes():
        ntype = node_type(node)
        color = (
            "#ef4444" if ntype == "threat" else
            "#3b82f6" if ntype in ["domain", "cve"] else
            "#10b981"
        )
        net.add_node(node, label=node, color=color)
    for u, v, d in G.edges(data=True):
        net.add_edge(u, v, value=d["weight"])
    html_path = os.path.join(NETWORK_DIR, "threat_network.html")
    net.write_html(html_path, open_browser=False)
    print(f"🌐 Interactive threat network → {html_path}")
except Exception as e:
    print(f"ℹ️ Skipped visualization (PyVis missing or error): {e}")
    print("   To enable, run: pip install pyvis")

print("🏁 Threat-entity network analysis completed successfully.")
