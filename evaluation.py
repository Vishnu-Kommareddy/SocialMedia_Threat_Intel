"""
evaluate_cti.py

Real evaluation script for your CTI pipeline.
- Compares rule-based labels vs zero-shot labels from two CSVs
- Prints precision, recall, F1-score, and a classification report

Run from project root: python evaluation.py
"""

import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report

from config import OUTPUT_DIR

# ============
# CONFIG
# ============

# Paths to your CSVs (relative to project root)
RULE_BASED_CSV = OUTPUT_DIR / "cyber_tweets_classified.csv"
HF_RESULTS_CSV = OUTPUT_DIR / "cyber_tweets_hf_results.csv"

# Column names (change here if your headers differ)
TWEET_ID_COL = "tweet_id"
RULE_LABEL_COL = "category"   # rule-based classifier label
HF_LABEL_COL = "hf_label"     # zero-shot / HF label


def main():
    # 1. Load CSVs
    print("Loading CSV files...")
    df_rule = pd.read_csv(RULE_BASED_CSV)
    df_hf = pd.read_csv(HF_RESULTS_CSV)

    print("\n[Rule-based file] Columns:", list(df_rule.columns))
    print("[HF results file] Columns:", list(df_hf.columns))

    # 2. Basic sanity check: ensure required columns exist
    for col, name in [
        (TWEET_ID_COL, "TWEET_ID_COL"),
        (RULE_LABEL_COL, "RULE_LABEL_COL"),
        (HF_LABEL_COL, "HF_LABEL_COL"),
    ]:
        if col not in df_rule.columns and col not in df_hf.columns:
            raise ValueError(
                f"Configured column '{col}' ({name}) not found in either CSV. "
                f"Check your file headers and update the script."
            )

    # 3. Merge on tweet_id
    print("\nMerging on tweet_id...")
    merged = pd.merge(
        df_rule[[TWEET_ID_COL, RULE_LABEL_COL]],
        df_hf[[TWEET_ID_COL, HF_LABEL_COL]],
        on=TWEET_ID_COL,
        how="inner",
    )

    print(f"Number of tweets with both labels: {len(merged)}")

    # Drop rows with missing labels (just in case)
    merged = merged.dropna(subset=[RULE_LABEL_COL, HF_LABEL_COL])

    # 4. Inspect label distributions
    print("\n=== Label distribution (Rule-based) ===")
    print(merged[RULE_LABEL_COL].value_counts())

    print("\n=== Label distribution (HF / zero-shot) ===")
    print(merged[HF_LABEL_COL].value_counts())

    # 5. Compute metrics: treat rule-based as reference (y_true)
    y_true = merged[RULE_LABEL_COL].astype(str)
    y_pred = merged[HF_LABEL_COL].astype(str)

    macro_precision = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_recall = recall_score(y_true, y_pred, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)

    print("\n=== Overall Macro Metrics (HF vs Rule-based) ===")
    print(f"Precision: {macro_precision:.2f}")
    print(f"Recall   : {macro_recall:.2f}")
    print(f"F1-score : {macro_f1:.2f}")

    # 6. Full classification report
    print("\n=== Classification Report (per class) ===")
    print(classification_report(y_true, y_pred, zero_division=0))


if __name__ == "__main__":
    main()
