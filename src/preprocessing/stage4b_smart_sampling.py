"""
Stage 4b: Smart Sampling + Hand-crafted Feature Extraction.

Strategi smart sampling:
  Untuk tiap active class:
    - Take semua positive function di Wild (cap MAX_POS_PER_CLASS)
    - Take negatives = 3x positives (random sample)
  Union semua → ~50-80k function balanced
  Plus SEMUA Curated function (gold)

Lalu ekstrak ~50 hand-crafted features per function.

Output:
  processed/sampled_functions.parquet  (function rows + 50 hand-crafted features)
  processed/handcrafted_feature_names.json
  processed/sampling_summary.json
"""
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

# Tambahkan parent dir ke path biar bisa import features module
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.config import PROCESSED_DIR, VULN_CATEGORIES, RANDOM_STATE
from features.handcrafted import extract_features, feature_names

# Sampling config
MAX_POS_PER_CLASS_WILD = 5000     # cap positive Wild function per class
NEG_RATIO = 3                      # negatif = 3x positif


# =====================================================================
# Smart sampling
# =====================================================================

def smart_sample_wild(wild_fn: pd.DataFrame, active_classes: list[str]) -> pd.DataFrame:
    """
    Stratified sampling per-class:
      - Untuk tiap active class, ambil semua positives (capped)
      - Tambah negatives 3x positives, random sampled
      - Dedup union
    """
    rng = np.random.RandomState(RANDOM_STATE)
    selected_idx = set()

    print("\n[..] Smart sampling Wild functions per active class:")
    for cat in active_classes:
        positives = wild_fn[wild_fn[cat] == 1]
        negatives = wild_fn[wild_fn[cat] == 0]

        n_pos_keep = min(len(positives), MAX_POS_PER_CLASS_WILD)
        if n_pos_keep == 0:
            print(f"     [skip]  {cat:30s} : 0 positives di Wild (skip)")
            continue

        pos_sampled = positives.sample(n=n_pos_keep, random_state=RANDOM_STATE)
        n_neg_keep = min(len(negatives), n_pos_keep * NEG_RATIO)
        neg_sampled = negatives.sample(n=n_neg_keep, random_state=RANDOM_STATE)

        selected_idx.update(pos_sampled.index.tolist())
        selected_idx.update(neg_sampled.index.tolist())
        print(f"     {cat:30s} : pos={n_pos_keep:5,} neg={n_neg_keep:5,}")

    sampled = wild_fn.loc[sorted(selected_idx)].reset_index(drop=True)
    print(f"     TOTAL Wild sampled (after dedup): {len(sampled):,}")
    return sampled


# =====================================================================
# Hand-crafted feature extraction
# =====================================================================

def extract_handcrafted_for_df(df: pd.DataFrame, fn_names: list[str]) -> pd.DataFrame:
    """Apply hand-crafted feature extractor to every row, return DataFrame with new columns."""
    feature_rows = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Hand-crafted"):
        feats = extract_features(row["function_source"], row.get("header_context", ""))
        feature_rows.append([feats[name] for name in fn_names])

    feat_arr = np.array(feature_rows, dtype=np.float32)
    feat_df = pd.DataFrame(feat_arr, columns=[f"hc_{n}" for n in fn_names])
    return feat_df


# =====================================================================
# Main
# =====================================================================

def main() -> None:
    print(">>> Stage 4b: Smart sampling + hand-crafted feature extraction\n")

    # Load function-level data
    curated_fn = pd.read_parquet(PROCESSED_DIR / "curated_functions.parquet")
    wild_fn = pd.read_parquet(PROCESSED_DIR / "wild_functions.parquet")
    print(f"[ok] Loaded curated_functions : {len(curated_fn):,}")
    print(f"[ok] Loaded wild_functions    : {len(wild_fn):,}")

    # Load active classes
    with open(PROCESSED_DIR / "active_classes.json") as f:
        active = json.load(f)["active"]
    print(f"[ok] Active classes : {active}")

    # Smart sample Wild
    wild_sampled = smart_sample_wild(wild_fn, active)

    # Combine: Curated (all) + Wild sampled
    print("\n[..] Combining Curated (all) + Wild (sampled)...")
    combined = pd.concat([curated_fn, wild_sampled], ignore_index=True)
    print(f"     TOTAL combined: {len(combined):,} functions")

    # Extract hand-crafted features
    fn_names = feature_names()
    print(f"\n[..] Extracting {len(fn_names)} hand-crafted features per function...")
    feat_df = extract_handcrafted_for_df(combined, fn_names)
    print(f"     Feature matrix shape: {feat_df.shape}")

    # Concat features ke combined df
    combined = pd.concat([combined.reset_index(drop=True), feat_df], axis=1)

    # Save
    out_path = PROCESSED_DIR / "sampled_functions.parquet"
    combined.to_parquet(out_path, index=False)
    print(f"\n[ok] Saved: {out_path} ({len(combined):,} rows × {len(combined.columns)} cols)")

    with open(PROCESSED_DIR / "handcrafted_feature_names.json", "w") as f:
        json.dump([f"hc_{n}" for n in fn_names], f, indent=2)

    # Summary
    summary = {
        "total_functions": int(len(combined)),
        "curated_functions": int(len(curated_fn)),
        "wild_sampled_functions": int(len(wild_sampled)),
        "n_handcrafted_features": int(len(fn_names)),
        "by_source": combined["source"].value_counts().to_dict(),
        "by_label_quality": combined["label_quality"].value_counts().to_dict(),
        "label_distribution": {c: int(combined[c].sum()) for c in VULN_CATEGORIES},
        "label_distribution_curated": {c: int(curated_fn[c].sum()) for c in VULN_CATEGORIES},
        "label_distribution_wild_sampled": {c: int(wild_sampled[c].sum()) for c in VULN_CATEGORIES},
    }
    with open(PROCESSED_DIR / "sampling_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Print
    print("\n" + "=" * 78)
    print("STAGE 4b SUMMARY")
    print("=" * 78)
    print(f"Total functions             : {summary['total_functions']:,}")
    print(f"  Curated (gold)            : {summary['curated_functions']:,}")
    print(f"  Wild sampled (silver)     : {summary['wild_sampled_functions']:,}")
    print(f"Hand-crafted features       : {summary['n_handcrafted_features']}")

    print(f"\nLabel distribution per kategori (combined):")
    for cat in VULN_CATEGORIES:
        marker = "+" if cat in active else "-"
        n_total = summary["label_distribution"][cat]
        n_cur = summary["label_distribution_curated"][cat]
        n_wild = summary["label_distribution_wild_sampled"][cat]
        print(f"  [{marker}] {cat:30s}: {n_total:6,} total  (cur={n_cur:4,}, wild={n_wild:5,})")


if __name__ == "__main__":
    main()
