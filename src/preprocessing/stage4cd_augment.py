"""
Stage 4cd: Augment sampled_functions.parquet dengan tool features + rule features.

Tambahkan kolom:
  - tool_*    : ~90 fitur dari hasil 9 SmartBugs tools (per kontrak, propagate ke functions)
  - rule_*    : ~10 expert rule features (per function)

Output: processed/sampled_functions_v2.parquet
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.config import PROCESSED_DIR
from features import tool_features, rules


def main():
    print(">>> Stage 4cd: Augment dengan tool features + rule features\n")

    df = pd.read_parquet(PROCESSED_DIR / "sampled_functions.parquet")
    print(f"[ok] Loaded sampled_functions.parquet : {len(df):,} rows")

    # ===== Stage 4c: Tool features per kontrak =====
    print("\n[..] Loading tool results (results_wild.json + results_curated.json)...")
    tool_features.load_results_wild()
    tool_features.load_results_curated()

    tool_fn_names = tool_features.feature_names()
    print(f"[ok] Tool features: {len(tool_fn_names)} per kontrak")

    print("[..] Extracting tool features per kontrak...")
    contract_tool_cache: dict[str, dict] = {}

    def get_tool_feats(row) -> dict:
        cid = row["contract_id"]
        if cid in contract_tool_cache:
            return contract_tool_cache[cid]
        if row["source"] == "wild":
            data = tool_features.get_contract_data_wild(cid)
        else:
            data = tool_features.get_contract_data_curated(cid)
        feats = tool_features.extract_for_contract(data)
        contract_tool_cache[cid] = feats
        return feats

    tool_rows = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Tool features"):
        feats = get_tool_feats(row)
        tool_rows.append([feats[n] for n in tool_fn_names])
    tool_arr = np.array(tool_rows, dtype=np.float32)
    tool_df = pd.DataFrame(tool_arr, columns=tool_fn_names)
    print(f"     Tool feature matrix: {tool_arr.shape}")
    print(f"     Cached unique contracts: {len(contract_tool_cache):,}")

    # ===== Stage 4d: Rule features per function =====
    rule_fn_names = rules.feature_names()
    print(f"\n[..] Extracting rule features ({len(rule_fn_names)} per function)...")

    rule_rows = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Rule features"):
        feats = rules.extract_rule_features(
            row["function_source"], row.get("header_context", "")
        )
        rule_rows.append([feats[n] for n in rule_fn_names])
    rule_arr = np.array(rule_rows, dtype=np.float32)
    rule_df = pd.DataFrame(rule_arr, columns=rule_fn_names)
    print(f"     Rule feature matrix: {rule_arr.shape}")

    # ===== Concat semua =====
    print("\n[..] Concatenating ke sampled_functions_v2.parquet...")
    augmented = pd.concat([
        df.reset_index(drop=True),
        tool_df.reset_index(drop=True),
        rule_df.reset_index(drop=True),
    ], axis=1)
    print(f"     Final shape: {augmented.shape}")

    out = PROCESSED_DIR / "sampled_functions_v2.parquet"
    augmented.to_parquet(out, index=False)
    print(f"\n[ok] Saved: {out}")

    # Statistics
    n_hc = sum(1 for c in augmented.columns if c.startswith("hc_"))
    n_tool = sum(1 for c in augmented.columns if c.startswith("tool_"))
    n_rule = sum(1 for c in augmented.columns if c.startswith("rule_"))
    print(f"\nFeature breakdown:")
    print(f"  Hand-crafted features : {n_hc}")
    print(f"  Tool features         : {n_tool}")
    print(f"  Rule features         : {n_rule}")
    print(f"  + TF-IDF (di Stage 5) : ~5000")
    print(f"  TOTAL features        : ~{n_hc + n_tool + n_rule + 5000}")

    # Save feature names
    with open(PROCESSED_DIR / "tool_feature_names.json", "w") as f:
        json.dump(tool_fn_names, f, indent=2)
    with open(PROCESSED_DIR / "rule_feature_names.json", "w") as f:
        json.dump(rule_fn_names, f, indent=2)


if __name__ == "__main__":
    main()
