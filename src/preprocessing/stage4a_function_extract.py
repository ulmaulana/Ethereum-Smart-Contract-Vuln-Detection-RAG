"""
Stage 4a: Function-Level Extraction.

Pakai solidity_parser.py untuk extract setiap function dari setiap kontrak.
Setiap function jadi 1 row dengan:
  - source code function
  - header context (pragma + state vars + modifiers + inheritance)
  - combined_input = header + function (siap untuk CodeBERT/XGBoost)
  - label di-propagate dari level kontrak

Untuk Curated, kita refine label per function via line-mapping:
  - Kalau vuln line ada di range function → label function = 1
  - Kalau tidak → label function = 0
  (Ini asumsi: vuln biasanya lokal di function tertentu)

Untuk Wild, label di-inherit dari contract level (silver labels gak punya line info).

Output:
  processed/curated_functions.parquet
  processed/wild_functions.parquet
  processed/function_extract_summary.json
"""
import json
import sys
from collections import Counter

import pandas as pd
from tqdm import tqdm

from config import PROCESSED_DIR, VULN_CATEGORIES
from solidity_parser import parse_source_file, build_header_context

# Filter
MIN_FUNCTION_CHARS = 30      # skip getter trivial
MAX_FUNCTION_CHARS = 8000    # skip function raksasa (kemungkinan auto-generated)
MAX_FUNCTIONS_PER_CONTRACT = 50  # safety cap


def line_in_function(line: int, fn: dict) -> bool:
    return fn["start_line"] <= line <= fn["end_line"]


def labels_for_function_curated(fn: dict, vuln_lines_dict: dict) -> dict:
    """Mapping vuln_lines (per-kategori list of line numbers) -> binary label per function."""
    labels = {cat: 0 for cat in VULN_CATEGORIES}
    for cat, lines in vuln_lines_dict.items():
        if cat not in labels or not lines:
            continue
        for ln in lines:
            if line_in_function(ln, fn):
                labels[cat] = 1
                break
    return labels


def extract_curated_functions(curated_folds: pd.DataFrame) -> pd.DataFrame:
    rows = []
    parse_failures = 0
    parse_zero_functions = 0

    for _, row in tqdm(curated_folds.iterrows(), total=len(curated_folds), desc="Curated"):
        try:
            parsed = parse_source_file(row["source_code"])
        except Exception as e:
            parse_failures += 1
            continue

        if not parsed["contracts"]:
            parse_zero_functions += 1
            continue

        vuln_lines_dict = json.loads(row["vuln_lines"]) if "vuln_lines" in row and row["vuln_lines"] else {}

        for contract in parsed["contracts"]:
            if contract["kind"] == "interface":
                continue
            header = build_header_context(parsed, contract["name"])

            for fn in contract["functions"][:MAX_FUNCTIONS_PER_CONTRACT]:
                fn_src = fn["source"]
                if not (MIN_FUNCTION_CHARS <= len(fn_src) <= MAX_FUNCTION_CHARS):
                    continue

                fn_labels = labels_for_function_curated(fn, vuln_lines_dict)

                rows.append({
                    "contract_id": row["contract_id"],
                    "contract_name": contract["name"],
                    "function_name": fn["name"],
                    "function_kind": fn["kind"],
                    "function_signature": fn["signature"],
                    "function_source": fn_src,
                    "header_context": header,
                    "combined_input": header + "\n\n    " + fn_src + "\n",
                    "start_line": fn["start_line"],
                    "end_line": fn["end_line"],
                    "fn_loc": fn["end_line"] - fn["start_line"] + 1,
                    "fold": int(row["fold"]),
                    "source": row["source"],
                    "label_quality": row["label_quality"],
                    **fn_labels,
                })

    print(f"\n[stats] parse_failures      : {parse_failures}")
    print(f"[stats] parse_zero_contracts : {parse_zero_functions}")
    print(f"[stats] functions extracted  : {len(rows)}")
    return pd.DataFrame(rows)


def extract_wild_functions(wild_pool: pd.DataFrame) -> pd.DataFrame:
    rows = []
    parse_failures = 0
    parse_zero_functions = 0

    for _, row in tqdm(wild_pool.iterrows(), total=len(wild_pool), desc="Wild"):
        try:
            parsed = parse_source_file(row["source_code"])
        except Exception:
            parse_failures += 1
            continue

        if not parsed["contracts"]:
            parse_zero_functions += 1
            continue

        # Inherit contract-level labels
        contract_labels = {cat: int(row[cat]) for cat in VULN_CATEGORIES if cat in row}

        for contract in parsed["contracts"]:
            if contract["kind"] == "interface":
                continue
            header = build_header_context(parsed, contract["name"])

            for fn in contract["functions"][:MAX_FUNCTIONS_PER_CONTRACT]:
                fn_src = fn["source"]
                if not (MIN_FUNCTION_CHARS <= len(fn_src) <= MAX_FUNCTION_CHARS):
                    continue

                rows.append({
                    "contract_id": row["contract_id"],
                    "contract_name": contract["name"],
                    "function_name": fn["name"],
                    "function_kind": fn["kind"],
                    "function_signature": fn["signature"],
                    "function_source": fn_src,
                    "header_context": header,
                    "combined_input": header + "\n\n    " + fn_src + "\n",
                    "start_line": fn["start_line"],
                    "end_line": fn["end_line"],
                    "fn_loc": fn["end_line"] - fn["start_line"] + 1,
                    "fold": -1,  # Wild tidak ada fold (selalu masuk training)
                    "source": row["source"],
                    "label_quality": row["label_quality"],
                    **contract_labels,
                })

    print(f"\n[stats] parse_failures      : {parse_failures}")
    print(f"[stats] parse_zero_contracts : {parse_zero_functions}")
    print(f"[stats] functions extracted  : {len(rows)}")
    return pd.DataFrame(rows)


def print_summary(curated_fn: pd.DataFrame, wild_fn: pd.DataFrame) -> None:
    print("\n" + "=" * 78)
    print("STAGE 4a SUMMARY — FUNCTION-LEVEL EXTRACTION")
    print("=" * 78)

    print(f"\nCurated functions : {len(curated_fn):,}")
    print(f"Wild functions    : {len(wild_fn):,}")
    print(f"Total functions   : {len(curated_fn) + len(wild_fn):,}")

    if len(curated_fn) > 0:
        print(f"\n[Curated] Function statistics:")
        print(f"  Avg LOC per function   : {curated_fn['fn_loc'].mean():.1f}")
        print(f"  Median LOC per function: {curated_fn['fn_loc'].median():.0f}")
        print(f"  Max LOC per function   : {curated_fn['fn_loc'].max()}")
        print(f"  Functions per contract : {len(curated_fn) / curated_fn['contract_id'].nunique():.1f}")
        print(f"  Function kinds         : {dict(Counter(curated_fn['function_kind']))}")
        print(f"\n[Curated] Function label distribution:")
        for cat in VULN_CATEGORIES:
            n_pos = int(curated_fn[cat].sum())
            print(f"  {cat:30s} : {n_pos:5,} positive functions")

    if len(wild_fn) > 0:
        print(f"\n[Wild] Function statistics:")
        print(f"  Avg LOC per function   : {wild_fn['fn_loc'].mean():.1f}")
        print(f"  Median LOC per function: {wild_fn['fn_loc'].median():.0f}")
        print(f"  Functions per contract : {len(wild_fn) / wild_fn['contract_id'].nunique():.1f}")
        print(f"\n[Wild] Function label distribution (inherited from contract):")
        for cat in VULN_CATEGORIES:
            n_pos = int(wild_fn[cat].sum())
            print(f"  {cat:30s} : {n_pos:5,} positive functions")


def main() -> None:
    print(">>> Stage 4a: Function-level extraction (Curated + Wild)...\n")

    curated_folds = pd.read_parquet(PROCESSED_DIR / "curated_folds.parquet")
    wild_pool = pd.read_parquet(PROCESSED_DIR / "wild_pool.parquet")
    print(f"[ok] Loaded curated_folds : {len(curated_folds):,} kontrak")
    print(f"[ok] Loaded wild_pool     : {len(wild_pool):,} kontrak")

    print("\n[..] Extracting functions dari Curated...")
    curated_fn = extract_curated_functions(curated_folds)
    if len(curated_fn) == 0:
        print("[ERROR] 0 function dari Curated — parser bermasalah!")
        sys.exit(1)

    print("\n[..] Extracting functions dari Wild (~20k kontrak, sabar)...")
    wild_fn = extract_wild_functions(wild_pool)

    # Save
    curated_fn.to_parquet(PROCESSED_DIR / "curated_functions.parquet", index=False)
    wild_fn.to_parquet(PROCESSED_DIR / "wild_functions.parquet", index=False)

    summary = {
        "curated_n_contracts": int(curated_folds["contract_id"].nunique()),
        "curated_n_functions": int(len(curated_fn)),
        "wild_n_contracts": int(wild_pool["contract_id"].nunique()),
        "wild_n_functions": int(len(wild_fn)),
        "curated_label_dist": {c: int(curated_fn[c].sum()) for c in VULN_CATEGORIES},
        "wild_label_dist": {c: int(wild_fn[c].sum()) for c in VULN_CATEGORIES},
    }
    with open(PROCESSED_DIR / "function_extract_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[ok] curated_functions.parquet : {len(curated_fn):,} rows")
    print(f"[ok] wild_functions.parquet    : {len(wild_fn):,} rows")
    print(f"[ok] function_extract_summary.json")

    print_summary(curated_fn, wild_fn)


if __name__ == "__main__":
    main()
