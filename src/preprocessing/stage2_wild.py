"""
Stage 2: Olah dataset Wild + Results menjadi silver labels via tool voting.

Input  : - smartbugs-results-master/metadata/results_wild.json (agregat hasil 9 tools)
         - smartbugs-wild-master/contracts/0x*.sol (47k source files)
         - smartbugs-wild-master/nb_lines.csv
         - smartbugs-wild-master/duplicates.json
Output : processed/wild_labels.parquet (multi-label binary per kontrak)
         processed/wild_labels.csv     (versi human-readable)

Strategi labeling:
  - Untuk tiap kontrak, hitung berapa tool mendeteksi tiap kategori
  - Apply threshold SILVER_VOTE_THRESHOLD (default 2 tools)
  - Filter:
    * skip kontrak <WILD_MIN_LOC atau >WILD_MAX_LOC
    * skip kontrak duplikat (ambil canonical)
    * skip kontrak yg tidak ada di Wild folder
"""
import json
import sys
from collections import Counter

import pandas as pd
from tqdm import tqdm

from config import (
    RESULTS_WILD_JSON,
    WILD_CONTRACTS_DIR,
    WILD_NB_LINES,
    WILD_DUPLICATES,
    PROCESSED_DIR,
    VULN_CATEGORIES,
    RESULTS_CATEGORY_MAP,
    SILVER_VOTE_THRESHOLD,
    WILD_MIN_LOC,
    WILD_MAX_LOC,
)


def load_loc_index() -> dict[str, int]:
    """Baca nb_lines.csv → mapping address → LOC."""
    df = pd.read_csv(WILD_NB_LINES, header=None, names=["address", "loc"])
    return dict(zip(df["address"], df["loc"]))


def load_duplicate_set() -> set[str]:
    """
    Baca duplicates.json -> set address yang merupakan duplikat (akan di-skip).

    Format file: { canonical_address: [canonical, dup1, dup2, ...] }
    Item ke-0 adalah canonical itu sendiri. Item ke-1 dst adalah duplikatnya.
    Kita hanya skip item ke-1 dst (canonical tetap dipertahankan).
    """
    if not WILD_DUPLICATES.exists():
        return set()
    with open(WILD_DUPLICATES, "r", encoding="utf-8") as f:
        data = json.load(f)
    duplicates: set[str] = set()
    if isinstance(data, dict):
        for canonical, cluster in data.items():
            if isinstance(cluster, list) and len(cluster) > 1:
                # Skip semua kecuali canonical
                for addr in cluster:
                    if addr != canonical:
                        duplicates.add(addr)
    return duplicates


def load_results_wild() -> dict:
    """Baca results_wild.json (agregat 9 tools)."""
    print(f"[..] Loading {RESULTS_WILD_JSON.name} (~31MB, mohon tunggu)...")
    with open(RESULTS_WILD_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def vote_for_contract(contract_data: dict) -> dict[str, int]:
    """
    Hitung berapa tool mendeteksi tiap kategori.
    contract_data['tools'] = { tool_name: { 'categories': { 'reentrancy': N, ... } } }
    """
    votes = Counter()
    tool_categories = contract_data.get("tools", {})

    for _tool_name, tool_result in tool_categories.items():
        cats = tool_result.get("categories", {}) or {}
        for raw_cat in cats.keys():
            std_cat = RESULTS_CATEGORY_MAP.get(raw_cat)
            if std_cat is not None:
                votes[std_cat] += 1  # +1 per tool yang detect (regardless berapa instance)
    return dict(votes)


def build_wild_dataframe() -> pd.DataFrame:
    loc_index = load_loc_index()
    print(f"[ok] {len(loc_index):,} kontrak ada di nb_lines.csv")

    duplicates = load_duplicate_set()
    print(f"[ok] {len(duplicates):,} kontrak duplikat akan di-skip")

    results = load_results_wild()
    print(f"[ok] {len(results):,} kontrak ada hasil tool di results_wild.json")

    rows = []
    skip_no_source = 0
    skip_loc = 0
    skip_dup = 0
    skip_no_tool = 0

    for address, contract_data in tqdm(results.items(), desc="Voting"):
        # Skip duplikat
        if address in duplicates:
            skip_dup += 1
            continue

        # Skip kalau tidak ada source code
        sol_path = WILD_CONTRACTS_DIR / f"{address}.sol"
        if not sol_path.exists():
            skip_no_source += 1
            continue

        # Filter LOC
        loc = loc_index.get(address)
        if loc is None or loc < WILD_MIN_LOC or loc > WILD_MAX_LOC:
            skip_loc += 1
            continue

        # Tool voting
        votes = vote_for_contract(contract_data)
        if not votes:
            skip_no_tool += 1
            continue

        # Apply threshold → binary label
        labels = {cat: 0 for cat in VULN_CATEGORIES}
        for cat, vote_count in votes.items():
            if vote_count >= SILVER_VOTE_THRESHOLD:
                labels[cat] = 1

        # Skip kontrak yang tidak ada label positif sama sekali (tidak informatif untuk training)
        # Catatan: untuk negative sampling, sebagian akan kita masukkan juga
        if sum(labels.values()) == 0:
            # 50% probability include sebagai "negative sample" — supaya model tahu kontrak aman
            # Pakai hash address untuk deterministic sampling
            if hash(address) % 2 != 0:
                continue

        rows.append(
            {
                "contract_id": address,
                "loc": loc,
                "votes_json": json.dumps(votes),
                **labels,
            }
        )

    print(f"\n[stats] skip_dup       : {skip_dup:,}")
    print(f"[stats] skip_no_source : {skip_no_source:,}")
    print(f"[stats] skip_loc       : {skip_loc:,}  (LOC < {WILD_MIN_LOC} atau > {WILD_MAX_LOC})")
    print(f"[stats] skip_no_tool   : {skip_no_tool:,}  (tidak ada tool detect apapun)")

    return pd.DataFrame(rows)


def attach_source_code(df: pd.DataFrame) -> pd.DataFrame:
    """Baca source code untuk setiap kontrak yang lolos filter."""
    sources = []
    for addr in tqdm(df["contract_id"], desc="Reading source"):
        sol_path = WILD_CONTRACTS_DIR / f"{addr}.sol"
        try:
            sources.append(sol_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            sources.append("")
    df = df.copy()
    df["source_code"] = sources
    return df


def print_summary(df: pd.DataFrame) -> None:
    print("\n" + "=" * 60)
    print("STAGE 2 SUMMARY — WILD DATASET (SILVER LABELS)")
    print("=" * 60)
    print(f"Total kontrak lolos filter : {len(df):,}")
    print(f"Total LOC                  : {df['loc'].sum():,}")
    print(f"Threshold tool voting      : >= {SILVER_VOTE_THRESHOLD} tools")

    print("\nDistribusi label per kategori:")
    print("-" * 60)
    for cat in VULN_CATEGORIES:
        positives = int(df[cat].sum())
        pct = positives / len(df) * 100
        bar = "█" * int(pct / 2)
        print(f"  {cat:30s} : {positives:6d} ({pct:5.1f}%) {bar}")

    print("\nDistribusi multi-label (jumlah kategori per kontrak):")
    print("-" * 60)
    label_counts = df[VULN_CATEGORIES].sum(axis=1).value_counts().sort_index()
    for n_labels, count in label_counts.items():
        print(f"  {int(n_labels)} kategori: {count:,} kontrak")

    print("\nSample 3 baris pertama:")
    print("-" * 60)
    cols = ["contract_id", "loc"] + VULN_CATEGORIES
    print(df[cols].head(3).to_string())


def main() -> None:
    print(">>> Stage 2: Memproses Wild dataset + Results...")
    df = build_wild_dataframe()

    if len(df) == 0:
        print("\n[ERROR] DataFrame kosong - semua kontrak ke-skip oleh filter.")
        print("        Cek statistik [stats] di atas untuk melihat penyebabnya.")
        sys.exit(1)

    df = attach_source_code(df)

    out_parquet = PROCESSED_DIR / "wild_labels.parquet"
    out_csv = PROCESSED_DIR / "wild_labels.csv"

    df.to_parquet(out_parquet, index=False)
    df.drop(columns=["source_code"]).to_csv(out_csv, index=False)

    print(f"\n[ok] Parquet : {out_parquet}")
    print(f"[ok] CSV     : {out_csv}")

    print_summary(df)


if __name__ == "__main__":
    main()
