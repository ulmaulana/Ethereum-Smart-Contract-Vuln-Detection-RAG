"""
Stage 1: Olah dataset Curated (gold label).

Input  : smartbugs-curated-main/vulnerabilities.json + dataset/*/*.sol
Output : processed/curated_labels.parquet (multi-label binary per kontrak)
         processed/curated_labels.csv     (versi human-readable)
"""
import json
import sys
from collections import Counter

import pandas as pd

from config import (
    CURATED_VULN_JSON,
    CURATED_CONTRACTS_DIR,
    PROCESSED_DIR,
    VULN_CATEGORIES,
)


def load_curated_annotations() -> list[dict]:
    """Baca vulnerabilities.json — daftar kontrak + line vulnerability-nya."""
    with open(CURATED_VULN_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def build_curated_dataframe(annotations: list[dict]) -> pd.DataFrame:
    """Bangun DataFrame: 1 baris = 1 kontrak, 10 kolom binary per kategori."""
    rows = []
    missing_files = 0

    for entry in annotations:
        sol_path = CURATED_CONTRACTS_DIR.parent / entry["path"]
        if not sol_path.exists():
            missing_files += 1
            continue

        try:
            source_code = sol_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"[skip] {sol_path.name}: {e}", file=sys.stderr)
            continue

        # Multi-label binary: 1 jika ada vuln di kategori, 0 jika tidak
        labels = {cat: 0 for cat in VULN_CATEGORIES}
        vuln_lines: dict[str, list[int]] = {cat: [] for cat in VULN_CATEGORIES}

        for vuln in entry.get("vulnerabilities", []):
            cat = vuln.get("category")
            if cat in labels:
                labels[cat] = 1
                vuln_lines[cat].extend(vuln.get("lines", []))

        rows.append(
            {
                "contract_id": entry["name"],
                "source_file": str(sol_path.relative_to(CURATED_CONTRACTS_DIR.parent)),
                "primary_category": entry["path"].split("/")[1],
                "pragma": entry.get("pragma", ""),
                "loc": source_code.count("\n") + 1,
                "source_code": source_code,
                "vuln_lines": json.dumps(vuln_lines),
                **labels,
            }
        )

    if missing_files:
        print(f"[warn] {missing_files} file di vulnerabilities.json tidak ditemukan")

    return pd.DataFrame(rows)


def print_summary(df: pd.DataFrame) -> None:
    print("\n" + "=" * 60)
    print("STAGE 1 SUMMARY — CURATED DATASET (GOLD LABELS)")
    print("=" * 60)
    print(f"Total kontrak terbaca : {len(df)}")
    print(f"Total LOC             : {df['loc'].sum():,}")
    print(f"Median LOC per kontrak: {int(df['loc'].median())}")

    print("\nDistribusi label per kategori:")
    print("-" * 60)
    for cat in VULN_CATEGORIES:
        positives = int(df[cat].sum())
        pct = positives / len(df) * 100
        bar = "█" * int(pct / 2)
        print(f"  {cat:30s} : {positives:4d} ({pct:5.1f}%) {bar}")

    print("\nDistribusi multi-label (jumlah kategori per kontrak):")
    print("-" * 60)
    label_counts = df[VULN_CATEGORIES].sum(axis=1).value_counts().sort_index()
    for n_labels, count in label_counts.items():
        print(f"  {int(n_labels)} kategori: {count} kontrak")

    print("\nDistribusi primary_category folder:")
    print("-" * 60)
    for cat, count in Counter(df["primary_category"]).most_common():
        print(f"  {cat:30s} : {count}")

    print("\nSample 3 baris pertama:")
    print("-" * 60)
    cols = ["contract_id", "primary_category", "loc"] + VULN_CATEGORIES
    print(df[cols].head(3).to_string())


def main() -> None:
    print(">>> Stage 1: Memproses Curated dataset...")
    annotations = load_curated_annotations()
    print(f"[ok] {len(annotations)} entri dibaca dari vulnerabilities.json")

    df = build_curated_dataframe(annotations)

    out_parquet = PROCESSED_DIR / "curated_labels.parquet"
    out_csv = PROCESSED_DIR / "curated_labels.csv"

    df.to_parquet(out_parquet, index=False)

    # Versi CSV tanpa source_code (biar ringan untuk inspeksi)
    df.drop(columns=["source_code"]).to_csv(out_csv, index=False)

    print(f"[ok] Parquet : {out_parquet}")
    print(f"[ok] CSV     : {out_csv}")

    print_summary(df)


if __name__ == "__main__":
    main()
