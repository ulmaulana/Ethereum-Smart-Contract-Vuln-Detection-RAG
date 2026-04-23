"""
Stage 3 v2 (K-Fold CV): Assign 143 Curated kontrak ke K folds + balance Wild pool.

Strategi:
  1. Detect active classes (>= ACTIVE_CLASS_MIN_CURATED sampel di Curated)
  2. Subsample Wild (cap arithmetic-only & all-negative)  -> wild_pool.parquet
  3. Multi-label stratified K-fold assignment untuk Curated  -> curated_folds.parquet
  4. Compute class weights dari (semua Curated + Wild pool)
  5. Generate report: distribusi label per fold (untuk laporan UAS)

Saat training (Stage 5):
  for fold in 0..K-1:
      test  = curated_folds[curated_folds.fold == fold]
      train = curated_folds[curated_folds.fold != fold] + wild_pool
      train model -> evaluate on test
  Aggregate F1 across K folds -> reported metrics

Output:
  processed/curated_folds.parquet
  processed/wild_pool.parquet
  processed/active_classes.json
  processed/class_weights.json
  processed/cv_split_summary.json
  processed/cv_split_report.md
"""
import json
from collections import Counter

import numpy as np
import pandas as pd

from config import (
    PROCESSED_DIR,
    VULN_CATEGORIES,
    ACTIVE_CLASS_MIN_CURATED,
    ARITHMETIC_ONLY_WILD_CAP,
    ALL_NEGATIVE_WILD_CAP,
    RANDOM_STATE,
)

K_FOLDS = 5  # standar di literatur ML smart contract


# =====================================================================
# Loading & normalization
# =====================================================================

def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    curated = pd.read_parquet(PROCESSED_DIR / "curated_labels.parquet")
    wild = pd.read_parquet(PROCESSED_DIR / "wild_labels.parquet")
    print(f"[ok] Curated loaded : {len(curated):,} kontrak")
    print(f"[ok] Wild loaded    : {len(wild):,} kontrak")
    return curated, wild


def normalize_columns(df: pd.DataFrame, source: str) -> pd.DataFrame:
    # Pertahankan kolom 'vuln_lines' (Curated) untuk per-function label refinement di Stage 4a
    cols = ["contract_id", "loc", "source_code", "vuln_lines"] + VULN_CATEGORIES
    out = df[[c for c in cols if c in df.columns]].copy()
    out["source"] = source
    out["label_quality"] = "gold" if source == "curated" else "silver"
    return out


# =====================================================================
# Active class detection
# =====================================================================

def detect_active_classes(curated: pd.DataFrame) -> tuple[list[str], list[str]]:
    counts = curated[VULN_CATEGORIES].sum().to_dict()
    active = [c for c in VULN_CATEGORIES if counts[c] >= ACTIVE_CLASS_MIN_CURATED]
    inactive = [c for c in VULN_CATEGORIES if counts[c] < ACTIVE_CLASS_MIN_CURATED]
    print(f"\n[..] Deteksi active classes (min {ACTIVE_CLASS_MIN_CURATED} sampel di Curated)")
    for c in VULN_CATEGORIES:
        marker = "ACTIVE  " if c in active else "inactive"
        print(f"     [{marker}] {c:30s} : {counts[c]:3d} sampel")
    return active, inactive


# =====================================================================
# Wild subsampling
# =====================================================================

def subsample_wild(wild: pd.DataFrame) -> pd.DataFrame:
    label_sum = wild[VULN_CATEGORIES].sum(axis=1)
    is_neg = label_sum == 0
    is_arith_only = (wild["arithmetic"] == 1) & (label_sum == 1)
    is_rest = ~(is_neg | is_arith_only)

    arith_only_df = wild[is_arith_only]
    neg_df = wild[is_neg]
    rest_df = wild[is_rest]

    n_arith_keep = min(len(arith_only_df), ARITHMETIC_ONLY_WILD_CAP)
    n_neg_keep = min(len(neg_df), ALL_NEGATIVE_WILD_CAP)

    arith_sampled = (arith_only_df.sample(n=n_arith_keep, random_state=RANDOM_STATE)
                     if n_arith_keep > 0 else arith_only_df.iloc[0:0])
    neg_sampled = (neg_df.sample(n=n_neg_keep, random_state=RANDOM_STATE)
                   if n_neg_keep > 0 else neg_df.iloc[0:0])

    balanced = pd.concat([rest_df, arith_sampled, neg_sampled], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    print(f"\n[..] Subsampling Wild:")
    print(f"     arithmetic_only : {len(arith_only_df):,} -> {n_arith_keep:,} (cap {ARITHMETIC_ONLY_WILD_CAP:,})")
    print(f"     all_negative    : {len(neg_df):,} -> {n_neg_keep:,} (cap {ALL_NEGATIVE_WILD_CAP:,})")
    print(f"     rest (kept)     : {len(rest_df):,}")
    print(f"     TOTAL Wild      : {len(wild):,} -> {len(balanced):,}")
    return balanced


# =====================================================================
# Multi-label stratified K-fold assignment (greedy iterative)
# =====================================================================

def multilabel_kfold_assign(
    df: pd.DataFrame,
    label_cols: list[str],
    k: int,
    random_state: int = RANDOM_STATE,
) -> pd.DataFrame:
    """
    Greedy multi-label stratified K-fold:
      - Process kontrak diurutkan dari yang punya label paling langka dulu
      - Untuk tiap kontrak, assign ke fold yang paling 'butuh' label kontrak tsb
      - Hasil: tiap fold balanced terhadap distribusi label

    Returns: df dengan tambahan kolom 'fold' (0..k-1)
    """
    n = len(df)
    target_size = [n // k] * k
    for i in range(n % k):
        target_size[i] += 1

    label_total = {c: int(df[c].sum()) for c in label_cols}
    target_pos = [{c: label_total[c] / k for c in label_cols} for _ in range(k)]

    cur_size = [0] * k
    cur_pos = [{c: 0 for c in label_cols} for _ in range(k)]

    rarity = {c: label_total[c] if label_total[c] > 0 else 1e9 for c in label_cols}

    def row_priority(row):
        actives = [c for c in label_cols if row[c] == 1]
        if not actives:
            return 1e10
        return min(rarity[c] for c in actives)

    df_pri = df.copy()
    df_pri["_pri"] = df_pri.apply(row_priority, axis=1)
    df_pri = df_pri.sample(frac=1, random_state=random_state).sort_values("_pri", kind="stable")

    fold_assign = []
    for _, row in df_pri.iterrows():
        scores = []
        for fold_id in range(k):
            if cur_size[fold_id] >= target_size[fold_id]:
                scores.append(-1e10)
                continue
            score = 0.0
            for c in label_cols:
                if row[c] == 1:
                    deficit = target_pos[fold_id][c] - cur_pos[fold_id][c]
                    if target_pos[fold_id][c] > 0:
                        score += deficit / target_pos[fold_id][c]
            score += (target_size[fold_id] - cur_size[fold_id]) / max(target_size[fold_id], 1) * 1e-3
            scores.append(score)

        best = int(np.argmax(scores))
        fold_assign.append(best)
        cur_size[best] += 1
        for c in label_cols:
            if row[c] == 1:
                cur_pos[best][c] += 1

    df_pri["fold"] = fold_assign
    return df_pri.drop(columns=["_pri"]).reset_index(drop=True)


# =====================================================================
# Class weights (untuk XGBoost scale_pos_weight)
# =====================================================================

def compute_class_weights(combined: pd.DataFrame, label_cols: list[str]) -> dict[str, float]:
    """scale_pos_weight = n_negative / n_positive (XGBoost convention)."""
    weights = {}
    for c in label_cols:
        n_pos = int(combined[c].sum())
        n_neg = len(combined) - n_pos
        weights[c] = round(n_neg / n_pos, 2) if n_pos > 0 else 1.0
    return weights


# =====================================================================
# Reporting
# =====================================================================

def build_summary(
    curated_folds: pd.DataFrame,
    wild_pool: pd.DataFrame,
    active: list[str],
    inactive: list[str],
    class_weights: dict[str, float],
    k: int,
) -> dict:
    summary = {
        "k_folds": k,
        "active_classes": active,
        "inactive_classes": inactive,
        "class_weights": class_weights,
        "wild_pool_total": len(wild_pool),
        "wild_pool_label_dist": {c: int(wild_pool[c].sum()) for c in VULN_CATEGORIES},
        "folds": {},
    }
    for fold_id in range(k):
        fold_df = curated_folds[curated_folds["fold"] == fold_id]
        summary["folds"][f"fold_{fold_id}"] = {
            "size": len(fold_df),
            "label_distribution": {c: int(fold_df[c].sum()) for c in VULN_CATEGORIES},
            "any_positive": int((fold_df[VULN_CATEGORIES].sum(axis=1) > 0).sum()),
            "all_negative": int((fold_df[VULN_CATEGORIES].sum(axis=1) == 0).sum()),
        }
    return summary


def build_markdown_report(summary: dict) -> str:
    k = summary["k_folds"]
    lines = []
    lines.append("# Stage 3 v2: K-Fold Cross Validation Split Report\n")
    lines.append(f"- **K folds**: {k}")
    lines.append(f"- **Active classes** ({len(summary['active_classes'])}): "
                 f"`{', '.join(summary['active_classes'])}`")
    lines.append(f"- **Inactive classes** ({len(summary['inactive_classes'])}): "
                 f"`{', '.join(summary['inactive_classes']) or '(none)'}`")
    lines.append(f"- **Wild pool** (always in training): {summary['wild_pool_total']:,} kontrak\n")

    # Folds size
    lines.append("\n## Fold Sizes (Curated)\n")
    lines.append("| Fold | Size | Any Positive | All Negative |")
    lines.append("|------|------|--------------|--------------|")
    for f, info in summary["folds"].items():
        lines.append(f"| {f} | {info['size']} | {info['any_positive']} | {info['all_negative']} |")

    # Label dist per fold
    lines.append("\n## Distribusi Label per Fold (Curated)\n")
    fold_names = list(summary["folds"].keys())
    header = "| Kategori | " + " | ".join(fold_names) + " | Wild Pool | scale_pos_weight |"
    sep = "|----------|" + "|".join(["---" for _ in fold_names]) + "|-----------|------------------|"
    lines.append(header)
    lines.append(sep)
    for cat in VULN_CATEGORIES:
        marker = "+" if cat in summary["active_classes"] else "-"
        cells = [str(summary["folds"][f]["label_distribution"][cat]) for f in fold_names]
        wild_count = summary["wild_pool_label_dist"][cat]
        weight = summary["class_weights"].get(cat, "N/A")
        lines.append(f"| [{marker}] {cat} | " + " | ".join(cells) + f" | {wild_count:,} | {weight} |")

    # Penjelasan training schema
    lines.append("\n## Skema Training (untuk Stage 5)\n")
    lines.append("```")
    lines.append("for fold in 0..4:")
    lines.append("    test  = curated_folds[curated_folds.fold == fold]")
    lines.append("    train = curated_folds[curated_folds.fold != fold] + wild_pool")
    lines.append("    model.fit(train) -> predict(test)")
    lines.append("aggregate F1 macro across 5 folds -> reported metrics")
    lines.append("```\n")
    lines.append("Total Curated terpakai sebagai test set: 143 (semua, via rotation)\n")

    return "\n".join(lines)


def print_summary(summary: dict) -> None:
    k = summary["k_folds"]
    print("\n" + "=" * 78)
    print(f"STAGE 3 v2 SUMMARY — {k}-FOLD CV ASSIGNMENT")
    print("=" * 78)
    print(f"Active classes  : {summary['active_classes']}")
    print(f"Inactive classes: {summary['inactive_classes']}")
    print(f"Wild pool size  : {summary['wild_pool_total']:,} (always in training)")

    print(f"\nClass weights (XGBoost scale_pos_weight, dari Curated+Wild combined):")
    for c, w in summary["class_weights"].items():
        marker = "+" if c in summary["active_classes"] else "-"
        print(f"  [{marker}] {c:30s} : {w}")

    print(f"\nFold sizes (Curated, total {sum(info['size'] for info in summary['folds'].values())}):")
    for f, info in summary["folds"].items():
        print(f"  {f}: {info['size']:3d} kontrak  (any_pos={info['any_positive']}, all_neg={info['all_negative']})")

    print(f"\nLabel distribution per fold (Curated, '+' = active class):")
    fold_names = list(summary["folds"].keys())
    header = f"  {'Kategori':30s}  " + "  ".join([f"{f:>7s}" for f in fold_names]) + "  Wild"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for cat in VULN_CATEGORIES:
        marker = "+" if cat in summary["active_classes"] else "-"
        cells = [f"{summary['folds'][f]['label_distribution'][cat]:>7d}" for f in fold_names]
        wild_count = summary["wild_pool_label_dist"][cat]
        print(f"  [{marker}] {cat:26s}  " + "  ".join(cells) + f"  {wild_count:>5d}")


# =====================================================================
# Main
# =====================================================================

def main() -> None:
    print(f">>> Stage 3 v2 ({K_FOLDS}-Fold CV): Assigning Curated to folds + balancing Wild...\n")
    curated, wild = load_inputs()

    active, inactive = detect_active_classes(curated)
    wild_balanced = subsample_wild(wild)

    curated_norm = normalize_columns(curated, "curated")
    wild_norm = normalize_columns(wild_balanced, "wild")

    print(f"\n[..] Multi-label stratified {K_FOLDS}-fold assignment untuk Curated...")
    curated_folds = multilabel_kfold_assign(curated_norm, VULN_CATEGORIES, K_FOLDS)

    combined = pd.concat([curated_folds.drop(columns=["fold"]), wild_norm], ignore_index=True)
    class_weights = compute_class_weights(combined, VULN_CATEGORIES)

    # Save outputs
    curated_folds.to_parquet(PROCESSED_DIR / "curated_folds.parquet", index=False)
    wild_norm.to_parquet(PROCESSED_DIR / "wild_pool.parquet", index=False)

    with open(PROCESSED_DIR / "active_classes.json", "w") as f:
        json.dump({"active": active, "inactive": inactive}, f, indent=2)
    with open(PROCESSED_DIR / "class_weights.json", "w") as f:
        json.dump(class_weights, f, indent=2)

    summary = build_summary(curated_folds, wild_norm, active, inactive, class_weights, K_FOLDS)
    with open(PROCESSED_DIR / "cv_split_summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    (PROCESSED_DIR / "cv_split_report.md").write_text(build_markdown_report(summary), encoding="utf-8")

    print(f"\n[ok] curated_folds.parquet   : {len(curated_folds):,} kontrak (dengan kolom 'fold')")
    print(f"[ok] wild_pool.parquet       : {len(wild_norm):,} kontrak (always in training)")
    print(f"[ok] active_classes.json     : {PROCESSED_DIR / 'active_classes.json'}")
    print(f"[ok] class_weights.json      : {PROCESSED_DIR / 'class_weights.json'}")
    print(f"[ok] cv_split_summary.json   : {PROCESSED_DIR / 'cv_split_summary.json'}")
    print(f"[ok] cv_split_report.md      : {PROCESSED_DIR / 'cv_split_report.md'}")

    print_summary(summary)


if __name__ == "__main__":
    main()
