"""
Stage 5 v2: XGBoost Training dengan 5-Fold CV + Label Refinement.

Fix dari v1:
  1. WILD label refinement per class:
     Function silver-positive hanya dipertahankan kalau punya pattern relevan.
     Contoh: reentrancy butuh `.call`/`.send`/`.transfer` di function body.
     Ini menghilangkan ~80% false positive di Wild silver labels (yang inherited dari kontrak).

  2. scale_pos_weight di-compute per fold per class dari TRAIN data aktual,
     dan di-cap di MAX_SPW (default 10) supaya tidak terlalu agresif.

  3. Threshold default 0.5, tapi bisa di-tune nanti per class.

Pipeline per fold:
  1. Train: Curated (fold != i) + Wild refined
  2. Test : Curated (fold == i)  -- gold labels, akurat
  3. Fit TF-IDF di TRAIN saja (no leakage)
  4. Train XGBoost binary per active class

Output:
  models/xgb/fold_{i}_{class}.pkl
  models/tfidf/fold_{i}.pkl
  processed/predictions_function_level.parquet
  processed/metrics_per_fold.json
  processed/metrics_aggregated.json
  processed/training_report.md
"""
import json
import sys
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    f1_score, precision_score, recall_score, accuracy_score,
)
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.config import PROCESSED_DIR, RANDOM_STATE

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)
(MODELS_DIR / "xgb").mkdir(exist_ok=True)
(MODELS_DIR / "tfidf").mkdir(exist_ok=True)

K_FOLDS = 5

TFIDF_MAX_FEATURES = 5000
TFIDF_NGRAM_RANGE = (1, 2)

MAX_SPW = 5.0   # cap scale_pos_weight, lebih konservatif
PRED_THRESHOLD = 0.5  # standard threshold; per-class tuning ada di Stage 6

XGB_PARAMS = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "n_estimators": 300,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 3,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
    "tree_method": "hist",
    "verbosity": 0,
}


# =====================================================================
# Label Refinement (KEY FIX)
# =====================================================================

def compute_relevance_masks(df: pd.DataFrame) -> dict:
    """
    Vectorized: untuk tiap class, mask boolean apakah function itu RELEVAN
    (punya pattern yang konsisten dengan class tsb).
    Function yang silver-positive tapi NOT relevant = false positive noise -> harus di-flip ke 0.
    """
    arith_ops = (df["hc_count_plus_eq"] + df["hc_count_minus_eq"]
                 + df["hc_count_mul_eq"] + df["hc_count_div_eq"])
    extcalls = (df["hc_count_external_calls"] > 0) | (df["hc_has_delegatecall"] > 0)
    return {
        "reentrancy": extcalls,
        "access_control": (
            (df["hc_uses_tx_origin"] > 0)
            | (df["hc_has_owner_check"] > 0)
            | (df["hc_has_selfdestruct"] > 0)
            | (df["hc_has_delegatecall"] > 0)
        ),
        "arithmetic": (arith_ops > 0) & (df["hc_uses_safemath"] == 0),
        "time_manipulation": (df["hc_uses_block_timestamp"] > 0)
                              | (df["hc_uses_block_number"] > 0),
        "bad_randomness": (df["hc_uses_blockhash"] > 0)
                           | (df["hc_uses_block_difficulty"] > 0)
                           | (df["hc_uses_block_coinbase"] > 0)
                           | (df["hc_uses_block_number"] > 0),
        "unchecked_low_level_calls": (
            (df["hc_has_call_value"] > 0)
            | (df["hc_has_send"] > 0)
            | (df["hc_has_call_legacy"] > 0)
            | (df["hc_has_call_brace"] > 0)
        ),
        "denial_of_service": (df["hc_count_for"] > 0) | (df["hc_count_while"] > 0)
                              | (df["hc_count_external_calls"] > 0),
        "front_running": extcalls,
    }


def compute_safety_masks(df: pd.DataFrame) -> dict:
    """
    Mask boolean: function memiliki pola AMAN yang membuktikan TIDAK punya vuln.
    Kalau silver label = 1 tapi function ada di safety mask -> kemungkinan besar
    false positive (mis. arithmetic dengan SafeMath = aman).
    """
    is_solidity_08_plus = (df["hc_pragma_major"] >= 1) | (
        (df["hc_pragma_major"] == 0) & (df["hc_pragma_minor"] >= 8)
    )
    return {
        # Solidity 0.8+ punya built-in overflow check, atau pakai SafeMath
        "arithmetic": is_solidity_08_plus | (df["hc_uses_safemath"] == 1),
        # nonReentrant modifier = anti-reentrancy guard
        "reentrancy": (df["hc_uses_nonreentrant"] == 1),
        # Owner check yg proper = bukan access_control vuln
        "access_control": (
            (df["hc_has_owner_check"] == 1)
            & (df["hc_uses_tx_origin"] == 0)  # tx.origin tetap vuln
        ),
        # send/transfer dengan limit gas = aman dari unchecked
        "unchecked_low_level_calls": (
            (df["hc_has_transfer"] == 1)
            & (df["hc_has_call_value"] == 0)
            & (df["hc_has_call_legacy"] == 0)
        ),
    }


def refine_wild_labels(df: pd.DataFrame, active: list[str]) -> pd.DataFrame:
    """
    Dua-tahap pembersihan label silver di Wild:
      1. POSITIVE filter: function silver-positive harus punya pattern RELEVAN
         (kalau tidak -> false positive dari inheritance)
      2. SAFETY filter: function silver-positive yang punya pola AMAN -> negatif
         (mis. arithmetic dengan SafeMath, reentrancy dengan nonReentrant)

    Curated labels (gold) TIDAK diubah.
    """
    df = df.copy()
    is_wild = df["source"] == "wild"
    relevance = compute_relevance_masks(df)
    safety = compute_safety_masks(df)

    print("\n[..] Refining Wild silver labels (positive + safety filters):")
    print(f"     {'Class':<30s} {'before':>7s}  {'after_rel':>10s}  {'after_safe':>11s}  {'flipped':>8s}")
    print("     " + "-" * 70)
    total_changed = 0
    for cls in active:
        before = int(((df[cls] == 1) & is_wild).sum())

        # Tahap 1: positive filter (relevance)
        if cls in relevance:
            mask_rel = is_wild & (df[cls] == 1) & (~relevance[cls])
            df.loc[mask_rel, cls] = 0
        after_rel = int(((df[cls] == 1) & is_wild).sum())

        # Tahap 2: safety filter
        if cls in safety:
            mask_safe = is_wild & (df[cls] == 1) & safety[cls]
            df.loc[mask_safe, cls] = 0
        after_safe = int(((df[cls] == 1) & is_wild).sum())

        flipped = before - after_safe
        total_changed += flipped
        print(f"     {cls:<30s} {before:>7,}  {after_rel:>10,}  {after_safe:>11,}  {flipped:>8,}")
    print(f"     TOTAL labels flipped: {total_changed:,}")
    return df


# =====================================================================
# Load + helpers
# =====================================================================

def load_data():
    # Pakai v2 (dengan tool + rule features) kalau ada, fallback ke v1
    v2 = PROCESSED_DIR / "sampled_functions_v2.parquet"
    v1 = PROCESSED_DIR / "sampled_functions.parquet"
    path = v2 if v2.exists() else v1
    df = pd.read_parquet(path)
    print(f"[ok] Using dataset: {path.name}")
    with open(PROCESSED_DIR / "active_classes.json") as f:
        active = json.load(f)["active"]
    return df, active


def split_train_test_by_fold(df: pd.DataFrame, fold: int):
    is_curated = df["source"] == "curated"
    test_df = df[is_curated & (df["fold"] == fold)].reset_index(drop=True)
    train_df = df[(~is_curated) | (df["fold"] != fold)].reset_index(drop=True)
    return train_df, test_df


def build_feature_matrix(df, numeric_cols, tfidf):
    """Stack numeric features (hc + tool + rule) + TF-IDF -> sparse matrix."""
    num = csr_matrix(df[numeric_cols].values.astype(np.float32))
    tf = tfidf.transform(df["function_source"].fillna("").tolist())
    return hstack([num, tf]).tocsr()


def adaptive_spw(y_train: np.ndarray) -> float:
    n_pos = y_train.sum()
    n_neg = len(y_train) - n_pos
    if n_pos == 0:
        return 1.0
    spw = n_neg / n_pos
    return float(min(spw, MAX_SPW))


# =====================================================================
# Per-fold
# =====================================================================

def train_fold(fold_id, df, active, numeric_cols):
    print(f"\n========================== FOLD {fold_id} ==========================")
    train_df, test_df = split_train_test_by_fold(df, fold_id)
    print(f"  Train: {len(train_df):,}  (curated: {(train_df['source']=='curated').sum()}, "
          f"wild: {(train_df['source']=='wild').sum()})")
    print(f"  Test : {len(test_df):,}  (Curated gold)")

    print(f"  [..] Fitting TF-IDF (max {TFIDF_MAX_FEATURES} features, ngram {TFIDF_NGRAM_RANGE})")
    tfidf = TfidfVectorizer(
        max_features=TFIDF_MAX_FEATURES,
        ngram_range=TFIDF_NGRAM_RANGE,
        token_pattern=r"\b\w+\b",
        lowercase=False,
        min_df=3,
        max_df=0.95,
    )
    tfidf.fit(train_df["function_source"].fillna("").tolist())
    joblib.dump(tfidf, MODELS_DIR / "tfidf" / f"fold_{fold_id}.pkl")

    print(f"  [..] Building feature matrix ({len(numeric_cols)} numeric + TF-IDF)...")
    X_train = build_feature_matrix(train_df, numeric_cols, tfidf)
    X_test = build_feature_matrix(test_df, numeric_cols, tfidf)
    print(f"     X_train: {X_train.shape}  X_test: {X_test.shape}")

    fold_metrics = {}
    fold_predictions = {}
    for cls in active:
        y_train = train_df[cls].values
        y_test = test_df[cls].values

        n_train_pos = int(y_train.sum())
        n_test_pos = int(y_test.sum())

        if n_train_pos < 10:
            print(f"  [skip] {cls:30s}: only {n_train_pos} positives in train")
            continue
        if n_test_pos == 0:
            print(f"  [skip] {cls:30s}: 0 positives in test (cannot evaluate)")
            continue

        spw = adaptive_spw(y_train)
        params = {**XGB_PARAMS, "scale_pos_weight": spw}
        model = xgb.XGBClassifier(**params)
        model.fit(X_train, y_train, verbose=False)
        joblib.dump(model, MODELS_DIR / "xgb" / f"fold_{fold_id}_{cls}.pkl")

        y_proba = model.predict_proba(X_test)[:, 1]
        y_pred = (y_proba >= PRED_THRESHOLD).astype(int)
        fold_predictions[cls] = {"y_true": y_test.tolist(),
                                  "y_pred": y_pred.tolist(),
                                  "y_proba": y_proba.tolist()}

        f1 = f1_score(y_test, y_pred, zero_division=0)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        acc = accuracy_score(y_test, y_pred)

        fold_metrics[cls] = {
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "accuracy": round(acc, 4),
            "scale_pos_weight": round(spw, 2),
            "n_train_pos": n_train_pos,
            "n_test_pos": n_test_pos,
            "n_test_total": len(y_test),
        }
        print(f"     {cls:30s}: F1={f1:.3f}  P={prec:.3f}  R={rec:.3f}  Acc={acc:.3f}  "
              f"(train_pos={n_train_pos:,}, test_pos={n_test_pos}/{len(y_test)}, spw={spw:.1f})")

    return {
        "fold": fold_id,
        "n_train": len(train_df),
        "n_test": len(test_df),
        "metrics": fold_metrics,
        "predictions": fold_predictions,
        "test_meta": {
            "contract_id": test_df["contract_id"].tolist(),
            "function_name": test_df["function_name"].tolist(),
        },
    }


# =====================================================================
# Aggregation
# =====================================================================

def aggregate_metrics(fold_results, active):
    agg = {}
    for cls in active:
        scores = defaultdict(list)
        for fr in fold_results:
            m = fr["metrics"].get(cls)
            if m is None:
                continue
            for k in ["f1", "precision", "recall", "accuracy"]:
                scores[k].append(m[k])
        if not scores:
            continue
        agg[cls] = {
            k: {"mean": round(float(np.mean(v)), 4),
                "std": round(float(np.std(v)), 4)}
            for k, v in scores.items()
        }
    macro_f1_per_fold = []
    for fr in fold_results:
        f1s = [fr["metrics"][c]["f1"] for c in active if c in fr["metrics"]]
        if f1s:
            macro_f1_per_fold.append(np.mean(f1s))
    agg["__macro_f1__"] = {
        "mean": round(float(np.mean(macro_f1_per_fold)), 4) if macro_f1_per_fold else 0.0,
        "std": round(float(np.std(macro_f1_per_fold)), 4) if macro_f1_per_fold else 0.0,
    }
    return agg


def build_predictions_dataframe(fold_results, active):
    rows = []
    for fr in fold_results:
        meta = fr["test_meta"]
        for i in range(fr["n_test"]):
            row = {"fold": fr["fold"],
                   "contract_id": meta["contract_id"][i],
                   "function_name": meta["function_name"][i]}
            for cls in active:
                if cls in fr["predictions"]:
                    row[f"{cls}_true"] = fr["predictions"][cls]["y_true"][i]
                    row[f"{cls}_pred"] = fr["predictions"][cls]["y_pred"][i]
                    row[f"{cls}_proba"] = fr["predictions"][cls]["y_proba"][i]
            rows.append(row)
    return pd.DataFrame(rows)


def build_markdown_report(agg, fold_results, active) -> str:
    lines = ["# Stage 5 v2: XGBoost Training Report (5-Fold CV + Label Refinement)\n"]
    lines.append(f"- Folds: {K_FOLDS}, Active classes: {len(active)}")
    lines.append(f"- Models trained: {sum(len(fr['metrics']) for fr in fold_results)}")
    lines.append(f"- TF-IDF: max_features={TFIDF_MAX_FEATURES}, ngram={TFIDF_NGRAM_RANGE}")
    lines.append(f"- XGBoost: n_est={XGB_PARAMS['n_estimators']}, "
                 f"depth={XGB_PARAMS['max_depth']}, max_spw={MAX_SPW}\n")

    lines.append("\n## Aggregated Metrics (Mean ± Std across 5 Folds)\n")
    lines.append("| Class | F1 | Precision | Recall | Accuracy |")
    lines.append("|-------|----|-----------|--------|----------|")
    for cls in active:
        if cls not in agg:
            continue
        m = agg[cls]
        lines.append(f"| {cls} | {m['f1']['mean']:.3f} ± {m['f1']['std']:.3f} | "
                     f"{m['precision']['mean']:.3f} ± {m['precision']['std']:.3f} | "
                     f"{m['recall']['mean']:.3f} ± {m['recall']['std']:.3f} | "
                     f"{m['accuracy']['mean']:.3f} ± {m['accuracy']['std']:.3f} |")
    macro = agg["__macro_f1__"]
    lines.append(f"| **MACRO F1** | **{macro['mean']:.3f} ± {macro['std']:.3f}** | - | - | - |")

    lines.append("\n## Per-Fold F1 Score\n")
    header = "| Class | " + " | ".join([f"Fold {f['fold']}" for f in fold_results]) + " |"
    sep = "|-------|" + "|".join(["------" for _ in fold_results]) + "|"
    lines.append(header)
    lines.append(sep)
    for cls in active:
        if cls not in agg:
            continue
        cells = []
        for fr in fold_results:
            f1 = fr["metrics"].get(cls, {}).get("f1", "-")
            cells.append(f"{f1:.3f}" if isinstance(f1, float) else "-")
        lines.append(f"| {cls} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    print(">>> Stage 5 v3: XGBoost Training + 5-Fold CV + ALL FEATURES\n")
    df, active = load_data()
    print(f"[ok] Loaded {len(df):,} functions")
    print(f"[ok] Active classes: {active}")

    # Numeric feature columns (handcrafted + tool + rule kalau ada)
    hc_cols = [c for c in df.columns if c.startswith("hc_")]
    tool_cols = [c for c in df.columns if c.startswith("tool_")]
    rule_cols = [c for c in df.columns if c.startswith("rule_")]
    numeric_cols = hc_cols + tool_cols + rule_cols
    print(f"[ok] Hand-crafted features  : {len(hc_cols)}")
    print(f"[ok] Tool features          : {len(tool_cols)}")
    print(f"[ok] Rule features          : {len(rule_cols)}")
    print(f"[ok] TOTAL numeric features : {len(numeric_cols)}")
    print(f"[ok] Plus TF-IDF (~{TFIDF_MAX_FEATURES} features)")

    # KEY FIX: refine wild labels
    df = refine_wild_labels(df, active)

    fold_results = []
    for fold_id in range(K_FOLDS):
        fold_results.append(train_fold(fold_id, df, active, numeric_cols))

    print("\n========================== AGGREGATING ==========================")
    agg = aggregate_metrics(fold_results, active)

    pred_df = build_predictions_dataframe(fold_results, active)
    pred_df.to_parquet(PROCESSED_DIR / "predictions_function_level.parquet", index=False)

    metrics_per_fold = {}
    for fr in fold_results:
        metrics_per_fold[f"fold_{fr['fold']}"] = {
            "n_train": fr["n_train"],
            "n_test": fr["n_test"],
            "metrics": fr["metrics"],
        }
    with open(PROCESSED_DIR / "metrics_per_fold.json", "w") as f:
        json.dump(metrics_per_fold, f, indent=2)
    with open(PROCESSED_DIR / "metrics_aggregated.json", "w") as f:
        json.dump(agg, f, indent=2)
    (PROCESSED_DIR / "training_report.md").write_text(
        build_markdown_report(agg, fold_results, active), encoding="utf-8")

    print("\n" + "=" * 78)
    print("STAGE 5 v2 SUMMARY — AGGREGATED ACROSS 5 FOLDS")
    print("=" * 78)
    print(f"{'Class':<30s} {'F1 (mean ± std)':<20s} {'Precision':<12s} {'Recall':<12s}")
    print("-" * 80)
    for cls in active:
        if cls not in agg:
            continue
        m = agg[cls]
        print(f"{cls:<30s} {m['f1']['mean']:.3f} ± {m['f1']['std']:.3f}      "
              f"{m['precision']['mean']:.3f}        "
              f"{m['recall']['mean']:.3f}")
    macro = agg["__macro_f1__"]
    print("-" * 80)
    print(f"{'MACRO F1':<30s} {macro['mean']:.3f} ± {macro['std']:.3f}")

    print(f"\n[ok] Models      : {MODELS_DIR}/xgb/, {MODELS_DIR}/tfidf/")
    print(f"[ok] Metrics     : processed/metrics_aggregated.json")
    print(f"[ok] Predictions : processed/predictions_function_level.parquet")
    print(f"[ok] Report      : processed/training_report.md")


if __name__ == "__main__":
    main()
