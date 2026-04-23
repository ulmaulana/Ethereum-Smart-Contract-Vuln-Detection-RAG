"""
Stage 6: Comprehensive Evaluation
  - Function-level metrics (sudah ada di metrics_per_fold.json)
  - Contract-level metrics via aggregation (any function positive -> contract positive)
  - Per-class threshold tuning (find optimal threshold via OOF predictions)
  - Comparison vs 9 SmartBugs tools baseline (di Curated)

Output:
  processed/contract_level_predictions.parquet
  processed/contract_level_metrics.json
  processed/threshold_tuning.json
  processed/baseline_comparison.json
  processed/evaluation_report.md
"""
import json
import sys
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.config import (
    PROCESSED_DIR, VULN_CATEGORIES, RESULTS_CURATED_JSON, RESULTS_CATEGORY_MAP
)


# =====================================================================
# Contract-level aggregation
# =====================================================================

def aggregate_to_contract(pred_df: pd.DataFrame, active: list[str]) -> pd.DataFrame:
    """
    Agregasi prediksi function-level -> contract-level.
    contract_pred[cls] = 1 jika ada function dgn pred=1 untuk cls
    contract_proba[cls] = max proba semua function

    Catatan: untuk class yang di-skip di suatu fold (n_train_pos < 10 di Stage 5),
    kolom prediksinya NaN. Kita treat sebagai 0 (model tidak prediksi positif).
    Truth tetap diambil dari curated_folds.parquet di attach_contract_truth().
    """
    rows = []
    for (fold, contract_id), group in pred_df.groupby(["fold", "contract_id"]):
        row = {"fold": int(fold), "contract_id": contract_id, "n_functions": len(group)}
        for cls in active:
            true_col, pred_col, proba_col = f"{cls}_true", f"{cls}_pred", f"{cls}_proba"
            if pred_col not in group.columns:
                # Class tidak pernah ditrain di fold manapun (jarang kejadian)
                row[f"{cls}_true"] = 0
                row[f"{cls}_pred"] = 0
                row[f"{cls}_proba_max"] = 0.0
                continue
            # Handle NaN: class di-skip di fold ini
            true_max = group[true_col].max()
            pred_max = group[pred_col].max()
            proba_max = group[proba_col].max()
            row[f"{cls}_true"] = int(true_max) if pd.notna(true_max) else 0
            row[f"{cls}_pred"] = int(pred_max) if pd.notna(pred_max) else 0
            row[f"{cls}_proba_max"] = float(proba_max) if pd.notna(proba_max) else 0.0
        rows.append(row)
    return pd.DataFrame(rows)


def attach_contract_truth(contract_df: pd.DataFrame, active: list[str]) -> pd.DataFrame:
    """
    Override per-class true dengan label kontrak GOLD dari curated_folds.parquet.

    Catatan: beberapa file .sol di Curated muncul di multiple kategori (mis. file yg
    sama di-tag access_control dan reentrancy). Untuk handle ini, agregasi via max()
    -> kontrak punya label = 1 kalau ada di salah satu entri.
    """
    curated_folds = pd.read_parquet(PROCESSED_DIR / "curated_folds.parquet")
    # Agregasi: kalau contract_id duplikat, OR semua label-nya
    truth_aggregated = curated_folds.groupby("contract_id")[VULN_CATEGORIES].max()
    truth_map = truth_aggregated.to_dict("index")

    contract_df = contract_df.copy()
    for cls in active:
        col = f"{cls}_true"
        if col not in contract_df.columns:
            contract_df[col] = 0
        contract_df[col] = contract_df["contract_id"].map(
            lambda cid: int(truth_map.get(cid, {}).get(cls, 0))
        )
    return contract_df


def compute_contract_metrics(contract_df: pd.DataFrame, active: list[str]) -> dict:
    """Per-class P/R/F1/Acc + macro F1 di contract level."""
    metrics = {}
    f1s = []
    for cls in active:
        true_col, pred_col = f"{cls}_true", f"{cls}_pred"
        if true_col not in contract_df.columns or pred_col not in contract_df.columns:
            continue
        y_true = contract_df[true_col].values
        y_pred = contract_df[pred_col].values
        n_pos = int(y_true.sum())
        if n_pos == 0:
            continue
        f1 = f1_score(y_true, y_pred, zero_division=0)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        acc = accuracy_score(y_true, y_pred)
        metrics[cls] = {
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "accuracy": round(acc, 4),
            "n_pos": n_pos,
            "n_total": len(y_true),
        }
        f1s.append(f1)
    metrics["__macro_f1__"] = round(float(np.mean(f1s)), 4) if f1s else 0.0
    return metrics


# =====================================================================
# Threshold tuning per class (cari threshold optimal dari OOF predictions)
# =====================================================================

def tune_thresholds_contract(contract_df: pd.DataFrame, active: list[str]) -> dict:
    """Cari threshold (atas proba_max) yang maximize F1 per class."""
    tuned = {}
    thresholds = np.arange(0.05, 0.96, 0.05)
    for cls in active:
        true_col, proba_col = f"{cls}_true", f"{cls}_proba_max"
        if true_col not in contract_df.columns or proba_col not in contract_df.columns:
            continue
        y_true = contract_df[true_col].values
        proba = contract_df[proba_col].values
        if y_true.sum() == 0:
            continue

        best_f1 = -1
        best_t = 0.5
        for t in thresholds:
            y_pred = (proba >= t).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = float(t)
        tuned[cls] = {"best_threshold": round(best_t, 2), "best_f1": round(best_f1, 4)}
    return tuned


def apply_tuned_thresholds(contract_df: pd.DataFrame, tuned: dict, active: list[str]) -> pd.DataFrame:
    df = contract_df.copy()
    for cls in active:
        if cls not in tuned:
            continue
        t = tuned[cls]["best_threshold"]
        df[f"{cls}_pred"] = (df[f"{cls}_proba_max"] >= t).astype(int)
    return df


# =====================================================================
# Baseline: 9 SmartBugs Tools
# =====================================================================

def load_curated_tool_results() -> dict:
    """Load results_curated.json (agregat 9 tools per kontrak)."""
    if not RESULTS_CURATED_JSON.exists():
        return {}
    with open(RESULTS_CURATED_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def baseline_tool_predictions(curated_folds: pd.DataFrame, active: list[str]) -> dict:
    """
    Untuk tiap kontrak Curated, hitung prediksi tiap tool berdasarkan results_curated.json.
    Tool detect class X jika tool report kategori X di kontrak tsb.

    Return: {tool_name: DataFrame[contract_id, {cls}_pred for cls in active]}
    """
    tool_results = load_curated_tool_results()
    if not tool_results:
        return {}

    # Map nama kontrak Curated (file name) ke key di results_curated.json
    # File name: "FibonacciBalance.sol" -> key di JSON: "FibonacciBalance"
    name_map = {row["contract_id"]: row["contract_id"].replace(".sol", "")
                for _, row in curated_folds.iterrows()}

    tool_names = ["mythril", "slither", "oyente", "osiris", "smartcheck",
                  "manticore", "maian", "securify", "honeybadger"]

    out = {}
    for tool in tool_names:
        rows = []
        for _, contract_row in curated_folds.iterrows():
            contract_id = contract_row["contract_id"]
            jkey_short = contract_id.replace(".sol", "")
            jdata = tool_results.get(jkey_short) or tool_results.get(contract_id)
            row = {"contract_id": contract_id}
            cats = {}
            if jdata:
                tool_data = jdata.get("tools", {}).get(tool, {})
                cats = tool_data.get("categories", {}) or {}
            for cls in active:
                # Map active class -> raw kategori name di JSON
                # RESULTS_CATEGORY_MAP: {raw -> std}, kita butuh inverse
                detected = 0
                for raw_cat, std_cat in RESULTS_CATEGORY_MAP.items():
                    if std_cat == cls and raw_cat in cats:
                        detected = 1
                        break
                row[f"{cls}_pred"] = detected
            rows.append(row)
        out[tool] = pd.DataFrame(rows)
    return out


def evaluate_baseline_tools(curated_folds: pd.DataFrame, active: list[str]) -> dict:
    """Compute F1/P/R per (tool, class) di Curated full.

    Dedup contract_id (file yg sama di-tag multiple kategori): agregasi via OR (max).
    """
    tool_preds = baseline_tool_predictions(curated_folds, active)
    # Dedup truth: kalau contract_id duplikat -> OR semua label-nya
    truth = curated_folds.groupby("contract_id")[VULN_CATEGORIES].max()

    out = {}
    for tool, pred_df in tool_preds.items():
        tool_metrics = {}
        f1s = []
        # Dedup predictions juga (mungkin ada duplikat dari iterrows)
        pred_df = pred_df.groupby("contract_id").max()
        # Align truth & pred via index intersection
        common_idx = truth.index.intersection(pred_df.index)
        truth_aligned = truth.loc[common_idx]
        pred_aligned = pred_df.loc[common_idx]
        for cls in active:
            y_true = truth_aligned[cls].values
            y_pred = pred_aligned[f"{cls}_pred"].values
            if y_true.sum() == 0:
                continue
            f1 = f1_score(y_true, y_pred, zero_division=0)
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            tool_metrics[cls] = {"f1": round(f1, 4), "precision": round(prec, 4),
                                  "recall": round(rec, 4)}
            f1s.append(f1)
        tool_metrics["__macro_f1__"] = round(float(np.mean(f1s)), 4) if f1s else 0.0
        out[tool] = tool_metrics
    return out


# =====================================================================
# Reporting
# =====================================================================

def build_markdown_report(
    fn_metrics: dict, contract_metrics: dict, contract_metrics_tuned: dict,
    baseline: dict, tuned_thresholds: dict, active: list[str]
) -> str:
    lines = ["# Stage 6: Comprehensive Evaluation Report\n"]

    # Function vs Contract level comparison
    lines.append("## Function-Level vs Contract-Level F1 Comparison\n")
    lines.append("| Class | Function-Level F1 | Contract-Level F1 | Contract+TunedThr F1 |")
    lines.append("|-------|-------------------|-------------------|----------------------|")
    for cls in active:
        fn_f1 = fn_metrics.get(cls, {}).get("f1", {}).get("mean", "-")
        cn_f1 = contract_metrics.get(cls, {}).get("f1", "-")
        ct_f1 = contract_metrics_tuned.get(cls, {}).get("f1", "-")
        lines.append(f"| {cls} | "
                     f"{fn_f1 if fn_f1 == '-' else f'{fn_f1:.3f}'} | "
                     f"{cn_f1 if cn_f1 == '-' else f'{cn_f1:.3f}'} | "
                     f"{ct_f1 if ct_f1 == '-' else f'{ct_f1:.3f}'} |")
    fn_macro = fn_metrics.get("__macro_f1__", {}).get("mean", "-")
    lines.append(f"| **MACRO** | "
                 f"**{fn_macro if fn_macro == '-' else f'{fn_macro:.3f}'}** | "
                 f"**{contract_metrics.get('__macro_f1__', '-'):.3f}** | "
                 f"**{contract_metrics_tuned.get('__macro_f1__', '-'):.3f}** |")

    # Tuned thresholds
    lines.append("\n## Tuned Thresholds per Class\n")
    lines.append("| Class | Best Threshold | F1 at Threshold |")
    lines.append("|-------|----------------|-----------------|")
    for cls in active:
        if cls in tuned_thresholds:
            t = tuned_thresholds[cls]
            lines.append(f"| {cls} | {t['best_threshold']} | {t['best_f1']:.3f} |")

    # Comparison vs baseline tools
    lines.append("\n## Comparison vs SmartBugs 9 Tools (Contract-Level F1 di Curated)\n")
    lines.append("| Class | Our Model | " + " | ".join(baseline.keys()) + " |")
    lines.append("|-------|-----------|" + "|".join(["---"] * len(baseline)) + "|")
    for cls in active:
        our = contract_metrics_tuned.get(cls, {}).get("f1", "-")
        cells = [f"{our:.3f}" if isinstance(our, float) else "-"]
        for tool, tool_m in baseline.items():
            f1 = tool_m.get(cls, {}).get("f1", "-")
            cells.append(f"{f1:.3f}" if isinstance(f1, float) else "-")
        lines.append(f"| {cls} | " + " | ".join(cells) + " |")

    our_macro = contract_metrics_tuned.get("__macro_f1__", 0)
    our_macro_str = f"{our_macro:.3f}" if isinstance(our_macro, float) else str(our_macro)
    baseline_strs = [f"{baseline[t].get('__macro_f1__', 0):.3f}" for t in baseline]
    lines.append(f"| **MACRO F1** | **{our_macro_str}** | " + " | ".join(baseline_strs) + " |")

    return "\n".join(lines)


# =====================================================================
# Main
# =====================================================================

def main():
    print(">>> Stage 6: Comprehensive Evaluation\n")

    # Load Stage 5 outputs
    pred_df = pd.read_parquet(PROCESSED_DIR / "predictions_function_level.parquet")
    with open(PROCESSED_DIR / "metrics_aggregated.json") as f:
        fn_metrics = json.load(f)
    with open(PROCESSED_DIR / "active_classes.json") as f:
        active = json.load(f)["active"]

    print(f"[ok] Function-level predictions: {len(pred_df):,} rows")
    print(f"[ok] Active classes: {active}")

    # === Step 1: Contract-level aggregation (default threshold 0.5) ===
    print("\n[..] Aggregating predictions to contract level (threshold=0.5)...")
    contract_df = aggregate_to_contract(pred_df, active)
    contract_df = attach_contract_truth(contract_df, active)
    contract_metrics = compute_contract_metrics(contract_df, active)

    # === Step 2: Threshold tuning ===
    print("[..] Tuning per-class threshold (maximize F1)...")
    tuned = tune_thresholds_contract(contract_df, active)
    contract_df_tuned = apply_tuned_thresholds(contract_df, tuned, active)
    contract_metrics_tuned = compute_contract_metrics(contract_df_tuned, active)

    # === Step 3: Baseline 9 tools ===
    print("[..] Computing baseline metrics for 9 SmartBugs tools...")
    curated_folds = pd.read_parquet(PROCESSED_DIR / "curated_folds.parquet")
    baseline = evaluate_baseline_tools(curated_folds, active)

    # === Save ===
    contract_df_tuned.to_parquet(PROCESSED_DIR / "contract_level_predictions.parquet", index=False)
    with open(PROCESSED_DIR / "contract_level_metrics.json", "w") as f:
        json.dump({
            "default_threshold_0.5": contract_metrics,
            "tuned_threshold": contract_metrics_tuned,
        }, f, indent=2)
    with open(PROCESSED_DIR / "threshold_tuning.json", "w") as f:
        json.dump(tuned, f, indent=2)
    with open(PROCESSED_DIR / "baseline_comparison.json", "w") as f:
        json.dump(baseline, f, indent=2)
    md = build_markdown_report(fn_metrics, contract_metrics, contract_metrics_tuned,
                                baseline, tuned, active)
    (PROCESSED_DIR / "evaluation_report.md").write_text(md, encoding="utf-8")

    # === Print comparison ===
    print("\n" + "=" * 95)
    print("EVALUATION COMPARISON (Function vs Contract level + vs 9 Tools)")
    print("=" * 95)
    print(f"{'Class':<28s} {'FnLvl F1':>9s} {'CntrLvl F1':>11s} {'CntrTuned F1':>13s} "
          f"{'Slither':>8s} {'Mythril':>8s} {'Oyente':>8s}")
    print("-" * 95)
    for cls in active:
        fn_f1 = fn_metrics.get(cls, {}).get("f1", {}).get("mean", 0)
        cn_f1 = contract_metrics.get(cls, {}).get("f1", 0)
        ct_f1 = contract_metrics_tuned.get(cls, {}).get("f1", 0)
        sl_f1 = baseline.get("slither", {}).get(cls, {}).get("f1", 0)
        my_f1 = baseline.get("mythril", {}).get(cls, {}).get("f1", 0)
        oy_f1 = baseline.get("oyente", {}).get(cls, {}).get("f1", 0)
        print(f"{cls:<28s} {fn_f1:>9.3f} {cn_f1:>11.3f} {ct_f1:>13.3f} "
              f"{sl_f1:>8.3f} {my_f1:>8.3f} {oy_f1:>8.3f}")
    print("-" * 95)
    fn_mac = fn_metrics.get("__macro_f1__", {}).get("mean", 0)
    cn_mac = contract_metrics.get("__macro_f1__", 0)
    ct_mac = contract_metrics_tuned.get("__macro_f1__", 0)
    sl_mac = baseline.get("slither", {}).get("__macro_f1__", 0)
    my_mac = baseline.get("mythril", {}).get("__macro_f1__", 0)
    oy_mac = baseline.get("oyente", {}).get("__macro_f1__", 0)
    print(f"{'MACRO F1':<28s} {fn_mac:>9.3f} {cn_mac:>11.3f} {ct_mac:>13.3f} "
          f"{sl_mac:>8.3f} {my_mac:>8.3f} {oy_mac:>8.3f}")

    print(f"\n[ok] contract_level_predictions.parquet : {len(contract_df_tuned)} rows")
    print(f"[ok] contract_level_metrics.json")
    print(f"[ok] threshold_tuning.json")
    print(f"[ok] baseline_comparison.json")
    print(f"[ok] evaluation_report.md")


if __name__ == "__main__":
    main()
