"""
Stage 6 dual-mode evaluation.

Outputs:
  processed/threshold_tuning_fast.json
  processed/threshold_tuning_deep.json
  processed/contract_level_metrics_fast.json
  processed/contract_level_metrics_deep.json
  processed/benchmark_metrics.json
  processed/product_readiness.json
  processed/ablation_report.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

SRC_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from src.api.schemas import ScanRequest
from src.api.service import scan_contract
from preprocessing.config import PROCESSED_DIR


ACTIVE_CLASSES = json.loads((PROCESSED_DIR / "active_classes.json").read_text(encoding="utf-8"))["active"]
CRITICAL_CLASSES = ["reentrancy", "access_control", "unchecked_low_level_calls"]
MODE_FILES = {
    "fast": {
        "metrics": PROCESSED_DIR / "metrics_fast_aggregated.json",
        "predictions": PROCESSED_DIR / "predictions_function_level_fast.parquet",
        "dataset": PROCESSED_DIR / "sampled_functions_fast.parquet",
    },
    "deep": {
        "metrics": PROCESSED_DIR / "metrics_deep_aggregated.json",
        "predictions": PROCESSED_DIR / "predictions_function_level_deep.parquet",
        "dataset": PROCESSED_DIR / "sampled_functions_deep.parquet",
    },
}
STRONG_RULE_COLUMNS = {
    "reentrancy": ["rule_reentrancy_strong"],
    "access_control": [
        "rule_access_control_tx_origin",
        "rule_access_control_no_modifier",
    ],
    "arithmetic": ["rule_arithmetic_pre08_no_safemath"],
    "unchecked_low_level_calls": ["rule_unchecked_call_value"],
}


def aggregate_to_contract(pred_df: pd.DataFrame, active: list[str], suffix: str) -> pd.DataFrame:
    rows = []
    for (fold, contract_id), group in pred_df.groupby(["fold", "contract_id"]):
        row = {"fold": int(fold), "contract_id": contract_id, "n_functions": len(group)}
        for vuln_class in active:
            true_col = f"{vuln_class}_true"
            pred_col = f"{vuln_class}_{suffix}"
            proba_col = f"{vuln_class}_proba"
            true_max = group[true_col].max() if true_col in group else 0
            pred_max = group[pred_col].max() if pred_col in group else 0
            proba_max = group[proba_col].max() if proba_col in group else 0.0
            row[f"{vuln_class}_true"] = int(true_max) if pd.notna(true_max) else 0
            row[f"{vuln_class}_pred"] = int(pred_max) if pd.notna(pred_max) else 0
            row[f"{vuln_class}_proba_max"] = (
                float(proba_max) if pd.notna(proba_max) else 0.0
            )
        rows.append(row)
    return pd.DataFrame(rows)


def compute_metrics(contract_df: pd.DataFrame, active: list[str]) -> dict:
    metrics = {}
    f1s = []
    for vuln_class in active:
        y_true = contract_df[f"{vuln_class}_true"].values
        y_pred = contract_df[f"{vuln_class}_pred"].values
        if y_true.sum() == 0:
            continue
        metrics[vuln_class] = {
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
        }
        f1s.append(metrics[vuln_class]["f1"])
    metrics["__macro_f1__"] = round(float(np.mean(f1s)), 4) if f1s else 0.0
    return metrics


def tune_thresholds(contract_df: pd.DataFrame, active: list[str]) -> dict:
    tuned = {}
    thresholds = np.arange(0.05, 0.96, 0.05)
    for vuln_class in active:
        y_true = contract_df[f"{vuln_class}_true"].values
        proba = contract_df[f"{vuln_class}_proba_max"].values
        if y_true.sum() == 0:
            continue
        best_f1 = -1.0
        best_threshold = 0.5
        for threshold in thresholds:
            y_pred = (proba >= threshold).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = float(threshold)
        tuned[vuln_class] = {
            "best_threshold": round(best_threshold, 2),
            "best_f1": round(best_f1, 4),
        }
    return tuned


def apply_tuned_thresholds(contract_df: pd.DataFrame, tuned: dict, active: list[str]) -> pd.DataFrame:
    tuned_df = contract_df.copy()
    for vuln_class in active:
        threshold = tuned.get(vuln_class, {}).get("best_threshold")
        if threshold is None:
            continue
        tuned_df[f"{vuln_class}_pred"] = (
            tuned_df[f"{vuln_class}_proba_max"] >= threshold
        ).astype(int)
    return tuned_df


def build_hybrid_signal_df(
    pred_df: pd.DataFrame,
    source_df: pd.DataFrame,
    tuned: dict,
    active: list[str],
) -> pd.DataFrame:
    join_cols = ["fold", "contract_id", "function_name"]
    rule_cols = sorted({column for cols in STRONG_RULE_COLUMNS.values() for column in cols})
    merged = pred_df.merge(
        source_df[join_cols + rule_cols].drop_duplicates(join_cols),
        on=join_cols,
        how="left",
    )

    for vuln_class in active:
        threshold = tuned.get(vuln_class, {}).get("best_threshold", 0.5)
        rule_hit = (
            merged[STRONG_RULE_COLUMNS.get(vuln_class, [])].max(axis=1)
            if STRONG_RULE_COLUMNS.get(vuln_class)
            else pd.Series(0, index=merged.index)
        )
        proba = merged[f"{vuln_class}_proba"].fillna(0.0)
        ml_detected = merged[f"{vuln_class}_pred"].fillna(0)
        hybrid_detected = (
            (ml_detected == 1)
            | ((rule_hit == 1) & (proba >= max(0.05, threshold * 0.6)))
        ).astype(int)
        hybrid_signal = ((hybrid_detected == 1) | (rule_hit == 1)).astype(int)
        merged[f"{vuln_class}_hybrid_detected"] = hybrid_detected
        merged[f"{vuln_class}_hybrid_signal"] = hybrid_signal

    return merged


def load_regression_manifest() -> list[dict]:
    return json.loads((PROCESSED_DIR / "regression_manifest.json").read_text(encoding="utf-8"))


def read_case_source(case: dict) -> str:
    if case["type"] == "inline":
        return case["source_code"]
    return Path(case["source_path"]).read_text(encoding="utf-8", errors="ignore")


def evaluate_regression_cases() -> dict:
    cases = load_regression_manifest()
    results = []

    for case in cases:
        source = read_case_source(case)
        request = ScanRequest(
            filename=case["filename"],
            source_code=source,
            options={
                "include_rag": False,
                "rag_provider": "minimax",
                "threshold_mode": "tuned",
                "scan_mode": "fast",
            },
        )
        response = scan_contract(request)
        flagged = sorted(
            vuln_class
            for vuln_class, prediction in response.predictions.items()
            if prediction.status != "clean"
        )
        expected = sorted(case["expected_classes"])
        missing = [vuln_class for vuln_class in expected if vuln_class not in flagged]
        unexpected = [vuln_class for vuln_class in flagged if vuln_class not in expected]
        results.append(
            {
                "id": case["id"],
                "name": case["name"],
                "expected_classes": expected,
                "flagged_classes": flagged,
                "missing_classes": missing,
                "unexpected_classes": unexpected,
                "passed": not missing,
            }
        )

    total_cases = len(results)
    passed_cases = sum(1 for result in results if result["passed"])
    critical_missing = sum(
        1
        for result in results
        for vuln_class in result["missing_classes"]
        if vuln_class in CRITICAL_CLASSES
    )

    return {
        "summary": {
            "total_cases": total_cases,
            "passed_cases": passed_cases,
            "pass_rate": round(passed_cases / total_cases, 4) if total_cases else 0.0,
            "critical_false_negatives": critical_missing,
        },
        "cases": results,
    }


def build_ablation_report(benchmark_metrics: dict, product_readiness: dict) -> str:
    lines = [
        "# Dual-mode Ablation Report",
        "",
        "| Experiment | Macro F1 | Notes |",
        "|------------|----------|-------|",
    ]
    for mode in ("fast", "deep"):
        benchmark = benchmark_metrics.get(mode, {})
        ml_only = benchmark.get("contract_tuned", {}).get("__macro_f1__", "-")
        hybrid_signal = benchmark.get("contract_hybrid_signal", {}).get("__macro_f1__", "-")
        lines.append(
            f"| {mode} ML-only tuned | {ml_only if isinstance(ml_only, str) else f'{ml_only:.3f}'} | Contract-level tuned threshold |"
        )
        lines.append(
            f"| {mode} hybrid signal | {hybrid_signal if isinstance(hybrid_signal, str) else f'{hybrid_signal:.3f}'} | Rule-assisted risk signal benchmark |"
        )
    summary = product_readiness["summary"]
    lines.append(
        f"| fast regression readiness | {summary['pass_rate']:.3f} | {summary['passed_cases']}/{summary['total_cases']} regression cases passed |"
    )
    return "\n".join(lines)


def evaluate_mode(mode: str) -> dict:
    metrics_path = MODE_FILES[mode]["metrics"]
    predictions_path = MODE_FILES[mode]["predictions"]
    dataset_path = MODE_FILES[mode]["dataset"]
    if not (metrics_path.exists() and predictions_path.exists() and dataset_path.exists()):
        return {}

    with open(metrics_path, encoding="utf-8") as handle:
        function_metrics = json.load(handle)
    pred_df = pd.read_parquet(predictions_path)
    source_df = pd.read_parquet(dataset_path)

    contract_df = aggregate_to_contract(pred_df, ACTIVE_CLASSES, "pred")
    tuned = tune_thresholds(contract_df, ACTIVE_CLASSES)
    tuned_contract_df = apply_tuned_thresholds(contract_df, tuned, ACTIVE_CLASSES)
    hybrid_df = build_hybrid_signal_df(pred_df, source_df, tuned, ACTIVE_CLASSES)
    hybrid_contract_df = aggregate_to_contract(hybrid_df, ACTIVE_CLASSES, "hybrid_signal")

    contract_metrics_default = compute_metrics(contract_df, ACTIVE_CLASSES)
    contract_metrics_tuned = compute_metrics(tuned_contract_df, ACTIVE_CLASSES)
    contract_metrics_hybrid = compute_metrics(hybrid_contract_df, ACTIVE_CLASSES)

    with open(PROCESSED_DIR / f"threshold_tuning_{mode}.json", "w", encoding="utf-8") as handle:
        json.dump(tuned, handle, indent=2)
    with open(PROCESSED_DIR / f"contract_level_metrics_{mode}.json", "w", encoding="utf-8") as handle:
        json.dump(
            {
                "default_threshold_0.5": contract_metrics_default,
                "tuned_threshold": contract_metrics_tuned,
                "hybrid_signal": contract_metrics_hybrid,
            },
            handle,
            indent=2,
        )

    return {
        "function_ml": function_metrics,
        "contract_default": contract_metrics_default,
        "contract_tuned": contract_metrics_tuned,
        "contract_hybrid_signal": contract_metrics_hybrid,
    }


def main() -> None:
    benchmark_metrics = {mode: evaluate_mode(mode) for mode in MODE_FILES}
    product_readiness = evaluate_regression_cases()

    with open(PROCESSED_DIR / "benchmark_metrics.json", "w", encoding="utf-8") as handle:
        json.dump(benchmark_metrics, handle, indent=2)
    with open(PROCESSED_DIR / "product_readiness.json", "w", encoding="utf-8") as handle:
        json.dump(product_readiness, handle, indent=2)
    (PROCESSED_DIR / "ablation_report.md").write_text(
        build_ablation_report(benchmark_metrics, product_readiness),
        encoding="utf-8",
    )

    print("[ok] benchmark_metrics.json")
    print("[ok] product_readiness.json")
    print("[ok] ablation_report.md")


if __name__ == "__main__":
    main()
