"""
Stage 5 dual-mode: train XGBoost artifacts for fast and deep inference.

Outputs:
  processed/sampled_functions_fast.parquet
  processed/sampled_functions_deep.parquet
  processed/silver_confidence_scores.parquet
  processed/regression_manifest.json
  processed/metrics_fast_aggregated.json
  processed/metrics_deep_aggregated.json
  processed/metrics_fast_per_fold.json
  processed/metrics_deep_per_fold.json
  processed/predictions_function_level_fast.parquet
  processed/predictions_function_level_deep.parquet
  processed/training_report_fast.md
  processed/training_report_deep.md

Model outputs:
  models/fast/{tfidf,xgb,calibrators}/...
  models/deep/{tfidf,xgb,calibrators}/...
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SRC_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from preprocessing.config import PROCESSED_DIR, RANDOM_STATE
from training.regression_cases import build_regression_cases
from training.stage5_train_xgb import compute_relevance_masks, compute_safety_masks


MODELS_DIR = PROJECT_ROOT / "models"
K_FOLDS = 5
TFIDF_MAX_FEATURES = 5000
TFIDF_NGRAM_RANGE = (1, 2)
MODE_CONFIGS = {
    "fast": {
        "numeric_prefixes": ("hc_", "rule_"),
        "artifact_root": MODELS_DIR / "fast",
        "dataset_name": "sampled_functions_fast.parquet",
    },
    "deep": {
        "numeric_prefixes": ("hc_", "tool_", "rule_"),
        "artifact_root": MODELS_DIR / "deep",
        "dataset_name": "sampled_functions_deep.parquet",
    },
}
HYPERPARAM_CANDIDATES = [
    {
        "n_estimators": 220,
        "max_depth": 4,
        "learning_rate": 0.08,
        "subsample": 0.85,
        "colsample_bytree": 0.85,
        "min_child_weight": 2,
        "reg_alpha": 0.0,
        "reg_lambda": 1.0,
    },
    {
        "n_estimators": 320,
        "max_depth": 6,
        "learning_rate": 0.06,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "reg_alpha": 0.1,
        "reg_lambda": 1.2,
    },
]
XGB_BASE_PARAMS = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
    "tree_method": "hist",
    "verbosity": 0,
}
TOOL_VOTE_COLUMNS = {
    "access_control": "tool_votes_access_control",
    "arithmetic": "tool_votes_arithmetic",
    "bad_randomness": "tool_votes_bad_randomness",
    "denial_of_service": "tool_votes_denial_service",
    "reentrancy": "tool_votes_reentrancy",
    "time_manipulation": "tool_votes_time_manipulation",
    "unchecked_low_level_calls": "tool_votes_unchecked_low_calls",
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


def load_data() -> tuple[pd.DataFrame, list[str]]:
    df = pd.read_parquet(PROCESSED_DIR / "sampled_functions_v2.parquet")
    with open(PROCESSED_DIR / "active_classes.json", encoding="utf-8") as handle:
        active = json.load(handle)["active"]
    return df, active


def compute_silver_confidence(df: pd.DataFrame, active: list[str]) -> pd.DataFrame:
    df = df.copy()
    relevance = compute_relevance_masks(df)
    safety = compute_safety_masks(df)
    is_wild = df["source"] == "wild"

    for vuln_class in active:
        vote_col = TOOL_VOTE_COLUMNS.get(vuln_class)
        votes = df[vote_col] if vote_col and vote_col in df.columns else 0.0
        rule_cols = STRONG_RULE_COLUMNS.get(vuln_class, [])
        strong_rule = (
            df[rule_cols].max(axis=1) if rule_cols else pd.Series(0, index=df.index)
        )
        rel_mask = relevance.get(vuln_class, pd.Series(False, index=df.index)).astype(int)
        safe_mask = safety.get(vuln_class, pd.Series(False, index=df.index)).astype(int)
        label_col = vuln_class

        confidence = np.where(
            df["source"] == "curated",
            1.0,
            np.where(
                df[label_col] == 1,
                np.clip(
                    0.25
                    + np.minimum(votes, 4) * 0.12
                    + rel_mask * 0.18
                    + strong_rule * 0.22
                    - safe_mask * 0.45,
                    0.0,
                    1.0,
                ),
                np.clip(rel_mask * 0.25 + strong_rule * 0.35, 0.0, 1.0),
            ),
        )

        df[f"silver_conf_{vuln_class}"] = confidence.astype(np.float32)
        df[f"hard_negative_{vuln_class}"] = (
            is_wild & (df[label_col] == 0) & (confidence >= 0.3)
        ).astype(int)

        if vuln_class in relevance:
            invalid_positive = is_wild & (df[label_col] == 1) & (~relevance[vuln_class])
            df.loc[invalid_positive, label_col] = 0
        if vuln_class in safety:
            safe_positive = is_wild & (df[label_col] == 1) & safety[vuln_class]
            df.loc[safe_positive, label_col] = 0

        too_weak = is_wild & (df[label_col] == 1) & (df[f"silver_conf_{vuln_class}"] < 0.55)
        df.loc[too_weak, label_col] = 0

    subset = np.full(len(df), "silver_regular", dtype=object)
    subset[df["source"] == "curated"] = "gold_train"
    any_high_conf = np.column_stack(
        [df[f"silver_conf_{cls}"].values >= 0.7 for cls in active]
    ).any(axis=1)
    any_hard_neg = np.column_stack(
        [df[f"hard_negative_{cls}"].values == 1 for cls in active]
    ).any(axis=1)
    subset[(df["source"] == "wild") & any_high_conf] = "silver_high_conf"
    subset[(df["source"] == "wild") & any_hard_neg] = "silver_hard_negative"
    df["training_subset"] = subset
    return df


def export_prepared_artifacts(df: pd.DataFrame, active: list[str]) -> None:
    base_columns = [
        "contract_id",
        "contract_name",
        "function_name",
        "function_kind",
        "function_signature",
        "function_source",
        "header_context",
        "combined_input",
        "start_line",
        "end_line",
        "fn_loc",
        "fold",
        "source",
        "label_quality",
        "training_subset",
    ] + active

    confidence_rows = []
    for vuln_class in active:
        confidence_rows.append(
            df[
                [
                    "contract_id",
                    "function_name",
                    "source",
                    vuln_class,
                    f"silver_conf_{vuln_class}",
                    f"hard_negative_{vuln_class}",
                ]
            ].rename(
                columns={
                    vuln_class: "label",
                    f"silver_conf_{vuln_class}": "silver_confidence",
                    f"hard_negative_{vuln_class}": "hard_negative",
                }
            ).assign(vulnerability=vuln_class)
        )
    pd.concat(confidence_rows, ignore_index=True).to_parquet(
        PROCESSED_DIR / "silver_confidence_scores.parquet",
        index=False,
    )

    for mode, config in MODE_CONFIGS.items():
        prefixes = config["numeric_prefixes"]
        numeric_cols = [column for column in df.columns if column.startswith(prefixes)]
        mode_df = df[base_columns + numeric_cols].copy()
        mode_df.to_parquet(PROCESSED_DIR / config["dataset_name"], index=False)

    regression_manifest = build_regression_cases()
    (PROCESSED_DIR / "regression_manifest.json").write_text(
        json.dumps(regression_manifest, indent=2),
        encoding="utf-8",
    )


def build_feature_matrix(df: pd.DataFrame, numeric_cols: list[str], tfidf: TfidfVectorizer):
    numeric = csr_matrix(df[numeric_cols].values.astype(np.float32))
    tfidf_matrix = tfidf.transform(df["function_source"].fillna("").tolist())
    return hstack([numeric, tfidf_matrix]).tocsr()


def split_outer_fold(df: pd.DataFrame, outer_fold: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    curated = df[df["source"] == "curated"].reset_index(drop=True)
    wild = df[df["source"] == "wild"].reset_index(drop=True)
    outer_test = curated[curated["fold"] == outer_fold].reset_index(drop=True)
    inner_val_fold = (outer_fold + 1) % K_FOLDS
    inner_val = curated[curated["fold"] == inner_val_fold].reset_index(drop=True)
    fit_curated = curated[
        (~curated["fold"].isin([outer_fold, inner_val_fold]))
    ].reset_index(drop=True)
    fit_df = pd.concat([fit_curated, wild], ignore_index=True)
    return fit_df, inner_val, outer_test


def build_class_frame(df: pd.DataFrame, vuln_class: str) -> pd.DataFrame:
    curated = df[df["source"] == "curated"]
    wild = df[df["source"] == "wild"]
    wild_positive = wild[wild[vuln_class] == 1]
    hard_negative_col = f"hard_negative_{vuln_class}"
    wild_hard_negative = wild[(wild[vuln_class] == 0) & (wild[hard_negative_col] == 1)]
    wild_easy_negative = wild[(wild[vuln_class] == 0) & (wild[hard_negative_col] == 0)]

    target_easy = min(
        len(wild_easy_negative),
        max(500, int(len(wild_positive) * 1.5) + len(wild_hard_negative)),
    )
    sampled_easy_negative = (
        wild_easy_negative.sample(target_easy, random_state=RANDOM_STATE)
        if target_easy > 0
        else wild_easy_negative.head(0)
    )

    class_df = pd.concat(
        [curated, wild_positive, wild_hard_negative, sampled_easy_negative],
        ignore_index=True,
    )
    return class_df.drop_duplicates(
        subset=["contract_id", "function_name", "start_line", "end_line"],
    ).reset_index(drop=True)


def build_sample_weights(df: pd.DataFrame, vuln_class: str) -> np.ndarray:
    weights = np.ones(len(df), dtype=np.float32)
    curated_mask = df["source"] == "curated"
    wild_mask = df["source"] == "wild"
    positive_mask = df[vuln_class] == 1

    weights[curated_mask] = 2.0
    weights[wild_mask & positive_mask] = (
        0.75 + df.loc[wild_mask & positive_mask, f"silver_conf_{vuln_class}"].values
    )
    hard_negative_mask = (
        wild_mask
        & (~positive_mask)
        & (df[f"hard_negative_{vuln_class}"] == 1)
    )
    weights[hard_negative_mask] = 1.2
    weights[wild_mask & (~positive_mask) & (~hard_negative_mask)] = 0.45
    return weights


def train_mode(
    mode: str,
    df: pd.DataFrame,
    active: list[str],
    quick: bool,
) -> tuple[list[dict], dict]:
    config = MODE_CONFIGS[mode]
    artifact_root = config["artifact_root"]
    tfidf_root = artifact_root / "tfidf"
    xgb_root = artifact_root / "xgb"
    calibrator_root = artifact_root / "calibrators"
    tfidf_root.mkdir(parents=True, exist_ok=True)
    xgb_root.mkdir(parents=True, exist_ok=True)
    calibrator_root.mkdir(parents=True, exist_ok=True)

    numeric_cols = [
        column
        for column in df.columns
        if column.startswith(config["numeric_prefixes"])
    ]
    fold_results: list[dict] = []

    candidates = HYPERPARAM_CANDIDATES[:1] if quick else HYPERPARAM_CANDIDATES

    for outer_fold in range(K_FOLDS):
        fit_df, val_df, test_df = split_outer_fold(df, outer_fold)
        tfidf = TfidfVectorizer(
            max_features=TFIDF_MAX_FEATURES,
            ngram_range=TFIDF_NGRAM_RANGE,
            token_pattern=r"\b\w+\b",
            lowercase=False,
            min_df=3,
            max_df=0.95,
        )
        tfidf.fit(pd.concat([fit_df["function_source"], val_df["function_source"]]).fillna("").tolist())
        joblib.dump(tfidf, tfidf_root / f"fold_{outer_fold}.pkl")

        fold_metrics = {}
        fold_predictions = {}
        for vuln_class in active:
            class_fit_df = build_class_frame(fit_df, vuln_class)
            class_val_df = val_df.copy()
            y_fit = class_fit_df[vuln_class].values
            y_val = class_val_df[vuln_class].values
            y_test = test_df[vuln_class].values

            if y_fit.sum() < 10 or y_val.sum() == 0 or y_test.sum() == 0:
                continue

            X_fit = build_feature_matrix(class_fit_df, numeric_cols, tfidf)
            X_val = build_feature_matrix(class_val_df, numeric_cols, tfidf)
            X_test = build_feature_matrix(test_df, numeric_cols, tfidf)
            fit_weights = build_sample_weights(class_fit_df, vuln_class)

            best_model = None
            best_params = None
            best_val_f1 = -1.0
            for candidate in candidates:
                params = {**XGB_BASE_PARAMS, **candidate}
                model = xgb.XGBClassifier(**params)
                model.fit(X_fit, y_fit, sample_weight=fit_weights, verbose=False)
                val_proba = model.predict_proba(X_val)[:, 1]
                val_pred = (val_proba >= 0.5).astype(int)
                val_f1 = f1_score(y_val, val_pred, zero_division=0)
                if val_f1 > best_val_f1:
                    best_model = model
                    best_params = candidate
                    best_val_f1 = val_f1

            if best_model is None:
                continue

            calibrator = None
            val_proba = best_model.predict_proba(X_val)[:, 1]
            if len(np.unique(y_val)) > 1:
                calibrator = LogisticRegression(random_state=RANDOM_STATE)
                calibrator.fit(val_proba.reshape(-1, 1), y_val)
                joblib.dump(
                    calibrator,
                    calibrator_root / f"fold_{outer_fold}_{vuln_class}.pkl",
                )

            joblib.dump(best_model, xgb_root / f"fold_{outer_fold}_{vuln_class}.pkl")

            test_proba = best_model.predict_proba(X_test)[:, 1]
            if calibrator is not None:
                test_proba = calibrator.predict_proba(test_proba.reshape(-1, 1))[:, 1]
            test_pred = (test_proba >= 0.5).astype(int)

            fold_predictions[vuln_class] = {
                "y_true": y_test.tolist(),
                "y_pred": test_pred.tolist(),
                "y_proba": test_proba.tolist(),
            }
            fold_metrics[vuln_class] = {
                "f1": round(f1_score(y_test, test_pred, zero_division=0), 4),
                "precision": round(precision_score(y_test, test_pred, zero_division=0), 4),
                "recall": round(recall_score(y_test, test_pred, zero_division=0), 4),
                "accuracy": round(accuracy_score(y_test, test_pred), 4),
                "best_val_f1": round(best_val_f1, 4),
                "best_params": best_params,
                "n_fit_pos": int(y_fit.sum()),
                "n_val_pos": int(y_val.sum()),
                "n_test_pos": int(y_test.sum()),
            }

        fold_results.append(
            {
                "fold": outer_fold,
                "metrics": fold_metrics,
                "predictions": fold_predictions,
                "test_meta": {
                    "contract_id": test_df["contract_id"].tolist(),
                    "function_name": test_df["function_name"].tolist(),
                },
            }
        )

    aggregated_metrics = aggregate_metrics(fold_results, active)
    prediction_df = build_predictions_dataframe(fold_results, active)
    prediction_df.to_parquet(
        PROCESSED_DIR / f"predictions_function_level_{mode}.parquet",
        index=False,
    )
    with open(PROCESSED_DIR / f"metrics_{mode}_aggregated.json", "w", encoding="utf-8") as handle:
        json.dump(aggregated_metrics, handle, indent=2)
    with open(PROCESSED_DIR / f"metrics_{mode}_per_fold.json", "w", encoding="utf-8") as handle:
        json.dump(
            {f"fold_{item['fold']}": item["metrics"] for item in fold_results},
            handle,
            indent=2,
        )
    (PROCESSED_DIR / f"training_report_{mode}.md").write_text(
        build_markdown_report(mode, aggregated_metrics, fold_results, active),
        encoding="utf-8",
    )
    return fold_results, aggregated_metrics


def aggregate_metrics(fold_results: list[dict], active: list[str]) -> dict:
    aggregated = {}
    for vuln_class in active:
        scores = defaultdict(list)
        for fold_result in fold_results:
            metrics = fold_result["metrics"].get(vuln_class)
            if not metrics:
                continue
            for key in ("f1", "precision", "recall", "accuracy"):
                scores[key].append(metrics[key])

        if not scores:
            continue

        aggregated[vuln_class] = {
            key: {
                "mean": round(float(np.mean(values)), 4),
                "std": round(float(np.std(values)), 4),
            }
            for key, values in scores.items()
        }

    macro_f1_per_fold = []
    for fold_result in fold_results:
        f1s = [metrics["f1"] for metrics in fold_result["metrics"].values()]
        if f1s:
            macro_f1_per_fold.append(float(np.mean(f1s)))
    aggregated["__macro_f1__"] = {
        "mean": round(float(np.mean(macro_f1_per_fold)), 4) if macro_f1_per_fold else 0.0,
        "std": round(float(np.std(macro_f1_per_fold)), 4) if macro_f1_per_fold else 0.0,
    }
    return aggregated


def build_predictions_dataframe(fold_results: list[dict], active: list[str]) -> pd.DataFrame:
    rows = []
    for fold_result in fold_results:
        test_meta = fold_result["test_meta"]
        n_rows = len(test_meta["contract_id"])
        for index in range(n_rows):
            row = {
                "fold": fold_result["fold"],
                "contract_id": test_meta["contract_id"][index],
                "function_name": test_meta["function_name"][index],
            }
            for vuln_class in active:
                prediction = fold_result["predictions"].get(vuln_class)
                if prediction is None:
                    row[f"{vuln_class}_true"] = np.nan
                    row[f"{vuln_class}_pred"] = np.nan
                    row[f"{vuln_class}_proba"] = np.nan
                    continue
                row[f"{vuln_class}_true"] = prediction["y_true"][index]
                row[f"{vuln_class}_pred"] = prediction["y_pred"][index]
                row[f"{vuln_class}_proba"] = prediction["y_proba"][index]
            rows.append(row)
    return pd.DataFrame(rows)


def build_markdown_report(mode: str, aggregated: dict, fold_results: list[dict], active: list[str]) -> str:
    lines = [
        f"# Stage 5 dual-mode Training Report ({mode})",
        "",
        f"- Folds: {K_FOLDS}",
        f"- TF-IDF: max_features={TFIDF_MAX_FEATURES}, ngram={TFIDF_NGRAM_RANGE}",
        "",
        "| Class | F1 | Precision | Recall | Accuracy |",
        "|-------|----|-----------|--------|----------|",
    ]
    for vuln_class in active:
        metrics = aggregated.get(vuln_class)
        if not metrics:
            continue
        lines.append(
            f"| {vuln_class} | "
            f"{metrics['f1']['mean']:.3f} ± {metrics['f1']['std']:.3f} | "
            f"{metrics['precision']['mean']:.3f} ± {metrics['precision']['std']:.3f} | "
            f"{metrics['recall']['mean']:.3f} ± {metrics['recall']['std']:.3f} | "
            f"{metrics['accuracy']['mean']:.3f} ± {metrics['accuracy']['std']:.3f} |"
        )
    lines.append(
        f"| **MACRO F1** | **{aggregated['__macro_f1__']['mean']:.3f} ± {aggregated['__macro_f1__']['std']:.3f}** | - | - | - |"
    )
    lines.append("")
    lines.append("## Per-fold F1")
    lines.append("")
    lines.append("| Class | " + " | ".join(f"Fold {result['fold']}" for result in fold_results) + " |")
    lines.append("|-------|" + "|".join("---" for _ in fold_results) + "|")
    for vuln_class in active:
        cells = []
        for fold_result in fold_results:
            metric = fold_result["metrics"].get(vuln_class, {}).get("f1", "-")
            cells.append(f"{metric:.3f}" if isinstance(metric, float) else "-")
        lines.append(f"| {vuln_class} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["fast", "deep", "all"], default="all")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    df, active = load_data()
    df = compute_silver_confidence(df, active)
    export_prepared_artifacts(df, active)

    modes = ["fast", "deep"] if args.mode == "all" else [args.mode]
    for mode in modes:
        print(f">>> Training mode={mode} ({'quick' if args.quick else 'full'})")
        _, aggregated = train_mode(mode, df, active, args.quick)
        print(
            f"[ok] {mode} macro F1: {aggregated['__macro_f1__']['mean']:.3f} ± "
            f"{aggregated['__macro_f1__']['std']:.3f}"
        )


if __name__ == "__main__":
    main()
