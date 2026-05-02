"""
Stage 7b: End-to-end demo — input .sol -> ML detection -> RAG mitigation.

Pipeline:
  1. Load .sol file
  2. Parse functions + header context (Stage 4a logic)
  3. Extract hand-crafted features (Stage 4b logic)
  4. TF-IDF transform pakai vectorizer dari Fold 0 (atau average semua fold)
  5. Predict per active class pakai XGBoost models
  6. Untuk tiap vuln yg detected: panggil RAG explainer
  7. Print final report

Usage:
  python src/rag/stage7_demo.py [path/to/contract.sol]
  (default: ambil 1 sample dari Curated)
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.config import PROCESSED_DIR
from preprocessing.solidity_parser import parse_source_file, build_header_context
from features.handcrafted import extract_features, feature_names
from rag.explainer import explain_with_llm

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
NUM_FOLDS = 5
DETECTION_THRESHOLD = 0.5  # default; bisa dioverride dari threshold_tuning.json


def load_active_classes() -> list[str]:
    with open(PROCESSED_DIR / "active_classes.json") as f:
        return json.load(f)["active"]


def load_tuned_thresholds() -> dict[str, float]:
    """Pakai threshold optimal dari Stage 6."""
    p = PROCESSED_DIR / "threshold_tuning.json"
    if not p.exists():
        return {}
    with open(p) as f:
        data = json.load(f)
    return {cls: info["best_threshold"] for cls, info in data.items()}


def parse_contract(source_code: str) -> list[dict]:
    """Parse semua functions dari source. Return list of {function_name, source, header}."""
    parsed = parse_source_file(source_code)
    funcs = []
    for contract in parsed["contracts"]:
        if contract["kind"] == "interface":
            continue
        header = build_header_context(parsed, contract["name"])
        for fn in contract["functions"]:
            if not (30 <= len(fn["source"]) <= 8000):
                continue
            funcs.append({
                "contract_name": contract["name"],
                "function_name": fn["name"],
                "source": fn["source"],
                "header": header,
                "start_line": fn["start_line"],
                "end_line": fn["end_line"],
            })
    return funcs


def extract_function_features(funcs: list[dict]) -> tuple[np.ndarray, list[str]]:
    """Hand-crafted features per function. Return matrix + feature names."""
    fn_names = feature_names()
    rows = []
    for f in funcs:
        feats = extract_features(f["source"], f["header"])
        rows.append([feats[n] for n in fn_names])
    return np.array(rows, dtype=np.float32), fn_names


def predict_per_function(funcs: list[dict], active: list[str],
                         tuned_thr: dict[str, float]) -> dict:
    """
    Untuk tiap function, predict per kelas (rata-ratakan probabilitas semua fold model).
    Apply tuned threshold per class. Return dict per function dengan binary predictions.
    """
    if not funcs:
        return {"functions": [], "summary": {}}

    # Hand-crafted features
    hc_matrix, _ = extract_function_features(funcs)
    hc_sparse = csr_matrix(hc_matrix)

    # Average prediction across folds
    proba_per_class = {cls: np.zeros(len(funcs)) for cls in active}
    n_models_per_class = {cls: 0 for cls in active}
    function_sources = [f["source"] for f in funcs]

    for fold in range(NUM_FOLDS):
        tfidf_path = MODELS_DIR / "tfidf" / f"fold_{fold}.pkl"
        if not tfidf_path.exists():
            continue
        tfidf = joblib.load(tfidf_path)
        tf_matrix = tfidf.transform(function_sources)
        X = hstack([hc_sparse, tf_matrix]).tocsr()

        for cls in active:
            model_path = MODELS_DIR / "xgb" / f"fold_{fold}_{cls}.pkl"
            if not model_path.exists():
                continue
            model = joblib.load(model_path)
            try:
                proba = model.predict_proba(X)[:, 1]
                proba_per_class[cls] += proba
                n_models_per_class[cls] += 1
            except Exception as e:
                print(f"[warn] predict fail fold {fold} {cls}: {e}")

    # Average
    for cls in active:
        if n_models_per_class[cls] > 0:
            proba_per_class[cls] /= n_models_per_class[cls]

    # Apply thresholds
    fn_results = []
    for i, f in enumerate(funcs):
        fn_pred = {}
        for cls in active:
            if n_models_per_class[cls] == 0:
                continue
            thr = tuned_thr.get(cls, DETECTION_THRESHOLD)
            proba = float(proba_per_class[cls][i])
            fn_pred[cls] = {
                "proba": round(proba, 4),
                "predicted": int(proba >= thr),
                "threshold": thr,
            }
        fn_results.append({
            "contract_name": f["contract_name"],
            "function_name": f["function_name"],
            "lines": f"{f['start_line']}-{f['end_line']}",
            "source": f["source"],
            "predictions": fn_pred,
        })

    # Contract-level summary (any function positive -> contract positive)
    contract_summary = {}
    for cls in active:
        if n_models_per_class[cls] == 0:
            continue
        any_pos = any(r["predictions"].get(cls, {}).get("predicted", 0) == 1
                      for r in fn_results)
        contract_summary[cls] = int(any_pos)
    return {"functions": fn_results, "summary": contract_summary}


def print_report(filename: str, results: dict):
    print("\n" + "=" * 78)
    print(f"VULNERABILITY DETECTION REPORT: {filename}")
    print("=" * 78)

    funcs = results["functions"]
    summary = results["summary"]

    print(f"\nTotal function di-analisis: {len(funcs)}")
    print(f"\nContract-level vulnerability summary:")
    detected_classes = []
    for cls, val in summary.items():
        marker = "DETECTED" if val == 1 else "  clean "
        print(f"  [{marker}] {cls}")
        if val == 1:
            detected_classes.append(cls)

    if not detected_classes:
        print("\n[ok] Tidak ada vulnerability terdeteksi pada threshold yg di-set.")
        return

    print(f"\n{'=' * 78}")
    print(f"FUNCTION-LEVEL DETAIL (yang predicted positive):")
    print("=" * 78)
    for fn in funcs:
        positives = {cls: info for cls, info in fn["predictions"].items()
                     if info["predicted"] == 1}
        if not positives:
            continue
        print(f"\n{fn['contract_name']}::{fn['function_name']}() (lines {fn['lines']}):")
        for cls, info in positives.items():
            print(f"  -> {cls:30s} (proba={info['proba']:.3f}, thr={info['threshold']:.2f})")

    # RAG explanation per detected class
    print(f"\n{'=' * 78}")
    print("RAG MITIGATION EXPLANATIONS:")
    print("=" * 78)
    for cls in detected_classes:
        # Pick first function predicted positive untuk class ini sebagai context
        relevant_fn = next(
            (f for f in funcs if f["predictions"].get(cls, {}).get("predicted") == 1),
            None
        )
        fn_source = relevant_fn["source"] if relevant_fn else ""
        contract_id = relevant_fn["contract_name"] if relevant_fn else ""

        print(f"\n{'~' * 78}")
        print(f"[ {cls.upper()} ]")
        print("~" * 78)
        print(explain_with_llm(cls, fn_source, contract_id, llm_provider="minimax"))


# =====================================================================
# Main
# =====================================================================

def main():
    args = sys.argv[1:]
    args = [a for a in args if not a.startswith("--")]

    # Load contract
    if args:
        sol_path = Path(args[0])
        if not sol_path.exists():
            print(f"[ERROR] File not found: {sol_path}")
            sys.exit(1)
        source_code = sol_path.read_text(encoding="utf-8", errors="ignore")
        filename = sol_path.name
    else:
        # Default: ambil sample reentrancy dari Curated
        import pandas as pd
        df = pd.read_parquet(PROCESSED_DIR / "curated_folds.parquet")
        # Pilih kontrak dengan reentrancy + access_control biar contoh menarik
        sample = df[df["reentrancy"] == 1].iloc[0]
        source_code = sample["source_code"]
        filename = sample["contract_id"]
        print(f"[info] Demo memakai sample Curated: {filename}")
        print(f"[info] Pakai 'python src/rag/stage7_demo.py path/to/contract.sol' "
              f"untuk file lain")

    # Load model artifacts
    active = load_active_classes()
    tuned_thr = load_tuned_thresholds()
    if tuned_thr:
        print(f"[ok] Loaded tuned thresholds dari Stage 6")

    # Pipeline
    print(f"\n[..] Parsing {filename} ({len(source_code):,} chars)...")
    funcs = parse_contract(source_code)
    print(f"[ok] Found {len(funcs)} functions")

    if not funcs:
        print("[!] No functions extracted, can't analyze.")
        return

    print(f"[..] Running ML inference (avg across {NUM_FOLDS} folds)...")
    results = predict_per_function(funcs, active, tuned_thr)

    print_report(filename, results)


if __name__ == "__main__":
    main()
