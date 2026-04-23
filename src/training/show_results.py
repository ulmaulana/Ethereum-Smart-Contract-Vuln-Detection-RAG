"""
Tampilkan semua metrik akurasi yang sudah dihitung Stage 5 & 6.
Bisa langsung di-screenshot untuk laporan UAS.

Usage: python src/training/show_results.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.config import PROCESSED_DIR

LINE = "=" * 88
SUBLINE = "-" * 88


def load(name: str) -> dict | None:
    p = PROCESSED_DIR / name
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


def main():
    fn_metrics = load("metrics_aggregated.json")
    cn_metrics = load("contract_level_metrics.json")
    baseline = load("baseline_comparison.json")
    tuned = load("threshold_tuning.json")
    active = load("active_classes.json")

    if not fn_metrics or not cn_metrics:
        print("[!] Belum ada metrics. Jalankan dulu Stage 5 & 6:")
        print("    python src/training/stage5_train_xgb.py")
        print("    python src/training/stage6_evaluate.py")
        return

    active_classes = active["active"] if active else []

    # ===== 1. FUNCTION-LEVEL METRICS (5-FOLD CV) =====
    print("\n" + LINE)
    print("1. FUNCTION-LEVEL F1 (5-Fold CV, Mean ± Std)")
    print(LINE)
    print(f"{'Class':<32s} {'F1':>14s} {'Precision':>12s} {'Recall':>10s} {'Accuracy':>10s}")
    print(SUBLINE)
    for cls in active_classes:
        m = fn_metrics.get(cls)
        if not m:
            continue
        print(f"{cls:<32s} "
              f"{m['f1']['mean']:.3f} ± {m['f1']['std']:.3f}  "
              f"{m['precision']['mean']:>10.3f}   "
              f"{m['recall']['mean']:>8.3f}  "
              f"{m['accuracy']['mean']:>8.3f}")
    macro = fn_metrics.get("__macro_f1__", {})
    if macro:
        print(SUBLINE)
        print(f"{'MACRO F1':<32s} {macro['mean']:.3f} ± {macro['std']:.3f}")

    # ===== 2. CONTRACT-LEVEL METRICS =====
    print("\n" + LINE)
    print("2. CONTRACT-LEVEL F1 (Aggregated function predictions per contract)")
    print(LINE)
    cn_default = cn_metrics.get("default_threshold_0.5", {})
    cn_tuned = cn_metrics.get("tuned_threshold", {})
    print(f"{'Class':<32s} {'F1 (thr=0.5)':>14s} {'F1 (Tuned Thr)':>18s} {'Best Thr':>10s}")
    print(SUBLINE)
    for cls in active_classes:
        d = cn_default.get(cls)
        t = cn_tuned.get(cls)
        if not d or not t:
            continue
        thr = tuned.get(cls, {}).get("best_threshold", "-") if tuned else "-"
        print(f"{cls:<32s} {d['f1']:>14.3f} {t['f1']:>18.3f} {str(thr):>10s}")
    print(SUBLINE)
    print(f"{'MACRO F1':<32s} "
          f"{cn_default.get('__macro_f1__', 0):>14.3f} "
          f"{cn_tuned.get('__macro_f1__', 0):>18.3f}")

    # ===== 3. COMPARISON VS BASELINE TOOLS =====
    print("\n" + LINE)
    print("3. COMPARISON vs 9 SMARTBUGS BASELINE TOOLS (Contract-level F1)")
    print(LINE)
    if baseline:
        # Header
        tool_names = list(baseline.keys())
        header = f"{'Class':<28s} {'OUR':>7s}"
        for t in tool_names:
            header += f" {t[:8]:>8s}"
        print(header)
        print(SUBLINE)
        for cls in active_classes:
            our_f1 = cn_tuned.get(cls, {}).get("f1", 0) if cn_tuned else 0
            row = f"{cls:<28s} {our_f1:>7.3f}"
            for t in tool_names:
                t_f1 = baseline[t].get(cls, {}).get("f1", 0)
                row += f" {t_f1:>8.3f}"
            print(row)
        print(SUBLINE)
        our_macro = cn_tuned.get("__macro_f1__", 0)
        macro_row = f"{'MACRO F1':<28s} {our_macro:>7.3f}"
        for t in tool_names:
            macro_row += f" {baseline[t].get('__macro_f1__', 0):>8.3f}"
        print(macro_row)

        # Quick wins count
        wins = 0
        ties = 0
        losses = 0
        for cls in active_classes:
            our_f1 = cn_tuned.get(cls, {}).get("f1", 0)
            best_baseline = max((baseline[t].get(cls, {}).get("f1", 0) for t in tool_names),
                                default=0)
            if our_f1 > best_baseline:
                wins += 1
            elif our_f1 == best_baseline:
                ties += 1
            else:
                losses += 1
        print(f"\nResult: WIN {wins}/{len(active_classes)} class | "
              f"TIE {ties} | LOSS {losses}  vs best individual tool")

    # ===== 4. KEY HIGHLIGHTS =====
    print("\n" + LINE)
    print("4. KEY HIGHLIGHTS ")
    print(LINE)
    if cn_tuned:
        sorted_classes = sorted(
            [(cls, cn_tuned[cls]["f1"]) for cls in active_classes if cls in cn_tuned],
            key=lambda x: -x[1]
        )
        print(f"\nTop performing classes (contract-level, tuned threshold):")
        for cls, f1 in sorted_classes[:3]:
            print(f"  {cls:30s} : F1 = {f1:.3f}")
        print(f"\nClasses needing improvement:")
        for cls, f1 in sorted_classes[-3:]:
            print(f"  {cls:30s} : F1 = {f1:.3f}")

    # ===== 5. FILE LOCATIONS =====
    print("\n" + LINE)
    print("5. DETAIL REPORTS ")
    print(LINE)
    files = [
        ("processed/training_report.md", "Markdown table function-level per fold"),
        ("processed/evaluation_report.md", "Markdown table contract-level + vs 9 tools"),
        ("processed/metrics_aggregated.json", "Function-level metrics (raw)"),
        ("processed/contract_level_metrics.json", "Contract-level metrics (raw)"),
        ("processed/baseline_comparison.json", "9 tools baseline (raw)"),
        ("processed/threshold_tuning.json", "Tuned threshold per class"),
        ("processed/predictions_function_level.parquet", "Per-function predictions"),
        ("processed/contract_level_predictions.parquet", "Per-contract predictions"),
    ]
    for f, desc in files:
        p = PROCESSED_DIR.parent / f if not f.startswith("processed/") else PROCESSED_DIR / f.split("/")[1]
        marker = "OK" if p.exists() else "--"
        print(f"  [{marker}] {f:<50s} {desc}")


if __name__ == "__main__":
    main()
