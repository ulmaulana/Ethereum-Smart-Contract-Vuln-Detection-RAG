"""
Sanity check: pastikan semua file dataset ada sebelum menjalankan pipeline.
Jalankan ini DULU sebelum stage 1/2/3.
"""
import sys

from config import (
    CURATED_VULN_JSON,
    CURATED_CONTRACTS_DIR,
    WILD_CONTRACTS_DIR,
    WILD_NB_LINES,
    WILD_DUPLICATES,
    RESULTS_WILD_JSON,
    RESULTS_CURATED_JSON,
    VULN_MAPPING_CSV,
)


def check(label: str, path) -> bool:
    exists = path.exists()
    if exists:
        if path.is_dir():
            try:
                count = sum(1 for _ in path.iterdir())
                print(f"  [OK]   {label:30s} -> {path.name}/ ({count} entries)")
            except Exception:
                print(f"  [OK]   {label:30s} -> {path.name}/")
        else:
            size_kb = path.stat().st_size / 1024
            print(f"  [OK]   {label:30s} -> {path.name} ({size_kb:,.1f} KB)")
    else:
        print(f"  [FAIL] {label:30s} -> {path}")
    return exists


def main() -> None:
    print("=" * 70)
    print("VERIFIKASI DATASET")
    print("=" * 70)
    print("\nCurated dataset:")
    ok1 = check("vulnerabilities.json", CURATED_VULN_JSON)
    ok2 = check("contracts dir", CURATED_CONTRACTS_DIR)

    print("\nWild dataset:")
    ok3 = check("contracts dir", WILD_CONTRACTS_DIR)
    ok4 = check("nb_lines.csv", WILD_NB_LINES)
    ok5 = check("duplicates.json", WILD_DUPLICATES)

    print("\nResults dataset:")
    ok6 = check("results_wild.json", RESULTS_WILD_JSON)
    ok7 = check("results_curated.json", RESULTS_CURATED_JSON)
    ok8 = check("vulnerabilities_mapping.csv", VULN_MAPPING_CSV)

    all_ok = all([ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8])
    print("\n" + "=" * 70)
    if all_ok:
        print("STATUS: SEMUA OK — siap menjalankan stage 1/2/3")
    else:
        print("STATUS: ADA FILE HILANG — perbaiki dulu sebelum lanjut")
        sys.exit(1)
    print("=" * 70)


if __name__ == "__main__":
    main()
