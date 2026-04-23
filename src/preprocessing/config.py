"""Konfigurasi path & konstanta untuk pipeline preprocessing."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_ROOT = PROJECT_ROOT / "dataset"
CURATED_ROOT = DATASET_ROOT / "smartbugs-curated-main"
WILD_ROOT = DATASET_ROOT / "smartbugs-wild-master"
RESULTS_ROOT = DATASET_ROOT / "smartbugs-results-master"

CURATED_VULN_JSON = CURATED_ROOT / "vulnerabilities.json"
CURATED_CONTRACTS_DIR = CURATED_ROOT / "dataset"

WILD_CONTRACTS_DIR = WILD_ROOT / "contracts"
WILD_NB_LINES = WILD_ROOT / "nb_lines.csv"
WILD_DUPLICATES = WILD_ROOT / "duplicates.json"

RESULTS_WILD_JSON = RESULTS_ROOT / "metadata" / "results_wild.json"
RESULTS_CURATED_JSON = RESULTS_ROOT / "metadata" / "results_curated.json"
VULN_MAPPING_CSV = RESULTS_ROOT / "metadata" / "vulnerabilities_mapping.csv"

PROCESSED_DIR = PROJECT_ROOT / "processed"
PROCESSED_DIR.mkdir(exist_ok=True)

# 10 kategori vulnerability sesuai SmartBugs / DASP taksonomi
VULN_CATEGORIES = [
    "access_control",
    "arithmetic",
    "bad_randomness",
    "denial_of_service",
    "front_running",
    "other",
    "reentrancy",
    "short_addresses",
    "time_manipulation",
    "unchecked_low_level_calls",
]

# Mapping nama kategori di results_*.json (pakai nama berbeda) → nama standar
RESULTS_CATEGORY_MAP = {
    "access_control": "access_control",
    "arithmetic": "arithmetic",
    "bad_randomness": "bad_randomness",
    "denial_service": "denial_of_service",
    "front_running": "front_running",
    "Other": "other",
    "other": "other",
    "reentrancy": "reentrancy",
    "short_addresses": "short_addresses",
    "time_manipulation": "time_manipulation",
    "unchecked_low_calls": "unchecked_low_level_calls",
}

# Threshold tool voting untuk silver label di Wild
SILVER_VOTE_THRESHOLD = 2

# Filter LOC untuk Wild (skip kontrak terlalu kecil/besar)
WILD_MIN_LOC = 50
WILD_MAX_LOC = 2000

# === Stage 3: Split & Balancing config ===

# Class dianggap "aktif" (layak dipakai) kalau punya >= N sampel di Curated
ACTIVE_CLASS_MIN_CURATED = 5

# Cap jumlah kontrak Wild dengan label "arithmetic only" (untuk reduce dominasi)
ARITHMETIC_ONLY_WILD_CAP = 5000

# Cap jumlah kontrak Wild dengan label "all negative" (untuk reduce bias)
ALL_NEGATIVE_WILD_CAP = 2000

# Split ratio untuk Curated (gold) → train / val / test
TRAIN_RATIO = 0.60
VAL_RATIO = 0.20
TEST_RATIO = 0.20

RANDOM_STATE = 42
