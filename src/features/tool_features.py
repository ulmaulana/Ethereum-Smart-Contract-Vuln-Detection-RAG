"""
Tool features: ekstrak fitur dari hasil 9 SmartBugs analysis tools yang sudah pre-computed.

Strategi: alih-alih run Slither/Mythril dari awal (lambat & install ribet di Windows),
kita PARSE output yg SUDAH ADA di smartbugs-results-master/results/<tool>/{icse20|curated}/<contract>/result.json

Output: ~90 features per contract (count per detector across 9 tools).

Kelebihan:
  1. SUPER cepat (cuma read JSON, no compile/run)
  2. Deterministic (hasil tools tidak berubah)
  3. Compatible Wild + Curated (keduanya sudah di-run)
  4. Memberi model "expert knowledge" dari 9 tools yg dikembangkan akademisi/industri
"""
import json
import sys
from pathlib import Path
from collections import OrderedDict, Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from preprocessing.config import RESULTS_ROOT, RESULTS_WILD_JSON, RESULTS_CURATED_JSON

TOOLS = [
    "slither", "mythril", "oyente", "osiris", "smartcheck",
    "manticore", "maian", "securify", "honeybadger",
]


# =====================================================================
# Load aggregated results (sudah di-parse di metadata/)
# =====================================================================

_results_wild_cache = None
_results_curated_cache = None


def load_results_wild() -> dict:
    """Cache load results_wild.json (~31MB) sekali per process."""
    global _results_wild_cache
    if _results_wild_cache is None:
        with open(RESULTS_WILD_JSON, "r", encoding="utf-8") as f:
            _results_wild_cache = json.load(f)
    return _results_wild_cache


def load_results_curated() -> dict:
    global _results_curated_cache
    if _results_curated_cache is None:
        with open(RESULTS_CURATED_JSON, "r", encoding="utf-8") as f:
            _results_curated_cache = json.load(f)
    return _results_curated_cache


# =====================================================================
# Build feature schema
# =====================================================================

# Daftar detector yang relevan per tool (dari vulnerabilities_mapping.csv yg kita baca dulu)
# Format: tool -> list of (detector_name, std_category)
TOOL_DETECTORS = {
    "slither": [
        "arbitrary-send", "calls-loop", "controlled-delegatecall", "incorrect-equality",
        "locked-ether", "low-level-calls", "reentrancy-benign", "reentrancy-eth",
        "reentrancy-no-eth", "suicidal", "timestamp", "tx-origin",
        "uninitialized-local", "uninitialized-state", "uninitialized-storage",
        "unused-return",
    ],
    "mythril": [
        "Call data forwarded with delegatecall()", "DELEGATECALL to a user-supplied address",
        "Dependence on predictable environment variable", "Dependence on predictable variable",
        "Ether send", "Exception state", "Integer Overflow", "Integer Underflow",
        "Message call to external contract", "Multiple Calls",
        "State change after external call", "Transaction order dependence",
        "Unchecked CALL return value", "Unchecked SUICIDE", "Use of tx.origin",
    ],
    "oyente": [
        "Callstack Depth Attack Vulnerability.", "Integer Overflow.", "Integer Underflow.",
        "Parity Multisig Bug 2.", "Re-Entrancy Vulnerability.", "Timestamp Dependency.",
    ],
    "osiris": [
        "callstack_bug", "concurrency_bug", "division_bugs", "overflow_bugs",
        "reentrancy_bug", "signedness_bugs", "time_dependency_bug",
        "truncation_bugs", "underflow_bugs",
    ],
    "smartcheck": [
        "SOLIDITY_CALL_WITHOUT_DATA", "SOLIDITY_DIV_MUL", "SOLIDITY_EXACT_TIME",
        "SOLIDITY_GAS_LIMIT_IN_LOOPS", "SOLIDITY_INCORRECT_BLOCKHASH",
        "SOLIDITY_LOCKED_MONEY", "SOLIDITY_SEND", "SOLIDITY_TRANSFER_IN_LOOP",
        "SOLIDITY_TX_ORIGIN", "SOLIDITY_UINT_CANT_BE_NEGATIVE",
        "SOLIDITY_UNCHECKED_CALL", "SOLIDITY_VAR", "SOLIDITY_VAR_IN_LOOP_FOR",
    ],
    "manticore": [
        "Delegatecall to user controlled address", "Potential reentrancy vulnerability",
        "Reachable ether leak to sender", "Reachable SELFDESTRUCT",
        "Reentrancy multi-million ether bug", "Returned value at CALL instruction is not used",
        "Unsigned integer overflow at ADD instruction",
        "Unsigned integer overflow at MUL instruction",
        "Unsigned integer overflow at SUB instruction",
        "Warning ORIGIN instruction used", "Warning TIMESTAMP instruction used",
    ],
    "maian": [
        "is_lock_vulnerable", "is_prodigal_vulnerable", "is_suicidal_vulnerable",
    ],
    "securify": [
        "DAO", "DAOConstantGas", "LockedEther", "TODAmount", "TODReceiver",
        "TODTransfer", "UnhandledException", "UnrestrictedEtherFlow", "UnrestrictedWrite",
    ],
    "honeybadger": [
        "balance_disorder", "hidden_state_update", "hidden_transfer",
        "inheritance_disorder", "straw_man_contract", "type_overflow",
        "uninitialised_struct",
    ],
}


def feature_names() -> list[str]:
    """List nama fitur tool features (~100 fitur)."""
    out = []
    # Per-detector counts
    for tool, dets in TOOL_DETECTORS.items():
        for det in dets:
            # Sanitize nama untuk jadi column name
            safe_name = det.lower().replace(" ", "_").replace(".", "").replace("-", "_")[:40]
            out.append(f"tool_{tool}_{safe_name}")
    # Per-tool aggregate counts
    for tool in TOOLS:
        out.append(f"tool_{tool}_total_vulns")
    # Per-category aggregate (jumlah tool yg deteksi class ini)
    for cat in ["access_control", "arithmetic", "denial_service", "reentrancy",
                "unchecked_low_calls", "bad_randomness", "front_running",
                "time_manipulation"]:
        out.append(f"tool_votes_{cat}")
    return out


# =====================================================================
# Extract features for a single contract
# =====================================================================

def extract_for_contract(contract_data: dict | None) -> OrderedDict:
    """
    Diberi data per kontrak dari results_wild.json atau results_curated.json,
    extract semua fitur tool.

    Format input:
      {
        "tools": {
          "slither": {"vulnerabilities": {"reentrancy-eth": 2, ...}, "categories": {...}},
          "mythril": {...},
          ...
        },
        "lines": [...],
        "nb_vulnerabilities": N
      }
    """
    feats = OrderedDict()
    fn_names = feature_names()
    # Initialize all to 0
    for n in fn_names:
        feats[n] = 0.0

    if not contract_data:
        return feats

    tools_data = contract_data.get("tools", {})

    # Per-detector counts
    for tool, dets in TOOL_DETECTORS.items():
        tool_result = tools_data.get(tool, {})
        vuln_counts = tool_result.get("vulnerabilities", {}) or {}
        for det in dets:
            safe_name = det.lower().replace(" ", "_").replace(".", "").replace("-", "_")[:40]
            count = vuln_counts.get(det, 0)
            feats[f"tool_{tool}_{safe_name}"] = float(count)

    # Per-tool total
    for tool in TOOLS:
        tool_result = tools_data.get(tool, {})
        vuln_counts = tool_result.get("vulnerabilities", {}) or {}
        feats[f"tool_{tool}_total_vulns"] = float(sum(vuln_counts.values()))

    # Per-category votes (berapa tool deteksi)
    cat_votes = Counter()
    for tool in TOOLS:
        tool_result = tools_data.get(tool, {})
        cats = tool_result.get("categories", {}) or {}
        for cat in cats:
            cat_votes[cat] += 1
    for cat in ["access_control", "arithmetic", "denial_service", "reentrancy",
                "unchecked_low_calls", "bad_randomness", "front_running",
                "time_manipulation"]:
        feats[f"tool_votes_{cat}"] = float(cat_votes.get(cat, 0))

    return feats


# =====================================================================
# Helper: lookup contract di results
# =====================================================================

def get_contract_data_wild(address: str) -> dict | None:
    return load_results_wild().get(address)


def get_contract_data_curated(filename: str) -> dict | None:
    """Curated key = name tanpa .sol."""
    key = filename.replace(".sol", "")
    return load_results_curated().get(key) or load_results_curated().get(filename)


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    print(">>> Tool features self-test\n")
    fn_names = feature_names()
    print(f"Total tool features: {len(fn_names)}")
    print(f"Sample features: {fn_names[:5]} ... {fn_names[-3:]}")

    # Test on a sample contract
    print("\n[..] Loading results_wild.json (akan cache)...")
    wild = load_results_wild()
    print(f"     {len(wild):,} contracts in results_wild.json")

    sample_addr = list(wild.keys())[0]
    print(f"\nSample contract: {sample_addr}")
    feats = extract_for_contract(wild[sample_addr])
    print(f"\nNonzero features:")
    for k, v in feats.items():
        if v != 0:
            print(f"  {k:50s} = {v}")
