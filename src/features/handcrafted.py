"""
Hand-crafted feature extractor untuk Solidity functions.

Setiap function -> vector ~50 fitur numerik berdasarkan pattern yang relevant
untuk vulnerability detection. Pattern dipilih berdasarkan:
  - SWC Registry common patterns
  - Slither detector heuristics
  - Manual security audit checklist (ConsenSys, OZ)

Returns:
  feature_vector: dict {feature_name: float}
  Semua fitur sudah numeric, siap di-stack jadi matrix.
"""
import re
from collections import OrderedDict


# =====================================================================
# Pattern definitions
# =====================================================================

# External call patterns (potensi reentrancy / unchecked call)
RE_CALL_VALUE = re.compile(r"\.call\.value\s*\(", re.IGNORECASE)
RE_CALL_METHOD = re.compile(r"\.call\s*\{", re.IGNORECASE)  # 0.6+
RE_CALL_LEGACY = re.compile(r"\.call\s*\(", re.IGNORECASE)
RE_DELEGATECALL = re.compile(r"\.delegatecall\s*[\(\{]", re.IGNORECASE)
RE_STATICCALL = re.compile(r"\.staticcall\s*[\(\{]", re.IGNORECASE)
RE_CALLCODE = re.compile(r"\.callcode\s*\(", re.IGNORECASE)
RE_SEND = re.compile(r"\.send\s*\(")
RE_TRANSFER = re.compile(r"\.transfer\s*\(")

# Authorization / access patterns
RE_TX_ORIGIN = re.compile(r"\btx\.origin\b")
RE_MSG_SENDER = re.compile(r"\bmsg\.sender\b")
RE_MSG_VALUE = re.compile(r"\bmsg\.value\b")
RE_OWNER_CHECK = re.compile(r"(only[A-Z]\w*|require\s*\(\s*msg\.sender\s*==\s*owner)", re.IGNORECASE)
RE_NONREENTRANT = re.compile(r"\bnonReentrant\b")

# Block / time / randomness pitfalls
RE_BLOCK_TIMESTAMP = re.compile(r"\bblock\.timestamp\b|\bnow\b")
RE_BLOCK_NUMBER = re.compile(r"\bblock\.number\b")
RE_BLOCKHASH = re.compile(r"\bblockhash\s*\(|\bblock\.blockhash")
RE_BLOCK_DIFFICULTY = re.compile(r"\bblock\.difficulty\b")
RE_BLOCK_COINBASE = re.compile(r"\bblock\.coinbase\b")

# Arithmetic patterns
RE_PLUS_EQ = re.compile(r"[^=!<>]\+=")
RE_MINUS_EQ = re.compile(r"[^=!<>]-=")
RE_MUL_EQ = re.compile(r"[^=!<>]\*=")
RE_DIV_EQ = re.compile(r"[^=!<>]/=")
RE_UNCHECKED = re.compile(r"\bunchecked\s*\{")  # Solidity 0.8+
RE_SAFEMATH = re.compile(r"\bSafeMath\b|\busing\s+SafeMath\b")

# Control flow
RE_REQUIRE = re.compile(r"\brequire\s*\(")
RE_ASSERT = re.compile(r"\bassert\s*\(")
RE_REVERT = re.compile(r"\brevert\s*\(")
RE_IF = re.compile(r"\bif\s*\(")
RE_FOR = re.compile(r"\bfor\s*\(")
RE_WHILE = re.compile(r"\bwhile\s*\(")
RE_RETURN = re.compile(r"\breturn\b")

# Visibility / modifiers
RE_PAYABLE = re.compile(r"\bpayable\b")
RE_PUBLIC = re.compile(r"\bpublic\b")
RE_EXTERNAL = re.compile(r"\bexternal\b")
RE_PRIVATE = re.compile(r"\bprivate\b")
RE_INTERNAL = re.compile(r"\binternal\b")
RE_VIEW = re.compile(r"\bview\b")
RE_PURE = re.compile(r"\bpure\b")

# State changes
RE_SELFDESTRUCT = re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\(")
RE_THROW = re.compile(r"\bthrow\b")
RE_ASSEMBLY = re.compile(r"\bassembly\s*\{")

# Header context patterns
RE_PRAGMA_VER = re.compile(r"pragma\s+solidity\s+[\^~>=<\s]*(\d+)\.(\d+)")
RE_IMPORT_OZ = re.compile(r"@openzeppelin", re.IGNORECASE)
RE_IMPORT_REENTRANCY = re.compile(r"ReentrancyGuard", re.IGNORECASE)
RE_IMPORT_OWNABLE = re.compile(r"\bOwnable\b")
RE_USING_SAFEMATH = re.compile(r"using\s+SafeMath", re.IGNORECASE)

# Reentrancy heuristic: external call diikuti state assignment
RE_EXTERNAL_CALL = re.compile(r"(\.call|\.send|\.transfer)\s*[\(\{]")
RE_STATE_ASSIGN = re.compile(r"\b\w+\s*[\[\]\w\.]*\s*[+\-]?=\s*[^=]")


def _count(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text))


def _has(pattern: re.Pattern, text: str) -> int:
    return 1 if pattern.search(text) else 0


def reentrancy_pattern_score(body: str) -> int:
    """
    Heuristik reentrancy: ada external call diikuti oleh state assignment di dalam function.
    Return 1 kalau ada pattern beresiko, 0 kalau tidak.
    """
    matches = list(RE_EXTERNAL_CALL.finditer(body))
    if not matches:
        return 0
    last_call_pos = matches[-1].end()
    # Cari state assignment SETELAH last external call
    after = body[last_call_pos:]
    if RE_STATE_ASSIGN.search(after):
        return 1
    return 0


def pragma_major_minor(header: str) -> tuple[int, int]:
    m = RE_PRAGMA_VER.search(header)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 0, 0


# =====================================================================
# Main extractor
# =====================================================================

def extract_features(function_source: str, header_context: str = "") -> OrderedDict:
    """
    Ekstrak ~50 fitur numerik dari function source + header context.
    Return: OrderedDict {feature_name: float} (deterministic order).
    """
    body = function_source
    full = function_source + "\n" + header_context

    feats = OrderedDict()

    # ===== Size features =====
    feats["fn_chars"] = float(len(body))
    feats["fn_lines"] = float(body.count("\n") + 1)
    feats["fn_statements"] = float(body.count(";"))

    # ===== External call features =====
    feats["has_call_value"] = _has(RE_CALL_VALUE, body)
    feats["has_call_brace"] = _has(RE_CALL_METHOD, body)  # 0.6+ syntax
    feats["has_call_legacy"] = _has(RE_CALL_LEGACY, body)
    feats["has_delegatecall"] = _has(RE_DELEGATECALL, body)
    feats["has_staticcall"] = _has(RE_STATICCALL, body)
    feats["has_callcode"] = _has(RE_CALLCODE, body)
    feats["has_send"] = _has(RE_SEND, body)
    feats["has_transfer"] = _has(RE_TRANSFER, body)
    feats["count_external_calls"] = float(
        _count(RE_CALL_VALUE, body) + _count(RE_CALL_METHOD, body)
        + _count(RE_CALL_LEGACY, body) + _count(RE_SEND, body) + _count(RE_TRANSFER, body)
    )

    # ===== Authorization features =====
    feats["uses_tx_origin"] = _has(RE_TX_ORIGIN, body)
    feats["count_msg_sender"] = float(_count(RE_MSG_SENDER, body))
    feats["uses_msg_value"] = _has(RE_MSG_VALUE, body)
    feats["has_owner_check"] = _has(RE_OWNER_CHECK, body)
    feats["uses_nonreentrant"] = _has(RE_NONREENTRANT, body)

    # ===== Time / randomness pitfalls =====
    feats["uses_block_timestamp"] = _has(RE_BLOCK_TIMESTAMP, body)
    feats["uses_block_number"] = _has(RE_BLOCK_NUMBER, body)
    feats["uses_blockhash"] = _has(RE_BLOCKHASH, body)
    feats["uses_block_difficulty"] = _has(RE_BLOCK_DIFFICULTY, body)
    feats["uses_block_coinbase"] = _has(RE_BLOCK_COINBASE, body)

    # ===== Arithmetic features =====
    feats["count_plus_eq"] = float(_count(RE_PLUS_EQ, body))
    feats["count_minus_eq"] = float(_count(RE_MINUS_EQ, body))
    feats["count_mul_eq"] = float(_count(RE_MUL_EQ, body))
    feats["count_div_eq"] = float(_count(RE_DIV_EQ, body))
    feats["has_unchecked_block"] = _has(RE_UNCHECKED, body)
    feats["uses_safemath"] = _has(RE_SAFEMATH, full)

    # ===== Control flow =====
    feats["count_require"] = float(_count(RE_REQUIRE, body))
    feats["count_assert"] = float(_count(RE_ASSERT, body))
    feats["count_revert"] = float(_count(RE_REVERT, body))
    feats["count_if"] = float(_count(RE_IF, body))
    feats["count_for"] = float(_count(RE_FOR, body))
    feats["count_while"] = float(_count(RE_WHILE, body))
    feats["count_return"] = float(_count(RE_RETURN, body))

    # ===== Visibility / kind =====
    feats["is_payable"] = _has(RE_PAYABLE, body[:200])  # cek di signature
    feats["is_public"] = _has(RE_PUBLIC, body[:200])
    feats["is_external"] = _has(RE_EXTERNAL, body[:200])
    feats["is_private"] = _has(RE_PRIVATE, body[:200])
    feats["is_internal"] = _has(RE_INTERNAL, body[:200])
    feats["is_view"] = _has(RE_VIEW, body[:200])
    feats["is_pure"] = _has(RE_PURE, body[:200])

    # ===== Dangerous operations =====
    feats["has_selfdestruct"] = _has(RE_SELFDESTRUCT, body)
    feats["has_throw"] = _has(RE_THROW, body)
    feats["has_assembly"] = _has(RE_ASSEMBLY, body)

    # ===== Reentrancy heuristic =====
    feats["reentrancy_pattern"] = reentrancy_pattern_score(body)

    # ===== Header context features =====
    feats["header_has_oz"] = _has(RE_IMPORT_OZ, header_context)
    feats["header_has_reentrancy_guard"] = _has(RE_IMPORT_REENTRANCY, header_context)
    feats["header_has_ownable"] = _has(RE_IMPORT_OWNABLE, header_context)
    feats["header_uses_safemath"] = _has(RE_USING_SAFEMATH, header_context)

    # Pragma version
    pragma_major, pragma_minor = pragma_major_minor(header_context)
    feats["pragma_major"] = float(pragma_major)
    feats["pragma_minor"] = float(pragma_minor)
    # Pre-0.8 = manual SafeMath needed
    feats["is_pre_safe_arithmetic"] = float(
        pragma_major == 0 and pragma_minor < 8 and pragma_major + pragma_minor > 0
    )

    return feats


def feature_names() -> list[str]:
    """Return ordered list of feature names (untuk reproducibility)."""
    sample = extract_features("function f() public {}", "")
    return list(sample.keys())


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    test_fn = """
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        msg.sender.call.value(amount)();
        balances[msg.sender] -= amount;
    }
    """
    test_header = """
    pragma solidity ^0.4.25;
    contract Vault is Ownable, ReentrancyGuard {
        mapping(address => uint) public balances;
        modifier onlyOwner() { ... }
    }
    """
    feats = extract_features(test_fn, test_header)
    print(f"Total features: {len(feats)}")
    print("\nNonzero features:")
    for k, v in feats.items():
        if v != 0:
            print(f"  {k:30s} : {v}")
    print(f"\nReentrancy pattern detected? {feats['reentrancy_pattern']}")
