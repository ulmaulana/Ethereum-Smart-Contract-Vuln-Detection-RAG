"""
Expert rule features: high-precision deterministic patterns per vulnerability class.

Berbeda dari hand-crafted features (yang count/has pattern), rules ini lebih SPESIFIK:
"Function ini punya pattern yang HAMPIR PASTI vulnerable untuk class X."

Contoh:
  rule_reentrancy_strong = 1 jika function ada external call dengan value transfer
                           DAN ada state variable assignment SETELAH call
                           DAN tidak ada nonReentrant modifier
                           DAN function bersifat public/external

Setiap rule: high precision, bisa low recall. Model ML pakai rules sbg STRONG SIGNAL.
"""
import re
from collections import OrderedDict


# Reuse patterns dari handcrafted (untuk konsistensi)
RE_CALL_VALUE = re.compile(r"\.call\.value\s*\(", re.IGNORECASE)
RE_CALL_BRACE = re.compile(r"\.call\s*\{")
RE_CALL_LEGACY = re.compile(r"\.call\s*\(")
RE_DELEGATECALL = re.compile(r"\.delegatecall\s*[\(\{]", re.IGNORECASE)
RE_SEND = re.compile(r"\.send\s*\(")
RE_TRANSFER = re.compile(r"\.transfer\s*\(")
RE_TX_ORIGIN = re.compile(r"\btx\.origin\b")
RE_NONREENTRANT = re.compile(r"\bnonReentrant\b")
RE_BLOCK_TIMESTAMP = re.compile(r"\bblock\.timestamp\b|\bnow\b")
RE_BLOCKHASH = re.compile(r"\bblockhash\s*\(|\bblock\.blockhash")
RE_SELFDESTRUCT = re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\(")
RE_PUBLIC_EXTERNAL = re.compile(r"\b(public|external)\b")
RE_REQUIRE = re.compile(r"\brequire\s*\(")
RE_ASSERT = re.compile(r"\bassert\s*\(")
RE_FOR_LOOP = re.compile(r"\bfor\s*\(")
RE_WHILE_LOOP = re.compile(r"\bwhile\s*\(")
RE_SAFEMATH = re.compile(r"\bSafeMath\b|\busing\s+SafeMath\b")
RE_OWNER_CHECK = re.compile(
    r"only[A-Z]\w*|require\s*\(\s*msg\.sender\s*==\s*owner|"
    r"require\s*\(\s*owner\s*==\s*msg\.sender", re.IGNORECASE
)
RE_PLUS_MINUS = re.compile(r"[^=!<>]([+\-])=")
RE_PRAGMA_VER = re.compile(r"pragma\s+solidity\s+[\^~>=<\s]*(\d+)\.(\d+)")
RE_EXTERNAL_CALL = re.compile(
    r"(\.call\.value|\.call|\.send|\.transfer|\.delegatecall)\s*[\(\{]"
)
RE_STATE_ASSIGN = re.compile(r"\b\w+\s*[\[\]\w\.]*\s*[+\-]?=\s*[^=]")


def _has(p, t):
    return 1 if p.search(t) else 0


def _count(p, t):
    return len(p.findall(t))


def is_solidity_pre_08(header: str) -> int:
    m = RE_PRAGMA_VER.search(header)
    if not m:
        return 0
    major = int(m.group(1))
    minor = int(m.group(2))
    if major == 0 and minor < 8:
        return 1
    return 0


# =====================================================================
# Rules per class
# =====================================================================

def rule_reentrancy_strong(body: str, header: str) -> int:
    """
    STRONG signal reentrancy:
      external call dengan value DAN state assignment SETELAH call
      DAN tidak ada nonReentrant modifier.
    """
    if RE_NONREENTRANT.search(body):
        return 0
    if not (RE_CALL_VALUE.search(body) or RE_CALL_BRACE.search(body)
            or RE_CALL_LEGACY.search(body) or RE_DELEGATECALL.search(body)):
        return 0
    # Check state change AFTER external call
    matches = list(RE_EXTERNAL_CALL.finditer(body))
    if not matches:
        return 0
    after_last_call = body[matches[-1].end():]
    if RE_STATE_ASSIGN.search(after_last_call):
        return 1
    return 0


def rule_reentrancy_weak(body: str, header: str) -> int:
    """Weak signal: ada external call DAN tidak ada nonReentrant."""
    if RE_NONREENTRANT.search(body):
        return 0
    if RE_CALL_VALUE.search(body) or RE_CALL_BRACE.search(body):
        return 1
    return 0


def rule_access_control_tx_origin(body: str, header: str) -> int:
    """tx.origin di authentication context = pasti vuln."""
    if RE_TX_ORIGIN.search(body):
        return 1
    return 0


def rule_access_control_no_modifier(body: str, header: str) -> int:
    """
    Sensitive function (selfdestruct, ownership change) tanpa modifier check.
    """
    sig = body[:300]  # signature & first lines
    if not RE_PUBLIC_EXTERNAL.search(sig):
        return 0
    if RE_OWNER_CHECK.search(body):
        return 0
    if (RE_SELFDESTRUCT.search(body)
            or "owner =" in body or "owner=" in body):
        return 1
    return 0


def rule_arithmetic_pre_08_no_safemath(body: str, header: str) -> int:
    """Solidity < 0.8, ada arithmetic op, no SafeMath = potential overflow."""
    if not is_solidity_pre_08(header):
        return 0
    if RE_SAFEMATH.search(header) or RE_SAFEMATH.search(body):
        return 0
    if RE_PLUS_MINUS.search(body):
        return 1
    return 0


def rule_unchecked_call_value(body: str, header: str) -> int:
    """call.value() / send() tanpa require/check."""
    if not (RE_CALL_VALUE.search(body) or RE_SEND.search(body)
            or RE_CALL_BRACE.search(body)):
        return 0
    # Check for require/check after call
    matches = list(re.finditer(r"(\.call|\.send)", body))
    if not matches:
        return 0
    # Heuristic: kalau ada `require` di body, anggap dichecked
    if RE_REQUIRE.search(body) or RE_ASSERT.search(body):
        # Bisa dichecked, but check more strictly: require di line setelah call
        for m in matches:
            line_end = body.find("\n", m.end())
            if line_end == -1:
                line_end = len(body)
            line = body[m.start():line_end + 100]
            if not ("require" in line or "assert" in line
                    or "if " in line or "if(" in line):
                return 1
        return 0
    return 1


def rule_time_manipulation(body: str, header: str) -> int:
    """block.timestamp/now di kontrak dengan ether transfer."""
    if not RE_BLOCK_TIMESTAMP.search(body):
        return 0
    if (RE_TRANSFER.search(body) or RE_SEND.search(body)
            or RE_CALL_VALUE.search(body)):
        return 1
    return 0


def rule_bad_randomness(body: str, header: str) -> int:
    """Pakai blockhash/timestamp untuk randomness."""
    has_random = (RE_BLOCKHASH.search(body) or RE_BLOCK_TIMESTAMP.search(body))
    if not has_random:
        return 0
    # Dipakai untuk decision (if, modulo)
    if "%" in body or "if " in body or "if(" in body:
        return 1
    return 0


def rule_dos_loop_external_call(body: str, header: str) -> int:
    """Loop dengan external call di dalam = potential DoS."""
    has_loop = RE_FOR_LOOP.search(body) or RE_WHILE_LOOP.search(body)
    if not has_loop:
        return 0
    if (RE_TRANSFER.search(body) or RE_SEND.search(body)
            or RE_CALL_VALUE.search(body) or RE_CALL_BRACE.search(body)):
        return 1
    return 0


def rule_dos_unbounded_loop(body: str, header: str) -> int:
    """Loop tanpa upper bound jelas (rough heuristic)."""
    if not (RE_FOR_LOOP.search(body) or RE_WHILE_LOOP.search(body)):
        return 0
    # Hint: iterate over array.length
    if ".length" in body and ("for" in body or "while" in body):
        return 1
    return 0


# =====================================================================
# Aggregator
# =====================================================================

def extract_rule_features(body: str, header: str = "") -> OrderedDict:
    """Extract semua rule features sebagai OrderedDict."""
    feats = OrderedDict()
    feats["rule_reentrancy_strong"] = rule_reentrancy_strong(body, header)
    feats["rule_reentrancy_weak"] = rule_reentrancy_weak(body, header)
    feats["rule_access_control_tx_origin"] = rule_access_control_tx_origin(body, header)
    feats["rule_access_control_no_modifier"] = rule_access_control_no_modifier(body, header)
    feats["rule_arithmetic_pre08_no_safemath"] = rule_arithmetic_pre_08_no_safemath(body, header)
    feats["rule_unchecked_call_value"] = rule_unchecked_call_value(body, header)
    feats["rule_time_manipulation"] = rule_time_manipulation(body, header)
    feats["rule_bad_randomness"] = rule_bad_randomness(body, header)
    feats["rule_dos_loop_external_call"] = rule_dos_loop_external_call(body, header)
    feats["rule_dos_unbounded_loop"] = rule_dos_unbounded_loop(body, header)
    return feats


def feature_names() -> list[str]:
    sample = extract_rule_features("function f() public {}", "")
    return list(sample.keys())


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    test_cases = [
        ("Reentrancy classic", """
            function withdraw() public {
                uint amount = balances[msg.sender];
                msg.sender.call.value(amount)();
                balances[msg.sender] = 0;
            }
        """, "pragma solidity ^0.4.25;\ncontract Vault { mapping(address => uint) balances; }"),

        ("Safe withdraw with nonReentrant", """
            function withdraw() public nonReentrant {
                uint amount = balances[msg.sender];
                balances[msg.sender] = 0;
                msg.sender.transfer(amount);
            }
        """, "pragma solidity ^0.8.10;"),

        ("tx.origin check", """
            function transferOwnership(address newOwner) public {
                require(tx.origin == owner);
                owner = newOwner;
            }
        """, ""),

        ("DoS via loop", """
            function refundAll() public {
                for (uint i = 0; i < users.length; i++) {
                    users[i].transfer(amount);
                }
            }
        """, ""),
    ]

    fn_names = feature_names()
    for name, body, header in test_cases:
        print(f"\n=== {name} ===")
        feats = extract_rule_features(body, header)
        for k, v in feats.items():
            if v != 0:
                print(f"  {k:42s} = {v}")
