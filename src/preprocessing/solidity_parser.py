"""
Lightweight Solidity parser berbasis regex + brace matching.

Tujuan: ekstrak struktur kontrak tanpa dependency berat (no antlr/tree-sitter/solc).
Akurasi target: ~90-95% pada Solidity 0.4.x – 0.8.x kontrak umum.

Output utama: parse_source_file(src) -> dict dengan struktur:
  {
    "pragma": str,
    "contracts": [
      {
        "name": str,
        "kind": "contract" | "interface" | "library",
        "inherits": [str, ...],
        "state_vars": [str, ...],     # baris deklarasi state vars
        "modifiers": [{"name": str, "source": str, "start": int, "end": int}, ...],
        "functions": [{"name": str, "signature": str, "source": str, "start": int, "end": int}, ...],
        "events": [str, ...],
        "structs": [str, ...],
        "start": int, "end": int,     # offset karakter dari awal source
        "header_lines": [int, ...],   # baris-baris yang termasuk header (sebelum function pertama)
      },
      ...
    ]
  }
"""
import re
from dataclasses import dataclass, field


# =====================================================================
# Cleaning: strip comments & strings agar brace matching aman
# =====================================================================

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_DOUBLE = re.compile(r'"(?:\\.|[^"\\])*"')
_STRING_SINGLE = re.compile(r"'(?:\\.|[^'\\])*'")


def clean_for_parsing(src: str) -> str:
    """
    Replace comments & string literals with whitespace agar offset karakter tetap konsisten
    dengan source aslinya. Ini penting agar ekstraksi pakai start/end dari cleaned source
    bisa di-mapping balik ke source asli.
    """
    def _blank(m):
        s = m.group(0)
        return "".join(c if c == "\n" else " " for c in s)

    out = src
    out = _BLOCK_COMMENT.sub(_blank, out)
    out = _LINE_COMMENT.sub(_blank, out)
    out = _STRING_DOUBLE.sub(_blank, out)
    out = _STRING_SINGLE.sub(_blank, out)
    return out


def find_matching_brace(text: str, open_pos: int) -> int | None:
    """Diberi posisi '{' di text, cari posisi '}' yang match. Return None kalau tidak ketemu."""
    if open_pos >= len(text) or text[open_pos] != "{":
        return None
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


# =====================================================================
# Top-level extraction
# =====================================================================

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_CONTRACT_DECL_RE = re.compile(
    r"\b(contract|library|interface|abstract\s+contract)\s+([A-Za-z_]\w*)"
    r"(?:\s+is\s+([^{]+))?"
    r"\s*\{",
    re.MULTILINE,
)


def extract_pragma(src: str) -> str:
    m = _PRAGMA_RE.search(src)
    return m.group(1).strip() if m else ""


def extract_contract_blocks(cleaned: str) -> list[dict]:
    """Cari semua deklarasi contract/library/interface + body-nya."""
    blocks = []
    for m in _CONTRACT_DECL_RE.finditer(cleaned):
        kind_raw = m.group(1).strip()
        kind = "contract" if "contract" in kind_raw else kind_raw
        name = m.group(2)
        inherits_str = (m.group(3) or "").strip()
        # Parse "is A, B, C(arg)" -> ["A", "B", "C"]
        inherits = []
        if inherits_str:
            for parent in inherits_str.split(","):
                parent_name = re.split(r"[\s(]", parent.strip(), maxsplit=1)[0]
                if parent_name:
                    inherits.append(parent_name)

        body_open = cleaned.find("{", m.end() - 1)
        if body_open == -1:
            continue
        body_close = find_matching_brace(cleaned, body_open)
        if body_close is None:
            continue
        blocks.append({
            "name": name,
            "kind": kind,
            "inherits": inherits,
            "decl_start": m.start(),
            "body_start": body_open,
            "body_end": body_close,
        })
    return blocks


# =====================================================================
# Per-contract: extract functions, modifiers, state vars
# =====================================================================

# function/modifier/constructor declaration patterns
_FN_DECL_RE = re.compile(
    r"\b(function|modifier|constructor|fallback|receive)\b"
    r"(?:\s+([A-Za-z_]\w*))?"      # nama (constructor/fallback/receive boleh tanpa nama)
    r"\s*\([^)]*\)",
    re.MULTILINE,
)


def extract_members(cleaned: str, body_start: int, body_end: int) -> dict:
    """
    Pindai isi contract body (cleaned[body_start+1:body_end]) untuk:
      - functions, modifiers, constructors
      - state variables (deklarasi di luar function)
      - events, structs
    """
    body = cleaned[body_start + 1:body_end]
    body_offset = body_start + 1

    functions = []
    modifiers = []

    # Track posisi yang sudah di-cover oleh function/modifier (untuk ekstrak state vars)
    covered_ranges = []

    for m in _FN_DECL_RE.finditer(body):
        kind = m.group(1)
        name = m.group(2) or kind  # constructor/fallback/receive: name = kind
        sig_start = m.start()
        sig_end = m.end()

        # Cari body atau ';' (interface declaration)
        next_open = body.find("{", sig_end)
        next_semi = body.find(";", sig_end)
        if next_semi != -1 and (next_open == -1 or next_semi < next_open):
            # Declaration only (interface or virtual without body)
            end = next_semi
        elif next_open != -1:
            close = find_matching_brace(body, next_open)
            if close is None:
                continue
            end = close
        else:
            continue

        signature = body[sig_start:sig_end].strip()
        source = body[sig_start:end + 1].strip()
        abs_start = body_offset + sig_start
        abs_end = body_offset + end

        item = {
            "kind": kind,
            "name": name,
            "signature": signature,
            "source": source,
            "abs_start": abs_start,
            "abs_end": abs_end,
        }
        if kind == "modifier":
            modifiers.append(item)
        else:
            functions.append(item)
        covered_ranges.append((sig_start, end + 1))

    # Extract state variables: parse line per line di body, skip yang ada di covered_ranges
    # State var pattern: "type [modifier] name [= ...];" di scope contract (kedalaman 0)
    state_vars = extract_state_vars(body, covered_ranges)

    # Extract events & structs (untuk header context tambahan)
    events = re.findall(r"\bevent\s+[A-Za-z_]\w*\s*\([^)]*\)\s*;", body)
    structs = re.findall(r"\bstruct\s+[A-Za-z_]\w*\s*\{[^}]*\}", body)
    enums = re.findall(r"\benum\s+[A-Za-z_]\w*\s*\{[^}]*\}", body)

    return {
        "functions": functions,
        "modifiers": modifiers,
        "state_vars": state_vars,
        "events": events,
        "structs": structs,
        "enums": enums,
    }


def extract_state_vars(body: str, covered: list[tuple[int, int]]) -> list[str]:
    """
    Cari state variable declarations: baris di kedalaman brace 0 yang berakhir dengan ';'
    dan tidak masuk dalam range function/modifier.
    """
    out = []
    n = len(body)
    depth = 0
    i = 0
    line_start = 0

    def in_covered(pos: int) -> bool:
        for s, e in covered:
            if s <= pos < e:
                return True
        return False

    statement_start = 0
    while i < n:
        c = body[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0 and not in_covered(i):
            stmt = body[statement_start:i].strip()
            if stmt and looks_like_state_var(stmt):
                out.append(stmt + ";")
            statement_start = i + 1
        elif c == ";" and depth == 0:
            statement_start = i + 1
        i += 1
    return out


_STATE_VAR_HINT_RE = re.compile(
    r"^(?:uint\d*|int\d*|bool|address|bytes\d*|string|mapping|"
    r"[A-Z]\w*|enum\s+\w+|struct\s+\w+)"
)


def looks_like_state_var(stmt: str) -> bool:
    """Heuristik: deklarasi state var dimulai dengan tipe primitif atau nama type."""
    stmt = stmt.strip()
    if not stmt:
        return False
    # Skip deklarasi pragma/import/using
    if stmt.startswith(("pragma", "import", "using")):
        return False
    # Skip event/struct/enum (akan diambil terpisah)
    if stmt.startswith(("event", "struct", "enum", "modifier", "function")):
        return False
    return bool(_STATE_VAR_HINT_RE.match(stmt))


# =====================================================================
# Public API
# =====================================================================

def parse_source_file(src: str) -> dict:
    """Parse satu file .sol → struktur lengkap."""
    cleaned = clean_for_parsing(src)
    pragma = extract_pragma(cleaned)
    contract_blocks = extract_contract_blocks(cleaned)

    contracts = []
    for cb in contract_blocks:
        members = extract_members(cleaned, cb["body_start"], cb["body_end"])

        # Untuk source yang dikembalikan, kita ekstrak dari source ASLI (bukan cleaned)
        # karena offset karakter sama (clean_for_parsing pakai whitespace replacement)
        for fn in members["functions"]:
            fn["source"] = src[fn["abs_start"]:fn["abs_end"] + 1]
            fn["start_line"] = src.count("\n", 0, fn["abs_start"]) + 1
            fn["end_line"] = src.count("\n", 0, fn["abs_end"]) + 1
        for mod in members["modifiers"]:
            mod["source"] = src[mod["abs_start"]:mod["abs_end"] + 1]

        contracts.append({
            "name": cb["name"],
            "kind": cb["kind"],
            "inherits": cb["inherits"],
            "state_vars": members["state_vars"],
            "events": members["events"],
            "structs": members["structs"],
            "enums": members["enums"],
            "modifiers": members["modifiers"],
            "functions": members["functions"],
            "start": cb["decl_start"],
            "end": cb["body_end"],
        })

    return {"pragma": pragma, "contracts": contracts}


def build_header_context(parsed: dict, contract_name: str, max_chars: int = 1500) -> str:
    """
    Bangun header context untuk function di kontrak tertentu:
      - pragma
      - deklarasi contract + inherits
      - state variables (truncated)
      - modifier definitions (signature only, biar irit token)

    Header ini akan di-prepend ke source function saat training/inference.
    """
    contract = next((c for c in parsed["contracts"] if c["name"] == contract_name), None)
    if contract is None:
        return ""

    parts = []
    if parsed["pragma"]:
        parts.append(f"pragma solidity {parsed['pragma']};")

    # Inheritance line
    inh_str = f" is {', '.join(contract['inherits'])}" if contract["inherits"] else ""
    parts.append(f"{contract['kind']} {contract['name']}{inh_str} {{")

    # State vars (max 20 untuk irit)
    for sv in contract["state_vars"][:20]:
        parts.append(f"    {sv}")

    # Events (signature)
    for ev in contract["events"][:5]:
        parts.append(f"    {ev}")

    # Modifier signatures (tanpa body — irit token)
    for mod in contract["modifiers"][:10]:
        sig = mod["signature"]
        parts.append(f"    {sig} {{ ... }}")

    parts.append("    // ... functions ...")
    parts.append("}")

    header = "\n".join(parts)
    if len(header) > max_chars:
        header = header[:max_chars] + "\n    // ... (header truncated)"
    return header


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    sample = """
    pragma solidity ^0.4.25;

    contract Vault is Ownable, ReentrancyGuard {
        mapping(address => uint) public balances;
        address public owner;
        uint256 constant FEE = 100;

        event Withdraw(address indexed user, uint amount);

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            // <yes> <report> REENTRANCY
            msg.sender.call.value(amount)();
            balances[msg.sender] -= amount;
        }
    }
    """
    parsed = parse_source_file(sample)
    print(f"Pragma: {parsed['pragma']}")
    for c in parsed["contracts"]:
        print(f"\nContract: {c['name']} (kind={c['kind']}, inherits={c['inherits']})")
        print(f"  state_vars ({len(c['state_vars'])}):")
        for sv in c["state_vars"]:
            print(f"    {sv}")
        print(f"  modifiers ({len(c['modifiers'])}):")
        for mod in c["modifiers"]:
            print(f"    {mod['name']} (line {mod.get('start_line', '?')})")
        print(f"  functions ({len(c['functions'])}):")
        for fn in c["functions"]:
            print(f"    {fn['name']} (line {fn['start_line']}-{fn['end_line']}, "
                  f"{len(fn['source'])} chars)")

    print("\n--- Header context for 'Vault' ---")
    print(build_header_context(parsed, "Vault"))
