"""
Knowledge Base untuk RAG: penjelasan + mitigasi vulnerability smart contract.

Sumber: SWC Registry (https://swcregistry.io/), ConsenSys Smart Contract Best
Practices, OpenZeppelin docs, DASP Top 10. Disusun ulang untuk match dengan
taksonomi 10 kategori SmartBugs Curated.

Setiap entry punya:
  - swc_id           : SWC identifier (kalau ada)
  - category         : nama kategori SmartBugs (untuk mapping ke output ML model)
  - title            : judul singkat
  - description      : penjelasan apa & kenapa berbahaya
  - vulnerable_code  : contoh kode yang vulnerable
  - mitigation       : strategi mitigasi (bisa multi-langkah)
  - fix_code         : contoh kode yang sudah aman
  - references       : link sumber
"""

KNOWLEDGE_BASE = [
    # ===== REENTRANCY =====
    {
        "swc_id": "SWC-107",
        "category": "reentrancy",
        "title": "Reentrancy Attack",
        "description": (
            "Reentrancy terjadi ketika contract melakukan external call ke address lain "
            "SEBELUM mengupdate state-nya sendiri. Contract attacker bisa memanggil ulang "
            "(re-enter) function yang sama dan menguras dana berkali-kali. The DAO hack "
            "(2016) yang merugikan $60M USD adalah contoh paling terkenal."
        ),
        "vulnerable_code": (
            "function withdraw() public {\n"
            "    uint amount = balances[msg.sender];\n"
            "    (bool ok,) = msg.sender.call{value: amount}(\"\");  // external call DULU\n"
            "    require(ok);\n"
            "    balances[msg.sender] = 0;  // state update SETELAH (RAWAN)\n"
            "}"
        ),
        "mitigation": (
            "1. Pakai pola Checks-Effects-Interactions: validasi -> update state -> external call.\n"
            "2. Gunakan ReentrancyGuard dari OpenZeppelin (modifier nonReentrant).\n"
            "3. Pakai transfer() atau send() yang memberikan gas limit 2300 (cukup untuk emit event saja)."
        ),
        "fix_code": (
            "// Pakai ReentrancyGuard\n"
            "import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n"
            "contract Vault is ReentrancyGuard {\n"
            "    function withdraw() public nonReentrant {\n"
            "        uint amount = balances[msg.sender];\n"
            "        balances[msg.sender] = 0;  // state update DULU\n"
            "        (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
            "        require(ok);\n"
            "    }\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-107",
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
        ],
    },
    {
        "swc_id": "SWC-107",
        "category": "reentrancy",
        "title": "Cross-Function Reentrancy",
        "description": (
            "Variant dari reentrancy yang lebih halus: attacker tidak re-enter ke function "
            "yang sama, tapi ke function LAIN yang share state yang sama. Modifier nonReentrant "
            "hanya melindungi function yang ditandai. Function lain dengan akses state yang "
            "sama tetap rentan kalau tidak ditandai juga."
        ),
        "vulnerable_code": (
            "function withdraw() nonReentrant { ... }     // diproteksi\n"
            "function transfer(address to, uint amt) {    // tidak diproteksi -> rawan\n"
            "    balances[msg.sender] -= amt;\n"
            "    balances[to] += amt;\n"
            "}"
        ),
        "mitigation": (
            "1. Tambahkan nonReentrant ke SEMUA function yang mengakses state shared.\n"
            "2. Audit semua function yang membaca/menulis state yang sama untuk pola CEI."
        ),
        "fix_code": (
            "function withdraw() public nonReentrant { ... }\n"
            "function transfer(address to, uint amt) public nonReentrant { ... }"
        ),
        "references": [
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
        ],
    },

    # ===== ACCESS CONTROL =====
    {
        "swc_id": "SWC-115",
        "category": "access_control",
        "title": "Penggunaan tx.origin untuk Authentication",
        "description": (
            "tx.origin SELALU mengembalikan EOA (externally owned account) yang originally "
            "memulai transaksi, BUKAN caller langsung. Kalau user memanggil contract A yang "
            "memanggil contract B, di B: tx.origin = user, msg.sender = A. Attacker bisa "
            "membuat contract perantara untuk men-trick contract Anda."
        ),
        "vulnerable_code": (
            "modifier onlyOwner() {\n"
            "    require(tx.origin == owner);  // RAWAN\n"
            "    _;\n"
            "}"
        ),
        "mitigation": (
            "1. SELALU pakai msg.sender untuk authorization, bukan tx.origin.\n"
            "2. tx.origin hanya boleh dipakai untuk anti-bot/anti-contract check (jarang)."
        ),
        "fix_code": (
            "modifier onlyOwner() {\n"
            "    require(msg.sender == owner);\n"
            "    _;\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-115",
            "https://docs.soliditylang.org/en/latest/security-considerations.html#tx-origin",
        ],
    },
    {
        "swc_id": "SWC-105",
        "category": "access_control",
        "title": "Function Tanpa Access Control (Unprotected Ether Withdrawal)",
        "description": (
            "Function yang sensitif (withdraw, mint, burn, selfdestruct) tidak memiliki "
            "check siapa yang boleh memanggil. Siapapun bisa eksekusi. Parity multisig hack "
            "(2017) merugikan $30M USD karena initWallet() bisa dipanggil siapa saja."
        ),
        "vulnerable_code": (
            "function setOwner(address newOwner) public {  // tidak ada check\n"
            "    owner = newOwner;\n"
            "}\n"
            "function destroy() public {  // siapa saja bisa hancurkan contract\n"
            "    selfdestruct(payable(msg.sender));\n"
            "}"
        ),
        "mitigation": (
            "1. Pakai modifier onlyOwner / pattern AccessControl untuk semua function sensitif.\n"
            "2. Pakai OpenZeppelin Ownable atau AccessControl untuk role-based authorization.\n"
            "3. Audit semua function public/external yang mengubah state penting."
        ),
        "fix_code": (
            "import \"@openzeppelin/contracts/access/Ownable.sol\";\n"
            "contract MyContract is Ownable {\n"
            "    function setOwner(address newOwner) public onlyOwner {\n"
            "        _transferOwnership(newOwner);\n"
            "    }\n"
            "    function destroy() public onlyOwner {\n"
            "        selfdestruct(payable(owner()));\n"
            "    }\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-105",
            "https://docs.openzeppelin.com/contracts/4.x/access-control",
        ],
    },
    {
        "swc_id": "SWC-112",
        "category": "access_control",
        "title": "Delegatecall ke Address Tidak Terpercaya",
        "description": (
            "delegatecall mengeksekusi code dari contract lain DENGAN STORAGE & msg.sender "
            "contract pemanggil. Kalau target address bisa dikontrol attacker, mereka bisa "
            "menulis ke storage Anda dan mencuri ownership/dana."
        ),
        "vulnerable_code": (
            "function execute(address target, bytes data) public {\n"
            "    target.delegatecall(data);  // RAWAN: target dikontrol user\n"
            "}"
        ),
        "mitigation": (
            "1. JANGAN pakai delegatecall ke address yang bisa di-set/dikontrol oleh user.\n"
            "2. Kalau perlu (mis. proxy pattern), pakai whitelist target yg dipercaya.\n"
            "3. Pakai OpenZeppelin Proxy contracts yang audited."
        ),
        "fix_code": (
            "address public immutable trustedImpl;\n"
            "constructor(address _impl) { trustedImpl = _impl; }\n"
            "function execute(bytes data) public {\n"
            "    trustedImpl.delegatecall(data);  // target tetap, dipercaya\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-112",
        ],
    },

    # ===== ARITHMETIC =====
    {
        "swc_id": "SWC-101",
        "category": "arithmetic",
        "title": "Integer Overflow & Underflow",
        "description": (
            "Sebelum Solidity 0.8, operasi aritmatika tidak otomatis check overflow/underflow. "
            "uint256 max = 2^256-1; kalau ditambah 1, akan kembali ke 0. Begitu juga uint 0 "
            "dikurangi 1 jadi 2^256-1. Attacker bisa transfer/withdraw lebih dari saldo dengan "
            "trigger underflow. The BeautyChain (BEC) token hack (2018) eksploitasi ini."
        ),
        "vulnerable_code": (
            "pragma solidity ^0.4.25;\n"
            "function transfer(address to, uint amount) public {\n"
            "    balances[msg.sender] -= amount;  // underflow kalau amount > balance\n"
            "    balances[to] += amount;          // overflow kalau result > 2^256-1\n"
            "}"
        ),
        "mitigation": (
            "1. Upgrade ke Solidity >= 0.8 yang punya built-in overflow check (revert otomatis).\n"
            "2. Untuk Solidity < 0.8, pakai SafeMath library dari OpenZeppelin.\n"
            "3. Hindari unchecked block kecuali sudah yakin aman dan butuh gas saving."
        ),
        "fix_code": (
            "// Solidity >= 0.8: aman by default\n"
            "pragma solidity ^0.8.20;\n"
            "function transfer(address to, uint amount) public {\n"
            "    balances[msg.sender] -= amount;  // auto-revert kalau underflow\n"
            "    balances[to] += amount;\n"
            "}\n"
            "\n"
            "// Solidity < 0.8: pakai SafeMath\n"
            "using SafeMath for uint256;\n"
            "balances[msg.sender] = balances[msg.sender].sub(amount);\n"
            "balances[to] = balances[to].add(amount);"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-101",
            "https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath",
        ],
    },

    # ===== UNCHECKED LOW-LEVEL CALLS =====
    {
        "swc_id": "SWC-104",
        "category": "unchecked_low_level_calls",
        "title": "Unchecked Return Value of Low-Level Call",
        "description": (
            "Function low-level seperti call(), send(), delegatecall() tidak revert otomatis "
            "kalau gagal. Mereka return bool. Kalau Anda tidak check return value, contract "
            "akan lanjut seolah-olah berhasil padahal tidak. Bisa menyebabkan inconsistent "
            "state atau loss of funds."
        ),
        "vulnerable_code": (
            "function withdraw() public {\n"
            "    msg.sender.send(amount);  // tidak di-check, bisa fail diam-diam\n"
            "    balances[msg.sender] = 0; // state diubah meski transfer fail\n"
            "}"
        ),
        "mitigation": (
            "1. SELALU check return value low-level call.\n"
            "2. Pakai require() untuk revert kalau gagal.\n"
            "3. Atau pakai transfer() yang otomatis revert (tapi punya gas limit 2300).\n"
            "4. Untuk pattern pull-payment, dokumentasi kegagalan dan retry mechanism."
        ),
        "fix_code": (
            "function withdraw() public nonReentrant {\n"
            "    uint amount = balances[msg.sender];\n"
            "    balances[msg.sender] = 0;\n"
            "    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(ok, \"Transfer failed\");\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-104",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
        ],
    },

    # ===== TIME MANIPULATION =====
    {
        "swc_id": "SWC-116",
        "category": "time_manipulation",
        "title": "Block Timestamp Dependence",
        "description": (
            "block.timestamp (alias 'now') bisa dimanipulasi miner sampai ~15 detik (atau "
            "lebih untuk PoS). Kalau contract Anda pakai timestamp untuk randomness, payment "
            "deadline kritis, atau win condition, miner bisa manipulasi outcome."
        ),
        "vulnerable_code": (
            "function lottery() public payable {\n"
            "    // miner bisa pilih timestamp untuk menang\n"
            "    if (block.timestamp % 2 == 0) {\n"
            "        msg.sender.transfer(address(this).balance);\n"
            "    }\n"
            "}"
        ),
        "mitigation": (
            "1. JANGAN pakai block.timestamp untuk randomness atau decision kritis.\n"
            "2. Untuk randomness pakai oracle seperti Chainlink VRF.\n"
            "3. Kalau timestamp memang dibutuhkan, toleransi window minimal 15 menit.\n"
            "4. Block.number lebih sulit dimanipulasi tapi tidak akurat sebagai timekeeper."
        ),
        "fix_code": (
            "// Pakai Chainlink VRF untuk randomness\n"
            "import \"@chainlink/contracts/src/v0.8/VRFConsumerBase.sol\";\n"
            "// ... atau toleransi waktu yg longgar\n"
            "require(block.timestamp >= startTime + 1 days, \"Too early\");"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-116",
        ],
    },

    # ===== BAD RANDOMNESS =====
    {
        "swc_id": "SWC-120",
        "category": "bad_randomness",
        "title": "Weak Sources of Randomness",
        "description": (
            "On-chain data seperti block.timestamp, block.number, blockhash, block.difficulty "
            "BUKAN sumber randomness yang aman. Semua publik dan beberapa bisa dimanipulasi miner. "
            "Attacker bisa precompute hasil dan eksploitasi gambling/lottery."
        ),
        "vulnerable_code": (
            "function pickWinner() public {\n"
            "    uint random = uint(keccak256(abi.encodePacked(\n"
            "        block.timestamp, block.difficulty, msg.sender\n"
            "    )));\n"
            "    winner = participants[random % participants.length];\n"
            "}"
        ),
        "mitigation": (
            "1. Pakai oracle Chainlink VRF untuk randomness yang verifiable.\n"
            "2. Atau commit-reveal scheme (user submit hash dulu, baru reveal nanti).\n"
            "3. JANGAN PERNAH pakai block hash/timestamp/difficulty langsung untuk random."
        ),
        "fix_code": (
            "import \"@chainlink/contracts/src/v0.8/VRFConsumerBase.sol\";\n"
            "contract Lottery is VRFConsumerBase {\n"
            "    function getRandomNumber() public returns (bytes32) {\n"
            "        return requestRandomness(keyHash, fee);\n"
            "    }\n"
            "    function fulfillRandomness(bytes32, uint256 randomness) internal override {\n"
            "        winner = participants[randomness % participants.length];\n"
            "    }\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-120",
            "https://docs.chain.link/vrf/v2/introduction",
        ],
    },

    # ===== DENIAL OF SERVICE =====
    {
        "swc_id": "SWC-113",
        "category": "denial_of_service",
        "title": "DoS via Failed External Call (push pattern)",
        "description": (
            "Kalau contract Anda iterate loop yang call external address, satu address yang "
            "selalu revert akan menggagalkan SELURUH loop. Auction yang refund participants "
            "via push pattern bisa stuck karena 1 attacker."
        ),
        "vulnerable_code": (
            "function refundAll() public {\n"
            "    for (uint i = 0; i < participants.length; i++) {\n"
            "        // 1 contract yg revert = semua refund gagal\n"
            "        participants[i].transfer(refundAmount);\n"
            "    }\n"
            "}"
        ),
        "mitigation": (
            "1. Pakai PULL pattern: user yang call withdraw sendiri, bukan kontrak yang push.\n"
            "2. Catat saldo refund di mapping, biarkan user claim saat siap.\n"
            "3. Hindari loop yang external call ke address eksternal."
        ),
        "fix_code": (
            "mapping(address => uint) public pendingRefunds;\n"
            "function recordRefund(address user, uint amount) internal {\n"
            "    pendingRefunds[user] += amount;  // PUSH ke mapping (selalu sukses)\n"
            "}\n"
            "function withdrawRefund() public nonReentrant {\n"
            "    uint amount = pendingRefunds[msg.sender];\n"
            "    pendingRefunds[msg.sender] = 0;\n"
            "    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(ok);\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-113",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
        ],
    },
    {
        "swc_id": "SWC-128",
        "category": "denial_of_service",
        "title": "DoS via Block Gas Limit",
        "description": (
            "Loop yang iterate over array bisa exceed block gas limit (sekitar 30M gas) "
            "kalau array tumbuh terlalu besar. Function jadi tidak bisa dipanggil sama sekali. "
            "GovernMental hack (2016) stuck karena array participants terlalu besar."
        ),
        "vulnerable_code": (
            "address[] public users;\n"
            "function distributeReward() public {\n"
            "    // kalau users[] sudah ribuan, gas exceed limit\n"
            "    for (uint i = 0; i < users.length; i++) {\n"
            "        users[i].transfer(reward);\n"
            "    }\n"
            "}"
        ),
        "mitigation": (
            "1. Hindari loop yang grow unbounded.\n"
            "2. Pakai pagination: process batch kecil per call.\n"
            "3. Pakai pull pattern (user claim sendiri).\n"
            "4. Set hard cap untuk array size."
        ),
        "fix_code": (
            "function distributeRewardBatch(uint start, uint end) public onlyOwner {\n"
            "    require(end - start <= 100, \"Batch too big\");\n"
            "    for (uint i = start; i < end; i++) {\n"
            "        users[i].transfer(reward);\n"
            "    }\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-128",
        ],
    },

    # ===== FRONT RUNNING =====
    {
        "swc_id": "SWC-114",
        "category": "front_running",
        "title": "Transaction Order Dependence (Front-Running)",
        "description": (
            "Mempool Ethereum publik. Attacker bisa lihat transaksi pending Anda dan submit "
            "transaksi serupa dengan gas price lebih tinggi untuk dieksekusi DULU. Bahaya untuk "
            "DEX (sandwich attack), ENS auctions, dan reveal-then-commit schemes."
        ),
        "vulnerable_code": (
            "function buyToken(uint maxPrice) public payable {\n"
            "    uint price = getCurrentPrice();\n"
            "    require(price <= maxPrice);\n"
            "    // attacker bisa front-run untuk push price up dulu, baru sell\n"
            "    tokens[msg.sender] += msg.value / price;\n"
            "}"
        ),
        "mitigation": (
            "1. Pakai commit-reveal scheme: submit hash dulu, reveal nanti.\n"
            "2. Slippage protection: user spec maxPrice/minOutput.\n"
            "3. Pakai private mempool (Flashbots) untuk transaksi sensitif.\n"
            "4. Batch auctions untuk DEX (semua trade pada price sama)."
        ),
        "fix_code": (
            "// Commit-reveal\n"
            "function commit(bytes32 hash) public {\n"
            "    commitments[msg.sender] = Commitment(hash, block.number);\n"
            "}\n"
            "function reveal(uint value, uint nonce) public {\n"
            "    require(block.number > commitments[msg.sender].block + 5);\n"
            "    require(keccak256(abi.encodePacked(value, nonce)) == commitments[msg.sender].hash);\n"
            "    // process value\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-114",
        ],
    },

    # ===== SHORT ADDRESS =====
    {
        "swc_id": "SWC-117",
        "category": "short_addresses",
        "title": "Short Address / Padding Attack",
        "description": (
            "EVM accept calldata yang lebih pendek dari expected dan auto-pad dengan 0. "
            "Attacker bisa kirim address dengan trailing zero dropped, dan amount param di-shift "
            "bit dengan padding 0, jadi token transfer dengan amount 256x lebih besar."
        ),
        "vulnerable_code": (
            "// ERC20 transfer call yang vulnerable di sisi exchange/wallet:\n"
            "// transfer(0xABCD...EF00, 100)  ditulis sebagai\n"
            "// transfer(0xABCD...EF, 100)   -> EVM pad jadi transfer(0xABCD...EF00, 25600)"
        ),
        "mitigation": (
            "1. Validasi address length di sisi client/wallet (BUKAN di smart contract).\n"
            "2. Hindari pass address dari user input langsung ke transfer.\n"
            "3. Solidity modern (>= 0.5) auto-validate calldata length, jadi vulnerability "
            "ini lebih relevan di sisi off-chain (wallet/exchange API)."
        ),
        "fix_code": (
            "// Di smart contract (Solidity >= 0.5): otomatis aman\n"
            "// Di sisi wallet/exchange API: validate input address length"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-117",
        ],
    },

    # ===== OTHER (general best practices) =====
    {
        "swc_id": "SWC-106",
        "category": "other",
        "title": "Unprotected Selfdestruct Instruction",
        "description": (
            "Function yang call selfdestruct() tanpa proper access control bisa hancurkan "
            "contract dan transfer semua dana ke attacker. Parity wallet (2017) hilangkan "
            "$280M USD karena ini."
        ),
        "vulnerable_code": (
            "function kill() public {\n"
            "    selfdestruct(payable(msg.sender));  // siapa saja bisa hancurkan\n"
            "}"
        ),
        "mitigation": (
            "1. Pasang modifier onlyOwner pada function destruct.\n"
            "2. Pertimbangkan tidak menggunakan selfdestruct sama sekali.\n"
            "3. Solidity 0.8.18+: selfdestruct sudah deprecated."
        ),
        "fix_code": (
            "function kill() public onlyOwner {\n"
            "    selfdestruct(payable(owner));\n"
            "}"
        ),
        "references": [
            "https://swcregistry.io/docs/SWC-106",
        ],
    },
]


def get_categories() -> list[str]:
    """Daftar unique kategori yang ada di KB."""
    return sorted(set(e["category"] for e in KNOWLEDGE_BASE))


def entries_for_category(category: str) -> list[dict]:
    """Filter entries berdasarkan kategori."""
    return [e for e in KNOWLEDGE_BASE if e["category"] == category]


def total_entries() -> int:
    return len(KNOWLEDGE_BASE)


if __name__ == "__main__":
    print(f"Total entries: {total_entries()}")
    print(f"\nCategories covered:")
    for cat in get_categories():
        n = len(entries_for_category(cat))
        print(f"  {cat:30s}: {n} entry(ies)")
    print(f"\nSample entry:")
    e = KNOWLEDGE_BASE[0]
    print(f"  SWC: {e['swc_id']}, Category: {e['category']}")
    print(f"  Title: {e['title']}")
    print(f"  Description: {e['description'][:100]}...")
