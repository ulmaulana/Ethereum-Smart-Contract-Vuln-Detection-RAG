"""
Metadata 10 famous hack contracts (sudah include di SmartBugs Curated dataset).

Setiap entry mendokumentasikan:
  - Real-world incident (nama, tahun, kerugian USD/ETH)
  - Expected vulnerability classes (gold label dari Curated)
  - Postmortem URL untuk validasi reader
  - Vulnerable function hint (untuk highlight di report)

Source contracts ada di:
  dataset/smartbugs-curated-main/dataset/<category_folder>/<filename>
"""

HACK_CONTRACTS = [
    # =================================================================
    # REENTRANCY CLASS
    # =================================================================
    {
        "id": "the_dao",
        "name": "The DAO",
        "year": 2016,
        "loss_str": "$60,000,000",
        "loss_summary": "60 juta USD ETH dicuri (~3.6 juta ETH), memicu hard fork Ethereum jadi ETH + ETC",
        "filename": "reentrancy_dao.sol",
        "category_folder": "reentrancy",
        "expected_classes": ["reentrancy"],
        "vulnerable_function_hints": ["withdrawReward", "splitDAO", "withdraw"],
        "description": (
            "Hack DeFi pertama yang sangat besar. Attacker eksploitasi recursive call "
            "pada fungsi splitDAO() — call.value() ke external address SEBELUM update "
            "internal state, sehingga attacker bisa withdraw berkali-kali dalam 1 transaksi."
        ),
        "postmortem_url": "https://www.gemini.com/cryptopedia/the-dao-hack-makerdao",
    },
    {
        "id": "spankchain",
        "name": "SpankChain Payment Channel",
        "year": 2018,
        "loss_str": "$40,000",
        "loss_summary": "165 ETH (~$40k) dicuri via reentrancy pada payment channel",
        "filename": "spank_chain_payment.sol",
        "category_folder": "reentrancy",
        "expected_classes": ["reentrancy"],
        "vulnerable_function_hints": ["LCOpenTimeout", "deposit", "consensusCloseChannel"],
        "description": (
            "Adult-entertainment platform crypto. Bug di state channel implementation: "
            "ETH transfer dilakukan SEBELUM channel state direset. Attacker reentrant call "
            "ke fungsi yang sama untuk drain saldo channel."
        ),
        "postmortem_url": "https://medium.com/spankchain/we-got-spanked-what-we-know-so-far-d5ed3a0f38fe",
    },
    {
        "id": "etherstore",
        "name": "EtherStore (Educational Reentrancy Pattern)",
        "year": 2017,
        "loss_str": "Demo / Educational",
        "loss_summary": "Pola klasik reentrancy yang dipakai sebagai contoh di textbook security audit",
        "filename": "etherstore.sol",
        "category_folder": "reentrancy",
        "expected_classes": ["reentrancy"],
        "vulnerable_function_hints": ["withdrawFunds"],
        "description": (
            "Kontrak edukasi yang merepresentasikan pola DAO-style reentrancy: "
            "withdraw() melakukan external call SEBELUM mengubah state mapping balance."
        ),
        "postmortem_url": "https://github.com/sigp/solidity-security-blog#reentrancy",
    },

    # =================================================================
    # ACCESS CONTROL CLASS
    # =================================================================
    {
        "id": "parity_wallet",
        "name": "Parity Multisig Wallet (Library v2)",
        "year": 2017,
        "loss_str": "$280,000,000 frozen",
        "loss_summary": "513,774 ETH frozen permanen via accidental selfdestruct() pada library wallet",
        "filename": "parity_wallet_bug_2.sol",
        "category_folder": "access_control",
        "expected_classes": ["access_control"],
        "vulnerable_function_hints": ["initWallet", "kill", "initMultiowned"],
        "description": (
            "Library kontrak Parity Multisig tanpa initialization protection. Seorang user "
            "bernama 'devops199' tidak sengaja jadi owner library, lalu memanggil kill() "
            "yang men-suicide library, membekukan dana di SEMUA wallet yang depend padanya."
        ),
        "postmortem_url": "https://www.parity.io/blog/security-alert-2/",
    },
    {
        "id": "rubixi",
        "name": "Rubixi Ponzi Contract",
        "year": 2016,
        "loss_str": "Ownership stolen",
        "loss_summary": "Constructor bug — kontrak direname dari 'DynamicPyramid' ke 'Rubixi' tapi "
                        "constructor lama tidak diubah. Siapapun bisa jadi owner dengan call DynamicPyramid().",
        "filename": "rubixi.sol",
        "category_folder": "access_control",
        "expected_classes": ["access_control"],
        "vulnerable_function_hints": ["DynamicPyramid", "collectAllFees"],
        "description": (
            "Bug klasik Solidity <0.4.22: constructor diidentifikasi dari nama function "
            "yang sama dengan kontrak. Kalau kontrak di-rename tapi function lama (DynamicPyramid) "
            "tidak diubah, fungsi itu jadi public dan siapapun bisa overwrite ownership."
        ),
        "postmortem_url": "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7/",
    },

    # =================================================================
    # BAD RANDOMNESS CLASS
    # =================================================================
    {
        "id": "smart_billions",
        "name": "SmartBillions Lottery",
        "year": 2017,
        "loss_str": "400 ETH (~$120,000)",
        "loss_summary": "Jackpot ~400 ETH di-drain karena RNG pakai blockhash yang predictable",
        "filename": "smart_billions.sol",
        "category_folder": "bad_randomness",
        "expected_classes": ["bad_randomness"],
        "vulnerable_function_hints": ["play", "spin"],
        "description": (
            "Lottery contract pakai blockhash(blocknumber - N) sebagai sumber randomness. "
            "Attacker bisa hitung di muka karena blockhash deterministic & publik. "
            "Hanya butuh smart contract sebagai client untuk auto-bet hanya saat menang."
        ),
        "postmortem_url": "https://www.reddit.com/r/ethereum/comments/74d3dc/smartbillions_lottery_contract_just_got_hacked/",
    },
    {
        "id": "lottery",
        "name": "SmartBugs Lottery (PRNG vulnerability)",
        "year": 2017,
        "loss_str": "Exploitable demo",
        "loss_summary": "Lottery yang pakai keccak256(now, block.difficulty, ...) — predictable RNG",
        "filename": "lottery.sol",
        "category_folder": "bad_randomness",
        "expected_classes": ["bad_randomness"],
        "vulnerable_function_hints": ["draw", "play"],
        "description": (
            "Lottery dengan PRNG dari kombinasi block variables (timestamp, difficulty, "
            "blockhash). Semua input bersifat publik atau bisa dipengaruhi miner."
        ),
        "postmortem_url": "https://github.com/smartbugs/smartbugs-curated/tree/main/dataset/bad_randomness",
    },

    # =================================================================
    # ARITHMETIC OVERFLOW CLASS
    # =================================================================
    {
        "id": "bec_token",
        "name": "BeautyChain (BEC) Token",
        "year": 2018,
        "loss_str": "$900,000,000 market cap loss",
        "loss_summary": "Integer overflow pada batchTransfer() menciptakan token dari udara, "
                        "market cap BEC anjlok dari $900M jadi nyaris 0 dalam 1 hari",
        "filename": "BECToken.sol",
        "category_folder": "arithmetic",
        "expected_classes": ["arithmetic"],
        "vulnerable_function_hints": ["batchTransfer"],
        "description": (
            "Fungsi batchTransfer(receivers, value) hitung amount = receivers.length * value. "
            "Tanpa SafeMath, nilai value yang sangat besar bikin overflow ke 0, lulus require() "
            "balance check, dan attacker dapat 2^255 token gratis."
        ),
        "postmortem_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-10299",
    },

    # =================================================================
    # UNCHECKED LOW-LEVEL CALLS / KING OF THE ETHER
    # =================================================================
    {
        "id": "king_of_the_ether",
        "name": "King of the Ether Throne",
        "year": 2016,
        "loss_str": "Dana stuck (game broken)",
        "loss_summary": "Game throne broken: send() ke previous king bisa fail (gas limit), "
                        "tapi return value tidak dicek — claim throne berhasil meskipun refund gagal",
        "filename": "king_of_the_ether_throne.sol",
        "category_folder": "unchecked_low_level_calls",
        "expected_classes": ["unchecked_low_level_calls", "denial_of_service"],
        "vulnerable_function_hints": ["claimThrone", "fallback"],
        "description": (
            "Game 'King of the Ether': siapa kirim ETH terbesar jadi raja, dan refund ke "
            "raja lama. Kalau raja lama adalah kontrak yang fallback-nya gas-greedy, send() "
            "fail tapi return value tidak diperiksa. King terdahulu kehilangan refund-nya."
        ),
        "postmortem_url": "https://www.kingoftheether.com/postmortem.html",
    },

    # =================================================================
    # TIME MANIPULATION
    # =================================================================
    {
        "id": "governmental",
        "name": "GovernMental Ponzi",
        "year": 2016,
        "loss_str": "1,100 ETH stuck",
        "loss_summary": "Jackpot 1100 ETH (~$300k saat itu) tidak bisa di-payout karena gas "
                        "limit exceed — loop terlalu panjang, plus dependency ke block.timestamp",
        "filename": "governmental_survey.sol",
        "category_folder": "time_manipulation",
        "expected_classes": ["time_manipulation", "denial_of_service"],
        "vulnerable_function_hints": ["claimReward", "lendGovernmentMoney"],
        "description": (
            "Ponzi yang bayar jackpot kalau tidak ada peserta baru selama 12 jam. "
            "Pakai block.timestamp untuk cek deadline + loop iterasi semua peserta. "
            "Saat jackpot membesar, payout function mengexceed block gas limit (DoS) dan "
            "miner bisa manipulasi timestamp ±15 detik untuk extend deadline."
        ),
        "postmortem_url": "https://www.kingoftheether.com/postmortem.html",
    },
]


CLASS_LABELS = {
    "reentrancy": "Reentrancy",
    "access_control": "Access Control",
    "arithmetic": "Arithmetic (Over/Underflow)",
    "bad_randomness": "Bad Randomness",
    "denial_of_service": "Denial of Service",
    "time_manipulation": "Time Manipulation",
    "unchecked_low_level_calls": "Unchecked Low-Level Calls",
}


def get_hack_by_filename(filename: str) -> dict | None:
    for h in HACK_CONTRACTS:
        if h["filename"] == filename:
            return h
    return None


if __name__ == "__main__":
    print(f"Total hack contracts: {len(HACK_CONTRACTS)}")
    print("\nClass coverage:")
    from collections import Counter
    cov = Counter()
    for h in HACK_CONTRACTS:
        for c in h["expected_classes"]:
            cov[c] += 1
    for c, n in sorted(cov.items()):
        print(f"  {c:30s} : {n} contract(s)")
