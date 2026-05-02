"""
Explainer: gabungkan deteksi ML + retrieved chunks -> response untuk user.

Mode yang didukung:
  - MiniMax LLM-augmented RAG (wajib)

Tidak ada lagi fallback template. Kalau kredensial MiniMax tidak tersedia
atau request API gagal, proses akan raise error secara eksplisit.
"""
import json
import os
import sys
from pathlib import Path
from urllib import error, request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag.retriever import retrieve_for_category


MINIMAX_API_URL = os.environ.get(
    "MINIMAX_API_URL",
    "https://api.minimax.io/v1/chat/completions",
)
MINIMAX_MODEL = os.environ.get("MINIMAX_MODEL", "MiniMax-M2.7")
MINIMAX_MAX_TOKENS = int(os.environ.get("MINIMAX_MAX_TOKENS", "1024"))


LLM_PROMPT_TEMPLATE = """Anda adalah security auditor smart contract Ethereum.

Berikut hasil deteksi vulnerability dari model machine learning:

KATEGORI: {category}
KONTRAK: {contract_id}

KODE FUNCTION YANG TERDETEKSI:
```solidity
{function_source}
```

KNOWLEDGE BASE CONTEXT (SWC Registry + best practices):

{retrieved_context}

TUGAS:
1. Validasi apakah indikasi vulnerability ini masuk akal berdasarkan kode yang diberikan.
2. Jelaskan secara spesifik pola atau baris logika yang bermasalah.
3. Berikan mitigation yang konkret dan relevan dengan potongan kode ini.
4. Berikan contoh patch code Solidity yang lebih aman.
5. Tutup dengan referensi yang relevan.

Aturan jawaban:
- Gunakan Bahasa Indonesia.
- Ringkas, teknis, dan spesifik.
- Jangan memberi jawaban generik.
- Jika indikasinya lemah atau berpotensi false positive, katakan itu dengan jelas.
- Format jawaban pakai Markdown.
"""


def _build_retrieved_context(category: str, k: int) -> str:
    chunks = retrieve_for_category(category, k=k)
    if not chunks:
        raise RuntimeError(
            f"Tidak ada knowledge base entry untuk kategori '{category}'. "
            "Build index RAG terlebih dahulu."
        )

    return "\n\n".join(
        [
            f"[{chunk['meta']['swc_id']} - {chunk['meta']['title']} - {chunk['meta']['chunk_type']}]\n"
            f"{chunk['text']}"
            for chunk in chunks
        ]
    )


def _call_minimax(prompt: str) -> str:
    api_key = os.environ.get("MINIMAX_API_KEY")
    if not api_key:
        raise RuntimeError(
            "MINIMAX_API_KEY belum di-set. RAG sekarang wajib menggunakan MiniMax LLM."
        )

    payload = {
        "model": MINIMAX_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert Ethereum smart contract security auditor. "
                    "Produce precise, code-aware vulnerability analysis in Bahasa Indonesia."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "max_tokens": MINIMAX_MAX_TOKENS,
    }

    req = request.Request(
        MINIMAX_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=90) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"MiniMax API HTTP {exc.code}: {raw}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Gagal menghubungi MiniMax API: {exc}") from exc

    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"MiniMax API response tidak memiliki choices: {body}")

    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise RuntimeError(f"MiniMax API response tidak memiliki message.content: {body}")

    return content.strip()


def explain_with_llm(
    category: str,
    function_source: str,
    contract_id: str = "",
    k: int = 3,
    llm_provider: str = "minimax",
) -> str:
    """
    Generate personalized RAG explanation via MiniMax.

    Args:
        category: kelas vulnerability
        function_source: source function yang terdeteksi
        contract_id: nama contract/file
        k: jumlah retrieved chunks
        llm_provider: harus 'minimax' atau 'auto'
    """
    if llm_provider not in ("minimax", "auto"):
        raise ValueError(
            f"Provider '{llm_provider}' tidak didukung. Gunakan 'minimax'."
        )

    retrieved_context = _build_retrieved_context(category, k=k)
    prompt = LLM_PROMPT_TEMPLATE.format(
        category=category,
        contract_id=contract_id or "-",
        function_source=function_source[:1500] or "// function source unavailable",
        retrieved_context=retrieved_context,
    )
    return _call_minimax(prompt)


if __name__ == "__main__":
    print(">>> Explainer Self-Test (MiniMax)\n")
    sample_code = """function withdraw() public {
    uint amount = balances[msg.sender];
    msg.sender.call.value(amount)();
    balances[msg.sender] = 0;
}"""
    print(
        explain_with_llm(
            category="reentrancy",
            function_source=sample_code,
            contract_id="VulnerableVault.sol",
        )
    )
