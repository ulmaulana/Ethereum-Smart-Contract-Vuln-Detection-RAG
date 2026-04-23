"""
Explainer: gabungkan deteksi ML + retrieved chunks -> response untuk user.

Dua mode:
  1. Template-based (default, gratis, tidak butuh LLM API)
     - Format response dari knowledge base entry langsung
  2. LLM-augmented (opsional, butuh API key Anthropic atau OpenAI)
     - Pakai retrieved chunks + kode user sebagai context
     - Generate penjelasan personalized
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag.retriever import retrieve_for_category


# =====================================================================
# Template-based explanation (no LLM needed)
# =====================================================================

def explain_template(category: str, function_source: str = "",
                     contract_id: str = "", k: int = 2) -> str:
    """
    Generate template response berdasarkan retrieved chunks.
    Tidak butuh LLM, langsung pakai konten knowledge base.
    """
    chunks = retrieve_for_category(category, k=k)
    if not chunks:
        return f"[!] Tidak ada knowledge base entry untuk kategori '{category}'."

    # Pisahkan description vs mitigation
    desc_chunks = [c for c in chunks if c["meta"]["chunk_type"] == "description"]
    mitig_chunks = [c for c in chunks if c["meta"]["chunk_type"] == "mitigation"]

    main = desc_chunks[0] if desc_chunks else chunks[0]
    mitig = mitig_chunks[0] if mitig_chunks else chunks[-1]

    output = []
    output.append(f"### Vulnerability Detected: {main['meta']['title']}")
    output.append(f"**SWC**: {main['meta']['swc_id']} | **Kategori**: {category}")
    if contract_id:
        output.append(f"**Contract**: {contract_id}")
    output.append("")

    output.append("**Penjelasan**:")
    output.append(main["text"])
    output.append("")

    output.append("**Mitigasi & Cara Memperbaiki**:")
    output.append(mitig["text"])
    output.append("")

    if function_source:
        output.append("**Kode Anda yang Terdeteksi**:")
        output.append("```solidity")
        snippet = function_source[:500] + ("..." if len(function_source) > 500 else "")
        output.append(snippet)
        output.append("```")

    output.append("\n**Referensi**:")
    output.append(f"- https://swcregistry.io/docs/{main['meta']['swc_id']}")
    output.append(f"- https://consensys.github.io/smart-contract-best-practices/")

    return "\n".join(output)


# =====================================================================
# LLM-augmented explanation (opsional)
# =====================================================================

LLM_PROMPT_TEMPLATE = """Anda adalah security auditor smart contract Ethereum. Berikut hasil deteksi vulnerability dari ML model:

KATEGORI: {category}
KONTRAK: {contract_id}

KODE FUNCTION YANG DETEKSI POSITIF:
```solidity
{function_source}
```

KNOWLEDGE BASE CONTEXT (dari SWC Registry & ConsenSys best practices):

{retrieved_context}

TUGAS:
1. Konfirmasi apakah deteksi ini valid berdasarkan kode (kemungkinan true positive vs false positive).
2. Jelaskan SECARA SPESIFIK bagian kode yang vulnerable (line/pattern).
3. Berikan kode perbaikan konkret untuk function ini (bukan generic).
4. Sebutkan referensi yang relevan.

Jawab dalam Bahasa Indonesia, ringkas tapi teknis (max 400 kata)."""


def explain_with_llm(category: str, function_source: str,
                     contract_id: str = "", k: int = 3,
                     llm_provider: str = "auto") -> str:
    """
    Generate response personalized pakai LLM (Claude atau OpenAI).

    Args:
        llm_provider: 'anthropic', 'openai', atau 'auto' (pilih yg ada API key)

    Returns:
        Generated text dari LLM. Kalau LLM tidak available, fallback ke template.
    """
    chunks = retrieve_for_category(category, k=k)
    retrieved_context = "\n\n".join([
        f"[{c['meta']['swc_id']} - {c['meta']['title']}]\n{c['text']}"
        for c in chunks
    ])

    prompt = LLM_PROMPT_TEMPLATE.format(
        category=category,
        contract_id=contract_id or "-",
        function_source=function_source[:1500],
        retrieved_context=retrieved_context,
    )

    # Try Anthropic first (kalau ANTHROPIC_API_KEY set)
    if llm_provider in ("auto", "anthropic") and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic
            client = anthropic.Anthropic()
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as e:
            print(f"[warn] Anthropic API gagal: {e}")

    # Fallback ke OpenAI
    if llm_provider in ("auto", "openai") and os.environ.get("OPENAI_API_KEY"):
        try:
            from openai import OpenAI
            client = OpenAI()
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )
            return resp.choices[0].message.content
        except Exception as e:
            print(f"[warn] OpenAI API gagal: {e}")

    # Fallback final: template-based
    print("[info] LLM tidak available (set ANTHROPIC_API_KEY atau OPENAI_API_KEY), "
          "fallback ke template")
    return explain_template(category, function_source, contract_id, k=2)


# =====================================================================
# Self-test
# =====================================================================

if __name__ == "__main__":
    print(">>> Explainer Self-Test (template-based)\n")
    sample_code = """function withdraw() public {
    uint amount = balances[msg.sender];
    msg.sender.call.value(amount)();
    balances[msg.sender] = 0;
}"""

    out = explain_template(
        category="reentrancy",
        function_source=sample_code,
        contract_id="VulnerableVault.sol",
    )
    print(out)
