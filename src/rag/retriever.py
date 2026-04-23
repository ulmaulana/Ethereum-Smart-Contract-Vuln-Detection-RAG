"""
Retriever interface untuk RAG. Pakai ChromaDB yang sudah di-build oleh build_index.py.

Dua mode query:
  1. retrieve(query_text, k=3)              -> top-k chunks paling relevan
  2. retrieve_for_category(category, k=3)   -> filter by kategori vulnerability
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.config import PROCESSED_DIR

INDEX_DIR = PROCESSED_DIR / "rag_index"
COLLECTION_NAME = "smart_contract_vuln_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"


_collection_cache = None


def _get_collection():
    """Lazy load collection (sekali per process)."""
    global _collection_cache
    if _collection_cache is None:
        try:
            import chromadb
            from chromadb.utils import embedding_functions
        except ImportError as e:
            raise RuntimeError(f"Install chromadb: pip install chromadb\n{e}")

        if not INDEX_DIR.exists():
            raise FileNotFoundError(
                f"RAG index belum di-build. Jalankan: python src/rag/build_index.py"
            )

        client = chromadb.PersistentClient(path=str(INDEX_DIR))
        embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBED_MODEL
        )
        _collection_cache = client.get_collection(
            name=COLLECTION_NAME, embedding_function=embed_fn
        )
    return _collection_cache


def retrieve(query: str, k: int = 3, category_filter: str | None = None) -> list[dict]:
    """
    Search top-k chunks paling relevan untuk query.

    Args:
        query: text query (mis. "reentrancy mitigation Solidity")
        k: jumlah chunks dikembalikan
        category_filter: kalau di-set, hanya return chunks di kategori tsb

    Returns:
        List of dicts: {id, text, meta, distance}
    """
    coll = _get_collection()
    where = {"category": category_filter} if category_filter else None

    results = coll.query(
        query_texts=[query],
        n_results=k,
        where=where,
    )
    out = []
    for i in range(len(results["ids"][0])):
        out.append({
            "id": results["ids"][0][i],
            "text": results["documents"][0][i],
            "meta": results["metadatas"][0][i],
            "distance": results["distances"][0][i] if "distances" in results else None,
        })
    return out


def retrieve_for_category(category: str, k: int = 3) -> list[dict]:
    """Shortcut: retrieve menggunakan kategori sebagai query + filter."""
    return retrieve(
        query=f"{category} vulnerability mitigation Solidity smart contract",
        k=k,
        category_filter=category,
    )


# =====================================================================
# Self-test / demo
# =====================================================================

if __name__ == "__main__":
    print(">>> RAG Retriever Self-Test\n")
    queries = [
        ("reentrancy attack mitigation", None),
        ("integer overflow", None),
        ("randomness oracle", None),
        ("tx.origin authentication", "access_control"),
    ]
    for q, cat in queries:
        cat_str = f" (filter={cat})" if cat else ""
        print(f"\n=== Query: '{q}'{cat_str} ===")
        try:
            results = retrieve(q, k=2, category_filter=cat)
            for r in results:
                print(f"  [{r['meta']['swc_id']}] {r['meta']['title']} "
                      f"({r['meta']['chunk_type']}, dist={r['distance']:.3f})")
                print(f"    {r['text'][:120]}...")
        except Exception as e:
            print(f"  ERROR: {e}")
