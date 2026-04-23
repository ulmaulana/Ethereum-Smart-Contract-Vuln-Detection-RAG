"""
Stage 7a: Build & populate ChromaDB vector store dari KNOWLEDGE_BASE.

Setiap entry di-split menjadi beberapa "chunks":
  - description chunk
  - mitigation chunk
  - fix_code chunk

Setiap chunk di-embed pakai sentence-transformers (all-MiniLM-L6-v2),
disimpan di ChromaDB dengan metadata (swc_id, category, type, title).

Output: vector store di processed/rag_index/ (persistent ChromaDB)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from preprocessing.config import PROCESSED_DIR
from rag.knowledge_base import KNOWLEDGE_BASE, get_categories

INDEX_DIR = PROCESSED_DIR / "rag_index"
COLLECTION_NAME = "smart_contract_vuln_kb"
EMBED_MODEL = "all-MiniLM-L6-v2"


def make_chunks() -> list[dict]:
    """Pecah tiap entry KB jadi chunks (description, mitigation, fix_code)."""
    chunks = []
    for i, entry in enumerate(KNOWLEDGE_BASE):
        base_meta = {
            "swc_id": entry["swc_id"],
            "category": entry["category"],
            "title": entry["title"],
            "entry_idx": i,
        }
        # Description chunk
        chunks.append({
            "id": f"{entry['swc_id']}_{i}_desc",
            "text": f"{entry['title']} ({entry['swc_id']}, kategori {entry['category']}).\n"
                    f"{entry['description']}\n"
                    f"Contoh kode vulnerable:\n{entry['vulnerable_code']}",
            "meta": {**base_meta, "chunk_type": "description"},
        })
        # Mitigation chunk
        chunks.append({
            "id": f"{entry['swc_id']}_{i}_mitig",
            "text": f"Mitigasi untuk {entry['title']} ({entry['category']}):\n"
                    f"{entry['mitigation']}\n"
                    f"Contoh kode yang sudah aman:\n{entry['fix_code']}",
            "meta": {**base_meta, "chunk_type": "mitigation"},
        })
    return chunks


def build_index():
    print(">>> Stage 7a: Building RAG vector store from KNOWLEDGE_BASE\n")

    # Lazy import (biar kalau pip install belum, error pesan jelas)
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError as e:
        print(f"[ERROR] {e}")
        print("        pip install -r requirements.txt")
        sys.exit(1)

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[ok] Knowledge base: {len(KNOWLEDGE_BASE)} entries")
    print(f"[ok] Categories    : {get_categories()}")

    chunks = make_chunks()
    print(f"[ok] Chunks         : {len(chunks)} (description + mitigation per entry)")

    # Setup ChromaDB persistent client
    print(f"\n[..] Init ChromaDB at {INDEX_DIR}")
    client = chromadb.PersistentClient(path=str(INDEX_DIR))

    # Reset collection kalau sudah ada
    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"     (deleted existing collection)")
    except Exception:
        pass

    # Embedding function pakai sentence-transformers
    print(f"[..] Loading embedding model: {EMBED_MODEL}")
    print(f"     (first time will download ~90MB, then cached)")
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL
    )

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"description": "Smart contract vulnerability knowledge base"},
    )

    # Add all chunks
    print(f"[..] Embedding & indexing {len(chunks)} chunks...")
    collection.add(
        ids=[c["id"] for c in chunks],
        documents=[c["text"] for c in chunks],
        metadatas=[c["meta"] for c in chunks],
    )

    # Verify
    n = collection.count()
    print(f"\n[ok] Index built: {n} chunks indexed")
    print(f"[ok] Persistent at: {INDEX_DIR}")
    print(f"[ok] Collection name: {COLLECTION_NAME}")
    print(f"\nUntuk query: from src.rag.retriever import retrieve")
    print(f"             results = retrieve('reentrancy mitigation', k=3)")


if __name__ == "__main__":
    build_index()
