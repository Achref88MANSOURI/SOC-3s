from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.http import models

from config import QDRANT_COLLECTION, QDRANT_EMBEDDING_MODEL, QDRANT_URL

_client: QdrantClient | None = None
_embedder = None  # sentence-transformers is a heavy import — load lazily, once


def _get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(url=QDRANT_URL)
    return _client


def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(QDRANT_EMBEDDING_MODEL)
    return _embedder


def _search(kb_collection: str, query_text: str, top_k: int) -> list:
    """kb_collection is the 'collection' payload discriminator inside the single
    live Qdrant collection ('mitre_attack' | 'cve_intel' | 'playbooks') — the
    deployed triage_kb is one collection with a discriminator field, not three
    separate named collections. Queried with a raw vector from QDRANT_EMBEDDING_MODEL
    (BAAI/bge-m3 by default) since triage_kb's 1024-dim vectors don't match any
    fastembed-supported model (verified empirically), so qdrant_client's built-in
    Document auto-embed convenience can't be used here.
    """
    try:
        client = _get_client()
        vector = _get_embedder().encode(query_text).tolist()
        resp = client.query_points(
            collection_name=QDRANT_COLLECTION,
            query=vector,
            query_filter=models.Filter(
                must=[models.FieldCondition(key="collection", match=models.MatchValue(value=kb_collection))]
            ),
            limit=top_k,
            with_payload=True,
            with_vectors=False,
        )
        return resp.points if resp and resp.points else []
    except Exception:
        return []


def retrieve_mitre(query_text: str, top_k: int = 5) -> list[dict]:
    hits = _search("mitre_attack", query_text, top_k)
    results = []
    for h in hits:
        md = h.payload.get("metadata", {})
        tactics = md.get("tactics", []) or []
        results.append({
            "score": h.score,
            "tactic": ", ".join(tactics),
            "technique": md.get("name", ""),
            "technique_id": md.get("technique_id", h.payload.get("source", "")),
            "sub_technique": md.get("name", "") if md.get("is_subtechnique") else "",
            "description": h.payload.get("text", "")[:500],
        })
    return results


def retrieve_playbooks(query_text: str, top_k: int = 3) -> list[dict]:
    hits = _search("playbooks", query_text, top_k)
    results = []
    for h in hits:
        md = h.payload.get("metadata", {})
        results.append({
            "score": h.score,
            "title": md.get("title", ""),
            "content": h.payload.get("text", "")[:1000],
            "tags": md.get("mitre_techniques", []),
        })
    return results


def retrieve_cve(query_text: str, top_k: int = 3) -> list[dict]:
    hits = _search("cve_intel", query_text, top_k)
    results = []
    for h in hits:
        md = h.payload.get("metadata", {})
        affected = " ".join(p for p in (md.get("vendor_project", ""), md.get("product", "")) if p)
        results.append({
            "score": h.score,
            "cve_id": md.get("cve_id", h.payload.get("source", "")),
            "description": h.payload.get("text", "")[:500],
            "cvss_score": md.get("cvss_score"),
            "affected_software": affected,
        })
    return results


if __name__ == "__main__":
    import json
    test_query = "remote code execution web server"
    print("=== MITRE ===")
    print(json.dumps(retrieve_mitre(test_query), indent=2, default=str))
    print("\n=== Playbooks ===")
    print(json.dumps(retrieve_playbooks(test_query), indent=2, default=str))
    print("\n=== CVE ===")
    print(json.dumps(retrieve_cve(test_query), indent=2, default=str))
