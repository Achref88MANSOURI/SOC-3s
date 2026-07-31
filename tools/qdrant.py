from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.http import models

from config import QDRANT_URL


_client: QdrantClient | None = None


def _get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(url=QDRANT_URL)
    return _client


def _search(collection: str, query_text: str, top_k: int) -> list:
    try:
        client = _get_client()
        resp = client.query_points(
            collection_name=collection,
            query=models.Document(text=query_text, model=client.DEFAULT_EMBEDDING_MODEL),
            limit=top_k,
            with_payload=True,
            with_vectors=False,
        )
        return resp.points if resp and resp.points else []
    except Exception as e:
        return []


def retrieve_mitre(query_text: str, top_k: int = 5) -> list[dict]:
    hits = _search("mitre_attack", query_text, top_k)
    return [
        {
            "score": h.score,
            "tactic": h.payload.get("tactic", ""),
            "technique": h.payload.get("technique", ""),
            "technique_id": h.payload.get("technique_id", ""),
            "sub_technique": h.payload.get("sub_technique", ""),
            "description": h.payload.get("description", "")[:500],
        }
        for h in hits
    ]


def retrieve_playbooks(query_text: str, top_k: int = 3) -> list[dict]:
    hits = _search("playbooks", query_text, top_k)
    return [
        {
            "score": h.score,
            "title": h.payload.get("title", ""),
            "content": h.payload.get("content", "")[:1000],
            "tags": h.payload.get("tags", []),
        }
        for h in hits
    ]


def retrieve_cve(query_text: str, top_k: int = 3) -> list[dict]:
    hits = _search("cve", query_text, top_k)
    return [
        {
            "score": h.score,
            "cve_id": h.payload.get("cve_id", ""),
            "description": h.payload.get("description", "")[:500],
            "cvss_score": h.payload.get("cvss_score"),
            "affected_software": h.payload.get("affected_software", ""),
        }
        for h in hits
    ]


if __name__ == "__main__":
    import json
    test_query = "remote code execution web server"
    print("=== MITRE ===")
    print(json.dumps(retrieve_mitre(test_query), indent=2, default=str))
    print("\n=== Playbooks ===")
    print(json.dumps(retrieve_playbooks(test_query), indent=2, default=str))
    print("\n=== CVE ===")
    print(json.dumps(retrieve_cve(test_query), indent=2, default=str))
