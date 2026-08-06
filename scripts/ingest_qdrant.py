#!/usr/bin/env python3
"""Populate Qdrant's shared triage_kb collection with MITRE ATT&CK, CVE, and
playbook data.

Usage:
  python scripts/ingest_qdrant.py mitre                    # MITRE ATT&CK
  python scripts/ingest_qdrant.py cve                      # NVD CVEs
  python scripts/ingest_qdrant.py playbooks <dir>          # local playbook files
  python scripts/ingest_qdrant.py all [--playbooks-dir=.]  # everything
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ingest_qdrant")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        Distance,
        FieldCondition,
        Filter,
        FilterSelector,
        MatchValue,
        PointStruct,
        VectorParams,
    )
except ImportError:
    logger.error("qdrant-client not installed. pip install qdrant-client sentence-transformers")
    sys.exit(1)

from config import QDRANT_COLLECTION, QDRANT_EMBEDDING_MODEL, QDRANT_URL

# Must match tools/qdrant.py exactly: one shared Qdrant collection
# (QDRANT_COLLECTION, default "triage_kb"), 1024-dim vectors from
# sentence-transformers' BAAI/bge-m3 — not fastembed, whose supported models
# don't produce 1024-dim vectors (confirmed empirically in tools/qdrant.py) —
# discriminated by a "collection" payload field. This script used to create
# three separate named Qdrant collections with fastembed/bge-small 384-dim
# vectors, silently incompatible with what tools/qdrant.py actually queries.
# See REPO-STATUS.md §9 for how that was found.
EMBED_DIM = 1024

# Discriminator values for the shared collection's "collection" payload
# field — must match tools/qdrant.py::_search()'s kb_collection argument
# exactly. Note "cve_intel", not "cve" — the two used to disagree.
KB_MITRE = "mitre_attack"
KB_CVE = "cve_intel"
KB_PLAYBOOKS = "playbooks"

MITRE_JSON_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_BATCH_SIZE = 200
CVE_MAX = 5000

_embedder = None  # sentence-transformers is a heavy import — load lazily, once


def _get_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(QDRANT_EMBEDDING_MODEL)
    return _embedder


def _ensure_shared_collection(client: QdrantClient):
    """Create the shared collection once if it doesn't exist yet. Never delete
    it here — unlike the old per-type-collection design, this one collection
    holds all three kb types, so a single ingest_mitre()/ingest_cve()/
    ingest_playbooks() run must not wipe the other two types' data."""
    if client.collection_exists(QDRANT_COLLECTION):
        logger.info("Collection '%s' already exists — reusing", QDRANT_COLLECTION)
        return
    client.create_collection(
        QDRANT_COLLECTION,
        vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
    )
    logger.info("Created collection '%s' (dim=%d, distance=%s)", QDRANT_COLLECTION, EMBED_DIM, Distance.COSINE)


def _clear_kb_type(client: QdrantClient, kb_collection: str):
    """Delete existing points for this discriminator value only, so re-running
    a single type (e.g. 'mitre') refreshes just that type's points instead of
    duplicating them or touching the other two types sharing this collection."""
    client.delete(
        collection_name=QDRANT_COLLECTION,
        points_selector=FilterSelector(
            filter=Filter(must=[FieldCondition(key="collection", match=MatchValue(value=kb_collection))])
        ),
    )


def _embed(texts: list[str], batch: int = 10) -> list[list[float]]:
    import gc
    model = _get_embedder()
    all_vecs: list[list[float]] = []
    for i in range(0, len(texts), batch):
        chunk = texts[i : i + batch]
        for vec in model.encode(chunk):
            all_vecs.append(vec.tolist())
        gc.collect()
        if (i + batch) % 100 < batch:
            logger.info("  embedded %d/%d texts", min(i + batch, len(texts)), len(texts))
    return all_vecs


def _upsert(client: QdrantClient, points: list[PointStruct], batch: int = 50):
    import gc
    for i in range(0, len(points), batch):
        chunk = points[i : i + batch]
        client.upsert(QDRANT_COLLECTION, chunk)
        del chunk
        gc.collect()
        logger.info("  upserted %d/%d points", min(i + batch, len(points)), len(points))


def _stable_id(kb_collection: str, key: str) -> int:
    return int(hashlib.sha256(f"{kb_collection}:{key}".encode()).hexdigest()[:16], 16)


def _fetch_json(url: str, retries: int = 3) -> dict:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "soc-triage-agent/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.warning("Fetch failed (attempt %d/%d): %s", attempt + 1, retries, e)
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}")


def _fetch_json_with_retry(url: str, retries: int = 3, **kwargs) -> dict | None:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "soc-triage-agent/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.error("HTTP 403 — API key required? %s", url)
                return None
            logger.warning("HTTP %d (attempt %d/%d): %s", e.code, attempt + 1, retries, e)
        except Exception as e:
            logger.warning("Fetch failed (attempt %d/%d): %s", attempt + 1, retries, e)
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    logger.error("Failed after %d retries: %s", retries, url)
    return None


def ingest_mitre(client: QdrantClient | None = None):
    logger.info("=== Ingesting MITRE ATT&CK ===")
    if client is None:
        client = _get_client()
    _ensure_shared_collection(client)
    _clear_kb_type(client, KB_MITRE)

    logger.info("Downloading MITRE ATT&CK data from MITRE CTI...")
    bundle = _fetch_json(MITRE_JSON_URL)
    objects: list[dict] = bundle.get("objects", [])

    tactics: dict[str, dict] = {}
    techniques: list[dict] = []

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "x-mitre-tactic":
            ext = obj.get("x_mitre_shortname", "")
            tactics[obj["id"]] = {
                "name": obj.get("name", ""),
                "id": obj.get("id", ""),
                "shortname": ext,
            }
        elif obj_type == "attack-pattern":
            techniques.append(obj)

    logger.info("Found %d tactics, %d attack-pattern objects", len(tactics), len(techniques))

    points: list[PointStruct] = []
    texts: list[str] = []
    payloads: list[dict] = []

    for obj in techniques:
        name = obj.get("name", "")
        description = obj.get("description", "") or ""
        technique_id = ""
        external_refs = obj.get("external_references", [])
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        if not technique_id:
            continue

        is_sub = obj.get("x_mitre_is_subtechnique", False)

        kill_chain = obj.get("kill_chain_phases", [])
        obj_tactics = []
        for kcp in kill_chain:
            phase = kcp.get("phase_name", "")
            for tid, tdata in tactics.items():
                if tdata.get("shortname") == phase:
                    obj_tactics.append(tdata["name"])
                    break
        if not obj_tactics:
            obj_tactics = ["unknown"]
        tactic_str = ", ".join(obj_tactics)

        parent_technique = ""
        if is_sub:
            x_mitre_modified_by_ref = obj.get("x_mitre_modified_by_ref", "")
            if x_mitre_modified_by_ref:
                for t in techniques:
                    if t.get("id") == x_mitre_modified_by_ref:
                        parent_technique = t.get("name", "")
                        break

        content = f"Tactic: {tactic_str}\nTechnique: {name}"
        if is_sub:
            content += f" (sub-technique of {parent_technique})"
        content += f"\nID: {technique_id}\nDescription: {description}"

        text_for_embed = (
            f"{name} ({technique_id}): {description[:2000]} "
            f"Tactics: {tactic_str}"
        )

        # Payload shape must match tools/qdrant.py::retrieve_mitre() exactly:
        # top-level text/source/collection, structured fields under metadata.
        payload = {
            "text": content,
            "source": technique_id,
            "collection": KB_MITRE,
            "metadata": {
                "technique_id": technique_id,
                "name": name,
                "tactics": obj_tactics,
                "is_subtechnique": is_sub,
                "parent_technique": parent_technique,
            },
        }

        texts.append(text_for_embed)
        payloads.append(payload)

    logger.info("Embedding %d MITRE entries with %s...", len(texts), QDRANT_EMBEDDING_MODEL)
    vectors = _embed(texts)

    for vec, payload in zip(vectors, payloads):
        pid = _stable_id(KB_MITRE, payload["metadata"]["technique_id"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, points)
    logger.info("MITRE ATT&CK ingestion done — %d points", len(points))


def ingest_cve(client: QdrantClient | None = None, max_cves: int = CVE_MAX):
    logger.info("=== Ingesting CVE data from NVD ===")
    if client is None:
        client = _get_client()
    _ensure_shared_collection(client)
    _clear_kb_type(client, KB_CVE)

    points: list[PointStruct] = []
    texts: list[str] = []
    payloads: list[dict] = []
    start_index = 0
    total_fetched = 0

    while total_fetched < max_cves:
        url = (
            f"{CVE_API_BASE}?resultsPerPage={CVE_BATCH_SIZE}"
            f"&startIndex={start_index}"
        )
        logger.info("Fetching CVEs %d-%d...", start_index, start_index + CVE_BATCH_SIZE)
        data = _fetch_json_with_retry(url)
        if data is None:
            logger.warning("NVD API returned error — stopping")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            logger.info("No more CVEs returned — done")
            break

        for vuln in vulns:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss_score: float | None = None
            for scale in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if scale in metrics:
                    cvss_score = metrics[scale][0].get("cvssData", {}).get("baseScore")
                    break

            affected_software = []
            configurations = cve.get("configurations", [])
            for cfg in configurations:
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if "enterprise_sw" in criteria or "application" in criteria:
                            parts = criteria.split(":")
                            if len(parts) > 4:
                                affected_software.append(parts[4])
            affected_str = ", ".join(sorted(set(affected_software)))[:500]

            if not description:
                continue

            text_for_embed = (
                f"{cve_id}: {description[:2000]} "
                f"CVSS: {cvss_score or 'N/A'} "
                f"Affected: {affected_str[:200]}"
            )

            # Payload shape must match tools/qdrant.py::retrieve_cve() exactly:
            # top-level text/source/collection, structured fields under
            # metadata. retrieve_cve() joins vendor_project + product with a
            # space to build affected_software — this NVD cpeMatch extraction
            # doesn't cleanly separate vendor from product, so the combined
            # string goes into vendor_project and product is left empty
            # rather than guessed (pre-existing extraction limitation, not
            # changed here).
            payload = {
                "text": description[:3000],
                "source": cve_id,
                "collection": KB_CVE,
                "metadata": {
                    "cve_id": cve_id,
                    "vendor_project": affected_str,
                    "product": "",
                    "cvss_score": cvss_score,
                },
            }

            texts.append(text_for_embed)
            payloads.append(payload)
            total_fetched += 1
            if total_fetched >= max_cves:
                break

        start_index += CVE_BATCH_SIZE
        time.sleep(0.6)

    if not texts:
        logger.warning("No CVE data fetched")
        return

    logger.info("Embedding %d CVE entries...", len(texts))
    vectors = _embed(texts)

    for vec, payload in zip(vectors, payloads):
        pid = _stable_id(KB_CVE, payload["metadata"]["cve_id"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, points)
    logger.info("CVE ingestion done — %d points", len(points))


def ingest_playbooks(client: QdrantClient | None = None, playbooks_dir: str = "."):
    logger.info("=== Ingesting playbooks from %s ===", playbooks_dir)
    if client is None:
        client = _get_client()
    _ensure_shared_collection(client)
    _clear_kb_type(client, KB_PLAYBOOKS)

    root = Path(playbooks_dir).resolve()
    if not root.is_dir():
        logger.error("Playbooks directory not found: %s", root)
        return

    content_map: dict[str, tuple[str, list[str], str]] = {}

    for ext in ("*.md", "*.mdoc", "*.yaml", "*.yml"):
        for fpath in root.rglob(ext):
            if ".git" in fpath.parts:
                continue
            try:
                raw = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.warning("Skipping %s: %s", fpath, e)
                continue

            title = fpath.stem.replace("_", " ").replace("-", " ").title()
            tags: list[str] = []

            content = raw.strip()

            if raw.startswith("---"):
                parts = raw.split("---", 2)
                if len(parts) >= 3:
                    front_raw = parts[1].strip()
                    content = parts[2].strip()
                    for line in front_raw.split("\n"):
                        if line.startswith("title:"):
                            title = line.split(":", 1)[1].strip().strip("\"'")
                        elif line.startswith("tags:"):
                            rest = line[5:].strip()
                            if rest.startswith("["):
                                tags = json.loads(rest)
                            elif rest:
                                tags = [t.strip().strip("\"'") for t in rest.split(",")]

            key = str(fpath.relative_to(root))
            content_map[key] = (content, tags, title)

    if not content_map:
        logger.warning("No playbook files found in %s", root)
        return

    points: list[PointStruct] = []
    texts: list[str] = []
    payloads: list[dict] = []

    for key, (content, tags, title) in content_map.items():
        text_for_embed = f"{title}\n{' '.join(tags)}\n{content[:2000]}"
        # Payload shape must match tools/qdrant.py::retrieve_playbooks()
        # exactly: top-level text/source/collection, title/mitre_techniques
        # under metadata.
        payload = {
            "text": content[:5000],
            "source": key,
            "collection": KB_PLAYBOOKS,
            "metadata": {
                "title": title,
                "mitre_techniques": tags,
            },
        }
        texts.append(text_for_embed)
        payloads.append(payload)

    logger.info("Embedding %d playbook entries...", len(texts))
    vectors = _embed(texts)

    for vec, payload in zip(vectors, payloads):
        pid = _stable_id(KB_PLAYBOOKS, payload["source"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, points)
    logger.info("Playbooks ingestion done — %d points", len(points))


def ingest_all(playbooks_dir: str = "."):
    client = _get_client()
    ingest_mitre(client)
    ingest_cve(client)
    ingest_playbooks(client, playbooks_dir)


def main():
    parser = argparse.ArgumentParser(description="Ingest data into Qdrant")
    parser.add_argument(
        "command",
        nargs="?",
        default="all",
        choices=["mitre", "cve", "playbooks", "all"],
        help="What to ingest (default: all)",
    )
    parser.add_argument(
        "--playbooks-dir",
        default=".",
        help="Directory containing playbook files (for 'playbooks' or 'all')",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=CVE_MAX,
        help=f"Maximum CVEs to ingest (default: {CVE_MAX})",
    )
    args = parser.parse_args()

    cmds = {"mitre": ingest_mitre, "cve": ingest_cve}
    if args.command == "all":
        ingest_all(playbooks_dir=args.playbooks_dir)
    elif args.command == "playbooks":
        ingest_playbooks(playbooks_dir=args.playbooks_dir)
    else:
        cmds[args.command]()


if __name__ == "__main__":
    main()
