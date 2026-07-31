#!/usr/bin/env python3
"""Populate Qdrant collections: mitre_attack, cve, playbooks.

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
import os
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ingest_qdrant")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams
except ImportError:
    logger.error("qdrant-client not installed. pip install qdrant-client fastembed")
    sys.exit(1)

from config import QDRANT_URL

EMBED_MODEL = "BAAI/bge-small-en"
EMBED_DIM = 384

COLLECTION_CONFIGS = {
    "mitre_attack": VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
    "cve": VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
    "playbooks": VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
}

MITRE_JSON_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_BATCH_SIZE = 200
CVE_MAX = 5000


def _get_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL)


def _ensure_collection(client: QdrantClient, name: str):
    vec_cfg = COLLECTION_CONFIGS.get(name)
    if not vec_cfg:
        raise ValueError(f"Unknown collection: {name}")
    existing = client.collection_exists(name)
    if existing:
        logger.info("Collection '%s' already exists — recreating", name)
        client.delete_collection(name)
    client.create_collection(name, vectors_config=vec_cfg)
    logger.info("Created collection '%s' (dim=%d, distance=%s)", name, EMBED_DIM, Distance.COSINE)


def _embed(texts: list[str], batch: int = 10) -> list[list[float]]:
    import gc
    from fastembed import TextEmbedding
    model = TextEmbedding(EMBED_MODEL)
    all_vecs: list[list[float]] = []
    for i in range(0, len(texts), batch):
        chunk = texts[i : i + batch]
        for vec in model.embed(chunk):
            all_vecs.append(vec.tolist())
        gc.collect()
        if (i + batch) % 100 < batch:
            logger.info("  embedded %d/%d texts", min(i + batch, len(texts)), len(texts))
    return all_vecs


def _upsert(client: QdrantClient, collection: str, points: list[PointStruct], batch: int = 50):
    import gc
    for i in range(0, len(points), batch):
        chunk = points[i : i + batch]
        client.upsert(collection, chunk)
        del chunk
        gc.collect()
        logger.info("  upserted %d/%d points", min(i + batch, len(points)), len(points))


def _stable_id(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest()[:16], 16)


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
    _ensure_collection(client, "mitre_attack")

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
        stix_id = obj.get("id", "")
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
        sub_technique = name if is_sub else ""

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

        payload = {
            "technique_id": technique_id,
            "technique": name,
            "tactic": tactic_str,
            "sub_technique": sub_technique,
            "description": description[:3000] if description else "",
            "parent_technique": parent_technique,
        }

        texts.append(text_for_embed)
        payloads.append(payload)

    logger.info("Embedding %d MITRE entries with %s...", len(texts), EMBED_MODEL)
    vectors = _embed(texts)

    for i, (vec, payload) in enumerate(zip(vectors, payloads)):
        pid = _stable_id(payload["technique_id"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, "mitre_attack", points)
    logger.info("MITRE ATT&CK ingestion done — %d points", len(points))


def ingest_cve(client: QdrantClient | None = None, max_cves: int = CVE_MAX):
    logger.info("=== Ingesting CVE data from NVD ===")
    if client is None:
        client = _get_client()
    _ensure_collection(client, "cve")

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

            payload = {
                "cve_id": cve_id,
                "description": description[:3000],
                "cvss_score": cvss_score,
                "affected_software": affected_str,
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

    for i, (vec, payload) in enumerate(zip(vectors, payloads)):
        pid = _stable_id(payload["cve_id"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, "cve", points)
    logger.info("CVE ingestion done — %d points", len(points))


def ingest_playbooks(client: QdrantClient | None = None, playbooks_dir: str = "."):
    logger.info("=== Ingesting playbooks from %s ===", playbooks_dir)
    if client is None:
        client = _get_client()
    _ensure_collection(client, "playbooks")

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
        payload = {
            "title": title,
            "content": content[:5000],
            "tags": tags,
            "source": key,
        }
        texts.append(text_for_embed)
        payloads.append(payload)

    logger.info("Embedding %d playbook entries...", len(texts))
    vectors = _embed(texts)

    for i, (vec, payload) in enumerate(zip(vectors, payloads)):
        pid = _stable_id(payload["source"])
        points.append(PointStruct(id=pid, vector=vec, payload=payload))

    _upsert(client, "playbooks", points)
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
