from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

_REQUIRED = [
    "CORTEX_URL",
    "CORTEX_API_KEY",
    "THEHIVE_URL",
    "THEHIVE_API_KEY",
    "ITOP_URL",
    "ITOP_USER",
    "ITOP_KEY",
    "ES_URL",
    "LLM_BASE_URL",
    "LLM_MODEL",
]

_missing = [name for name in _REQUIRED if not os.environ.get(name)]
if _missing:
    raise RuntimeError(
        f"Missing required environment variable(s): {', '.join(_missing)}. "
        f"Set them in .env before starting the service."
    )


@dataclass
class Settings:
    cortex_url: str = field(default_factory=lambda: os.environ["CORTEX_URL"].rstrip("/"))
    cortex_api_key: str = field(default_factory=lambda: os.environ["CORTEX_API_KEY"])

    thehive_url: str = field(default_factory=lambda: os.environ["THEHIVE_URL"].rstrip("/"))
    thehive_api_key: str = field(default_factory=lambda: os.environ["THEHIVE_API_KEY"])

    itop_url: str = field(default_factory=lambda: os.environ["ITOP_URL"].rstrip("/"))
    itop_user: str = field(default_factory=lambda: os.environ["ITOP_USER"])
    itop_key: str = field(default_factory=lambda: os.environ["ITOP_KEY"])

    es_url: str = field(default_factory=lambda: os.environ["ES_URL"].rstrip("/"))
    es_api_key: str = field(default_factory=lambda: os.environ.get("ES_API_KEY", ""))

    llm_base_url: str = field(default_factory=lambda: os.environ["LLM_BASE_URL"].rstrip("/"))
    llm_model: str = field(default_factory=lambda: os.environ["LLM_MODEL"])
    llm_api_key: str = field(default_factory=lambda: os.environ.get("LLM_API_KEY", ""))

    llm_analyze_base_url: str = field(default_factory=lambda: os.environ.get("LLM_ANALYZE_BASE_URL", "").rstrip("/") or os.environ["LLM_BASE_URL"].rstrip("/"))
    llm_analyze_model: str = field(default_factory=lambda: os.environ.get("LLM_ANALYZE_MODEL", "") or os.environ["LLM_MODEL"])
    llm_analyze_api_key: str = field(default_factory=lambda: os.environ.get("LLM_ANALYZE_API_KEY", "") or os.environ.get("LLM_API_KEY", ""))

    qdrant_url: str = field(default_factory=lambda: os.environ.get("QDRANT_URL", "http://localhost:6333"))
    qdrant_collection: str = field(default_factory=lambda: os.environ.get("QDRANT_COLLECTION", "triage_kb"))
    qdrant_embedding_model: str = field(default_factory=lambda: os.environ.get("QDRANT_EMBEDDING_MODEL", "BAAI/bge-m3"))

    redis_url: str | None = field(default_factory=lambda: os.environ.get("REDIS_URL") or None)

    fp_db_path: str = field(default_factory=lambda: os.environ.get("FP_DB_PATH", "./data/fp_events.db"))

    max_tool_calls_new: int = field(default_factory=lambda: int(os.environ.get("MAX_TOOL_CALLS_NEW", "8")))
    max_tool_calls_merge: int = field(default_factory=lambda: int(os.environ.get("MAX_TOOL_CALLS_MERGE", "5")))
    dedup_window_seconds: int = field(default_factory=lambda: int(os.environ.get("DEDUP_WINDOW_SECONDS", "300")))


settings = Settings()


CORTEX_URL: str = settings.cortex_url
CORTEX_API_KEY: str = settings.cortex_api_key

THEHIVE_URL: str = settings.thehive_url
THEHIVE_API_KEY: str = settings.thehive_api_key

ITOP_URL: str = settings.itop_url
ITOP_USER: str = settings.itop_user
ITOP_KEY: str = settings.itop_key

ES_URL: str = settings.es_url
ES_API_KEY: str = settings.es_api_key

LLM_BASE_URL: str = settings.llm_base_url
LLM_MODEL: str = settings.llm_model
LLM_API_KEY: str = settings.llm_api_key

LLM_ANALYZE_BASE_URL: str = settings.llm_analyze_base_url
LLM_ANALYZE_MODEL: str = settings.llm_analyze_model
LLM_ANALYZE_API_KEY: str = settings.llm_analyze_api_key

QDRANT_URL: str = settings.qdrant_url
QDRANT_COLLECTION: str = settings.qdrant_collection
QDRANT_EMBEDDING_MODEL: str = settings.qdrant_embedding_model

REDIS_URL: str | None = settings.redis_url

FP_DB_PATH: str = settings.fp_db_path

AGENT1_MAX_ITERATIONS_NEW: int = settings.max_tool_calls_new
AGENT1_MAX_ITERATIONS_MERGE: int = settings.max_tool_calls_merge
DEDUP_WINDOW_SECONDS: int = settings.dedup_window_seconds


def _mask(value: str) -> str:
    if not value:
        return "(empty)"
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


if __name__ == "__main__":
    print("Cortex")
    print(f"  CORTEX_URL           = {CORTEX_URL}")
    print(f"  CORTEX_API_KEY       = {_mask(CORTEX_API_KEY)}")

    print("TheHive")
    print(f"  THEHIVE_URL          = {THEHIVE_URL}")
    print(f"  THEHIVE_API_KEY      = {_mask(THEHIVE_API_KEY)}")

    print("iTop")
    print(f"  ITOP_URL             = {ITOP_URL}")
    print(f"  ITOP_USER            = {ITOP_USER}")
    print(f"  ITOP_KEY             = {_mask(ITOP_KEY)}")

    print("Elasticsearch")
    print(f"  ES_URL               = {ES_URL}")
    print(f"  ES_API_KEY           = {_mask(ES_API_KEY)}")

    print("LLM (shared — perceive, investigate)")
    print(f"  LLM_BASE_URL         = {LLM_BASE_URL}")
    print(f"  LLM_MODEL            = {LLM_MODEL}")
    print(f"  LLM_API_KEY          = {_mask(LLM_API_KEY) if LLM_API_KEY else '(not set)'}")

    print("LLM (analyze — set separately to use a different model)")
    print(f"  LLM_ANALYZE_BASE_URL = {LLM_ANALYZE_BASE_URL}")
    print(f"  LLM_ANALYZE_MODEL    = {LLM_ANALYZE_MODEL}")
    print(f"  LLM_ANALYZE_API_KEY  = {_mask(LLM_ANALYZE_API_KEY) if LLM_ANALYZE_API_KEY else '(not set)'}")

    print("Qdrant")
    print(f"  QDRANT_URL           = {QDRANT_URL}")
    print(f"  QDRANT_COLLECTION    = {QDRANT_COLLECTION}")
    print(f"  QDRANT_EMBEDDING_MODEL = {QDRANT_EMBEDDING_MODEL}")

    print("Redis")
    print(f"  REDIS_URL            = {REDIS_URL if REDIS_URL else '(not set — Redis disabled)'}")

    print("FP tracking")
    print(f"  FP_DB_PATH           = {FP_DB_PATH}")

    print("Tunables")
    print(f"  AGENT1_MAX_ITERATIONS_NEW   = {AGENT1_MAX_ITERATIONS_NEW}")
    print(f"  AGENT1_MAX_ITERATIONS_MERGE = {AGENT1_MAX_ITERATIONS_MERGE}")
    print(f"  DEDUP_WINDOW_SECONDS        = {DEDUP_WINDOW_SECONDS}")
