from __future__ import annotations

import requests

from config import THEHIVE_API_KEY, THEHIVE_URL

REQUEST_TIMEOUT = 15


def _headers():
    return {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
    }


def _thehive_get(path: str, params: dict | None = None) -> dict | list:
    resp = requests.get(
        f"{THEHIVE_URL}/api{path}",
        headers=_headers(),
        params=params,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _thehive_post(path: str, body: dict) -> dict | list:
    resp = requests.post(
        f"{THEHIVE_URL}/api{path}",
        headers=_headers(),
        json=body,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _thehive_patch(path: str, body: dict) -> dict | list:
    resp = requests.patch(
        f"{THEHIVE_URL}/api{path}",
        headers=_headers(),
        json=body,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def search_open_cases(
    observables: list[str] | None = None,
    host: str | None = None,
    user: str | None = None,
) -> list[dict]:
    should_clauses = []

    if observables:
        for obs in observables:
            should_clauses.append({
                "terms": {"observable": [obs]},
            })

    if host:
        should_clauses.append({"match": {"host": host}})

    if user:
        should_clauses.append({"match": {"user": user}})

    if not should_clauses:
        return []

    query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
        "filter": [
            {"terms": {"status": ["Open", "InProgress"]}},
        ],
    }

    try:
        result = _thehive_post("/v1/query", query)
        cases = result if isinstance(result, list) else result.get("data", [])
        return [
            {
                "case_id": c.get("_id", c.get("id", "")),
                "title": c.get("title", ""),
                "severity": c.get("severity", 0),
                "status": c.get("status", ""),
                "tags": c.get("tags", []),
                "description": c.get("description", ""),
                "host": c.get("host", ""),
                "user": c.get("user", ""),
                "observables": c.get("observables", []),
                "created_at": c.get("createdAt", ""),
            }
            for c in cases
        ]
    except requests.exceptions.RequestException:
        return []


def search_closed_cases(
    rule_uuid: str | None = None,
    observables: list[str] | None = None,
) -> list[dict]:
    should_clauses = []

    if rule_uuid:
        should_clauses.append({"match": {"rule_uuid": rule_uuid}})

    if observables:
        for obs in observables:
            should_clauses.append({"terms": {"observable": [obs]}})

    if not should_clauses:
        return []

    query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
        "filter": [
            {"terms": {"status": ["Resolved", "Closed"]}},
        ],
        "size": 20,
        "sort": [{"createdAt": "desc"}],
    }

    try:
        result = _thehive_post("/v1/query", query)
        cases = result if isinstance(result, list) else result.get("data", [])
        return [
            {
                "case_id": c.get("_id", c.get("id", "")),
                "title": c.get("title", ""),
                "severity": c.get("severity", 0),
                "status": c.get("status", ""),
                "tags": c.get("tags", []),
                "resolution": c.get("resolution", ""),
                "summary": c.get("summary", ""),
                "created_at": c.get("createdAt", ""),
            }
            for c in cases
        ]
    except requests.exceptions.RequestException:
        return []


def search_fp_history(rule_uuid: str, host: str, limit: int = 3) -> list[dict]:
    """Search TheHive alerts closed as Ignored (the FP-close status) for this
    rule/host combo, returning the reasoning text left behind at closure time.
    Conditional by design (SOC-3s-ARCHITECTURE-v3-final.md §7a) — the caller
    only invokes this once the local SQLite FP counter (tools/fp_tracking.py)
    indicates it's worth pulling the detailed past reasoning."""
    if not rule_uuid or not host:
        return []

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule_uuid": rule_uuid}},
                    {"match": {"host": host}},
                ],
            }
        },
        "filter": [
            {"terms": {"status": ["Ignored"]}},
        ],
        "size": limit,
        "sort": [{"createdAt": "desc"}],
    }

    try:
        result = _thehive_post("/v1/query", query)
        alerts = result if isinstance(result, list) else result.get("data", [])
        return [
            {
                "alert_id": a.get("_id", a.get("id", "")),
                "title": a.get("title", ""),
                "comment": a.get("summary", a.get("closeComment", "")),
                "closed_at": a.get("updatedAt", a.get("createdAt", "")),
            }
            for a in alerts
        ]
    except requests.exceptions.RequestException:
        return []


def get_full_alert_with_analysis(alert_id: str) -> dict | None:
    """Fetch an alert plus its observables, with each observable's Cortex analyzer
    reports attached via TheHive's extraData mechanism (reports are excluded by
    default since TheHive 5.0 and must be requested explicitly).

    Two calls, not one: TheHive's v1 query API rejected an object-keyed multi-query
    (`{"query": {"alert": [...], "observables": [...]}}`) with
    "error.expected.jsarray" against the live 5.6.1 instance this was verified
    against, so alert metadata and observables are fetched as separate array-form
    queries and merged here.
    """
    try:
        alert_resp = _thehive_post("/v1/query", {"query": [{"_name": "getAlert", "idOrName": alert_id}]})
    except requests.exceptions.RequestException:
        return None

    if not isinstance(alert_resp, list) or not alert_resp:
        return None
    alert = alert_resp[0]

    try:
        obs_resp = _thehive_post(
            "/v1/query",
            {
                "query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}],
                "extraData": ["reports"],
            },
        )
        alert["observables"] = obs_resp if isinstance(obs_resp, list) else []
    except requests.exceptions.RequestException:
        alert["observables"] = []

    return alert


def get_case_full(case_id: str) -> dict | None:
    try:
        case = _thehive_get(f"/v1/case/{case_id}")
        if isinstance(case, dict):
            return {
                "case_id": case.get("_id", case.get("id", case_id)),
                "title": case.get("title", ""),
                "description": case.get("description", ""),
                "severity": case.get("severity", 0),
                "status": case.get("status", ""),
                "tags": case.get("tags", []),
                "metrics": case.get("metrics", {}),
                "custom_fields": case.get("customFields", {}),
                "created_at": case.get("createdAt", ""),
                "owner": case.get("owner", ""),
                "summary": case.get("summary", ""),
            }
        return None
    except requests.exceptions.RequestException:
        return None


# ---------------------------------------------------------------------------
# Write operations — used only by nodes/case_action.py, the post-approval path.
# All read-only functions above are also used by the automated triage pipeline
# (tools/registry.py); these are not, and are never registered as agent tools.
#
# UNVERIFIED against the live TheHive instance, unlike get_full_alert_with_
# analysis() above — this module has no way to test writes against production
# from here. Endpoint paths follow TheHive 5's documented v1 REST API shape.
# Confirm against the live 5.6.1 instance's Swagger UI before this is ever
# wired into a real approval flow.
# ---------------------------------------------------------------------------

def promote_alert_to_case(alert_id: str) -> dict | None:
    """Promote a TheHive alert into a new case. Returns the created case."""
    try:
        return _thehive_post(f"/v1/alert/{alert_id}/case", {})
    except requests.exceptions.RequestException:
        return None


def update_case(
    case_id: str,
    title: str | None = None,
    severity: int | None = None,
    tags: list[str] | None = None,
) -> dict | None:
    body: dict = {}
    if title is not None:
        body["title"] = title
    if severity is not None:
        body["severity"] = severity
    if tags is not None:
        body["tags"] = tags
    if not body:
        return None
    try:
        return _thehive_patch(f"/v1/case/{case_id}", body)
    except requests.exceptions.RequestException:
        return None


def add_case_comment(case_id: str, comment: str) -> dict | None:
    try:
        return _thehive_post(f"/v1/case/{case_id}/comment", {"message": comment})
    except requests.exceptions.RequestException:
        return None


def update_alert_status(alert_id: str, status: str) -> dict | None:
    try:
        return _thehive_patch(f"/v1/alert/{alert_id}", {"status": status})
    except requests.exceptions.RequestException:
        return None


def add_alert_comment(alert_id: str, comment: str) -> dict | None:
    try:
        return _thehive_post(f"/v1/alert/{alert_id}/comment", {"message": comment})
    except requests.exceptions.RequestException:
        return None


def merge_alert_into_case(alert_id: str, case_id: str) -> dict | None:
    try:
        return _thehive_post(f"/v1/alert/{alert_id}/merge/{case_id}", {})
    except requests.exceptions.RequestException:
        return None
