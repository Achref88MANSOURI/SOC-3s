"""Client for TheHive Cortex analyzer engine.

Runs the best-available analyzer against an observable and reduces the
Cortex job report down to a single verdict for triage.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

CORTEX_URL = os.environ.get("CORTEX_URL", "").rstrip("/")
CORTEX_API_KEY = os.environ.get("CORTEX_API_KEY", "")

REQUEST_TIMEOUT = 15  # seconds, for plain API calls (not the polling wait)
DEFAULT_POLL_TIMEOUT = 180  # seconds, how long to wait for a job to finish

VALID_TYPES = {"ip", "domain", "url", "hash"}

# Worst-case-wins ordering for Cortex/TheHive taxonomy levels.
LEVEL_SCORES = {"malicious": 90, "suspicious": 55, "safe": 5, "info": 0}
LEVEL_TO_VERDICT = {"malicious": "malicious", "suspicious": "suspicious", "safe": "clean"}


def _headers():
    return {
        "Authorization": f"Bearer {CORTEX_API_KEY}",
        "Content-Type": "application/json",
    }


def _unknown(observable_type, observable_value, details, raw=None):
    return {
        "observable": observable_value,
        "type": observable_type,
        "verdict": "unknown",
        "score": 0,
        "details": details,
        "analyzer": None,
        "raw": raw or {},
    }


def _get_analyzers(observable_type):
    resp = requests.get(
        f"{CORTEX_URL}/api/analyzer/type/{observable_type}",
        headers=_headers(),
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _pick_analyzer(analyzers, observable_type):
    if not analyzers:
        return None

    def name_of(a):
        return a.get("name", "").lower()

    for a in analyzers:
        if "virustotal" in name_of(a):
            return a

    if observable_type == "ip":
        for a in analyzers:
            if "abuseipdb" in name_of(a):
                return a

    return analyzers[0]


def _run_analyzer(analyzer_id, observable_value, observable_type):
    resp = requests.post(
        f"{CORTEX_URL}/api/analyzer/{analyzer_id}/run",
        headers=_headers(),
        json={"data": observable_value, "dataType": observable_type, "tlp": 2},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["id"]


def _wait_report(job_id, timeout):
    resp = requests.get(
        f"{CORTEX_URL}/api/job/{job_id}/waitreport",
        headers=_headers(),
        params={"atMost": f"{timeout}second"},
        timeout=timeout + REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _extract_taxonomies(job):
    return job.get("report", {}).get("summary", {}).get("taxonomies", [])


def _summarize(taxonomies):
    """Reduce a list of Cortex taxonomies to a (verdict, score, details) triple."""
    if not taxonomies:
        return "unknown", 0, "Analyzer returned no taxonomy data."

    worst_level = max(taxonomies, key=lambda t: LEVEL_SCORES.get(t.get("level"), 0)).get("level")
    verdict = LEVEL_TO_VERDICT.get(worst_level, "unknown")
    score = LEVEL_SCORES.get(worst_level, 0)

    details = "; ".join(
        f"{t.get('namespace')}:{t.get('predicate')}={t.get('value')} ({t.get('level')})"
        for t in taxonomies
    )
    return verdict, score, details


def analyze_observable(observable_type: str, observable_value: str, timeout: int = DEFAULT_POLL_TIMEOUT) -> dict:
    """Run the best available Cortex analyzer against an observable and return a verdict.

    Never raises: any failure (bad type, no analyzer, network error, timeout)
    comes back as a dict with verdict "unknown" and the problem in "details".
    """
    if observable_type not in VALID_TYPES:
        return _unknown(
            observable_type,
            observable_value,
            f"Unsupported observable type '{observable_type}'. Expected one of {sorted(VALID_TYPES)}.",
        )

    if not CORTEX_URL or not CORTEX_API_KEY:
        return _unknown(observable_type, observable_value, "CORTEX_URL / CORTEX_API_KEY not configured.")

    try:
        analyzers = _get_analyzers(observable_type)
    except requests.exceptions.RequestException as e:
        return _unknown(observable_type, observable_value, f"Failed to list analyzers: {e}")

    analyzer = _pick_analyzer(analyzers, observable_type)
    if analyzer is None:
        return _unknown(observable_type, observable_value, f"No analyzer available for type '{observable_type}'.")

    analyzer_name = analyzer.get("name", "unknown")

    try:
        job_id = _run_analyzer(analyzer["id"], observable_value, observable_type)
    except requests.exceptions.RequestException as e:
        return _unknown(observable_type, observable_value, f"Failed to start analyzer '{analyzer_name}': {e}")

    try:
        job = _wait_report(job_id, timeout)
    except requests.exceptions.RequestException as e:
        return _unknown(observable_type, observable_value, f"Failed to fetch report from '{analyzer_name}': {e}")

    status = job.get("status")
    if status != "Success":
        message = job.get("message") or f"Job ended with status '{status}' (analyzer may still be running)."
        return _unknown(observable_type, observable_value, message, raw=job)

    taxonomies = _extract_taxonomies(job)
    verdict, score, details = _summarize(taxonomies)

    return {
        "observable": observable_value,
        "type": observable_type,
        "verdict": verdict,
        "score": score,
        "details": details,
        "analyzer": analyzer_name,
        "raw": job,
    }


if __name__ == "__main__":
    print(analyze_observable("ip", "8.8.8.8"))
