from __future__ import annotations

import json

import requests

from config import ITOP_KEY, ITOP_URL, ITOP_USER

REQUEST_TIMEOUT = 15


def _json_rpc(method: str, params: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    resp = requests.post(
        ITOP_URL + "/webservices/rest.php?version=1.3",
        data={
            "auth_user": ITOP_USER,
            "auth_pwd": ITOP_KEY,
            "json_data": json.dumps(payload),
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def lookup_asset(hostname_or_ip: str) -> dict:
    if not ITOP_URL or not ITOP_USER or not ITOP_KEY:
        return {"found": False, "error": "iTop not configured", "hostname": hostname_or_ip}

    try:
        result = _json_rpc("core.get", {
            "class": "Server",
            "key": f"SELECT Server WHERE (name = '{hostname_or_ip}' OR ip = '{hostname_or_ip}')",
            "output_fields": "id, name, status, business_criticality, location_name,"
                             "contacts_list, services_list, description, org_name,"
                             "network_zone",
        })
    except requests.exceptions.RequestException as e:
        return {"found": False, "error": str(e), "hostname": hostname_or_ip}

    objects = result.get("result", {}).get("objects", {})
    if not objects:
        return {"found": False, "error": "No asset found", "hostname": hostname_or_ip}

    first_key = next(iter(objects))
    server = objects[first_key].get("fields", {})

    return {
        "found": True,
        "hostname": server.get("name", hostname_or_ip),
        "criticality": server.get("business_criticality", "unknown"),
        "status": server.get("status", "unknown"),
        "location": server.get("location_name", ""),
        "organization": server.get("org_name", ""),
        "contacts": server.get("contacts_list", ""),
        "services": server.get("services_list", ""),
        "description": server.get("description", ""),
        "network_zone": server.get("network_zone", ""),
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(json.dumps(lookup_asset(target), indent=2))
