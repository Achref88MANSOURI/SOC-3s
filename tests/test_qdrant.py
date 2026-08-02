from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.qdrant import retrieve_cve, retrieve_mitre, retrieve_playbooks


def _point(score, payload):
    p = MagicMock()
    p.score = score
    p.payload = payload
    return p


@patch("tools.qdrant._get_embedder")
@patch("tools.qdrant._get_client")
def test_retrieve_mitre_unwraps_metadata_and_filters_by_collection(mock_get_client, mock_get_embedder):
    mock_embedder = MagicMock()
    mock_embedder.encode.return_value.tolist.return_value = [0.1] * 1024
    mock_get_embedder.return_value = mock_embedder

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.points = [
        _point(0.57, {
            "text": "T1059.001 - PowerShell (tactics: execution): ...",
            "collection": "mitre_attack",
            "source": "T1059.001",
            "metadata": {"technique_id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "is_subtechnique": True},
        })
    ]
    mock_client.query_points.return_value = mock_resp
    mock_get_client.return_value = mock_client

    results = retrieve_mitre("PowerShell downloading remote payload", top_k=3)

    assert len(results) == 1
    assert results[0]["technique_id"] == "T1059.001"
    assert results[0]["tactic"] == "execution"
    assert results[0]["sub_technique"] == "PowerShell"
    assert results[0]["score"] == 0.57

    call_kwargs = mock_client.query_points.call_args.kwargs
    assert call_kwargs["collection_name"] == "triage_kb"
    filt = call_kwargs["query_filter"]
    assert filt.must[0].key == "collection"
    assert filt.must[0].match.value == "mitre_attack"


@patch("tools.qdrant._get_embedder")
@patch("tools.qdrant._get_client")
def test_retrieve_cve_filters_by_cve_intel(mock_get_client, mock_get_embedder):
    mock_embedder = MagicMock()
    mock_embedder.encode.return_value.tolist.return_value = [0.1] * 1024
    mock_get_embedder.return_value = mock_embedder

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.points = [
        _point(0.71, {
            "text": "CVE-2021-3493 - Linux Kernel Privilege Escalation ...",
            "collection": "cve_intel",
            "source": "CVE-2021-3493",
            "metadata": {"cve_id": "CVE-2021-3493", "vendor_project": "Linux", "product": "Kernel", "cvss_score": 7.8},
        })
    ]
    mock_client.query_points.return_value = mock_resp
    mock_get_client.return_value = mock_client

    results = retrieve_cve("linux privilege escalation", top_k=2)

    assert results[0]["cve_id"] == "CVE-2021-3493"
    assert results[0]["affected_software"] == "Linux Kernel"
    call_kwargs = mock_client.query_points.call_args.kwargs
    assert call_kwargs["query_filter"].must[0].match.value == "cve_intel"


@patch("tools.qdrant._get_embedder")
@patch("tools.qdrant._get_client")
def test_retrieve_playbooks_unwraps_metadata(mock_get_client, mock_get_embedder):
    mock_embedder = MagicMock()
    mock_embedder.encode.return_value.tolist.return_value = [0.1] * 1024
    mock_get_embedder.return_value = mock_embedder

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.points = [
        _point(0.64, {
            "text": "Playbook: Ransomware / Mass Encryption Activity ...",
            "collection": "playbooks",
            "source": "ransomware:detection_and_scope",
            "metadata": {"title": "Ransomware / Mass Encryption Activity", "mitre_techniques": ["T1486", "T1490"]},
        })
    ]
    mock_client.query_points.return_value = mock_resp
    mock_get_client.return_value = mock_client

    results = retrieve_playbooks("ransomware encryption", top_k=1)

    assert results[0]["title"] == "Ransomware / Mass Encryption Activity"
    assert results[0]["tags"] == ["T1486", "T1490"]


@patch("tools.qdrant._get_embedder")
@patch("tools.qdrant._get_client")
def test_search_swallows_exceptions(mock_get_client, mock_get_embedder):
    mock_get_embedder.side_effect = RuntimeError("model load failed")
    assert retrieve_mitre("anything") == []
    assert retrieve_cve("anything") == []
    assert retrieve_playbooks("anything") == []
