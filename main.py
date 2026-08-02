from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from alert_builder import build_canonical_alert
from graph import graph
from schemas import AlertWebhookPayload, TriageResult
from tools.thehive import get_full_alert_with_analysis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("agent-service")

app = FastAPI(title="SOC Triage Agent", version="1.0.0")


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str = "agent-service"


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/triage", response_model=TriageResult)
async def triage(payload: AlertWebhookPayload):
    try:
        hive_alert = get_full_alert_with_analysis(payload.thehive_alert_id)
        alert = build_canonical_alert(
            raw_alert=payload.raw_alert,
            hive_alert=hive_alert,
            asset_context=payload.asset_context,
            thehive_alert_id=payload.thehive_alert_id,
        )
        logger.info("Triage request received: alert_id=%s, rule=%s, profile=%s",
                     alert.alert_id, alert.rule.name, alert.investigation_profile)

        initial_state = {
            "canonical_alert": alert,
            "mode": "new",
            "correlation_result": None,
            "existing_case_context": None,
            "evidence_package": None,
            "delta_evidence": None,
            "triage_verdict": None,
            "delta_verdict": None,
            "triage_result": None,
        }

        final_state = graph.invoke(initial_state)
        result = final_state.get("triage_result")

        if not result:
            logger.error("No triage_result in final state for alert_id=%s", alert.alert_id)
            raise HTTPException(status_code=500, detail="Triage pipeline did not produce a result")

        logger.info("Triage complete: alert_id=%s, action=%s, verdict=%s",
                     alert.alert_id, result.action, result.verdict)
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Triage failed for thehive_alert_id=%s: %s\n%s",
                      payload.thehive_alert_id, str(e), traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
