"""AuthMind inbound webhook receiver.

Lets AuthMind push issues to Vigil instead of Vigil polling
``GET /amapi/v1/issues`` (the federation path in ``adapter.py``). AuthMind has
no publicly documented outbound-webhook contract yet, so this receiver takes
the same row shape the polling adapter already parses via
``_issue_to_finding`` — whatever AuthMind's push feature ends up sending, as
long as each event matches a ``/v1/issues`` row.

Endpoints:
    POST /api/webhooks/authmind
    GET  /api/webhooks/authmind/health

Auth: bearer token in the ``Authorization`` header, checked against
``AUTHMIND_WEBHOOK_TOKEN`` (secrets store). Plain shared-secret comparison,
not a body signature — same pattern as the VStrike inbound push endpoint
(``services/api/routers/vstrike.py``).
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Header, HTTPException, status

from core.config import get_settings
from core.ingestion.ingestion_service import IngestionService
from core.integrations.authmind.adapter import _issue_to_finding
from core.routing import Auth, RouterMeta
from core.secrets import get_secret

logger = logging.getLogger(__name__)

router = APIRouter()


def authmind_webhook_enabled() -> bool:
    """Master flag for the AuthMind webhook receiver. Off unless explicitly enabled."""
    return get_settings().authmind_webhook_enabled


ROUTER_META = RouterMeta(
    prefix="/api/webhooks/authmind",
    tags=["authmind"],
    auth=Auth.PUBLIC_WEBHOOK,
    reason=(
        "Inbound receiver for AuthMind pushes — the caller is a machine, so "
        "there is no session to authenticate. The endpoint checks a bearer "
        "token against AUTHMIND_WEBHOOK_TOKEN and fails closed when no "
        "token is configured."
    ),
    enabled=authmind_webhook_enabled,
)


def _expected_token() -> Optional[str]:
    try:
        return get_secret("AUTHMIND_WEBHOOK_TOKEN") or None
    except Exception as exc:  # noqa: BLE001
        logger.debug("AUTHMIND_WEBHOOK_TOKEN lookup failed: %s", exc)
        return None


def _verify_token(authorization: Optional[str]) -> None:
    expected = _expected_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "AuthMind webhook receiver not configured "
                "(AUTHMIND_WEBHOOK_TOKEN missing)"
            ),
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token"
        )
    token = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token"
        )


def _extract_issues(payload: Any) -> List[Dict[str, Any]]:
    """Accept a single issue object, a bare list, or ``{"issues": [...]}``."""
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        issues = payload.get("issues")
        if isinstance(issues, list):
            return [row for row in issues if isinstance(row, dict)]
        return [payload]
    return []


def _ingest(payload: Any) -> Dict[str, Any]:
    issues = _extract_issues(payload)
    if not issues:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Webhook payload must be an AuthMind issue object, or a "
            "list/`issues` array of them",
        )

    accepted: List[str] = []
    for issue in issues:
        finding = _issue_to_finding(issue)
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unable to transform AuthMind issue: missing issue_id",
            )
        try:
            ok = IngestionService().ingest_finding(finding)
        except Exception as exc:
            logger.exception("AuthMind webhook ingestion failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ingestion error: {exc}",
            )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Finding was not persisted",
            )
        accepted.append(finding["finding_id"])

    logger.info("AuthMind webhook ingested %d finding(s)", len(accepted))
    return {"accepted": True, "finding_ids": accepted}


@router.get("/health")
async def health() -> Dict[str, Any]:
    """Liveness probe."""
    return {
        "status": "ok",
        "receiver": "authmind",
        "enabled": authmind_webhook_enabled(),
        "token_configured": _expected_token() is not None,
    }


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def receive(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _verify_token(authorization)
    return await asyncio.to_thread(_ingest, payload)
