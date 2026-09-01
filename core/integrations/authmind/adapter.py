"""AuthMind federation adapter — v1 issues with v2 posture fallback.

The alert stream is ``GET /amapi/v1/issues``. Issue ids are monotonically
increasing integers, so the cursor holds the highest id ingested and each
poll walks newest-first until it reaches it.

``/v1/getIssues`` looks like the natural SIEM fit, but it is a separate
pipeline with its own composite id space and can be empty even when the
console holds tens of thousands of open issues. ``/v1/issues`` is what the
console itself reads.

If the token cannot read v1 issues (missing ``issues`` permission, or a
process already bookmarked on v2), the adapter falls back to high-score
v2 posture entities (identities, assets, secrets) via
``latest_activity_time_gt``.

First enable (empty cursor) baselines to the latest watermark and ingests
nothing — matching the federation MVP "no backfill on cold start" rule.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.config import is_integration_enabled
from core.federation.contract import (
    FederationAdapter,
    FetchResult,
    register_adapter,
)
from core.time import utcnow

logger = logging.getLogger(__name__)

# AuthMind encodes risk numerically on /v1/issues; the SIEM endpoint used
# words, so accept both rather than depending on which surface produced
# the row.
_SEVERITY_BY_RISK = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
}
_SEVERITY_BY_NAME = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Console messages mark up entity names, e.g.
# "<i><b>cdn.example.com</i></b> was accessed from <i><b>India</i></b>".
# The tags are mis-nested in the API payload, so match loosely.
_HIGHLIGHT_RE = re.compile(r"<i><b>(.*?)</i></b>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")

# Pages are 1-based on /v1/issues. Bound the walk so a cursor that falls
# far behind can't turn one poll into an unbounded crawl of 26k+ issues.
_FIRST_PAGE = 1
_MAX_PAGES = 10
_MAX_PAGE_SIZE = 200

# Higher posture score = worse. 50 is the floor at which an entity is
# worth promoting to a finding rather than inventory noise.
_MIN_SCORE = 50.0
_POSTURE_MAX_PAGES = 5
_SEVERITY_BY_SCORE = (
    (80.0, "critical"),
    (60.0, "high"),
    (40.0, "medium"),
)


class AuthMindAdapter:
    name = "authmind"

    def __init__(self) -> None:
        self._service = None

    def is_configured(self) -> bool:
        return is_integration_enabled("authmind")

    def default_interval(self) -> int:
        # Identity-security issues are closer to SIEM cadence than EDR.
        return 300

    def _get_service(self):
        if self._service is not None:
            return self._service
        if not self.is_configured():
            return None
        try:
            from core.integrations.authmind.client import get_authmind_service

            self._service = get_authmind_service()
        except Exception as e:
            logger.warning("AuthMind service init failed: %s", e)
            self._service = None
        return self._service

    async def fetch(
        self,
        *,
        since: Optional[datetime],
        cursor: Dict[str, Any],
        max_items: int,
    ) -> FetchResult:
        del since  # AuthMind uses issue_id / latest_activity_time bookmarks.
        svc = self._get_service()
        if svc is None:
            return FetchResult(findings=[], cursor=dict(cursor or {}))

        cursor = cursor or {}
        if _read_issue_bookmark(cursor) is not None:
            try:
                return await self._fetch_issues(svc, cursor, max_items)
            except Exception as exc:
                logger.warning("AuthMind v1 issues poll failed: %s", exc)
                return FetchResult(findings=[], cursor=dict(cursor))

        if _read_posture_bookmark(cursor) is not None:
            return await self._fetch_posture(svc, cursor, max_items)

        try:
            return await self._fetch_issues(svc, cursor, max_items)
        except Exception as exc:
            logger.warning(
                "AuthMind v1 issues unavailable (%s); falling back to v2 posture",
                exc,
            )
            return await self._fetch_posture(svc, {}, max_items)

    async def _fetch_issues(
        self, svc, cursor: Dict[str, Any], max_items: int
    ) -> FetchResult:
        bookmark = _read_issue_bookmark(cursor)
        if bookmark is None:
            return await self._baseline_issues(svc)

        budget = max(1, int(max_items))
        collected, reached_bookmark = await self._walk_back_to(
            svc, bookmark, page_size=min(budget, _MAX_PAGE_SIZE)
        )

        if not reached_bookmark and collected:
            logger.warning(
                "AuthMind federation walked %d pages without reaching "
                "issue_id=%s; the backlog may outpace the poll interval",
                _MAX_PAGES,
                bookmark,
            )

        # Walked newest-first, so hand findings back oldest-first and let
        # the budget bite at the newest end. Advancing the cursor only as
        # far as what we kept means the remainder arrives on the next poll
        # instead of being skipped.
        collected.sort(key=lambda row: row[0])
        kept = collected[:budget]
        watermark = kept[-1][0] if kept else bookmark
        return FetchResult(
            findings=[finding for _, finding in kept],
            cursor={"issue_id": watermark},
        )

    async def _walk_back_to(
        self,
        svc,
        bookmark: int,
        *,
        page_size: int,
    ) -> tuple:
        """Page newest-first until ``bookmark``, collecting newer issues.

        ``/v1/issues`` has no ``issue_id_gt`` filter, so the bookmark has to
        be found by walking. Returns ``([(issue_id, finding)], reached)``.
        """
        collected: List[tuple] = []

        for page in range(_FIRST_PAGE, _FIRST_PAGE + _MAX_PAGES):
            payload = await asyncio.to_thread(
                svc.list_issues,
                sort_by="issue_id",
                order_by="desc",
                from_=page,
                size=page_size,
            )
            rows = _issue_rows(payload)
            if not rows:
                return collected, True

            newer, reached_bookmark = _take_newer_than(rows, bookmark)
            collected.extend(newer)
            if reached_bookmark or len(rows) < page_size:
                return collected, True

        return collected, False

    async def _baseline_issues(self, svc) -> FetchResult:
        """Record the latest issue_id as the watermark; ingest nothing."""
        payload = await asyncio.to_thread(
            svc.list_issues,
            sort_by="issue_id",
            order_by="desc",
            from_=_FIRST_PAGE,
            size=1,
        )
        rows = _issue_rows(payload)
        watermark = _as_int(rows[0].get("issue_id")) if rows else None
        if watermark is None:
            watermark = 0
        logger.info(
            "AuthMind federation baselined at issue_id=%s (no backfill)",
            watermark,
        )
        return FetchResult(findings=[], cursor={"issue_id": watermark})

    async def _fetch_posture(
        self, svc, cursor: Dict[str, Any], max_items: int
    ) -> FetchResult:
        bookmark = _read_posture_bookmark(cursor)
        if bookmark is None:
            return self._baseline_posture()

        budget = max(1, int(max_items))
        page_size = min(budget, _MAX_PAGE_SIZE)
        query_time = _to_query_time(bookmark)
        collected: List[Tuple[str, Dict[str, Any]]] = []

        for _kind, lister, mapper in _POSTURE_SOURCES:
            rows = await self._walk_posture_source(
                lister=lambda fn=lister, **kw: fn(svc, **kw),
                query_time=query_time,
                page_size=page_size,
            )
            for row in rows:
                finding = mapper(row)
                if finding is None:
                    continue
                activity = _activity_key(row) or bookmark
                collected.append((activity, finding))

        collected.sort(key=lambda item: item[0])
        kept = collected[:budget]
        watermark = kept[-1][0] if kept else bookmark
        return FetchResult(
            findings=[finding for _, finding in kept],
            cursor={"latest_activity_time": watermark},
        )

    async def _walk_posture_source(
        self,
        *,
        lister,
        query_time: str,
        page_size: int,
    ) -> List[Dict[str, Any]]:
        collected: List[Dict[str, Any]] = []
        for page in range(_FIRST_PAGE, _FIRST_PAGE + _POSTURE_MAX_PAGES):
            try:
                payload = await asyncio.to_thread(
                    lister,
                    latest_activity_time_gt=query_time,
                    score=_MIN_SCORE,
                    from_=page,
                    size=page_size,
                )
            except Exception as exc:
                logger.warning("AuthMind federation list failed: %s", exc)
                return collected
            rows = _posture_rows(payload)
            collected.extend(rows)
            if len(rows) < page_size:
                return collected
        return collected

    def _baseline_posture(self) -> FetchResult:
        watermark = _to_rfc3339(utcnow())
        logger.info(
            "AuthMind federation baselined at latest_activity_time=%s (no backfill)",
            watermark,
        )
        return FetchResult(findings=[], cursor={"latest_activity_time": watermark})


def _list_identities(svc, **kwargs):
    return svc.list_identities(**kwargs)


def _list_assets(svc, **kwargs):
    return svc.list_assets(**kwargs)


def _list_secrets(svc, **kwargs):
    return svc.list_secrets(**kwargs)


_POSTURE_SOURCES: Tuple[Tuple[str, Callable, Callable], ...] = (
    ("identity", _list_identities, lambda row: _entity_to_finding(row, "identity")),
    ("asset", _list_assets, lambda row: _entity_to_finding(row, "asset")),
    ("secret", _list_secrets, lambda row: _entity_to_finding(row, "secret")),
)


def _take_newer_than(rows: List[Dict[str, Any]], bookmark: int) -> tuple:
    """Map the leading run of issues newer than ``bookmark`` to findings.

    ``rows`` arrive newest-first, so the first id at or below the bookmark
    ends the run. Returns ``([(issue_id, finding)], reached_bookmark)``.
    """
    newer: List[tuple] = []
    for issue in rows:
        issue_id = _as_int(issue.get("issue_id"))
        if issue_id is None:
            continue
        if issue_id <= bookmark:
            return newer, True
        finding = _issue_to_finding(issue)
        if finding is not None:
            newer.append((issue_id, finding))
    return newer, False


def _read_issue_bookmark(cursor: Optional[Dict[str, Any]]) -> Optional[int]:
    """Return the highest ingested issue_id, or None to skip the issues path.

    ``issue_id_gt`` is the legacy key from the /v1/getIssues era. Its
    composite ids don't compare against these integers, so an unparseable
    value is ignored rather than replaying history.
    """
    cursor = cursor or {}
    for key in ("issue_id", "issue_id_gt"):
        if key not in cursor:
            continue
        value = _as_int(cursor.get(key))
        if value is not None:
            return value
    return None


def _read_posture_bookmark(cursor: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return the latest_activity_time watermark, or None."""
    cursor = cursor or {}
    value = cursor.get("latest_activity_time")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


# Back-compat alias used by older tests / imports.
def _read_bookmark(cursor: Optional[Dict[str, Any]]) -> Optional[int]:
    return _read_issue_bookmark(cursor)


def _issue_rows(payload: Any) -> List[Dict[str, Any]]:
    """Pull the row list out of AuthMind's v1 ``result`` envelope."""
    if not isinstance(payload, dict):
        return []
    result = payload.get("result")
    if isinstance(result, dict):
        result = result.get("data")
    if not isinstance(result, list):
        return []
    return [row for row in result if isinstance(row, dict)]


def _posture_rows(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict)]


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _severity(risk: Any) -> str:
    as_int = _as_int(risk)
    if as_int is not None:
        return _SEVERITY_BY_RISK.get(as_int, "medium")
    return _SEVERITY_BY_NAME.get(str(risk or "").strip().lower(), "medium")


def _issue_to_finding(issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    issue_id = _as_int(issue.get("issue_id"))
    if issue_id is None:
        return None

    external_id = str(issue_id)
    finding_id = f"am-{external_id}"

    severity = _severity(issue.get("risk"))
    issue_type = issue.get("issue_type") or "AuthMind Issue"
    playbook = issue.get("playbook_name") or ""
    title = f"{issue_type}" + (f" — {playbook}" if playbook else "")

    raw_message = str(issue.get("message") or "")
    highlights = [h.strip() for h in _HIGHLIGHT_RE.findall(raw_message) if h.strip()]
    description = _TAG_RE.sub("", raw_message).strip()

    usernames: List[str] = []
    hostnames: List[str] = []
    for text in highlights:
        if "@" in text:
            usernames.append(text)
        elif "." in text and " " not in text:
            hostnames.append(text)

    entity_context = {
        "usernames": usernames,
        "hostnames": hostnames,
        "domains": [],
        "issue_type": issue_type,
        "playbook_name": playbook,
        "highlights": highlights,
        "incidents_url": issue.get("incident_accesses_url"),
        "issue_accesses_api": issue.get("incident_accesses_api"),
        "flow_count": issue.get("issue_flows_count"),
        "access_count": issue.get("issue_access_count"),
        "first_flow_time": issue.get("first_flow_time"),
        "entity_kind": "issue",
        "issue_id": issue_id,
    }

    timestamp = (
        issue.get("gen_timestamp")
        or issue.get("first_flow_time")
        or utcnow().isoformat()
    )

    return {
        "finding_id": finding_id,
        "data_source": "authmind",
        "external_id": external_id,
        "timestamp": timestamp,
        "severity": severity,
        "status": "new",
        "title": title,
        "description": description,
        "entity_context": entity_context,
        "raw_event": issue,
        "anomaly_score": _risk_to_score(severity),
        "mitre_predictions": {},
        "embedding": [],
    }


def _risk_to_score(severity: str) -> float:
    return {
        "critical": 0.95,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
    }.get(severity, 0.5)


def _activity_key(row: Dict[str, Any]) -> str:
    raw = row.get("latest_activity_time") or ""
    return str(raw).strip()


def _to_query_time(value: str) -> str:
    """AuthMind list filters accept ``YYYY-MM-DD HH:MM:SS``."""
    text = (value or "").strip()
    if not text:
        return text
    if "T" in text:
        text = text.replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    if "+" in text[10:]:
        text = text.split("+", 1)[0]
    return text[:19]


def _to_rfc3339(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _score_severity(score: Any) -> str:
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return "medium"
    for threshold, label in _SEVERITY_BY_SCORE:
        if numeric >= threshold:
            return label
    return "low"


def _entity_to_finding(row: Dict[str, Any], kind: str) -> Optional[Dict[str, Any]]:
    entity_id = str(row.get("id") or "").strip()
    if not entity_id:
        return None

    asset_type = str(row.get("asset_type") or "").strip()
    if kind == "asset" and asset_type:
        external_id = f"{kind}:{asset_type}:{entity_id}"
    else:
        external_id = f"{kind}:{entity_id}"
    finding_id = f"am-{external_id}"

    severity = _score_severity(row.get("score"))
    title = _title_for(kind, row, entity_id)
    timestamp = _iso_timestamp(row.get("latest_activity_time")) or _to_rfc3339(utcnow())

    usernames: List[str] = []
    hostnames: List[str] = []
    if kind == "identity":
        usernames.append(entity_id)
        usernames.extend(str(alias) for alias in (row.get("aliases") or []) if alias)
    elif kind == "asset":
        hostnames.append(entity_id)

    entity_context = {
        "usernames": usernames,
        "hostnames": hostnames,
        "domains": [row["domain"]] if row.get("domain") else [],
        "entity_kind": kind,
        "entity_id": entity_id,
        "asset_type": asset_type or None,
        "identity_type": row.get("identity_type"),
        "secret_type": row.get("type") if kind == "secret" else None,
        "is_known": row.get("is_known"),
        "score": row.get("score"),
        "flow_count": row.get("flow_count"),
        "first_activity_time": row.get("first_activity_time"),
        "latest_activity_time": row.get("latest_activity_time"),
    }

    return {
        "finding_id": finding_id,
        "data_source": "authmind",
        "external_id": external_id,
        "timestamp": timestamp,
        "severity": severity,
        "status": "new",
        "title": title,
        "description": _description_for(kind, row, entity_id),
        "entity_context": entity_context,
        "raw_event": row,
        "anomaly_score": _score_to_anomaly(row.get("score")),
        "mitre_predictions": {},
        "embedding": [],
    }


def _title_for(kind: str, row: Dict[str, Any], entity_id: str) -> str:
    if kind == "identity":
        label = row.get("full_name") or entity_id
        return f"AuthMind identity risk — {label}"
    if kind == "asset":
        asset_type = row.get("asset_type") or "asset"
        return f"AuthMind asset risk — {entity_id} ({asset_type})"
    name = row.get("name") or entity_id
    return f"AuthMind secret risk — {name}"


def _description_for(kind: str, row: Dict[str, Any], entity_id: str) -> str:
    score = row.get("score")
    known = row.get("is_known")
    known_bit = ""
    if known is False:
        known_bit = " unknown/shadow"
    return f"High-score AuthMind {kind}{known_bit}: {entity_id} " f"(score={score})."


def _iso_timestamp(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    if "T" not in text:
        text = text.replace(" ", "T", 1)
    if not text.endswith("Z") and "+" not in text[10:]:
        text = f"{text}Z"
    return text


def _score_to_anomaly(score: Any) -> float:
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, numeric / 100.0))


def _factory() -> FederationAdapter:
    return AuthMindAdapter()


register_adapter(AuthMindAdapter.name, _factory)
