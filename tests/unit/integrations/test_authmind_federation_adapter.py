"""Unit tests for the AuthMind federation adapter (v1 issues + v2 posture)."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from core.integrations.authmind.adapter import (
    AuthMindAdapter,
    _entity_to_finding,
    _issue_to_finding,
    _read_issue_bookmark,
    _read_posture_bookmark,
    _to_query_time,
)
from core.integrations.authmind.client import AuthMindError


def _issue(
    issue_id: int,
    *,
    risk: int = 3,
    issue_type: str = "Access from Unauthorized Countries",
    message: str = (
        "<i><b>cdn.example.com</i></b> was accessed from one or more hosts "
        "located in <i><b>India</i></b> which is flagged as unauthorized"
    ),
    playbook: str = "Access not from Israel",
) -> Dict[str, Any]:
    return {
        "issue_id": issue_id,
        "message": message,
        "issue_flows_count": 10,
        "issue_access_count": 2,
        "first_flow_time": "2026-08-14T01:33:38Z",
        "gen_timestamp": "2026-08-14T01:33:38Z",
        "issue_type": issue_type,
        "playbook_name": playbook,
        "risk": risk,
        "incident_accesses_url": (
            f"https://console.authmind.com/posture/accesses"
            f"?q=incident_id%3A{issue_id}"
        ),
        "incident_accesses_api": (
            f"https://console.authmind.com/amapi/v1/issue/{issue_id}/accesses"
        ),
    }


def _identity(id_: str, *, score: float = 72, activity: str = "2026-08-24 12:00:00"):
    return {
        "id": id_,
        "full_name": "Jane Doe" if "@" in id_ else id_,
        "identity_type": "User",
        "score": score,
        "latest_activity_time": activity,
        "first_activity_time": "2026-01-10 09:00:00",
        "aliases": ["jdoe"],
        "is_known": True,
        "flow_count": 420,
    }


def _asset(id_: str, *, score: float = 65, activity: str = "2026-08-24 12:05:00"):
    return {
        "id": id_,
        "asset_type": "SaaS",
        "score": score,
        "latest_activity_time": activity,
        "is_known": False,
        "is_saas": True,
        "flow_count": 80,
    }


def _secret(id_: str, *, score: float = 81, activity: str = "2026-08-24 12:10:00"):
    return {
        "id": id_,
        "name": id_,
        "type": "password",
        "score": score,
        "latest_activity_time": activity,
        "provider": "vault.example.com",
    }


class _FakeIssuesService:
    """Serves issues newest-first across 1-based pages, like /v1/issues."""

    def __init__(self, issues: List[Dict[str, Any]]):
        self.issues = sorted(
            issues, key=lambda i: int(i["issue_id"]), reverse=True
        )
        self.calls: List[Dict[str, Any]] = []

    def list_issues(self, **kwargs):
        self.calls.append(dict(kwargs))
        page = int(kwargs.get("from_", 1))
        size = int(kwargs.get("size", 50))
        start = (page - 1) * size
        window = self.issues[start : start + size]
        return {"result": window, "total": len(self.issues)}


class _FakePostureService:
    def __init__(
        self,
        *,
        identities: List[Dict[str, Any]] | None = None,
        assets: List[Dict[str, Any]] | None = None,
        secrets: List[Dict[str, Any]] | None = None,
        issues_error: Exception | None = None,
    ):
        self.identities = identities or []
        self.assets = assets or []
        self.secrets = secrets or []
        self.issues_error = issues_error
        self.calls: List[Dict[str, Any]] = []

    def list_issues(self, **kwargs):
        if self.issues_error is not None:
            raise self.issues_error
        raise AuthMindError("Permission denied: issues")

    def _page(self, rows: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        self.calls.append(dict(kwargs))
        page = int(kwargs.get("from_", 1))
        size = int(kwargs.get("size", 50))
        start = (page - 1) * size
        window = rows[start : start + size]
        return {
            "data": window,
            "meta": {"page": page, "page_size": size, "total": len(rows)},
        }

    def list_identities(self, **kwargs):
        return self._page(self.identities, **kwargs)

    def list_assets(self, **kwargs):
        return self._page(self.assets, **kwargs)

    def list_secrets(self, **kwargs):
        return self._page(self.secrets, **kwargs)


# --------------------------------------------------------------------------- #
# v1 issues
# --------------------------------------------------------------------------- #


def test_issue_to_finding_maps_risk_and_entities():
    finding = _issue_to_finding(_issue(881710, risk=4))
    assert finding is not None
    assert finding["data_source"] == "authmind"
    assert finding["external_id"] == "881710"
    assert finding["finding_id"] == "am-881710"
    assert finding["severity"] == "critical"
    assert finding["anomaly_score"] == 0.95
    assert finding["timestamp"] == "2026-08-14T01:33:38Z"
    assert finding["title"].startswith("Access from Unauthorized Countries")
    ctx = finding["entity_context"]
    assert "cdn.example.com" in ctx["hostnames"]
    assert "India" in ctx["highlights"]
    assert ctx["entity_kind"] == "issue"
    assert "<i>" not in finding["description"]
    assert finding["description"].startswith("cdn.example.com was accessed")


def test_issue_to_finding_extracts_usernames_from_highlights():
    finding = _issue_to_finding(
        _issue(1, message="<i><b>jane@example.com</i></b> failed MFA")
    )
    assert finding is not None
    assert finding["entity_context"]["usernames"] == ["jane@example.com"]


@pytest.mark.parametrize(
    "risk,expected",
    [
        (4, "critical"),
        (3, "high"),
        (2, "medium"),
        (1, "low"),
        ("Critical", "critical"),
        ("High", "high"),
        (None, "medium"),
        (99, "medium"),
    ],
)
def test_severity_mapping(risk, expected):
    finding = _issue_to_finding(_issue(7, risk=risk))
    assert finding is not None
    assert finding["severity"] == expected


def test_issue_to_finding_skips_missing_id():
    assert _issue_to_finding({"risk": 3}) is None


@pytest.mark.parametrize(
    "cursor,expected",
    [
        ({"issue_id": 500}, 500),
        ({"issue_id": "500"}, 500),
        ({}, None),
        (None, None),
        ({"issue_id_gt": "17263-1722579276407"}, None),
        ({"issue_id_gt": "0"}, 0),
        ({"latest_activity_time": "2026-08-24T12:00:00Z"}, None),
    ],
)
def test_read_issue_bookmark(cursor, expected):
    assert _read_issue_bookmark(cursor) == expected


def test_issues_baseline_sets_watermark_without_findings():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService([_issue(881710), _issue(881708)])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(adapter.fetch(since=None, cursor={}, max_items=50))
    assert result.findings == []
    assert result.cursor == {"issue_id": 881710}
    assert fake.calls[0]["size"] == 1
    assert fake.calls[0]["order_by"] == "desc"
    assert fake.calls[0]["from_"] == 1


def test_issues_baseline_empty_tenant_uses_zero():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService([])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(adapter.fetch(since=None, cursor={}, max_items=50))
    assert result.findings == []
    assert result.cursor == {"issue_id": 0}


def test_incremental_poll_ingests_only_newer_issues_oldest_first():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService(
        [_issue(500), _issue(501, risk=2), _issue(502, risk=4)]
    )
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(since=None, cursor={"issue_id": 500}, max_items=50)
    )
    assert [f["external_id"] for f in result.findings] == ["501", "502"]
    assert result.findings[0]["severity"] == "medium"
    assert result.findings[1]["severity"] == "critical"
    assert result.cursor == {"issue_id": 502}


def test_incremental_poll_with_nothing_new_keeps_cursor():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService([_issue(500), _issue(499)])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(since=None, cursor={"issue_id": 500}, max_items=50)
    )
    assert result.findings == []
    assert result.cursor == {"issue_id": 500}


def test_incremental_poll_pages_until_bookmark():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService([_issue(i) for i in range(100, 121)])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(since=None, cursor={"issue_id": 105}, max_items=5)
    )
    assert len(fake.calls) > 1
    assert [c["from_"] for c in fake.calls] == [1, 2, 3, 4]


def test_incremental_poll_budget_takes_oldest_issues_and_leaves_rest():
    adapter = AuthMindAdapter()
    fake = _FakeIssuesService([_issue(i) for i in range(100, 121)])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(since=None, cursor={"issue_id": 105}, max_items=5)
    )
    assert [f["external_id"] for f in result.findings] == [
        "106",
        "107",
        "108",
        "109",
        "110",
    ]
    assert result.cursor == {"issue_id": 110}

    seen = [f["external_id"] for f in result.findings]
    cursor = result.cursor
    for _ in range(3):
        nxt = asyncio.run(adapter.fetch(since=None, cursor=cursor, max_items=5))
        seen.extend(f["external_id"] for f in nxt.findings)
        cursor = nxt.cursor
    assert seen == [str(i) for i in range(106, 121)]
    assert cursor == {"issue_id": 120}


# --------------------------------------------------------------------------- #
# v2 posture fallback
# --------------------------------------------------------------------------- #


def test_identity_to_finding_maps_score_and_entities():
    finding = _entity_to_finding(_identity("jane@example.com", score=82), "identity")
    assert finding is not None
    assert finding["data_source"] == "authmind"
    assert finding["external_id"] == "identity:jane@example.com"
    assert finding["finding_id"] == "am-identity:jane@example.com"
    assert finding["severity"] == "critical"
    assert finding["title"].startswith("AuthMind identity risk")
    assert "jane@example.com" in finding["entity_context"]["usernames"]
    assert finding["entity_context"]["entity_kind"] == "identity"


def test_asset_to_finding_flags_unknown():
    finding = _entity_to_finding(_asset("salesforce.example.com", score=45), "asset")
    assert finding is not None
    assert finding["external_id"] == "asset:SaaS:salesforce.example.com"
    assert finding["severity"] == "medium"
    assert "unknown/shadow" in finding["description"]
    assert "salesforce.example.com" in finding["entity_context"]["hostnames"]


def test_secret_to_finding_never_includes_material():
    row = _secret("db-password")
    row["secret_value"] = "should-not-leak"
    finding = _entity_to_finding(row, "secret")
    assert finding is not None
    assert finding["severity"] == "critical"
    assert finding["external_id"] == "secret:db-password"
    assert "should-not-leak" not in finding["description"]
    assert finding["entity_context"]["secret_type"] == "password"


def test_entity_to_finding_skips_missing_id():
    assert _entity_to_finding({"score": 90}, "identity") is None


@pytest.mark.parametrize(
    "cursor,expected",
    [
        ({"latest_activity_time": "2026-08-24T12:00:00Z"}, "2026-08-24T12:00:00Z"),
        ({"latest_activity_time": "2026-08-24 12:00:00"}, "2026-08-24 12:00:00"),
        ({}, None),
        (None, None),
        ({"issue_id": 881710}, None),
        ({"issue_id_gt": "17263-1722579276407"}, None),
    ],
)
def test_read_posture_bookmark(cursor, expected):
    assert _read_posture_bookmark(cursor) == expected


def test_to_query_time_strips_rfc3339():
    assert _to_query_time("2026-08-24T12:00:00Z") == "2026-08-24 12:00:00"
    assert _to_query_time("2026-08-24 12:00:00") == "2026-08-24 12:00:00"


def test_posture_baseline_when_issues_unavailable():
    adapter = AuthMindAdapter()
    fake = _FakePostureService(identities=[_identity("jane@example.com")])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(adapter.fetch(since=None, cursor={}, max_items=50))
    assert result.findings == []
    assert "latest_activity_time" in result.cursor
    assert fake.calls == []


def test_posture_incremental_poll_ingests_high_score_entities_oldest_first():
    adapter = AuthMindAdapter()
    fake = _FakePostureService(
        identities=[
            _identity("jane@example.com", score=72, activity="2026-08-24 12:00:00")
        ],
        assets=[
            _asset("salesforce.example.com", score=65, activity="2026-08-24 12:05:00")
        ],
        secrets=[_secret("db-password", score=81, activity="2026-08-24 12:10:00")],
    )
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(
            since=None,
            cursor={"latest_activity_time": "2026-08-24T11:00:00Z"},
            max_items=50,
        )
    )
    kinds = [f["entity_context"]["entity_kind"] for f in result.findings]
    assert kinds == ["identity", "asset", "secret"]
    assert result.cursor["latest_activity_time"] == "2026-08-24 12:10:00"
    assert all(c.get("score") == 50.0 for c in fake.calls)


def test_posture_incremental_poll_budget_takes_oldest_and_leaves_rest():
    adapter = AuthMindAdapter()
    fake = _FakePostureService(
        identities=[
            _identity(
                f"user{i}@example.com",
                score=70,
                activity=f"2026-08-24 12:0{i}:00",
            )
            for i in range(3)
        ]
    )
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(
            since=None,
            cursor={"latest_activity_time": "2026-08-24T11:00:00Z"},
            max_items=2,
        )
    )
    assert [f["entity_context"]["entity_id"] for f in result.findings] == [
        "user0@example.com",
        "user1@example.com",
    ]
    assert result.cursor["latest_activity_time"] == "2026-08-24 12:01:00"


def test_issue_id_cursor_does_not_fall_back_to_posture():
    adapter = AuthMindAdapter()
    fake = _FakePostureService(identities=[_identity("jane@example.com")])
    adapter._service = fake  # type: ignore[attr-defined]

    result = asyncio.run(
        adapter.fetch(since=None, cursor={"issue_id": 881710}, max_items=50)
    )
    assert result.findings == []
    assert result.cursor == {"issue_id": 881710}
    assert fake.calls == []


def test_is_configured_checks_integration_enablement():
    adapter = AuthMindAdapter()
    with patch(
        "core.integrations.authmind.adapter.is_integration_enabled",
        return_value=True,
    ):
        assert adapter.is_configured() is True
    with patch(
        "core.integrations.authmind.adapter.is_integration_enabled",
        return_value=False,
    ):
        assert adapter.is_configured() is False


def test_adapter_registered_in_federation_registry():
    from core.federation import registry as fed_registry

    fed_registry._BUILTINS_LOADED = False  # noqa: SLF001
    names = {a.name for a in fed_registry.list_adapters()}
    assert "authmind" in names


def test_unconfigured_fetch_is_noop():
    adapter = AuthMindAdapter()
    with patch.object(adapter, "is_configured", return_value=False):
        result = asyncio.run(
            adapter.fetch(
                since=None,
                cursor={"issue_id": 1},
                max_items=10,
            )
        )
    assert result.findings == []
    assert result.cursor == {"issue_id": 1}
