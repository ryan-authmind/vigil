"""Tests for the AuthMind inbound webhook receiver."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Mirror services/api/main.py's sys.path setup so `core.*` / `services.*`
# resolve for a standalone pytest run.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
for p in (str(_REPO_ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)

# Load the receiver module directly, so the test doesn't drag in the heavy
# modules a full router import would.
_spec = importlib.util.spec_from_file_location(
    "authmind_webhook_under_test",
    _REPO_ROOT / "core" / "integrations" / "authmind" / "authmind_webhook_router.py",
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["authmind_webhook_under_test"] = _mod
_spec.loader.exec_module(_mod)
authmind_router = _mod.router

TOKEN = "unit-test-token"

ISSUE_SAMPLE = {
    "issue_id": 881710,
    "risk": 4,
    "issue_type": "Access from Unauthorized Countries",
    "playbook_name": "Access not from Israel",
    "message": (
        "<i><b>cdn.example.com</i></b> was accessed from one or more hosts "
        "located in <i><b>India</i></b> which is flagged as unauthorized"
    ),
    "issue_flows_count": 10,
    "issue_access_count": 2,
    "first_flow_time": "2026-08-14T01:33:38Z",
    "gen_timestamp": "2026-08-14T01:33:38Z",
}


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("AUTHMIND_WEBHOOK_TOKEN", TOKEN)
    _app = FastAPI()
    _app.include_router(authmind_router, prefix="/api/webhooks/authmind")
    return _app


@pytest.fixture()
def client(app):
    return TestClient(app)


def _post(client, payload, token=TOKEN):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post("/api/webhooks/authmind", json=payload, headers=headers)


class TestAuthVerification:
    def test_missing_token_rejected(self, client):
        r = _post(client, ISSUE_SAMPLE, token=None)
        assert r.status_code == 401

    def test_bad_token_rejected(self, client):
        r = _post(client, ISSUE_SAMPLE, token="wrong-token")
        assert r.status_code == 401

    def test_no_token_configured_returns_503(self, monkeypatch):
        monkeypatch.delenv("AUTHMIND_WEBHOOK_TOKEN", raising=False)
        app = FastAPI()
        app.include_router(authmind_router, prefix="/api/webhooks/authmind")
        c = TestClient(app)
        r = _post(c, ISSUE_SAMPLE)
        assert r.status_code == 503


class TestRoutes:
    def _patched_ingestion(self, ok=True):
        p = patch("authmind_webhook_under_test.IngestionService")
        MockSvc = p.start()
        mock_service = MockSvc.return_value
        mock_service.ingest_finding.return_value = ok
        return p, mock_service

    def test_single_issue_accepted(self, client):
        p, svc = self._patched_ingestion()
        try:
            r = _post(client, ISSUE_SAMPLE)
        finally:
            p.stop()
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] is True
        assert body["finding_ids"] == ["am-881710"]
        svc.ingest_finding.assert_called_once()

    def test_batch_issues_accepted(self, client):
        p, svc = self._patched_ingestion()
        try:
            r = _post(
                client,
                {"issues": [ISSUE_SAMPLE, {**ISSUE_SAMPLE, "issue_id": 881711}]},
            )
        finally:
            p.stop()
        assert r.status_code == 202
        assert r.json()["finding_ids"] == ["am-881710", "am-881711"]
        assert svc.ingest_finding.call_count == 2

    def test_bare_list_accepted(self, client):
        p, svc = self._patched_ingestion()
        try:
            r = _post(client, [ISSUE_SAMPLE])
        finally:
            p.stop()
        assert r.status_code == 202
        assert svc.ingest_finding.call_count == 1

    def test_missing_issue_id_422(self, client):
        r = _post(client, {"risk": 3})
        assert r.status_code == 422

    def test_ingestion_failure_returns_500(self, client):
        p, svc = self._patched_ingestion(ok=False)
        try:
            r = _post(client, ISSUE_SAMPLE)
        finally:
            p.stop()
        assert r.status_code == 500

    def test_health_endpoint(self, client):
        r = client.get("/api/webhooks/authmind/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["token_configured"] is True
