"""Unit tests for AuthMindService HTTP client (AM API v1 + v2)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from core.integrations.authmind.client import (
    AuthMindError,
    AuthMindService,
    get_authmind_service,
    normalize_base_url,
)


@pytest.fixture
def service() -> AuthMindService:
    return AuthMindService(
        base_url="https://console.authmind.com/amapi/v2",
        api_token="test-jwt",
    )


def _ok_json(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.text = ""
    resp.headers = {"Content-Type": "application/json"}
    return resp


def _v2_list(*rows: dict, total: int | None = None) -> dict:
    return {
        "data": list(rows),
        "meta": {
            "page": 1,
            "page_size": 50,
            "total": total if total is not None else len(rows),
            "request_id": "req-test",
        },
        "error": None,
    }


class TestAuthMindService:
    def test_list_identities_unwraps_data_meta(self, service: AuthMindService):
        body = _v2_list({"id": "jane@example.com", "score": 12})
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            out = service.list_identities(identity_type="User", score=10)
        assert out["data"][0]["id"] == "jane@example.com"
        assert out["meta"]["total"] == 1
        args, kwargs = req.call_args
        assert args[0] == "GET"
        assert args[1] == (
            "https://console.authmind.com/amapi/v2/posture/identities"
        )
        assert kwargs["params"]["identity_type"] == "User"
        assert kwargs["params"]["score"] == 10
        assert kwargs["headers"]["Authorization"] == "Bearer test-jwt"

    def test_list_accesses_uses_identity_name_filter(self, service: AuthMindService):
        body = _v2_list({"id": "abc123hash", "score": 5})
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            out = service.list_accesses(identity_name="jane@example.com")
        assert out["data"][0]["id"] == "abc123hash"
        assert req.call_args.kwargs["params"]["identity_name"] == "jane@example.com"
        assert req.call_args[0][1].endswith("/posture/accesses")

    def test_list_secrets_is_v2_first(self, service: AuthMindService):
        body = _v2_list({"id": "db-password", "type": "password", "score": 45})
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            out = service.list_secrets(score=40)
        assert out["data"][0]["id"] == "db-password"
        assert req.call_args[0][1].endswith("/posture/secrets")

    def test_401_raises(self, service: AuthMindService):
        resp = MagicMock()
        resp.status_code = 401
        resp.text = ""
        resp.headers = {}
        resp.json.side_effect = ValueError("no body")
        with patch.object(service._client, "request", return_value=resp):
            with pytest.raises(AuthMindError, match="401"):
                service.list_identity_systems(size=1)

    def test_403_problem_details_raises(self, service: AuthMindService):
        resp = MagicMock()
        resp.status_code = 403
        resp.text = '{"detail":"client IP not allowed"}'
        resp.headers = {}
        resp.json.return_value = {
            "title": "Forbidden",
            "status": 403,
            "detail": "client IP not allowed",
            "code": "forbidden",
        }
        with patch.object(service._client, "request", return_value=resp):
            with pytest.raises(AuthMindError, match="forbidden"):
                service.list_identity_systems(size=1)

    def test_envelope_error_on_200_raises(self, service: AuthMindService):
        body = {
            "data": [],
            "meta": {},
            "error": {"code": "invalid_request", "message": "from must be >= 1"},
        }
        with patch.object(service._client, "request", return_value=_ok_json(body)):
            with pytest.raises(AuthMindError, match="from must be >= 1"):
                service.list_assets(from_=0)

    def test_network_error_raises(self, service: AuthMindService):
        with patch.object(
            service._client,
            "request",
            side_effect=httpx.ConnectError("down"),
        ):
            with pytest.raises(AuthMindError, match="request failed"):
                service.list_assets()

    @pytest.mark.parametrize(
        "configured",
        [
            "https://console.authmind.com",
            "https://console.authmind.com/",
            "https://console.authmind.com/amapi",
            "https://console.authmind.com/amapi/",
            "https://console.authmind.com/amapi/v1",
            "https://console.authmind.com/amapi/v1/",
            "https://console.authmind.com/amapi/v2",
            "https://console.authmind.com/amapi/v2/",
        ],
    )
    def test_normalize_base_url_collapses_to_amapi_root(self, configured: str):
        assert (
            normalize_base_url(configured)
            == "https://console.authmind.com/amapi"
        )

    def test_normalize_base_url_empty_stays_empty(self):
        assert normalize_base_url("") == ""
        assert normalize_base_url("   ") == ""

    @pytest.mark.parametrize(
        "method_name,kwargs,expected_path",
        [
            ("list_identity_systems", {}, "/posture/identity-systems"),
            ("list_assets", {}, "/posture/assets"),
            ("list_identities", {}, "/posture/identities"),
            ("list_accesses", {}, "/posture/accesses"),
            ("list_secrets", {}, "/posture/secrets"),
            (
                "get_identity_details",
                {"id_": "jdoe@example.com"},
                "/posture/identities/details",
            ),
            (
                "get_asset_details",
                {"id_": "salesforce.example.com", "asset_type": "SaaS"},
                "/posture/assets/details",
            ),
            (
                "get_secret_details",
                {"id_": "db-password"},
                "/posture/secrets/details",
            ),
        ],
    )
    def test_pagination_default_is_page_one(
        self,
        service: AuthMindService,
        method_name: str,
        kwargs: dict,
        expected_path: str,
    ):
        body = _v2_list()
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            getattr(service, method_name)(**kwargs)
        assert expected_path in req.call_args[0][1]
        params = req.call_args.kwargs.get("params") or {}
        if method_name.startswith("list_"):
            assert params["from"] == 1

    def test_request_url_has_no_duplicate_prefix(self):
        svc = AuthMindService(
            base_url=normalize_base_url("https://console.authmind.com/amapi/v1"),
            api_token="test-jwt",
        )
        body = _v2_list()
        with patch.object(svc._client, "request", return_value=_ok_json(body)) as req:
            svc.list_identity_systems(size=1)
        assert (
            req.call_args[0][1]
            == "https://console.authmind.com/amapi/v2/posture/identity-systems"
        )

    def test_appends_amapi_when_missing(self):
        with (
            patch(
                "core.config.get_integration_config",
                return_value={"base_url": "https://console.authmind.com"},
            ),
            patch(
                "core.integrations.authmind.client.get_secret",
                side_effect=lambda k, d=None: {"AUTHMIND_API_TOKEN": "tok"}.get(k, d),
            ),
        ):
            svc = get_authmind_service()
        assert svc is not None
        assert svc.base_url.rstrip("/").endswith("/amapi")
        assert not svc.base_url.rstrip("/").endswith("/v2")
        assert not svc.base_url.rstrip("/").endswith("/v1")

    def test_unconfigured_returns_none(self):
        with (
            patch("core.config.get_integration_config", return_value={}),
            patch(
                "core.integrations.authmind.client.get_secret", return_value=None
            ),
        ):
            assert get_authmind_service() is None

    def test_test_connection_probes_identity_systems(self, service: AuthMindService):
        with patch.object(
            service._client, "request", return_value=_ok_json(_v2_list())
        ) as req:
            ok, msg = service.test_connection()
        assert ok is True
        assert "v2 posture" in msg.lower()
        assert req.call_args[0][1].endswith("/posture/identity-systems")

    def test_test_connection_falls_back_to_v1_issues(self, service: AuthMindService):
        posture_resp = MagicMock()
        posture_resp.status_code = 403
        posture_resp.text = "missing posture permission"
        posture_resp.headers = {}
        posture_resp.json.return_value = {
            "title": "Forbidden",
            "detail": "missing posture permission",
            "code": "forbidden",
        }
        issues_body = {
            "success": True,
            "result": [],
            "total": 0,
        }
        with patch.object(
            service._client,
            "request",
            side_effect=[posture_resp, _ok_json(issues_body)],
        ) as req:
            ok, msg = service.test_connection()
        assert ok is True
        assert "v1 issues" in msg.lower()
        assert req.call_args_list[1][0][1].endswith("/v1/issues")

    def test_list_issues_uses_v1_path(self, service: AuthMindService):
        body = {"success": True, "result": [{"issue_id": 881710}], "total": 1}
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            out = service.list_issues(status="Open", from_=1, size=50)
        assert out["result"][0]["issue_id"] == 881710
        assert out["total"] == 1
        assert req.call_args[0][1] == (
            "https://console.authmind.com/amapi/v1/issues"
        )
        assert req.call_args.kwargs["params"]["from"] == 1

    def test_list_issues_for_siem_uses_zero_based_offset(
        self, service: AuthMindService
    ):
        body = {
            "success": True,
            "results": [{"issue_id": "17263-1"}],
            "metadata": {"total": 1},
        }
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ) as req:
            out = service.list_issues_for_siem(issue_id_gt="0")
        assert out["results"][0]["issue_id"] == "17263-1"
        assert req.call_args[0][1].endswith("/v1/getIssues")
        assert req.call_args.kwargs["params"]["from"] == 0

    def test_v1_success_false_raises(self, service: AuthMindService):
        body = {"success": False, "error": "token expired"}
        with patch.object(
            service._client, "request", return_value=_ok_json(body)
        ):
            with pytest.raises(AuthMindError, match="token expired"):
                service.list_playbooks()


class TestAuthMindToolPaginationDefaults:
    def test_page_from_defaults_and_clamps(self):
        from core.integrations.authmind.tool import _page_from

        assert _page_from({}) == 1
        assert _page_from({"from": 0}) == 1
        assert _page_from({"from": -3}) == 1
        assert _page_from({"from": 4}) == 4

    def test_offset_from_defaults_and_clamps(self):
        from core.integrations.authmind.tool import _offset_from

        assert _offset_from({}) == 0
        assert _offset_from({"from": -3}) == 0
        assert _offset_from({"from": 12}) == 12
