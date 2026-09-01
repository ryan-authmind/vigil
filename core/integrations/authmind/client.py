"""AuthMind identity-security REST client — AM API v1 + v2.

One ``/amapi`` root, two versioned path families:

- **v1** (``/amapi/v1``) — issues, SIEM getIssues, issue-accesses, playbooks.
  These have no v2 counterpart.
- **v2** (``/amapi/v2/posture``) — identity systems, identities, assets,
  accesses, secrets. Prefer v2 for overlapping inventory resources.

Console user admin (create / update / delete users) is not exposed.

Config:
  - ``base_url`` — the console host, with or without ``/amapi`` / ``/amapi/v1``
    / ``/amapi/v2``. ``normalize_base_url`` reduces all spellings to the
    ``/amapi`` root; each method then prefixes ``/v1`` or ``/v2``.
  - ``AUTHMIND_API_TOKEN`` — Bearer JWT from AuthMind Admin → API Tokens.
    v2 posture calls need ``posture`` in the JWT permissions array; v1
    issues need ``issues``; v1 playbooks need ``playbooks``.

Docs: https://authmind-qa.redocly.app/openapi.bundled
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from core.secrets import get_secret

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
DEFAULT_PAGE_SIZE = 50
FIRST_PAGE = 1
FIRST_OFFSET = 0
API_ROOT = "/amapi"

# httpx.InvalidURL sits outside HTTPError; fold both so malformed URLs
# surface as AuthMindError instead of escaping to a 500.
_HTTP_ERRORS = (httpx.HTTPError, httpx.InvalidURL)

# requests followed redirects by default; httpx does not.
_FOLLOW_REDIRECTS = True


class AuthMindError(Exception):
    """Raised when AuthMind returns an auth, permission, or API error."""


class AuthMindService:
    """HTTP client that bridges AuthMind ``/amapi/v1`` and ``/amapi/v2``."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        verify_ssl: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = normalize_base_url(base_url).rstrip("/") + "/"
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=_FOLLOW_REDIRECTS,
        )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        # Concatenate rather than urljoin: a path starting with "/" would
        # replace the /amapi base path under urljoin's RFC 3986 rules.
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        clean_params = {
            k: v for k, v in (params or {}).items() if v is not None and v != ""
        }
        try:
            resp = self._client.request(
                method,
                url,
                headers=self._headers(),
                params=clean_params or None,
            )
        except _HTTP_ERRORS as exc:
            raise AuthMindError(f"AuthMind request failed: {exc}") from exc

        if resp.status_code == 401:
            raise AuthMindError(
                "Token missing, malformed, expired, or missing required "
                "permissions (HTTP 401). v2 posture needs `posture`; v1 "
                "issues need `issues`; v1 playbooks need `playbooks`."
            )

        body: Any = None
        try:
            body = resp.json()
        except ValueError:
            body = None

        if resp.status_code >= 400:
            raise AuthMindError(_problem_message(resp, body))

        if not isinstance(body, dict):
            raise AuthMindError(
                f"Non-JSON response (HTTP {resp.status_code}): {resp.text[:200]}"
            )

        # v2: error object on HTTP 200 (should not happen, still guard).
        if body.get("error"):
            err = body["error"]
            if isinstance(err, dict):
                raise AuthMindError(str(err.get("message") or err.get("code") or err))
            raise AuthMindError(str(err))
        # v1: envelope success=false with HTTP 200.
        if body.get("success") is False:
            raise AuthMindError(
                str(body.get("error") or body.get("errors") or "Unknown AuthMind error")
            )
        return body

    def _get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params=params)

    def _v1(self, path: str, **params: Any) -> Any:
        return self._get(f"/v1/{path.lstrip('/')}", **params)

    def _v2(self, path: str, **params: Any) -> Any:
        return self._get(f"/v2/{path.lstrip('/')}", **params)

    @staticmethod
    def _unwrap(body: Any) -> Any:
        """Normalize v1 and v2 success envelopes without mixing them.

        v2 → ``{data, meta}``. v1 SIEM → ``{results, metadata}``. v1 resource
        lists → ``{result, total}``.
        """
        if not isinstance(body, dict):
            return body
        if "data" in body and "result" not in body and "results" not in body:
            return {
                "data": body.get("data"),
                "meta": body.get("meta") or {},
            }
        if "results" in body:
            return {
                "results": body.get("results") or [],
                "metadata": body.get("metadata") or {},
            }
        if "result" in body:
            result = body["result"]
            out: Dict[str, Any] = {"result": result}
            if "total" in body:
                out["total"] = body["total"]
            elif isinstance(result, dict) and "total" in result:
                out["total"] = result.get("total")
                out["result"] = result.get("data", result)
            return out
        return body

    # ------------------------------------------------------------------ #
    # v1 issues + playbooks (no v2 counterpart)
    # ------------------------------------------------------------------ #

    def list_issues_for_siem(
        self,
        *,
        issue_id_gt: Optional[str] = None,
        issue_time_gt: Optional[str] = None,
        issue_type: Optional[str] = None,
        sort_by: str = "issue_id",
        sort_order: str = "ASC",
        from_: int = FIRST_OFFSET,
        size: int = 1000,
    ) -> Dict[str, Any]:
        """Incremental SIEM poll via ``GET /v1/getIssues``."""
        return self._unwrap(
            self._v1(
                "/getIssues",
                issue_id_gt=issue_id_gt,
                issue_time_gt=issue_time_gt,
                issue_type=issue_type,
                sort_by=sort_by,
                sort_order=sort_order,
                **{"from": from_, "size": size},
            )
        )

    def get_issue_details(
        self,
        issue_id: str,
        *,
        sort_by: str = "last_seen",
        sort_order: str = "DESC",
        from_: int = FIRST_OFFSET,
        size: int = 1000,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v1(
                "/getIssueDetails",
                issue_id=issue_id,
                sort_by=sort_by,
                sort_order=sort_order,
                **{"from": from_, "size": size},
            )
        )

    def list_issues(
        self,
        *,
        status: str = "Open",
        risk: Optional[str] = None,
        issue_type: Optional[str] = None,
        playbook_name: Optional[str] = None,
        issue_id: Optional[str] = None,
        gen_timestamp_gt: Optional[str] = None,
        first_flow_time_gt: Optional[str] = None,
        sort_by: Optional[str] = None,
        order_by: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v1(
                "/issues",
                status=status,
                risk=risk,
                issue_type=issue_type,
                playbook_name=playbook_name,
                issue_id=issue_id,
                gen_timestamp_gt=gen_timestamp_gt,
                first_flow_time_gt=first_flow_time_gt,
                sort_by=sort_by,
                order_by=order_by,
                **{"from": from_, "size": size},
            )
        )

    def list_issue_accesses(
        self,
        incident_id: str,
        *,
        sort_by: Optional[str] = None,
        order_by: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v1(
                f"/issue/{incident_id}/accesses",
                sort_by=sort_by,
                order_by=order_by,
                **{"from": from_, "size": size},
            )
        )

    def list_playbooks(
        self,
        *,
        include_all: bool = False,
        q: Optional[str] = None,
        sort_by: Optional[str] = None,
        order_by: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v1(
                "/playbooks",
                include_all=str(include_all).lower(),
                q=q,
                sort_by=sort_by,
                order_by=order_by,
                **{"from": from_, "size": size},
            )
        )

    # ------------------------------------------------------------------ #
    # v2 posture — identity systems
    # ------------------------------------------------------------------ #

    def list_identity_systems(
        self,
        *,
        directory_type: Optional[str] = None,
        latest_activity_time_gt: Optional[str] = None,
        score: Optional[float] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/identity-systems",
                directory_type=directory_type,
                latest_activity_time_gt=latest_activity_time_gt,
                score=score,
                **{"from": from_, "size": size},
            )
        )

    def get_identity_system_details(self, id_: str) -> Dict[str, Any]:
        return self._unwrap(self._v2("/posture/identity-systems/details", id=id_))

    # ------------------------------------------------------------------ #
    # v2 posture — assets
    # ------------------------------------------------------------------ #

    def list_assets(
        self,
        *,
        asset_type: Optional[str] = None,
        latest_activity_time_gt: Optional[str] = None,
        score: Optional[float] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/assets",
                asset_type=asset_type,
                latest_activity_time_gt=latest_activity_time_gt,
                score=score,
                **{"from": from_, "size": size},
            )
        )

    def get_asset_details(self, id_: str, asset_type: str) -> Dict[str, Any]:
        return self._unwrap(
            self._v2("/posture/assets/details", id=id_, asset_type=asset_type)
        )

    def list_asset_hosts(
        self,
        id_: str,
        asset_type: str,
        *,
        latest_activity_time_gt: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/assets/hosts",
                id=id_,
                asset_type=asset_type,
                latest_activity_time_gt=latest_activity_time_gt,
                **{"from": from_, "size": size},
            )
        )

    # ------------------------------------------------------------------ #
    # v2 posture — identities
    # ------------------------------------------------------------------ #

    def list_identities(
        self,
        *,
        identity_type: Optional[str] = None,
        identity_status: Optional[str] = None,
        latest_activity_time_gt: Optional[str] = None,
        score: Optional[float] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/identities",
                identity_type=identity_type,
                identity_status=identity_status,
                latest_activity_time_gt=latest_activity_time_gt,
                score=score,
                **{"from": from_, "size": size},
            )
        )

    def get_identity_details(self, id_: str) -> Dict[str, Any]:
        return self._unwrap(self._v2("/posture/identities/details", id=id_))

    def list_identity_hosts(
        self,
        id_: str,
        *,
        latest_activity_time_gt: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/identities/hosts",
                id=id_,
                latest_activity_time_gt=latest_activity_time_gt,
                **{"from": from_, "size": size},
            )
        )

    # ------------------------------------------------------------------ #
    # v2 posture — accesses
    # ------------------------------------------------------------------ #

    def list_accesses(
        self,
        *,
        identity_name: Optional[str] = None,
        identity_type: Optional[str] = None,
        asset_name: Optional[str] = None,
        asset_type: Optional[str] = None,
        directory_type: Optional[str] = None,
        directory_name: Optional[str] = None,
        latest_activity_time_gt: Optional[str] = None,
        score: Optional[float] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/accesses",
                identity_name=identity_name,
                identity_type=identity_type,
                asset_name=asset_name,
                asset_type=asset_type,
                directory_type=directory_type,
                directory_name=directory_name,
                latest_activity_time_gt=latest_activity_time_gt,
                score=score,
                **{"from": from_, "size": size},
            )
        )

    def get_access_details(
        self,
        *,
        identity_name: str,
        identity_type: str,
        asset_name: str,
        asset_type: str,
        directory_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/accesses/details",
                identity_name=identity_name,
                identity_type=identity_type,
                asset_name=asset_name,
                asset_type=asset_type,
                directory_name=directory_name,
            )
        )

    def list_access_source_hosts(
        self,
        id_: str,
        *,
        latest_activity_time_gt: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/accesses/source-hosts",
                id=id_,
                latest_activity_time_gt=latest_activity_time_gt,
                **{"from": from_, "size": size},
            )
        )

    def list_access_destination_hosts(
        self,
        id_: str,
        *,
        latest_activity_time_gt: Optional[str] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/accesses/destination-hosts",
                id=id_,
                latest_activity_time_gt=latest_activity_time_gt,
                **{"from": from_, "size": size},
            )
        )

    # ------------------------------------------------------------------ #
    # v2 secrets (v2-first; never returns secret material)
    # ------------------------------------------------------------------ #

    def list_secrets(
        self,
        *,
        latest_activity_time_gt: Optional[str] = None,
        score: Optional[float] = None,
        from_: int = FIRST_PAGE,
        size: int = DEFAULT_PAGE_SIZE,
    ) -> Dict[str, Any]:
        return self._unwrap(
            self._v2(
                "/posture/secrets",
                latest_activity_time_gt=latest_activity_time_gt,
                score=score,
                **{"from": from_, "size": size},
            )
        )

    def get_secret_details(self, id_: str) -> Dict[str, Any]:
        return self._unwrap(self._v2("/posture/secrets/details", id=id_))

    def test_connection(self) -> tuple[bool, str]:
        """Probe v2 posture first, then v1 issues if posture is out of scope."""
        try:
            self.list_identity_systems(size=1)
            return True, "Connection successful (v2 posture)"
        except AuthMindError as posture_exc:
            try:
                self.list_issues(from_=1, size=1)
                return True, "Connection successful (v1 issues; v2 posture unavailable)"
            except AuthMindError:
                return False, str(posture_exc)
        except Exception as exc:  # pragma: no cover - defensive
            return False, f"Unexpected error: {exc}"


def _problem_message(resp: httpx.Response, body: Any) -> str:
    """Format RFC 7807 ProblemDetails (v2) or v1 text/plain / JSON errors."""
    retry_after = resp.headers.get("Retry-After")
    suffix = f" (Retry-After: {retry_after})" if retry_after else ""
    if isinstance(body, dict):
        code = body.get("code") or ""
        detail = (
            body.get("detail")
            or body.get("title")
            or body.get("error")
            or body.get("errors")
            or ""
        )
        parts = [p for p in (code, detail) if p]
        if parts:
            return (
                f"{'; '.join(str(p) for p in parts)} "
                f"(HTTP {resp.status_code}){suffix}"
            )
    text = (resp.text or "").strip()
    if resp.status_code == 403 and text:
        return f"Permission denied: {text[:200]}{suffix}"
    if text:
        return f"HTTP {resp.status_code}: {text[:200]}{suffix}"
    return f"HTTP {resp.status_code}{suffix}"


def normalize_base_url(raw: str) -> str:
    """Reduce any accepted AuthMind base-URL spelling to the ``/amapi`` root.

    Methods prefix ``/v1`` or ``/v2`` themselves, so a configured version
    segment has to come off or the request doubles it.
    """
    base = (raw or "").strip().rstrip("/")
    if not base:
        return ""
    lowered = base.lower()
    for suffix in ("/amapi/v2", "/amapi/v1", "/amapi"):
        if lowered.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break
    return f"{base}{API_ROOT}"


def get_authmind_service() -> Optional[AuthMindService]:
    """Build an AuthMindService from Settings / secrets, or None if unconfigured."""
    from core.config import get_integration_config

    cfg = get_integration_config("authmind") or {}
    token = get_secret("AUTHMIND_API_TOKEN") or cfg.get("api_token")
    base_url = (cfg.get("base_url") or "").strip().rstrip("/")

    # Allow env bootstrap when the UI hasn't enabled the integration yet
    # (get_integration_config returns {} for disabled integrations).
    if not base_url:
        base_url = (get_secret("AUTHMIND_BASE_URL") or "").strip().rstrip("/")

    if not token or not base_url:
        return None

    verify_ssl = cfg.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.lower() not in ("false", "0", "no")

    return AuthMindService(
        base_url=base_url,
        api_token=str(token),
        verify_ssl=bool(verify_ssl),
    )
