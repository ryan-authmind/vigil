"""MCP server exposing AuthMind AM API v1 + v2 lookups as tools.

Read-only surface for SOC investigation. Console user administration
is intentionally not exposed.

v1 owns issues and playbooks (no v2 counterpart). v2 owns posture
inventory (identity systems, identities, assets, accesses, secrets).
Matched playbooks also appear on v2 entity detail payloads.

Tools:
  - authmind_list_issues_for_siem
  - authmind_get_issue_details
  - authmind_list_issues
  - authmind_list_issue_accesses
  - authmind_list_playbooks
  - authmind_list_identity_systems
  - authmind_get_identity_system_details
  - authmind_list_assets
  - authmind_get_asset_details
  - authmind_list_asset_hosts
  - authmind_list_identities
  - authmind_get_identity_details
  - authmind_list_identity_hosts
  - authmind_list_accesses
  - authmind_get_access_details
  - authmind_list_access_source_hosts
  - authmind_list_access_destination_hosts
  - authmind_list_secrets
  - authmind_get_secret_details
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logger = logging.getLogger(__name__)
server = Server("authmind")


def _result(data: Any) -> list[types.TextContent]:
    return [
        types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))
    ]


def _get_service():
    try:
        from core.integrations.authmind.client import get_authmind_service

        return get_authmind_service()
    except Exception as exc:
        logger.error("Failed to load AuthMind service: %s", exc)
        return None


def _opt_int(args: dict, key: str, default: Optional[int] = None) -> Optional[int]:
    val = args.get(key, default)
    if val is None or val == "":
        return default
    return int(val)


def _page_from(args: dict) -> int:
    """1-based page number used by v1 resource lists and every v2 list."""
    val = _opt_int(args, "from", 1)
    if val is None or val < 1:
        return 1
    return val


def _offset_from(args: dict) -> int:
    """0-based record offset used by /v1/getIssues and /v1/getIssueDetails."""
    val = _opt_int(args, "from", 0)
    if val is None or val < 0:
        return 0
    return val


def _opt_float(args: dict, key: str) -> Optional[float]:
    val = args.get(key)
    if val is None or val == "":
        return None
    return float(val)


def _first(*values: Any) -> Optional[str]:
    for value in values:
        if value is not None and value != "":
            return str(value)
    return None


_PAGE = {
    "from": {
        "type": "integer",
        "description": "1-based page number (default 1). Echoed as meta.page on v2.",
        "default": 1,
    },
    "size": {
        "type": "integer",
        "description": "Page size (default 50, max 1000 on most lists; hosts max 100).",
        "default": 50,
    },
    "latest_activity_time_gt": {
        "type": "string",
        "description": (
            "Only include rows whose latest activity is strictly after this "
            "timestamp (UTC). Prefer RFC 3339 (`2024-01-15T09:30:00Z`); "
            "`YYYY-MM-DD HH:MM:SS` is also accepted."
        ),
    },
    "score": {
        "type": "number",
        "description": (
            "Minimum posture score (inclusive). Higher scores indicate worse "
            "posture (typically 0–100)."
        ),
    },
}

_V1_PAGE = {
    "from": {
        "type": "integer",
        "description": (
            "Pagination cursor. On /v1/getIssues and /v1/getIssueDetails this "
            "is a 0-based record offset (default 0). On /v1/issues, "
            "/v1/issue/{id}/accesses, and /v1/playbooks it is a 1-based page "
            "number (default 1)."
        ),
    },
    "size": {
        "type": "integer",
        "description": "Page size.",
        "default": 50,
    },
}


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="authmind_list_issues_for_siem",
            description=(
                "Poll AuthMind issues for SIEM/SOAR ingestion "
                "(GET /amapi/v1/getIssues). Prefer issue_id_gt bookmarking "
                "for incremental pulls. Risk is Low/Medium/High/Critical."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_id_gt": {
                        "type": "string",
                        "description": (
                            "Return issues with id greater than this bookmark."
                        ),
                    },
                    "issue_time_gt": {
                        "type": "string",
                        "description": "YYYY-MM-DD HH:MM:SS lower bound on issue_time.",
                    },
                    "issue_type": {"type": "string"},
                    "sort_by": {
                        "type": "string",
                        "enum": [
                            "issue_id",
                            "issue_time",
                            "flow_count",
                            "incident_count",
                            "risk",
                        ],
                        "default": "issue_id",
                    },
                    "sort_order": {
                        "type": "string",
                        "enum": ["ASC", "DESC"],
                        "default": "ASC",
                    },
                    **_V1_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_issue_details",
            description=(
                "Get AuthMind issue details and related incidents "
                "(GET /amapi/v1/getIssueDetails). Requires issue_id from "
                "authmind_list_issues_for_siem."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_id": {
                        "type": "string",
                        "description": "Issue id, e.g. 17263-1722579276407",
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": [
                            "incident_id",
                            "incident_risk",
                            "flow_count",
                            "last_seen",
                            "first_seen",
                        ],
                        "default": "last_seen",
                    },
                    "sort_order": {
                        "type": "string",
                        "enum": ["ASC", "DESC"],
                        "default": "DESC",
                    },
                    **_V1_PAGE,
                },
                "required": ["issue_id"],
            },
        ),
        types.Tool(
            name="authmind_list_issues",
            description=(
                "List AuthMind issues with filters (GET /amapi/v1/issues). "
                "Defaults to Open status. Risk filter is numeric: "
                "4=Critical … 1=Low. This is the console issue list; "
                "prefer it over getIssues for investigation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["Open", "Closed", "Resolved"],
                        "default": "Open",
                    },
                    "risk": {
                        "type": "string",
                        "enum": ["4", "3", "2", "1"],
                        "description": "4 Critical, 3 High, 2 Medium, 1 Low",
                    },
                    "issue_type": {"type": "string"},
                    "playbook_name": {"type": "string"},
                    "issue_id": {"type": "string"},
                    "gen_timestamp_gt": {"type": "string"},
                    "first_flow_time_gt": {"type": "string"},
                    "sort_by": {"type": "string"},
                    "order_by": {"type": "string", "enum": ["asc", "desc"]},
                    **_V1_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_issue_accesses",
            description=(
                "List accesses associated with an AuthMind issue/incident "
                "(GET /amapi/v1/issue/{incident_id}/accesses)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string"},
                    "sort_by": {"type": "string"},
                    "order_by": {"type": "string", "enum": ["asc", "desc"]},
                    **_V1_PAGE,
                },
                "required": ["incident_id"],
            },
        ),
        types.Tool(
            name="authmind_list_playbooks",
            description=(
                "List AuthMind detection playbooks "
                "(GET /amapi/v1/playbooks). Active only by default."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "include_all": {
                        "type": "boolean",
                        "description": "Include inactive playbooks.",
                        "default": False,
                    },
                    "q": {
                        "type": "string",
                        "description": "Search by playbook name",
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": [
                            "playbook_name",
                            "risk",
                            "modified_date",
                            "is_active",
                        ],
                    },
                    "order_by": {"type": "string", "enum": ["asc", "desc"]},
                    **_V1_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_identity_systems",
            description=(
                "List AuthMind identity systems / directories "
                "(GET /amapi/v2/posture/identity-systems)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "directory_type": {
                        "type": "string",
                        "enum": ["On-premise", "Cloud IDP"],
                    },
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_identity_system_details",
            description=(
                "Get AuthMind identity system details including matched "
                "playbooks (GET /amapi/v2/posture/identity-systems/details)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": (
                            "Stable identity system id from the list endpoint."
                        ),
                    },
                    "identifier": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_assets",
            description="List AuthMind assets (GET /amapi/v2/posture/assets).",
            inputSchema={
                "type": "object",
                "properties": {
                    "asset_type": {
                        "type": "string",
                        "description": "Filter by asset type (e.g. SaaS, Server).",
                    },
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_asset_details",
            description=(
                "Get AuthMind asset details including matched playbooks "
                "(GET /amapi/v2/posture/assets/details). Requires id + asset_type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Stable asset id from the list endpoint.",
                    },
                    "asset_name": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                    "asset_type": {"type": "string"},
                },
                "required": ["asset_type"],
            },
        ),
        types.Tool(
            name="authmind_list_asset_hosts",
            description=(
                "List destination hosts for an AuthMind asset "
                "(GET /amapi/v2/posture/assets/hosts)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "asset_name": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                    "asset_type": {"type": "string"},
                    **_PAGE,
                },
                "required": ["asset_type"],
            },
        ),
        types.Tool(
            name="authmind_list_identities",
            description=(
                "List AuthMind identities (GET /amapi/v2/posture/identities). "
                "No free-text name filter — use details when the id is known."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "identity_type": {
                        "type": "string",
                        "description": "Filter by identity type (e.g. User, Service).",
                    },
                    "type": {
                        "type": "string",
                        "description": "Alias for identity_type.",
                    },
                    "identity_status": {"type": "string"},
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_identity_details",
            description=(
                "Get AuthMind identity details including matched playbooks "
                "(GET /amapi/v2/posture/identities/details)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Stable identity id from the list endpoint.",
                    },
                    "identifier": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_identity_hosts",
            description=(
                "List source hosts for an identity "
                "(GET /amapi/v2/posture/identities/hosts)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "identifier": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_accesses",
            description=(
                "List observed identity→asset accesses "
                "(GET /amapi/v2/posture/accesses), newest activity first."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "identity_name": {"type": "string"},
                    "identity": {
                        "type": "string",
                        "description": "Alias for identity_name.",
                    },
                    "identity_type": {"type": "string"},
                    "asset_name": {"type": "string"},
                    "asset": {
                        "type": "string",
                        "description": "Alias for asset_name.",
                    },
                    "asset_type": {"type": "string"},
                    "directory_type": {
                        "type": "string",
                        "enum": ["On-premise", "Cloud IDP"],
                    },
                    "directory_name": {"type": "string"},
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_access_details",
            description=(
                "Get details for a specific identity→asset access "
                "(GET /amapi/v2/posture/accesses/details)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "identity_name": {"type": "string"},
                    "identity_type": {"type": "string"},
                    "asset_name": {"type": "string"},
                    "asset_type": {"type": "string"},
                    "directory_name": {"type": "string"},
                },
                "required": [
                    "identity_name",
                    "identity_type",
                    "asset_name",
                    "asset_type",
                ],
            },
        ),
        types.Tool(
            name="authmind_list_access_source_hosts",
            description=(
                "List source hosts for an access "
                "(GET /amapi/v2/posture/accesses/source-hosts)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Access hash / id from the list endpoint.",
                    },
                    "identifier": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_access_destination_hosts",
            description=(
                "List destination hosts for an access "
                "(GET /amapi/v2/posture/accesses/destination-hosts)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Access hash / id from the list endpoint.",
                    },
                    "identifier": {
                        "type": "string",
                        "description": "Alias for id.",
                    },
                    **_PAGE,
                },
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_list_secrets",
            description=(
                "List AuthMind secrets / credentials metadata "
                "(GET /amapi/v2/posture/secrets). Never returns secret material."
            ),
            inputSchema={
                "type": "object",
                "properties": {**_PAGE},
                "required": [],
            },
        ),
        types.Tool(
            name="authmind_get_secret_details",
            description=(
                "Get AuthMind secret metadata including matched playbooks "
                "(GET /amapi/v2/posture/secrets/details). Never returns "
                "secret material."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": (
                            "Stable secret id / name from the list endpoint."
                        ),
                    },
                },
                "required": ["id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    from core.integrations.authmind.client import AuthMindError

    service = _get_service()
    if not service:
        return _result(
            {
                "error": "AuthMind not configured",
                "message": (
                    "Configure base_url and api_token under "
                    "Settings → Integrations → AuthMind, then enable the "
                    "authmind MCP server. The JWT needs `issues` for v1 "
                    "issue tools, `playbooks` for playbook list, and "
                    "`posture` for v2 inventory/secrets."
                ),
            }
        )

    args = arguments or {}
    page = _page_from(args)
    size = _opt_int(args, "size", 50) or 50
    since = args.get("latest_activity_time_gt")
    score = _opt_float(args, "score")
    try:
        if name == "authmind_list_issues_for_siem":
            return _result(
                service.list_issues_for_siem(
                    issue_id_gt=args.get("issue_id_gt"),
                    issue_time_gt=args.get("issue_time_gt"),
                    issue_type=args.get("issue_type"),
                    sort_by=args.get("sort_by") or "issue_id",
                    sort_order=args.get("sort_order") or "ASC",
                    from_=_offset_from(args),
                    size=_opt_int(args, "size", 1000) or 1000,
                )
            )

        if name == "authmind_get_issue_details":
            issue_id = args.get("issue_id")
            if not issue_id:
                return _result({"error": "issue_id required"})
            return _result(
                service.get_issue_details(
                    issue_id,
                    sort_by=args.get("sort_by") or "last_seen",
                    sort_order=args.get("sort_order") or "DESC",
                    from_=_offset_from(args),
                    size=_opt_int(args, "size", 1000) or 1000,
                )
            )

        if name == "authmind_list_issues":
            return _result(
                service.list_issues(
                    status=args.get("status") or "Open",
                    risk=args.get("risk"),
                    issue_type=args.get("issue_type"),
                    playbook_name=args.get("playbook_name"),
                    issue_id=args.get("issue_id"),
                    gen_timestamp_gt=args.get("gen_timestamp_gt"),
                    first_flow_time_gt=args.get("first_flow_time_gt"),
                    sort_by=args.get("sort_by"),
                    order_by=args.get("order_by"),
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_issue_accesses":
            incident_id = args.get("incident_id")
            if not incident_id:
                return _result({"error": "incident_id required"})
            return _result(
                service.list_issue_accesses(
                    incident_id,
                    sort_by=args.get("sort_by"),
                    order_by=args.get("order_by"),
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_playbooks":
            return _result(
                service.list_playbooks(
                    include_all=bool(args.get("include_all", False)),
                    q=args.get("q"),
                    sort_by=args.get("sort_by"),
                    order_by=args.get("order_by"),
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_identity_systems":
            return _result(
                service.list_identity_systems(
                    directory_type=args.get("directory_type"),
                    latest_activity_time_gt=since,
                    score=score,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_get_identity_system_details":
            id_ = _first(args.get("id"), args.get("identifier"))
            if not id_:
                return _result({"error": "id required"})
            return _result(service.get_identity_system_details(id_))

        if name == "authmind_list_assets":
            return _result(
                service.list_assets(
                    asset_type=args.get("asset_type"),
                    latest_activity_time_gt=since,
                    score=score,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_get_asset_details":
            id_ = _first(args.get("id"), args.get("asset_name"))
            asset_type = args.get("asset_type")
            if not id_ or not asset_type:
                return _result({"error": "id (or asset_name) and asset_type required"})
            return _result(service.get_asset_details(id_, asset_type))

        if name == "authmind_list_asset_hosts":
            id_ = _first(args.get("id"), args.get("asset_name"))
            asset_type = args.get("asset_type")
            if not id_ or not asset_type:
                return _result({"error": "id (or asset_name) and asset_type required"})
            return _result(
                service.list_asset_hosts(
                    id_,
                    asset_type,
                    latest_activity_time_gt=since,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_identities":
            return _result(
                service.list_identities(
                    identity_type=_first(args.get("identity_type"), args.get("type")),
                    identity_status=args.get("identity_status"),
                    latest_activity_time_gt=since,
                    score=score,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_get_identity_details":
            id_ = _first(args.get("id"), args.get("identifier"))
            if not id_:
                return _result({"error": "id required"})
            return _result(service.get_identity_details(id_))

        if name == "authmind_list_identity_hosts":
            id_ = _first(args.get("id"), args.get("identifier"))
            if not id_:
                return _result({"error": "id required"})
            return _result(
                service.list_identity_hosts(
                    id_,
                    latest_activity_time_gt=since,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_accesses":
            return _result(
                service.list_accesses(
                    identity_name=_first(
                        args.get("identity_name"), args.get("identity")
                    ),
                    identity_type=args.get("identity_type"),
                    asset_name=_first(args.get("asset_name"), args.get("asset")),
                    asset_type=args.get("asset_type"),
                    directory_type=args.get("directory_type"),
                    directory_name=args.get("directory_name"),
                    latest_activity_time_gt=since,
                    score=score,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_get_access_details":
            required = ("identity_name", "identity_type", "asset_name", "asset_type")
            missing = [k for k in required if not args.get(k)]
            if missing:
                return _result({"error": f"missing required: {', '.join(missing)}"})
            return _result(
                service.get_access_details(
                    identity_name=args["identity_name"],
                    identity_type=args["identity_type"],
                    asset_name=args["asset_name"],
                    asset_type=args["asset_type"],
                    directory_name=args.get("directory_name"),
                )
            )

        if name == "authmind_list_access_source_hosts":
            id_ = _first(args.get("id"), args.get("identifier"))
            if not id_:
                return _result({"error": "id (access hash) required"})
            return _result(
                service.list_access_source_hosts(
                    id_,
                    latest_activity_time_gt=since,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_access_destination_hosts":
            id_ = _first(args.get("id"), args.get("identifier"))
            if not id_:
                return _result({"error": "id (access hash) required"})
            return _result(
                service.list_access_destination_hosts(
                    id_,
                    latest_activity_time_gt=since,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_list_secrets":
            return _result(
                service.list_secrets(
                    latest_activity_time_gt=since,
                    score=score,
                    from_=page,
                    size=size,
                )
            )

        if name == "authmind_get_secret_details":
            id_ = args.get("id")
            if not id_:
                return _result({"error": "id required"})
            return _result(service.get_secret_details(id_))

        return _result({"error": f"Unknown tool: {name}"})
    except AuthMindError as exc:
        return _result({"error": str(exc)})
    except Exception as exc:
        logger.error("AuthMind tool %s failed: %s", name, exc, exc_info=True)
        return _result({"error": str(exc)})


async def main():
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="authmind",
                server_version="0.3.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
