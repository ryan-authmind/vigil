"""Deep links back to the AuthMind console UI for skill/tool results.

The v1 issues API returns a ready-made ``incident_accesses_url`` field, but
the v2 posture endpoints (identities/assets/secrets/accesses) return no URL
at all. These builders reverse the console's own React routes so agents can
cite "where to look in AuthMind" alongside enrichment data instead of just
raw JSON.

Confirmed against the console frontend source (authmind_web/frontend/src —
IdentitiesTable.tsx, AssetsTable.tsx, SecretsUsedSection.tsx, TopIssues.tsx)
and validated live against the real API: the ``identity_name``/``asset_name``/
``secret_name`` query filters match a posture entity's own ``id`` field (a
display label such as ``"Acts Like Service/Service Account: praneeth
(User)"``), not its ``full_name``. A live query filtering ``identity_name``
by ``full_name`` returned zero rows; filtering by ``id`` returned the
expected accesses.
"""

from __future__ import annotations

from urllib.parse import quote


def console_host(base_url: str) -> str:
    """Strip any ``/amapi[/vN]`` suffix from a configured/normalized
    base_url, leaving the browsable console origin
    (e.g. ``"https://console.authmind.com"``)."""
    base = (base_url or "").strip().rstrip("/")
    lowered = base.lower()
    for suffix in ("/amapi/v2", "/amapi/v1", "/amapi"):
        if lowered.endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


def _q(*tokens: str) -> str:
    return quote("+".join(str(t) for t in tokens), safe="")


def issue_link(host: str, incident_id) -> str:
    return (
        f"{host}/posture/accesses?order_by=desc&page=1&primary_identity=false"
        f"&q={_q(f'incident_id:{incident_id}')}&rpp=20&sort_by=latest_time"
    )


def identity_link(host: str, identity_name: str) -> str:
    return (
        f"{host}/posture/identities?order_by=desc&page=1"
        f"&q={_q(f'identity_name:{identity_name}')}&rpp=20&sort_by=flow_count"
    )


def asset_link(host: str, asset_name: str) -> str:
    return (
        f"{host}/posture/assets?order_by=desc&page=1"
        f"&q={_q(f'asset_name:{asset_name}')}&rpp=20&sort_by=flow_count"
    )


def secret_link(host: str, secret_name: str) -> str:
    return (
        f"{host}/posture/secret?q={_q(f'secret_name:{secret_name}')}"
        f"&sort_by=flow_count&order_by=desc"
    )


def access_link(host: str, identity_name: str, asset_name: str) -> str:
    return (
        f"{host}/posture/accesses?is_access_grouped=true&order_by=asc&page=1"
        f"&q={_q(f'identity_name:{identity_name}', f'asset_name:{asset_name}')}"
        f"&rpp=20&sort_by=latest_time&summaryFlag=false"
    )


def identity_accesses_link(host: str, identity_name: str) -> str:
    """All accesses for a single identity, no asset filter — same
    ``/posture/accesses`` route and field-prefixed ``q`` convention as
    ``access_link``, for calls scoped to just the identity side."""
    return (
        f"{host}/posture/accesses?is_access_grouped=true&order_by=asc&page=1"
        f"&q={_q(f'identity_name:{identity_name}')}&rpp=20&sort_by=latest_time"
    )


def asset_accesses_link(host: str, asset_name: str) -> str:
    """All accesses for a single asset, no identity filter — the mirror
    of ``identity_accesses_link``."""
    return (
        f"{host}/posture/accesses?is_access_grouped=true&order_by=asc&page=1"
        f"&q={_q(f'asset_name:{asset_name}')}&rpp=20&sort_by=latest_time"
    )


def identity_system_link(host: str, dir_name: str) -> str:
    return f"{host}/posture/identities?q={_q(f'dir_name:{dir_name}')}"
