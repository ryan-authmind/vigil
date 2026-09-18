"""Unit tests for AuthMind console deep-link builders.

The query syntax here was reverse-engineered from the console frontend
(authmind_web/frontend/src) and validated live against the real API:
filtering identity_name/asset_name by an entity's ``id`` field (a display
label) returns results; filtering by ``full_name``/``name`` does not.
These tests pin the exact URL shapes so a refactor can't silently drift
from that validated behavior.
"""

from __future__ import annotations

from core.integrations.authmind import console_links as cl


def test_console_host_strips_amapi_suffixes():
    assert cl.console_host("https://console.authmind.com") == "https://console.authmind.com"
    assert cl.console_host("https://console.authmind.com/") == "https://console.authmind.com"
    assert cl.console_host("https://console.authmind.com/amapi") == "https://console.authmind.com"
    assert cl.console_host("https://console.authmind.com/amapi/") == "https://console.authmind.com"
    assert cl.console_host("https://console.authmind.com/amapi/v1") == "https://console.authmind.com"
    assert cl.console_host("https://console.authmind.com/amapi/v2/") == "https://console.authmind.com"
    assert cl.console_host("") == ""


def test_issue_link_matches_the_api_provided_shape():
    # Real incident_accesses_url observed from GET /amapi/v1/issues.
    assert cl.issue_link("https://console.authmind.com", 697833) == (
        "https://console.authmind.com/posture/accesses?order_by=desc&page=1"
        "&primary_identity=false&q=incident_id%3A697833&rpp=20&sort_by=latest_time"
    )


def test_identity_link_filters_on_the_id_field():
    url = cl.identity_link("https://console.authmind.com", "hashicorp-vault-user")
    assert url == (
        "https://console.authmind.com/posture/identities?order_by=desc&page=1"
        "&q=identity_name%3Ahashicorp-vault-user&rpp=20&sort_by=flow_count"
    )


def test_asset_link_filters_on_the_id_field():
    url = cl.asset_link("https://console.authmind.com", "Hashicorp Vault")
    assert url == (
        "https://console.authmind.com/posture/assets?order_by=desc&page=1"
        "&q=asset_name%3AHashicorp%20Vault&rpp=20&sort_by=flow_count"
    )


def test_secret_link_uses_the_singular_secret_route():
    url = cl.secret_link("https://console.authmind.com", "prod/customersuccessportaldb/creds")
    assert url.startswith("https://console.authmind.com/posture/secret?q=")
    assert "secret_name%3Aprod%2Fcustomersuccessportaldb%2Fcreds" in url


def test_access_link_joins_identity_and_asset_tokens_with_a_plus():
    url = cl.access_link("https://console.authmind.com", "reporting-app-role", "am-qa-reports")
    assert url == (
        "https://console.authmind.com/posture/accesses?is_access_grouped=true"
        "&order_by=asc&page=1"
        "&q=identity_name%3Areporting-app-role%2Basset_name%3Aam-qa-reports"
        "&rpp=20&sort_by=latest_time&summaryFlag=false"
    )


def test_links_percent_encode_special_characters_in_entity_names():
    # Composite identity labels (e.g. "Acts Like Service/Service Account:
    # praneeth (User)") contain ':', '/', '(', ')' and spaces that must not
    # leak into the query string unescaped.
    url = cl.identity_link(
        "https://console.authmind.com",
        "Acts Like Service/Service Account: praneeth (User)",
    )
    assert " " not in url
    assert "/" not in url.split("?", 1)[1]
