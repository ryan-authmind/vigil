"""Unit tests for AuthMind MCP tool result enrichment with console links.

Each AuthMind tool's raw API result shape (data/result/results envelopes,
nested identity/asset objects) is exercised here to confirm
_attach_console_links finds the right rows and fields without needing a
live service or a real MCP round-trip.
"""

from __future__ import annotations

from core.integrations.authmind.tool import _attach_console_links

HOST = "https://console.authmind.com"


def test_list_issues_gets_a_console_url_per_row():
    data = {"result": [{"issue_id": 905943}, {"issue_id": 697833}], "total": 2}
    out = _attach_console_links("authmind_list_issues", {}, data, HOST)
    assert "incident_id%3A905943" in out["result"][0]["console_url"]
    assert "incident_id%3A697833" in out["result"][1]["console_url"]


def test_get_issue_details_uses_the_requested_issue_id():
    data = {"result": {}}
    out = _attach_console_links(
        "authmind_get_issue_details", {"issue_id": "905943"}, data, HOST
    )
    assert "incident_id%3A905943" in out["console_url"]


def test_list_identities_links_on_the_id_field_not_full_name():
    data = {
        "data": [
            {"id": "Acts Like Service/Service Account: praneeth (User)", "full_name": "userpass-praneeth"}
        ],
        "meta": {},
    }
    out = _attach_console_links("authmind_list_identities", {}, data, HOST)
    url = out["data"][0]["console_url"]
    assert "identity_name%3AActs" in url
    assert "userpass-praneeth" not in url


def test_list_assets_links_on_the_id_field():
    data = {"data": [{"id": "Hashicorp Vault"}], "meta": {}}
    out = _attach_console_links("authmind_list_assets", {}, data, HOST)
    assert "asset_name%3AHashicorp" in out["data"][0]["console_url"]


def test_list_secrets_links_on_the_id_field():
    data = {"data": [{"id": "pod-dynamodb-eks", "name": "pod-dynamodb-eks"}], "meta": {}}
    out = _attach_console_links("authmind_list_secrets", {}, data, HOST)
    assert "secret_name%3Apod-dynamodb-eks" in out["data"][0]["console_url"]


def test_list_accesses_reads_nested_identity_and_asset_names():
    data = {
        "data": [
            {
                "identity": {"name": "reporting-app-role"},
                "asset": {"name": "am-qa-reports"},
            }
        ],
        "meta": {},
    }
    out = _attach_console_links(
        "authmind_list_accesses",
        {"identity_name": "reporting-app-role", "asset_name": "am-qa-reports"},
        data,
        HOST,
    )
    url = out["data"][0]["console_url"]
    assert "identity_name%3Areporting-app-role" in url
    assert "asset_name%3Aam-qa-reports" in url


def test_list_accesses_filtered_by_identity_alone_gets_a_top_level_link():
    data = {"data": [], "meta": {}}
    out = _attach_console_links(
        "authmind_list_accesses", {"identity_name": "meenal.yadav@authmind.com"}, data, HOST
    )
    assert "identity_name%3Ameenal.yadav%40authmind.com" in out["console_url"]
    assert "/posture/accesses?" in out["console_url"]


def test_list_accesses_filtered_by_asset_alone_gets_a_top_level_link():
    data = {"data": [], "meta": {}}
    out = _attach_console_links(
        "authmind_list_accesses", {"asset_name": "Hashicorp Vault"}, data, HOST
    )
    assert "asset_name%3AHashicorp" in out["console_url"]


def test_list_accesses_with_no_filters_gets_no_top_level_link():
    data = {"data": [], "meta": {}}
    out = _attach_console_links("authmind_list_accesses", {}, data, HOST)
    assert "console_url" not in out


def test_get_access_details_uses_the_request_args():
    data = {"data": {}}
    out = _attach_console_links(
        "authmind_get_access_details",
        {"identity_name": "reporting-app-role", "asset_name": "am-qa-reports"},
        data,
        HOST,
    )
    assert "identity_name%3Areporting-app-role" in out["console_url"]


def test_get_asset_details_falls_back_to_asset_name_alias():
    data = {"data": {}}
    out = _attach_console_links(
        "authmind_get_asset_details",
        {"asset_name": "Hashicorp Vault", "asset_type": "Service/Application"},
        data,
        HOST,
    )
    assert "asset_name%3AHashicorp" in out["console_url"]


def test_no_host_leaves_data_untouched():
    data = {"data": [{"id": "x"}]}
    out = _attach_console_links("authmind_list_assets", {}, data, "")
    assert "console_url" not in out["data"][0]


def test_unrecognized_tool_name_is_a_noop():
    data = {"data": [{"id": "x"}]}
    out = _attach_console_links("authmind_list_playbooks", {}, data, HOST)
    assert "console_url" not in data["data"][0]


def test_missing_fields_skip_the_link_without_raising():
    data = {"data": [{"no_id_here": True}]}
    out = _attach_console_links("authmind_list_assets", {}, data, HOST)
    assert "console_url" not in out["data"][0]
