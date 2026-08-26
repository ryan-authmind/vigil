"""Unit tests for Phase 2 skill orchestration."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.skills.skill_executor import (
    execute_skill_steps,
    resolve_mcp_tool,
)
from core.skills.skill_tools_bridge import execute_skill_tool

pytestmark = pytest.mark.unit


class TestResolveMcpTool:
    def test_dot_notation(self):
        assert resolve_mcp_tool("splunk.search") == ("splunk", "search")

    def test_runtime_prefix(self):
        assert resolve_mcp_tool("splunk_search") == ("splunk", "search")

    def test_double_prefix_authmind(self):
        assert resolve_mcp_tool("authmind_authmind_list_issues") == (
            "authmind",
            "authmind_list_issues",
        )

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            resolve_mcp_tool("")


def _ok_text(payload: Any) -> Dict[str, Any]:
    import json

    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"content": [{"type": "text", "text": text}]}


@pytest.mark.asyncio
async def test_execute_skill_steps_runs_matching_and_skips_others():
    skill = {
        "name": "AuthMind Access Investigation",
        "required_tools": ["authmind_authmind_list_issue_accesses"],
        "execution_steps": [
            {
                "step_id": "1",
                "type": "mcp_tool_call",
                "tool": "authmind_authmind_list_issue_accesses",
                "when_all": ["issue_id"],
                "input_mapping": {"incident_id": "{{issue_id}}", "size": 10},
                "output_key": "issue_accesses",
            },
            {
                "step_id": "2",
                "type": "mcp_tool_call",
                "tool": "authmind_authmind_list_accesses",
                "when_any": ["identity", "asset"],
                "input_mapping": {"identity": "{{identity}}"},
                "output_key": "access_flows",
            },
        ],
    }

    mock_client = MagicMock()
    mock_client.connect_to_server = AsyncMock(return_value=True)
    mock_client.get_last_error = MagicMock(return_value=None)
    mock_client.call_tool = AsyncMock(
        return_value=_ok_text([{"identity": "jane", "asset": "Vault"}])
    )

    with patch(
        "core.integrations.mcp.client.process_mcp_client", return_value=mock_client
    ):
        out = await execute_skill_steps(skill, {"issue_id": "881710"})

    assert out["execution_status"] == "completed"
    assert "issue_accesses" in out["step_results"]
    assert out["step_results"]["issue_accesses"][0]["identity"] == "jane"
    assert any(s["step_id"] == "2" for s in out["steps_skipped"])
    mock_client.call_tool.assert_awaited()
    args = mock_client.call_tool.await_args
    assert args.args[0] == "authmind"
    assert args.args[1] == "authmind_list_issue_accesses"
    assert args.args[2]["incident_id"] == "881710"
    assert args.args[2]["size"] == 10


@pytest.mark.asyncio
async def test_execute_skill_steps_reports_connect_failure():
    skill = {
        "name": "X",
        "required_tools": ["authmind_authmind_list_issues"],
        "execution_steps": [
            {
                "step_id": "1",
                "type": "mcp_tool_call",
                "tool": "authmind_authmind_list_issues",
                "input_mapping": {"status": "Open"},
                "output_key": "issues",
                "optional": True,
            }
        ],
    }
    mock_client = MagicMock()
    mock_client.connect_to_server = AsyncMock(return_value=False)
    mock_client.get_last_error = MagicMock(return_value="spawn failed")
    mock_client.call_tool = AsyncMock()

    with patch(
        "core.integrations.mcp.client.process_mcp_client", return_value=mock_client
    ):
        out = await execute_skill_steps(skill, {})

    assert out["execution_status"] == "failed"
    assert out["servers_connected"]["authmind"]["connected"] is False
    mock_client.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_skill_tool_orchestrates_and_renders_prompt():
    skill = {
        "skill_id": "s-test",
        "name": "AuthMind Alert Qualification",
        "prompt_template": "Qualify issue {{issue_id}} for {{asset}}.",
        "required_tools": ["authmind_authmind_list_issue_accesses"],
        "execution_steps": [
            {
                "step_id": "1",
                "type": "mcp_tool_call",
                "tool": "authmind_authmind_list_issue_accesses",
                "when_all": ["issue_id"],
                "input_mapping": {"incident_id": "{{issue_id}}"},
                "output_key": "issue_accesses",
            }
        ],
    }
    mock_client = MagicMock()
    mock_client.connect_to_server = AsyncMock(return_value=True)
    mock_client.get_last_error = MagicMock(return_value=None)
    mock_client.call_tool = AsyncMock(
        return_value=_ok_text({"accesses": [{"id": 1}]})
    )

    with patch(
        "core.integrations.mcp.client.process_mcp_client", return_value=mock_client
    ):
        result = await execute_skill_tool(
            "skill_authmind_alert_qualification",
            {"issue_id": "881710", "asset": "Vault"},
            skills_by_tool_name={
                "skill_authmind_alert_qualification": skill
            },
        )

    assert result["skill_name"] == "AuthMind Alert Qualification"
    assert "881710" in result["rendered_prompt"]
    assert result["execution_status"] == "completed"
    assert result["step_results"]["issue_accesses"]["accesses"][0]["id"] == 1


@pytest.mark.asyncio
async def test_execute_skill_tool_noop_without_steps():
    skill = {
        "skill_id": "s-prompt-only",
        "name": "Prompt Only",
        "prompt_template": "Just think about {{topic}}.",
        "required_tools": [],
        "execution_steps": [],
    }
    result = await execute_skill_tool(
        "skill_prompt_only",
        {"topic": "MFA"},
        skills_by_tool_name={"skill_prompt_only": skill},
    )
    assert result["execution_status"] == "noop"
    assert result["step_results"] == {}
    assert "MFA" in result["rendered_prompt"]
