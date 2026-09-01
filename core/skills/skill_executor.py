"""Phase 2 skill orchestration — run ``execution_steps`` against MCP.

Issue #82 Phase 1 only rendered a prompt fragment and returned
``execution_steps_hint``. This module executes those steps inline in the
chat/agent path: connect the required MCP server, call each tool, and
return structured ``step_results`` alongside the rendered prompt so the
model can reason over real data.

ARQ offload remains optional for very long skills; typical investigation
skills (1–5 MCP reads) fit the existing chat tool-loop timeout.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")

# Cap how many MCP calls a single skill invocation can make.
_MAX_STEPS = 12
_DEFAULT_TOOL_TIMEOUT = 45.0


class SkillExecutionError(Exception):
    """Raised when a non-optional step fails fatally."""


def resolve_mcp_tool(logical: str) -> Tuple[str, str]:
    """Map a skill tool reference to ``(server_name, mcp_tool_name)``.

    Accepts three conventions that already coexist in the codebase:

    * ``server.tool`` — AI skill-generator / docs style (``splunk.search``)
    * ``server_tool`` — runtime Claude tool name (``splunk_search``)
    * double-prefix — AuthMind registers tools as ``authmind_list_*``, so
      the Claude-facing name is ``authmind_authmind_list_*``
    """
    name = (logical or "").strip()
    if not name:
        raise ValueError("empty tool name")

    if "." in name and "_" not in name.split(".", 1)[0]:
        server, tool = name.split(".", 1)
        return server, tool

    if "_" not in name:
        raise ValueError(f"cannot resolve MCP tool name: {logical!r}")

    server, rest = name.split("_", 1)
    # Double-prefix: authmind_authmind_list_issues → server=authmind,
    # tool=authmind_list_issues (what the MCP server actually exports).
    if rest.startswith(f"{server}_"):
        return server, rest
    return server, rest


def _inputs_present(inputs: Dict[str, Any], keys: List[str]) -> bool:
    for key in keys:
        value = inputs.get(key)
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
    return True


def _render_value(raw: Any, inputs: Dict[str, Any], prior: Dict[str, Any]) -> Any:
    """Substitute ``{{param}}`` placeholders; leave unresolved ones intact."""
    if not isinstance(raw, str):
        return raw
    if "{{" not in raw:
        return raw

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in inputs and inputs[key] is not None:
            return str(inputs[key])
        if key in prior and prior[key] is not None:
            return str(prior[key])
        return match.group(0)

    return _PLACEHOLDER_RE.sub(repl, raw)


def _render_mapping(
    mapping: Dict[str, Any],
    inputs: Dict[str, Any],
    prior: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str]]:
    """Render step input_mapping. Returns (args, unresolved_placeholders)."""
    out: Dict[str, Any] = {}
    unresolved: List[str] = []
    for key, raw in (mapping or {}).items():
        value = _render_value(raw, inputs, prior)
        out[key] = value
        if isinstance(value, str):
            for match in _PLACEHOLDER_RE.finditer(value):
                unresolved.append(match.group(1))
    return out, sorted(set(unresolved))


def _should_run_step(step: Dict[str, Any], inputs: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (run?, skip_reason)."""
    when_all = step.get("when_all") or step.get("when_inputs") or []
    when_any = step.get("when_any") or []

    if when_all and not _inputs_present(inputs, list(when_all)):
        return False, f"missing required inputs: {', '.join(when_all)}"
    if when_any and not any(_inputs_present(inputs, [k]) for k in when_any):
        return False, f"none of optional inputs present: {', '.join(when_any)}"
    return True, ""


async def _ensure_connected(server_name: str) -> Tuple[bool, Optional[str]]:
    from core.integrations.mcp.client import process_mcp_client

    client = process_mcp_client()
    if client is None:
        return False, "MCP client not available"
    try:
        ok = await client.connect_to_server(server_name, persistent=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if ok:
        return True, None
    err = client.get_last_error(server_name) or "connect returned False"
    return False, err


async def _call_mcp(
    server_name: str,
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    timeout: float,
) -> Any:
    from core.integrations.mcp.client import process_mcp_client

    client = process_mcp_client()
    if client is None:
        return {"error": "MCP client not available"}
    return await client.call_tool(server_name, tool_name, arguments, timeout=timeout)


def _extract_content(result: Any) -> Any:
    """Normalize MCP call_tool payloads into something agents can read."""
    if not isinstance(result, dict):
        return result
    if result.get("error") and not result.get("content"):
        return result
    content = result.get("content")
    if isinstance(content, list) and len(content) == 1:
        block = content[0]
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            # AuthMind tools often return JSON strings — try to parse.
            if isinstance(text, str):
                text_stripped = text.strip()
                if text_stripped[:1] in ("{", "["):
                    try:
                        import json

                        return json.loads(text_stripped)
                    except Exception:  # noqa: BLE001
                        return text
                return text
    return result


async def execute_skill_steps(
    skill: Dict[str, Any],
    inputs: Dict[str, Any],
) -> Dict[str, Any]:
    """Run the skill's ``execution_steps`` and return structured results.

    Return shape::

        {
          "step_results": {output_key: payload, ...},
          "steps_run": [...],
          "steps_skipped": [...],
          "execution_errors": [...],
          "execution_status": "completed"|"partial"|"failed"|"noop",
          "servers_connected": {...},
        }
    """
    steps = list(skill.get("execution_steps") or [])
    if not steps:
        return {
            "step_results": {},
            "steps_run": [],
            "steps_skipped": [],
            "execution_errors": [],
            "execution_status": "noop",
            "servers_connected": {},
        }

    if len(steps) > _MAX_STEPS:
        steps = steps[:_MAX_STEPS]

    inputs = dict(inputs or {})
    step_results: Dict[str, Any] = {}
    steps_run: List[Dict[str, Any]] = []
    steps_skipped: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    servers_connected: Dict[str, Any] = {}

    # Prefetch servers from required_tools + steps so the first call is warm.
    servers_needed: List[str] = []
    for logical in skill.get("required_tools") or []:
        try:
            server, _ = resolve_mcp_tool(str(logical))
            if server not in servers_needed:
                servers_needed.append(server)
        except ValueError:
            continue
    for step in steps:
        if step.get("type", "mcp_tool_call") != "mcp_tool_call":
            continue
        try:
            server, _ = resolve_mcp_tool(str(step.get("tool") or ""))
            if server not in servers_needed:
                servers_needed.append(server)
        except ValueError:
            continue

    for server in servers_needed:
        ok, err = await _ensure_connected(server)
        servers_connected[server] = {"connected": ok, "error": err}
        if not ok:
            logger.warning(
                "Skill %s could not connect MCP server %s: %s",
                skill.get("name"),
                server,
                err,
            )

    for index, step in enumerate(steps):
        step_id = str(step.get("step_id") or index + 1)
        step_type = step.get("type") or "mcp_tool_call"
        optional = bool(step.get("optional", True))
        continue_on_error = bool(step.get("continue_on_error", True))

        if step_type != "mcp_tool_call":
            steps_skipped.append(
                {
                    "step_id": step_id,
                    "reason": f"unsupported step type: {step_type}",
                }
            )
            continue

        run, skip_reason = _should_run_step(step, inputs)
        if not run:
            steps_skipped.append({"step_id": step_id, "reason": skip_reason})
            continue

        logical_tool = str(step.get("tool") or "")
        try:
            server_name, mcp_tool = resolve_mcp_tool(logical_tool)
        except ValueError as exc:
            entry = {
                "step_id": step_id,
                "tool": logical_tool,
                "error": str(exc),
            }
            errors.append(entry)
            if not optional and not continue_on_error:
                break
            continue

        conn = servers_connected.get(server_name)
        if conn is None or not conn.get("connected"):
            ok, err = await _ensure_connected(server_name)
            servers_connected[server_name] = {"connected": ok, "error": err}
            if not ok:
                entry = {
                    "step_id": step_id,
                    "tool": logical_tool,
                    "error": f"MCP server '{server_name}' not connected: {err}",
                }
                errors.append(entry)
                steps_skipped.append({"step_id": step_id, "reason": entry["error"]})
                if not optional and not continue_on_error:
                    break
                continue

        args, unresolved = _render_mapping(
            step.get("input_mapping") or {}, inputs, step_results
        )
        if unresolved:
            if optional:
                steps_skipped.append(
                    {
                        "step_id": step_id,
                        "reason": ("unresolved placeholders: " + ", ".join(unresolved)),
                    }
                )
                continue
            entry = {
                "step_id": step_id,
                "tool": logical_tool,
                "error": f"unresolved placeholders: {', '.join(unresolved)}",
            }
            errors.append(entry)
            if not continue_on_error:
                break
            continue

        # Drop empty-string args so MCP schemas with optional fields stay clean.
        clean_args = {
            k: v
            for k, v in args.items()
            if v is not None and not (isinstance(v, str) and v.strip() == "")
        }

        timeout = float(step.get("timeout") or _DEFAULT_TOOL_TIMEOUT)
        try:
            raw = await _call_mcp(server_name, mcp_tool, clean_args, timeout=timeout)
            payload = _extract_content(raw)
            # Treat explicit MCP error envelopes as failures.
            if isinstance(payload, dict) and payload.get("error"):
                raise RuntimeError(str(payload.get("error")))
        except Exception as exc:  # noqa: BLE001
            entry = {
                "step_id": step_id,
                "tool": logical_tool,
                "server": server_name,
                "mcp_tool": mcp_tool,
                "error": f"{type(exc).__name__}: {exc}",
            }
            errors.append(entry)
            logger.warning(
                "Skill step %s (%s) failed: %s",
                step_id,
                logical_tool,
                exc,
            )
            if not optional and not continue_on_error:
                break
            continue

        output_key = str(step.get("output_key") or f"step_{step_id}")
        step_results[output_key] = payload
        steps_run.append(
            {
                "step_id": step_id,
                "tool": logical_tool,
                "server": server_name,
                "mcp_tool": mcp_tool,
                "output_key": output_key,
                "arguments": clean_args,
            }
        )

    if not steps_run and errors:
        status = "failed"
    elif errors and steps_run:
        status = "partial"
    elif steps_run:
        status = "completed"
    else:
        status = "noop"

    return {
        "step_results": step_results,
        "steps_run": steps_run,
        "steps_skipped": steps_skipped,
        "execution_errors": errors,
        "execution_status": status,
        "servers_connected": servers_connected,
    }
