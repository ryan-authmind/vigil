"""Bridge: expose DB-backed Skills as Anthropic tools at agent runtime.

Issue #82 Phase 1 created the ``skills`` table + Skill Builder UI but deferred
execution: agents couldn't actually invoke what the user saved. This module
closes that gap by generating one Anthropic tool per active skill each time
an agent runs. The model sees ``skill_<slug>`` tools alongside the regular
backend and MCP toolset; when it picks one, ``execute_skill_tool`` expands
the skill's ``prompt_template`` with the provided inputs, runs any declared
``execution_steps`` against MCP (Phase 2), and returns both the rendered
prompt and structured ``step_results`` for the model to reason over.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Anthropic's hard limit on tool names is 64 characters.
_TOOL_NAME_MAX = 64
_TOOL_NAME_PREFIX = "skill_"
_SLUG_RE = re.compile(r"[^a-z0-9]+")
# Conservative placeholder pattern: {{param}} with optional whitespace.
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


def _slug_for_tool_name(name: str, skill_id: str) -> str:
    """Derive a deterministic, Anthropic-safe tool name for a skill.

    Prefer the human-readable name (so ``skill_cookie_recipe_generator``
    is what agents see), but fall back to the skill_id if the name is
    empty or slugifies to nothing.
    """
    base = _SLUG_RE.sub("_", (name or "").lower()).strip("_") or skill_id.lower()
    base = _SLUG_RE.sub("_", base).strip("_") or "skill"
    full = f"{_TOOL_NAME_PREFIX}{base}"
    return full[:_TOOL_NAME_MAX]


def _normalize_input_schema(schema: Any) -> Dict[str, Any]:
    """Return a JSON Schema object safe to attach as a tool input_schema.

    Anthropic requires ``type: object`` at the top level. Skills created
    without an explicit schema get an empty permissive object so agents
    can still invoke them.
    """
    if not isinstance(schema, dict) or not schema:
        return {"type": "object", "properties": {}}
    out = dict(schema)
    out.setdefault("type", "object")
    out.setdefault("properties", {})
    return out


def build_skill_tool(skill: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Build an Anthropic tool definition from a skill row.

    Returns ``(tool_name, tool_def)`` where ``tool_name`` is the
    prefixed slug the agent will call and ``tool_def`` is the Anthropic
    tool object to append to ``backend_tools``.
    """
    tool_name = _slug_for_tool_name(skill.get("name", ""), skill.get("skill_id", ""))
    desc_parts: List[str] = []
    if skill.get("description"):
        desc_parts.append(str(skill["description"]).strip())
    if skill.get("category"):
        desc_parts.append(f"Category: {skill['category']}.")
    required = skill.get("required_tools") or []
    if required:
        desc_parts.append(
            "Recommended upstream tools: " + ", ".join(str(t) for t in required[:6])
        )
    n_steps = len(skill.get("execution_steps") or [])
    if n_steps:
        desc_parts.append(
            f"Calling this runs {n_steps} MCP step(s) and returns "
            "structured step_results plus a rendered investigation prompt."
        )
    else:
        desc_parts.append(
            "Calling this returns the skill's rendered prompt fragment — "
            "use that as guidance for your next step."
        )
    description = " ".join(desc_parts)[:1024]

    tool_def = {
        "name": tool_name,
        "description": description,
        "input_schema": _normalize_input_schema(skill.get("input_schema")),
    }
    return tool_name, tool_def


def list_active_skill_tools() -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Fetch active skills from DB and return (tool_defs, skills_by_tool_name).

    The second element is a reverse index the executor uses to map a
    tool_name back to the original skill row without a DB round-trip.
    Failures are logged and degraded to an empty list, so a DB hiccup
    never breaks ClaudeService.
    """
    try:
        from core.skills.skill_service import SkillService

        rows = SkillService().list_skills(is_active=True)
    except Exception as e:
        logger.debug("skill_tools_bridge: could not list skills (%s)", e)
        return [], {}

    tools: List[Dict[str, Any]] = []
    by_name: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        tool_name, tool_def = build_skill_tool(row)
        # If two skill names collide, suffix the second with the id slug
        # so both remain distinct and discoverable.
        if tool_name in by_name:
            suffix = _SLUG_RE.sub("_", row.get("skill_id", "")).strip("_")
            tool_name = f"{tool_name}_{suffix}"[:_TOOL_NAME_MAX]
            tool_def["name"] = tool_name
        tools.append(tool_def)
        by_name[tool_name] = row
    return tools, by_name


def is_skill_tool_name(name: str) -> bool:
    return isinstance(name, str) and name.startswith(_TOOL_NAME_PREFIX)


def _render_prompt(template: str, inputs: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Substitute ``{{param}}`` placeholders with values from ``inputs``.

    Returns (rendered_text, list_of_missing_params). Placeholders whose
    values aren't supplied are left in place so the agent can see what
    was expected.
    """
    missing: List[str] = []

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in inputs and inputs[key] is not None:
            return str(inputs[key])
        missing.append(key)
        return match.group(0)

    rendered = _PLACEHOLDER_RE.sub(repl, template or "")
    return rendered, sorted(set(missing))


async def execute_skill_tool(
    tool_name: str,
    tool_input: Dict[str, Any],
    skills_by_tool_name: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Execute a skill tool call and return the result payload.

    Phase 2: when the skill declares ``execution_steps``, those MCP calls
    run inline and their payloads land in ``step_results``. The rendered
    prompt is always returned so the model can still produce a disposition
    / summary from the gathered evidence.

    Pass ``skills_by_tool_name`` to skip a DB lookup; otherwise we fetch
    fresh state (keeps this callable from the ARQ worker path where the
    reverse index isn't readily available).
    """
    if not is_skill_tool_name(tool_name):
        return {"error": f"Not a skill tool: {tool_name}"}

    skill: Optional[Dict[str, Any]] = None
    if skills_by_tool_name and tool_name in skills_by_tool_name:
        skill = skills_by_tool_name[tool_name]
    else:
        _, fresh = list_active_skill_tools()
        skill = fresh.get(tool_name)

    if skill is None:
        return {
            "error": (
                f"Skill tool '{tool_name}' not found or no longer active. "
                "Ask the user to check the Skills page."
            )
        }

    inputs = dict(tool_input or {})
    rendered, missing = _render_prompt(skill.get("prompt_template") or "", inputs)
    result: Dict[str, Any] = {
        "skill_id": skill.get("skill_id"),
        "skill_name": skill.get("name"),
        "rendered_prompt": rendered,
    }
    if missing:
        result["missing_inputs"] = missing
    if skill.get("required_tools"):
        result["required_tools"] = skill["required_tools"]

    exec_steps = skill.get("execution_steps") or []
    if exec_steps:
        try:
            from core.skills.skill_executor import execute_skill_steps

            orchestration = await execute_skill_steps(skill, inputs)
            result.update(orchestration)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Skill orchestration failed for %s", tool_name)
            result["execution_status"] = "failed"
            result["execution_errors"] = [
                {"error": f"{type(exc).__name__}: {exc}"}
            ]
            result["step_results"] = {}
    else:
        result["execution_status"] = "noop"
        result["step_results"] = {}

    return result
