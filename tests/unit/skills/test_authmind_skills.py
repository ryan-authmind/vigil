"""AuthMind SKILL.md files parse cleanly through the importer."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.skills.skill_importer import SkillImportError, _parse_skill_md

REPO_ROOT = Path(__file__).resolve().parents[3]
AUTHMIND_SKILLS = REPO_ROOT / "skills" / "authmind"


def _skill_md_paths() -> list[Path]:
    return sorted(AUTHMIND_SKILLS.glob("*/SKILL.md"))


@pytest.mark.unit
def test_authmind_skill_catalog_exists():
    paths = _skill_md_paths()
    assert paths, f"expected SKILL.md files under {AUTHMIND_SKILLS}"
    names = {p.parent.name for p in paths}
    assert names >= {
        "alert-qualification",
        "identity-investigation",
        "asset-investigation",
        "access-investigation",
        "secrets-credential-risk",
    }


@pytest.mark.unit
@pytest.mark.parametrize("path", _skill_md_paths(), ids=lambda p: p.parent.name)
def test_authmind_skill_md_parses(path: Path):
    name, patch = _parse_skill_md(path.read_text(encoding="utf-8"))
    assert name.startswith("AuthMind")
    assert patch["category"] in {
        "detection",
        "enrichment",
        "response",
        "reporting",
        "custom",
    }
    assert patch["prompt_template"].strip()
    assert patch["required_tools"], f"{name} should declare AuthMind MCP tools"
    assert all(t.startswith("authmind_") for t in patch["required_tools"])
    props = (patch.get("input_schema") or {}).get("properties") or {}
    assert isinstance(props, dict)
    # Phase 2: every AuthMind skill ships executable MCP steps.
    assert patch["execution_steps"], f"{name} needs execution_steps"
    for step in patch["execution_steps"]:
        assert step.get("type") == "mcp_tool_call"
        assert str(step.get("tool", "")).startswith("authmind_")
        assert step.get("output_key")


@pytest.mark.unit
def test_authmind_skill_md_rejects_empty_body(tmp_path: Path):
    bad = "---\nname: X\ncategory: enrichment\n---\n\n"
    with pytest.raises(SkillImportError):
        _parse_skill_md(bad)
