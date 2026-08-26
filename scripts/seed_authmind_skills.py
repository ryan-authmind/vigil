#!/usr/bin/env python3
"""Seed / refresh AuthMind investigation skills from skills/authmind/.

Each subdirectory under ``skills/authmind/`` that contains a ``SKILL.md`` is
upserted into the ``skills`` table (create on first run, update + version bump
on name collision). Safe to re-run.

Usage (from repo root, with the API/DB available):

    python scripts/seed_authmind_skills.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.skills.skill_importer import (  # noqa: E402
    SkillImportError,
    _parse_skill_md,
)
from core.skills.skill_service import SkillService  # noqa: E402
from core.storage.connection import init_database  # noqa: E402

SKILLS_ROOT = REPO_ROOT / "skills" / "authmind"
CREATED_BY = "seed_authmind_skills"


def _iter_skill_md() -> list[Path]:
    if not SKILLS_ROOT.is_dir():
        raise SystemExit(f"Missing skills directory: {SKILLS_ROOT}")
    paths = sorted(SKILLS_ROOT.glob("*/SKILL.md"))
    if not paths:
        raise SystemExit(f"No SKILL.md files under {SKILLS_ROOT}")
    return paths


def _find_by_name(svc: SkillService, name: str):
    for row in svc.list_skills():
        if row.get("name") == name:
            return row
    return None


def main() -> int:
    init_database()
    svc = SkillService()
    created = updated = 0

    for path in _iter_skill_md():
        text = path.read_text(encoding="utf-8")
        try:
            name, patch = _parse_skill_md(text)
        except SkillImportError as exc:
            print(f"FAIL  {path.relative_to(REPO_ROOT)}: {exc.message}")
            return 1

        existing = _find_by_name(svc, name)
        if existing is None:
            row = svc.create_skill(patch, created_by=CREATED_BY)
            created += 1
            action = "created"
        else:
            row = svc.update_skill(existing["skill_id"], patch)
            updated += 1
            action = "updated"

        print(
            f"{action:8} {row['skill_id']}  v{row['version']}  "
            f"{row['name']}  ({path.parent.name})"
        )

    print(f"Done. created={created} updated={updated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
