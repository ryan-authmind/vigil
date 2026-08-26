"""Runtime sync of the ``orchestrator.settings`` row into a live daemon.

The daemon used to load these limits once, in ``DaemonConfig.from_env()``, and
the periodic DB sync only re-read the ``enabled`` flag. So a cost limit saved
in Settings sat unused until the next restart while the pre-flight cost gate
kept quoting the startup value. These tests pin the sync that fixes it:

  1. Guardrails are applied, and the changed field names are reported.
  2. ``AgentRunner`` sees the new limit — it shares the config object, which
     is what makes the gate honour a saved value without a restart.
  3. ``workdir_base`` and the plan/review models are NOT hot-reloaded.
  4. A garbage value is skipped rather than stranding the other fields.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

from services.daemon.config import (  # noqa: E402
    HOT_RELOADABLE_ORCHESTRATOR_FIELDS,
    OrchestratorConfig,
    apply_orchestrator_settings,
)

pytestmark = pytest.mark.unit


def test_apply_reports_only_the_fields_that_changed():
    cfg = OrchestratorConfig()
    cfg.max_cost_per_investigation = 1.0

    changed = apply_orchestrator_settings(
        cfg,
        {
            "max_cost_per_investigation": 5.0,
            "max_iterations_per_agent": cfg.max_iterations_per_agent,
        },
    )

    assert changed == ["max_cost_per_investigation"]
    assert cfg.max_cost_per_investigation == 5.0


def test_apply_casts_values_stored_as_strings():
    cfg = OrchestratorConfig()
    cfg.max_cost_per_investigation = 1.0

    apply_orchestrator_settings(cfg, {"max_cost_per_investigation": "5.0"})

    assert cfg.max_cost_per_investigation == 5.0


def test_apply_skips_an_unusable_value_without_dropping_the_rest():
    cfg = OrchestratorConfig()
    cfg.max_cost_per_investigation = 1.0

    changed = apply_orchestrator_settings(
        cfg,
        {"max_cost_per_investigation": "not-a-number", "max_total_daily_cost": 250.0},
    )

    assert changed == ["max_total_daily_cost"]
    assert cfg.max_cost_per_investigation == 1.0


def test_hot_reload_excludes_workdir_and_the_resolved_models():
    """Swapping the workdir mid-run orphans in-flight investigations, and
    ai_model_configs — not this row — owns plan/review models (GH #89)."""
    cfg = OrchestratorConfig()
    cfg.workdir_base = "data/investigations"
    cfg.plan_model = "resolved-by-ai-model-configs"
    cfg.review_model = "resolved-by-ai-model-configs"
    cfg.max_cost_per_investigation = 1.0

    changed = apply_orchestrator_settings(
        cfg,
        {
            "workdir_base": "/tmp/elsewhere",
            "plan_model": "stale-row-value",
            "review_model": "stale-row-value",
            "max_cost_per_investigation": 5.0,
        },
        fields=HOT_RELOADABLE_ORCHESTRATOR_FIELDS,
    )

    assert changed == ["max_cost_per_investigation"]
    assert cfg.workdir_base == "data/investigations"
    assert cfg.plan_model == "resolved-by-ai-model-configs"
    assert cfg.review_model == "resolved-by-ai-model-configs"


def test_apply_replaces_auto_assign_severities():
    cfg = OrchestratorConfig()

    changed = apply_orchestrator_settings(cfg, {"auto_assign_severities": ["critical"]})

    assert changed == ["auto_assign_severities"]
    assert cfg.auto_assign_severities == ["critical"]


def test_agent_runner_sees_the_new_budget_without_a_restart():
    """The regression this exists for: the runner holds the same config
    object, so an in-place apply reaches the pre-flight gate immediately."""
    from services.daemon.agent_runner import AgentRunner

    cfg = OrchestratorConfig()
    cfg.max_cost_per_investigation = 1.0
    runner = AgentRunner(cfg, MagicMock())

    assert runner.config.max_cost_per_investigation == 1.0

    apply_orchestrator_settings(
        cfg,
        {"max_cost_per_investigation": 5.0},
        fields=HOT_RELOADABLE_ORCHESTRATOR_FIELDS,
    )

    assert runner.config.max_cost_per_investigation == 5.0
