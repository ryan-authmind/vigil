"""Unit tests for extracting mitre_predictions from cached enrichment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

from core.findings.enrichment.backfill import backfill_mitre_predictions  # noqa: E402

pytestmark = pytest.mark.unit


class _FakeDataService:
    def __init__(self, findings):
        self.findings = findings
        self.writes = []

    def get_findings(self, limit=500, offset=0, include_embedding=False):
        return self.findings[offset : offset + limit]

    def update_finding(self, finding_id, **updates):
        self.writes.append((finding_id, updates))
        return True


def test_backfill_dry_run_does_not_write():
    payload = {
        "related_techniques": [{"technique_id": "T1071.001"}],
        "confidence_score": 0.8,
    }
    svc = _FakeDataService(
        [
            {
                "finding_id": "f-1",
                "mitre_predictions": {},
                "ai_enrichment": payload,
            }
        ]
    )

    backfill_mitre_predictions(apply=False, data_service=svc)

    assert svc.writes == []


def test_backfill_apply_writes_extracted_techniques():
    svc = _FakeDataService(
        [
            {
                "finding_id": "f-1",
                "mitre_predictions": {},
                "ai_enrichment": {
                    "related_techniques": [],
                    "raw_response": json.dumps(
                        {
                            "related_techniques": [{"technique_id": "T1190"}],
                            "confidence_score": 0.75,
                        }
                    ),
                },
            }
        ]
    )

    backfill_mitre_predictions(apply=True, data_service=svc)

    assert svc.writes == [("f-1", {"mitre_predictions": {"T1190": 0.75}})]


def test_backfill_skips_findings_that_already_have_technique_ids():
    svc = _FakeDataService(
        [
            {
                "finding_id": "f-1",
                "mitre_predictions": {"T1059.001": 0.9},
                "ai_enrichment": {
                    "related_techniques": [{"technique_id": "T1190"}],
                },
            }
        ]
    )

    backfill_mitre_predictions(apply=True, data_service=svc)

    assert svc.writes == []


def test_backfill_force_merges_into_existing_predictions():
    svc = _FakeDataService(
        [
            {
                "finding_id": "f-1",
                "mitre_predictions": {"T1059.001": 0.9},
                "ai_enrichment": {
                    "related_techniques": [{"technique_id": "T1190"}],
                    "confidence_score": 0.7,
                },
            }
        ]
    )

    backfill_mitre_predictions(apply=True, force=True, data_service=svc)

    assert svc.writes == [
        ("f-1", {"mitre_predictions": {"T1059.001": 0.9, "T1190": 0.7}})
    ]
