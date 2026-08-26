"""Copy ATT&CK ids from cached enrichment onto ``findings.mitre_predictions``.

Does not call a provider. Historical rows stored techniques in
``ai_enrichment.related_techniques`` (or only in ``raw_response``); rollup,
Navigator, and coverage tools read the column instead.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterator

from core.findings.enrichment.parse import (
    merge_mitre_predictions,
    mitre_predictions_from_enrichment,
    normalize_technique_id,
)

logger = logging.getLogger(__name__)

BATCH_SIZE = 500


def has_technique_ids(predictions: Any) -> bool:
    if not isinstance(predictions, dict) or not predictions:
        return False
    return any(normalize_technique_id(key) for key in predictions)


def _iter_findings(data_service: Any) -> Iterator[Dict[str, Any]]:
    offset = 0
    while True:
        batch = data_service.get_findings(
            limit=BATCH_SIZE,
            offset=offset,
            include_embedding=False,
        )
        if not batch:
            return
        for finding in batch:
            yield finding
        if len(batch) < BATCH_SIZE:
            return
        offset += BATCH_SIZE


def backfill_mitre_predictions(
    *,
    apply: bool = False,
    force: bool = False,
    data_service: Any = None,
) -> Dict[str, int]:
    """Extract techniques from ``ai_enrichment`` onto ``mitre_predictions``.

    Dry-run unless ``apply`` is True. ``force`` also merges into rows that
    already have T-ids (ingest mappings are kept; enrichment only fills gaps).
    """
    if data_service is None:
        from core.storage.database_data_service import DatabaseDataService

        data_service = DatabaseDataService()

    stats = {"scanned": 0, "updated": 0, "skipped": 0, "failed": 0, "candidates": 0}

    for finding in _iter_findings(data_service):
        stats["scanned"] += 1
        finding_id = finding.get("finding_id")
        existing = finding.get("mitre_predictions") or {}
        if not force and has_technique_ids(existing):
            stats["skipped"] += 1
            continue

        extracted = mitre_predictions_from_enrichment(finding.get("ai_enrichment"))
        if not extracted:
            stats["skipped"] += 1
            continue

        merged = merge_mitre_predictions(existing, extracted)
        if merged == existing:
            stats["skipped"] += 1
            continue

        stats["candidates"] += 1
        logger.info("  %s: %s -> %s", finding_id, existing, merged)

        if not apply:
            stats["updated"] += 1
            continue

        if data_service.update_finding(finding_id, mitre_predictions=merged):
            stats["updated"] += 1
        else:
            stats["failed"] += 1
            logger.error("  Failed to update %s", finding_id)

    mode = "Updated" if apply else "Would update"
    logger.info(
        "Scanned %s findings; %s %s, skipped %s, failed %s",
        stats["scanned"],
        mode.lower(),
        stats["updated"],
        stats["skipped"],
        stats["failed"],
    )
    if not apply and stats["candidates"] > 0:
        logger.info("Run with --apply to persist changes.")
    return stats
