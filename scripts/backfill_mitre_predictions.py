#!/usr/bin/env python3
"""
Backfill findings.mitre_predictions from cached AI enrichment.

Enrichment already names ATT&CK techniques in related_techniques (or buried
in ai_enrichment.raw_response). Rollup, Navigator, and coverage tools read
mitre_predictions — this copies the extracted ids onto that column without
re-calling a provider.

Usage:
    python scripts/backfill_mitre_predictions.py              # dry-run
    python scripts/backfill_mitre_predictions.py --apply      # write
    python scripts/backfill_mitre_predictions.py --force      # also merge into rows with T-ids
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.findings.enrichment.backfill import backfill_mitre_predictions

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Backfill mitre_predictions from ai_enrichment"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes (default is dry-run)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Also merge into findings that already have T-ids",
    )
    args = parser.parse_args()
    backfill_mitre_predictions(apply=args.apply, force=args.force)
